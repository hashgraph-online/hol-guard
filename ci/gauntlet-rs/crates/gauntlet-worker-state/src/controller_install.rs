//! Fixed, isolated Root-owned controller install from already-pinned inert
//! source bytes. It creates a new generation and never executes controller code.

use gauntlet_contracts::is_git_sha;
use gauntlet_evidence::{plan_controller_install, verify_controller_tree};
use rustix::fs::{
    fchmod, fstat, fsync, mkdirat, open, openat, renameat_with, statat, AtFlags, FileType, Mode,
    OFlags, RenameFlags, Stat,
};
use rustix::io::Errno;
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

const BASE: &str = "/opt/hol-gauntlet";
const MAX_SOURCE_BYTES: usize = 64 * 1024 * 1024;
const MAX_FILE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerInstallError {
    RootRequired,
    InvalidPins,
    UnsafeSource,
    SourceChanged,
    SourceMismatch,
    TooLarge,
    UnsafeParent,
    ExistingInstall,
    CreateFailed,
    VerifyFailed,
    RenameFailed,
}

impl fmt::Display for ControllerInstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux ARM Root required for isolated controller install",
            Self::InvalidPins => "invalid commit, source map or controller tree pin",
            Self::UnsafeSource => "transferred controller source is unsafe or incomplete",
            Self::SourceChanged => "transferred controller source changed during read",
            Self::SourceMismatch => "transferred source differs from the pinned Git map",
            Self::TooLarge => "transferred controller source exceeds byte bounds",
            Self::UnsafeParent => "fixed controller parent is not exclusively Root controlled",
            Self::ExistingInstall => "controller generation or partial install already exists",
            Self::CreateFailed => "isolated controller tree could not be written",
            Self::VerifyFailed => "new Root-owned controller tree differs from its outside pin",
            Self::RenameFailed => "verified controller tree could not be published exclusively",
        })
    }
}

impl std::error::Error for ControllerInstallError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerInstallProof {
    pub source_sha: String,
    pub source_files: usize,
    pub source_bytes: usize,
    pub installed_files: usize,
    pub controller_path: String,
    pub controller_tree_digest: String,
}

impl ControllerInstallProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-controller-install-shadow.v1",
            "source_sha":self.source_sha,
            "source_files":self.source_files,
            "source_bytes":self.source_bytes,
            "installed_files":self.installed_files,
            "controller_path":self.controller_path,
            "controller_tree_digest":self.controller_tree_digest,
            "controller_executed":false,
            "outside_pin_provenance_verified":false,
            "execution_eligible":false,
        })
    }
}

fn hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn same_file(first: &Stat, second: &Stat) -> bool {
    first.st_dev == second.st_dev
        && first.st_ino == second.st_ino
        && first.st_mode == second.st_mode
        && first.st_uid == second.st_uid
        && first.st_nlink == second.st_nlink
        && first.st_size == second.st_size
        && first.st_mtime == second.st_mtime
        && first.st_mtime_nsec == second.st_mtime_nsec
        && first.st_ctime == second.st_ctime
        && first.st_ctime_nsec == second.st_ctime_nsec
}

fn open_source_root(path: &Path) -> Result<OwnedFd, ControllerInstallError> {
    if !path.is_absolute()
        || path
            .canonicalize()
            .map_err(|_| ControllerInstallError::UnsafeSource)?
            != path
    {
        return Err(ControllerInstallError::UnsafeSource);
    }
    let mut directory = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ControllerInstallError::UnsafeSource)?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = openat(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| ControllerInstallError::UnsafeSource)?;
            }
            _ => return Err(ControllerInstallError::UnsafeSource),
        }
    }
    Ok(directory)
}

fn read_source_file(root: &OwnedFd, path: &str) -> Result<Vec<u8>, ControllerInstallError> {
    let mut components = path.split('/').peekable();
    let mut directory = openat(
        root,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ControllerInstallError::UnsafeSource)?;
    while let Some(component) = components.next() {
        if components.peek().is_some() {
            directory = openat(
                &directory,
                component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| ControllerInstallError::UnsafeSource)?;
        } else {
            let descriptor = openat(
                &directory,
                component,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| ControllerInstallError::UnsafeSource)?;
            let before = fstat(&descriptor).map_err(|_| ControllerInstallError::UnsafeSource)?;
            if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
                || before.st_nlink != 1
                || before.st_size < 0
            {
                return Err(ControllerInstallError::UnsafeSource);
            }
            if before.st_size as usize > MAX_FILE_BYTES {
                return Err(ControllerInstallError::TooLarge);
            }
            let mut file = File::from(descriptor);
            let mut bytes = Vec::with_capacity(before.st_size as usize);
            Read::by_ref(&mut file)
                .take((MAX_FILE_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| ControllerInstallError::UnsafeSource)?;
            let after = fstat(&file).map_err(|_| ControllerInstallError::SourceChanged)?;
            let visible = statat(&directory, component, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| ControllerInstallError::SourceChanged)?;
            if !same_file(&before, &after)
                || !same_file(&before, &visible)
                || bytes.len() as i64 != before.st_size
            {
                return Err(ControllerInstallError::SourceChanged);
            }
            return Ok(bytes);
        }
    }
    Err(ControllerInstallError::UnsafeSource)
}

fn root_directory(fd: &OwnedFd) -> Result<(), ControllerInstallError> {
    let stat = fstat(fd).map_err(|_| ControllerInstallError::UnsafeParent)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_mode & 0o022 != 0
    {
        return Err(ControllerInstallError::UnsafeParent);
    }
    Ok(())
}

fn open_install_parent() -> Result<OwnedFd, ControllerInstallError> {
    let parent = open(
        BASE,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ControllerInstallError::UnsafeParent)?;
    root_directory(&parent)?;
    Ok(parent)
}

fn absent(parent: &OwnedFd, name: &str) -> Result<(), ControllerInstallError> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => Ok(()),
        Ok(_) => Err(ControllerInstallError::ExistingInstall),
        Err(_) => Err(ControllerInstallError::UnsafeParent),
    }
}

fn write_installed_file(
    stage: &OwnedFd,
    path: &str,
    bytes: &[u8],
) -> Result<(), ControllerInstallError> {
    let mut components = path.split('/').peekable();
    let mut directory = openat(
        stage,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ControllerInstallError::CreateFailed)?;
    while let Some(component) = components.next() {
        if components.peek().is_some() {
            match mkdirat(&directory, component, Mode::from_bits_truncate(0o700)) {
                Ok(()) => {
                    let created = openat(
                        &directory,
                        component,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_| ControllerInstallError::CreateFailed)?;
                    fchmod(&created, Mode::from_bits_truncate(0o755))
                        .map_err(|_| ControllerInstallError::CreateFailed)?;
                    fsync(&directory).map_err(|_| ControllerInstallError::CreateFailed)?;
                    directory = created;
                }
                Err(Errno::EXIST) => {
                    directory = openat(
                        &directory,
                        component,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_| ControllerInstallError::CreateFailed)?;
                    root_directory(&directory).map_err(|_| ControllerInstallError::CreateFailed)?;
                }
                Err(_) => return Err(ControllerInstallError::CreateFailed),
            }
        } else {
            let descriptor = openat(
                &directory,
                component,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(|_| ControllerInstallError::CreateFailed)?;
            let mut file = File::from(descriptor);
            file.write_all(bytes)
                .map_err(|_| ControllerInstallError::CreateFailed)?;
            fchmod(&file, Mode::from_bits_truncate(0o444))
                .map_err(|_| ControllerInstallError::CreateFailed)?;
            file.sync_all()
                .map_err(|_| ControllerInstallError::CreateFailed)?;
            fsync(&directory).map_err(|_| ControllerInstallError::CreateFailed)?;
            return Ok(());
        }
    }
    Err(ControllerInstallError::CreateFailed)
}

/// Install one new, non-replacing controller generation under the fixed
/// `/opt/hol-gauntlet` parent. All source bytes are read and hashed into memory
/// before the first write; an uncertain partial generation is retained for
/// inspection. The caller must provide reviewed, outside source/tree pins.
pub fn install_fixed_controller(
    source_root: &Path,
    source_sha: &str,
    source_hashes: &BTreeMap<String, String>,
    expected_tree_digest: &str,
) -> Result<ControllerInstallProof, ControllerInstallError> {
    if geteuid().as_raw() != 0 {
        return Err(ControllerInstallError::RootRequired);
    }
    if !is_git_sha(source_sha) || !hex_sha256(expected_tree_digest) {
        return Err(ControllerInstallError::InvalidPins);
    }
    let plan =
        plan_controller_install(source_hashes).map_err(|_| ControllerInstallError::InvalidPins)?;
    if plan.tree_digest != expected_tree_digest {
        return Err(ControllerInstallError::InvalidPins);
    }
    let source = open_source_root(source_root)?;
    let mut files = BTreeMap::new();
    let mut source_bytes = 0usize;
    for (path, hash) in source_hashes {
        let bytes = read_source_file(&source, path)?;
        source_bytes = source_bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= MAX_SOURCE_BYTES)
            .ok_or(ControllerInstallError::TooLarge)?;
        if format!("{:x}", Sha256::digest(&bytes)) != *hash {
            return Err(ControllerInstallError::SourceMismatch);
        }
        if plan.installed_files.contains_key(path) {
            files.insert(path.clone(), bytes);
        }
    }
    let parent = open_install_parent()?;
    let generation = &source_sha[..16];
    let name = format!("controller-{generation}");
    let partial = format!("{name}.partial");
    absent(&parent, &name)?;
    absent(&parent, &partial)?;
    mkdirat(&parent, partial.as_str(), Mode::from_bits_truncate(0o700)).map_err(|error| {
        if error == Errno::EXIST {
            ControllerInstallError::ExistingInstall
        } else {
            ControllerInstallError::CreateFailed
        }
    })?;
    let stage = openat(
        &parent,
        partial.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ControllerInstallError::CreateFailed)?;
    root_directory(&stage).map_err(|_| ControllerInstallError::CreateFailed)?;
    for (path, bytes) in &files {
        write_installed_file(&stage, path, bytes)?;
    }
    fchmod(&stage, Mode::from_bits_truncate(0o755))
        .map_err(|_| ControllerInstallError::CreateFailed)?;
    fsync(&stage).map_err(|_| ControllerInstallError::CreateFailed)?;
    let partial_path = Path::new(BASE).join(&partial);
    verify_controller_tree(&partial_path, expected_tree_digest)
        .map_err(|_| ControllerInstallError::VerifyFailed)?;
    renameat_with(
        &parent,
        partial.as_str(),
        &parent,
        name.as_str(),
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| ControllerInstallError::RenameFailed)?;
    fsync(&parent).map_err(|_| ControllerInstallError::RenameFailed)?;
    let installed_path = Path::new(BASE).join(&name);
    verify_controller_tree(&installed_path, expected_tree_digest)
        .map_err(|_| ControllerInstallError::VerifyFailed)?;
    Ok(ControllerInstallProof {
        source_sha: source_sha.to_owned(),
        source_files: source_hashes.len(),
        source_bytes,
        installed_files: files.len(),
        controller_path: installed_path.to_string_lossy().into_owned(),
        controller_tree_digest: expected_tree_digest.to_owned(),
    })
}
