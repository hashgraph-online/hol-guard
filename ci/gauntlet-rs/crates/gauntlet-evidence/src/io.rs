//! Descriptor-relative, read-only directory access for public evidence.

use crate::{EvidenceError, Result};
use gauntlet_contracts::MAX_RECORD_BYTES;
use rustix::fs::{fstat, open, openat, Dir, FileType, Mode, OFlags};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

const MAX_FILES: usize = 2048;
const MAX_ENTRIES: usize = MAX_FILES * 2;
const MAX_DEPTH: usize = 8;

pub struct BundleReader {
    root: OwnedFd,
}

fn segment_ok(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() <= 128
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes[1..]
            .iter()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'_' | b'-' | b'.'))
        && value != "."
        && value != ".."
}

pub fn valid_bundle_path(value: &str) -> bool {
    if value.len() > 512 || !value.ends_with(".json") || value.contains('\\') {
        return false;
    }
    let segments: Vec<_> = value.split('/').collect();
    !segments.is_empty() && segments.len() <= MAX_DEPTH && segments.iter().all(|s| segment_ok(s))
}

fn open_directory_at(root: &OwnedFd, name: &str) -> Result<OwnedFd> {
    openat(
        root,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| EvidenceError::Io(error.to_string()))
}

impl BundleReader {
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            root: open_absolute_directory(path)?,
        })
    }

    pub fn list_files(&self) -> Result<BTreeSet<String>> {
        let mut files = BTreeSet::new();
        let mut entries_seen = 0;
        scan(&self.root, "", 0, &mut files, &mut entries_seen)?;
        Ok(files)
    }

    pub fn read_file(&self, name: &str) -> Result<Vec<u8>> {
        if !valid_bundle_path(name) {
            return Err(EvidenceError::Invalid("unsafe bundle path"));
        }
        let parts: Vec<_> = name.split('/').collect();
        let mut parent = openat(
            &self.root,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| EvidenceError::Io(error.to_string()))?;
        for part in &parts[..parts.len() - 1] {
            parent = open_directory_at(&parent, part)?;
        }
        let fd = openat(
            &parent,
            parts[parts.len() - 1],
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| EvidenceError::Io(error.to_string()))?;
        let before = fstat(&fd).map_err(|error| EvidenceError::Io(error.to_string()))?;
        if !FileType::from_raw_mode(before.st_mode).is_file()
            || before.st_size < 0
            || before.st_size as usize > MAX_RECORD_BYTES
        {
            return Err(EvidenceError::Invalid(
                "nonregular or oversized bundle file",
            ));
        }
        let mut file = File::from(fd);
        let mut raw = Vec::with_capacity(before.st_size as usize);
        file.by_ref()
            .take((MAX_RECORD_BYTES + 1) as u64)
            .read_to_end(&mut raw)
            .map_err(|error| EvidenceError::Io(error.to_string()))?;
        let after = file
            .metadata()
            .map_err(|error| EvidenceError::Io(error.to_string()))?;
        if raw.len() > MAX_RECORD_BYTES
            || raw.len() != before.st_size as usize
            || after.len() != raw.len() as u64
        {
            return Err(EvidenceError::Invalid(
                "bundle file changed or exceeded its byte limit",
            ));
        }
        Ok(raw)
    }
}

pub(crate) fn open_absolute_directory(path: &Path) -> Result<OwnedFd> {
    if !path.is_absolute() {
        return Err(EvidenceError::Invalid("absolute bundle root required"));
    }
    let literal = path
        .to_str()
        .ok_or(EvidenceError::Invalid("noncanonical bundle root"))?;
    if literal != "/"
        && !literal.strip_prefix('/').is_some_and(|relative| {
            !relative.is_empty()
                && relative
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != "..")
        })
    {
        return Err(EvidenceError::Invalid("noncanonical bundle root"));
    }
    let mut root = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| EvidenceError::Io(error.to_string()))?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                root = openat(
                    &root,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| EvidenceError::Io(error.to_string()))?;
            }
            _ => return Err(EvidenceError::Invalid("noncanonical bundle root")),
        }
    }
    Ok(root)
}

fn scan(
    fd: &OwnedFd,
    prefix: &str,
    depth: usize,
    files: &mut BTreeSet<String>,
    entries_seen: &mut usize,
) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(EvidenceError::Invalid(
            "bundle directory exceeds depth limit",
        ));
    }
    let entries = Dir::read_from(fd).map_err(|error| EvidenceError::Io(error.to_string()))?;
    for entry in entries {
        let entry = entry.map_err(|error| EvidenceError::Io(error.to_string()))?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| EvidenceError::Invalid("non-UTF-8 bundle entry"))?;
        if matches!(name, "." | "..") {
            continue;
        }
        *entries_seen += 1;
        if *entries_seen > MAX_ENTRIES || !segment_ok(name) {
            return Err(EvidenceError::Invalid(
                "invalid or excessive bundle entries",
            ));
        }
        let path = format!("{prefix}{name}");
        let opened = openat(
            fd,
            entry.file_name(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| EvidenceError::Io(error.to_string()))?;
        let stat = fstat(&opened).map_err(|error| EvidenceError::Io(error.to_string()))?;
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => {
                if depth + 1 > MAX_DEPTH {
                    return Err(EvidenceError::Invalid(
                        "bundle directory exceeds depth limit",
                    ));
                }
                scan(&opened, &format!("{path}/"), depth + 1, files, entries_seen)?;
            }
            FileType::RegularFile => {
                if !valid_bundle_path(&path) || !files.insert(path) || files.len() > MAX_FILES {
                    return Err(EvidenceError::Invalid("invalid or excessive bundle files"));
                }
            }
            _ => return Err(EvidenceError::Invalid("nonregular bundle entry")),
        }
    }
    Ok(())
}
