//! Verify the complete immutable private interpreter before native use.
use crate::python_snapshot::{stamp, Stamp, VerifiedPythonSnapshot};
use crate::{paths, InstallError, PreparationControl, MAX_BYTES, MAX_FILES, MAX_FILE_BYTES};
use guard_cigar_release::{InterpreterBinding, ResolvedInterpreterBuild};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

/// Only a resolved trusted build plus complete protected-byte verification
/// construct this capability. It is not an activation or execution grant.
pub struct VerifiedPythonBundle {
    build: ResolvedInterpreterBuild,
    tree: PythonTree,
}
struct PythonTree {
    root: PathBuf,
    executable: PathBuf,
    files: usize,
    bytes: u64,
    tree_sha256: String,
    snapshot: VerifiedPythonSnapshot,
}
impl VerifiedPythonBundle {
    pub fn snapshot(&self) -> &VerifiedPythonSnapshot {
        &self.tree.snapshot
    }
    pub fn build(&self) -> &ResolvedInterpreterBuild {
        &self.build
    }
    pub fn root(&self) -> &Path {
        &self.tree.root
    }
    pub fn executable(&self) -> &Path {
        &self.tree.executable
    }
    pub fn files(&self) -> usize {
        self.tree.files
    }
    pub fn bytes(&self) -> u64 {
        self.tree.bytes
    }
    pub fn tree_sha256(&self) -> &str {
        &self.tree.tree_sha256
    }
}

pub fn verify_python_tree(
    build: &ResolvedInterpreterBuild,
    root: &Path,
    control: &PreparationControl,
) -> Result<VerifiedPythonBundle, InstallError> {
    let expected = build
        .build()
        .binding()
        .map_err(|_| InstallError::InputsInvalid)?;
    let tree = verify(&expected, root, &|| control.checkpoint())?;
    Ok(VerifiedPythonBundle {
        build: build.clone(),
        tree,
    })
}

/// Recheck a host-approved binding before process launch. Serialized claims
/// alone cannot construct a verified-installation capability through this API.
pub fn check_python_binding(
    expected: &InterpreterBinding,
    root: &Path,
    cancel: Option<&AtomicBool>,
) -> Result<(), InstallError> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let checkpoint = || {
        if cancel.is_some_and(|value| value.load(Ordering::Acquire)) {
            return Err(InstallError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(InstallError::DeadlineExceeded);
        }
        Ok(())
    };
    verify(expected, root, &checkpoint).map(|_| ())
}

/// Full protected-byte verification, yielding only a process-local artifact
/// cache. It is neither an installed-build receipt nor execution authority.
pub fn verify_python_binding(
    expected: &InterpreterBinding,
    root: &Path,
    cancel: Option<&AtomicBool>,
) -> Result<VerifiedPythonSnapshot, InstallError> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let checkpoint = || {
        if cancel.is_some_and(|value| value.load(Ordering::Acquire)) {
            return Err(InstallError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(InstallError::DeadlineExceeded);
        }
        Ok(())
    };
    verify(expected, root, &checkpoint).map(|tree| tree.snapshot)
}

pub(super) fn check_python_controlled(
    expected: &InterpreterBinding,
    root: &Path,
    checkpoint: &dyn Fn() -> Result<(), InstallError>,
) -> Result<(), InstallError> {
    verify(expected, root, checkpoint).map(|_| ())
}

fn verify(
    expected: &InterpreterBinding,
    root: &Path,
    checkpoint: &dyn Fn() -> Result<(), InstallError>,
) -> Result<PythonTree, InstallError> {
    checkpoint()?;
    expected
        .validate()
        .map_err(|_| InstallError::InputsInvalid)?;
    paths::private_directory(root)?;
    #[cfg(unix)]
    let root_before = fs::symlink_metadata(root).map_err(|_| InstallError::DestinationUnsafe)?;
    let mut scan = Walk {
        root,
        checkpoint,
        files: BTreeMap::new(),
        directories: Vec::new(),
        namespace: BTreeMap::new(),
        entries: BTreeMap::new(),
        total: 0,
    };
    scan.walk(root, 0)?;
    for directory in &scan.directories {
        if !scan
            .files
            .keys()
            .any(|name: &String| name.starts_with(&format!("{directory}/")))
        {
            return Err(InstallError::TreeMismatch);
        }
    }
    let mut digest = Sha256::new();
    digest.update(b"guard-cigar-python-tree.v1\0");
    for (name, hash) in &scan.files {
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update(hash.as_bytes());
    }
    let tree_sha256 = format!("{:x}", digest.finalize());
    if tree_sha256 != expected.tree_sha256
        || scan.files.len() != expected.files as usize
        || scan.total != expected.expanded_bytes
        || scan.files.get(expected.executable()) != Some(&expected.executable_sha256)
    {
        return Err(InstallError::TreeMismatch);
    }
    let executable = root.join(expected.executable());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if fs::symlink_metadata(&executable)
            .map_err(|_| InstallError::ArtifactUnreadable)?
            .mode()
            & 0o777
            != 0o500
        {
            return Err(InstallError::DestinationUnsafe);
        }
    }
    paths::private_directory(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let after = fs::symlink_metadata(root).map_err(|_| InstallError::DestinationUnsafe)?;
        if (
            root_before.dev(),
            root_before.ino(),
            root_before.ctime(),
            root_before.ctime_nsec(),
            root_before.mode(),
        ) != (
            after.dev(),
            after.ino(),
            after.ctime(),
            after.ctime_nsec(),
            after.mode(),
        ) {
            return Err(InstallError::DestinationUnsafe);
        }
    }
    let snapshot = VerifiedPythonSnapshot::new(root, expected, scan.entries);
    snapshot.recheck_with(checkpoint)?;
    checkpoint()?;
    Ok(PythonTree {
        root: root.into(),
        executable,
        files: scan.files.len(),
        bytes: scan.total,
        tree_sha256,
        snapshot,
    })
}

struct Walk<'a> {
    root: &'a Path,
    checkpoint: &'a dyn Fn() -> Result<(), InstallError>,
    files: BTreeMap<String, String>,
    directories: Vec<String>,
    namespace: BTreeMap<String, (String, bool)>,
    total: u64,
    entries: BTreeMap<String, Stamp>,
}
impl Walk<'_> {
    fn walk(&mut self, path: &Path, depth: usize) -> Result<(), InstallError> {
        (self.checkpoint)()?;
        if depth > 24 || self.files.len() + self.directories.len() > MAX_FILES {
            return Err(InstallError::LimitExceeded);
        }
        paths::private_directory(path)?;
        let directory_before =
            stamp(&fs::symlink_metadata(path).map_err(|_| InstallError::DestinationUnsafe)?)?;
        for entry in fs::read_dir(path).map_err(|_| InstallError::ArtifactUnreadable)? {
            (self.checkpoint)()?;
            let path = entry.map_err(|_| InstallError::ArtifactUnreadable)?.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|_| InstallError::ArtifactUnreadable)?;
            let name = path
                .strip_prefix(self.root)
                .ok()
                .and_then(|p| p.to_str())
                .ok_or(InstallError::EntryUnsafe)?;
            if metadata.file_type().is_symlink() {
                return Err(InstallError::EntryUnsafe);
            }
            if metadata.is_dir() {
                let name = paths::admit_interpreter_name(
                    format!("{name}/").as_bytes(),
                    true,
                    &mut self.namespace,
                )?;
                self.directories.push(name);
                self.walk(&path, depth + 1)?;
            } else if metadata.is_file() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if metadata.uid() != nix::unistd::geteuid().as_raw()
                        || !matches!(metadata.mode() & 0o777, 0o400 | 0o500)
                    {
                        return Err(InstallError::DestinationUnsafe);
                    }
                }
                let name =
                    paths::admit_interpreter_name(name.as_bytes(), false, &mut self.namespace)?;
                if metadata.len() > MAX_FILE_BYTES {
                    return Err(InstallError::LimitExceeded);
                }
                self.total = self
                    .total
                    .checked_add(metadata.len())
                    .ok_or(InstallError::LimitExceeded)?;
                if self.total > MAX_BYTES || self.files.len() >= MAX_FILES {
                    return Err(InstallError::LimitExceeded);
                }
                let content = guard_secure_fs::read_stable(&path, MAX_FILE_BYTES as usize, false)
                    .map_err(|_| InstallError::ArtifactUnreadable)?;
                (self.checkpoint)()?;
                let after = stamp(
                    &fs::symlink_metadata(&path).map_err(|_| InstallError::ArtifactUnreadable)?,
                )?;
                if stamp(&metadata)? != after {
                    return Err(InstallError::ArtifactMismatch);
                }
                self.entries.insert(name.clone(), after);
                self.files.insert(name, content.sha256);
            } else {
                return Err(InstallError::EntryUnsafe);
            }
        }
        let after =
            stamp(&fs::symlink_metadata(path).map_err(|_| InstallError::DestinationUnsafe)?)?;
        if directory_before != after {
            return Err(InstallError::DestinationUnsafe);
        }
        let relative = path
            .strip_prefix(self.root)
            .ok()
            .and_then(|value| value.to_str())
            .ok_or(InstallError::EntryUnsafe)?;
        self.entries.insert(relative.into(), after);
        Ok(())
    }
}
