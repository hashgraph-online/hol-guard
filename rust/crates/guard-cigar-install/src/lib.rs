//! Locked wheel preparation. No package resolver, Python installer, process
//! launch, network access, selected-runtime mutation or execution approval.
#![forbid(unsafe_code)]

mod paths;
mod python_bundle;
mod python_tree;
pub use python_bundle::prepare_python;
pub use python_tree::{verify_python_tree, VerifiedPythonBundle};
mod slot;
pub use slot::{slot_id, slot_id_with_python};
mod wheel;

use guard_cigar_release::ResolvedRelease;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::{atomic::AtomicBool, Arc};
#[cfg(test)]
use std::time::Duration;

const MAX_FILES: usize = 8192;
const MAX_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;

pub use guard_cigar_artifacts::{InstallError, PreparationControl, VerifiedPythonSnapshot};

#[derive(Clone)]
struct FileContent {
    bytes: Vec<u8>,
    executable: bool,
}

/// Only the exact trusted SDK/dependency lock can construct a plan. Validation
/// and the complete pinned tree digest finish before any output is written.
pub struct BundlePlan {
    files: BTreeMap<String, FileContent>,
    bytes: u64,
    tree_sha256: String,
}
impl BundlePlan {
    pub fn files(&self) -> usize {
        self.files.len()
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn tree_sha256(&self) -> &str {
        &self.tree_sha256
    }

    /// The native owner supplies a fresh, private, canonical staging directory.
    /// Failure may leave partial staging bytes, never an installation record.
    /// Its owner must journal/clean that one staging directory before retrying.
    pub fn write_into(
        &self,
        root: &Path,
        control: &PreparationControl,
    ) -> Result<(), InstallError> {
        control.checkpoint()?;
        paths::private_directory(root)?;
        if fs::read_dir(root)
            .map_err(|_| InstallError::DestinationUnsafe)?
            .next()
            .is_some()
        {
            return Err(InstallError::DestinationNotEmpty);
        }
        let mut directories = std::collections::BTreeSet::from([root.to_path_buf()]);
        for (name, content) in &self.files {
            control.checkpoint()?;
            let path = root.join(name);
            let relative = Path::new(name);
            let mut directory = root.to_path_buf();
            if let Some(parent) = relative.parent() {
                for part in parent.components() {
                    directory.push(part);
                    paths::private_child(&directory)?;
                    directories.insert(directory.clone());
                }
            }
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&path).map_err(|_| InstallError::WriteFailed)?;
            for chunk in content.bytes.chunks(64 * 1024) {
                control.checkpoint()?;
                file.write_all(chunk)
                    .map_err(|_| InstallError::WriteFailed)?;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(fs::Permissions::from_mode(if content.executable {
                    0o500
                } else {
                    0o400
                }))
                .map_err(|_| InstallError::WriteFailed)?;
            }
            file.sync_all().map_err(|_| InstallError::WriteFailed)?;
        }
        for directory in directories.iter().rev() {
            control.checkpoint()?;
            fs::File::open(directory)
                .and_then(|file| file.sync_all())
                .map_err(|_| InstallError::WriteFailed)?;
        }
        control.checkpoint()?;
        Ok(())
    }
}

/// Paths are native/operator-owned acquisition results, never browser supplied.
/// Extra/missing filenames, source builds and dependency resolution are refused.
pub fn prepare_locked(
    release: &ResolvedRelease,
    inputs: &BTreeMap<String, PathBuf>,
    control: &PreparationControl,
) -> Result<BundlePlan, InstallError> {
    control.checkpoint()?;
    let artifact = release.platform();
    let sdk = artifact.wheel.as_ref().ok_or(InstallError::InputsInvalid)?;
    let locks: Vec<_> = std::iter::once(sdk).chain(&artifact.dependencies).collect();
    if locks.len() != inputs.len()
        || locks
            .iter()
            .any(|lock| !inputs.contains_key(&lock.filename))
    {
        return Err(InstallError::InputsInvalid);
    }
    let mut files = BTreeMap::new();
    let mut namespace = BTreeMap::new();
    let mut compressed = 0u64;
    let mut total = 0u64;
    for lock in locks {
        control.checkpoint()?;
        compressed = compressed
            .checked_add(lock.bytes)
            .ok_or(InstallError::LimitExceeded)?;
        if compressed > MAX_BYTES {
            return Err(InstallError::LimitExceeded);
        }
        let input =
            guard_secure_fs::read_stable(&inputs[&lock.filename], MAX_FILE_BYTES as usize, false)
                .map_err(|_| InstallError::ArtifactUnreadable)?;
        control.checkpoint()?;
        if input.sha256 != lock.sha256 || input.bytes.len() as u64 != lock.bytes {
            return Err(InstallError::ArtifactMismatch);
        }
        wheel::read(
            &input.bytes,
            lock,
            &mut files,
            &mut namespace,
            &mut total,
            control,
        )?;
    }
    let mut digest = Sha256::new();
    digest.update(b"guard-cigar-package-tree.v1\0");
    for (name, content) in &files {
        control.checkpoint()?;
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update(format!("{:x}", Sha256::digest(&content.bytes)).as_bytes());
    }
    let tree_sha256 = format!("{:x}", digest.finalize());
    if artifact.package_tree_sha256.as_deref() != Some(&tree_sha256) {
        return Err(InstallError::TreeMismatch);
    }
    Ok(BundlePlan {
        files,
        bytes: total,
        tree_sha256,
    })
}

#[cfg(test)]
mod tests;
