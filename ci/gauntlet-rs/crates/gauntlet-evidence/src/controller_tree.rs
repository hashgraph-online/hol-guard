//! Read-only whole-controller custody. The expected digest must be supplied
//! by a reviewed install channel outside the candidate and this tree.

use crate::crypto::is_sha256;
use crate::tree_inventory::{inventory_tree, TreeKind};
use crate::{EvidenceError, Result};
use rustix::fs::{fstat, open, openat, FileType, Mode, OFlags};
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedControllerTree {
    root: PathBuf,
    digest: String,
    entries: usize,
    bytes: u64,
}

impl VerifiedControllerTree {
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn entries(&self) -> usize {
        self.entries
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

fn root_owned_directory(descriptor: &OwnedFd) -> Result<()> {
    let stat = fstat(descriptor).map_err(|error| EvidenceError::Io(error.to_string()))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_mode & 0o022 != 0
    {
        return Err(EvidenceError::Invalid(
            "controller ancestry is not exclusively Root controlled",
        ));
    }
    Ok(())
}

fn root_owned_ancestry(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(EvidenceError::Invalid("absolute controller root required"));
    }
    let mut descriptor = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| EvidenceError::Io(error.to_string()))?;
    root_owned_directory(&descriptor)?;
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => {
                descriptor = openat(
                    &descriptor,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| EvidenceError::Io(error.to_string()))?;
                root_owned_directory(&descriptor)?;
            }
            _ => return Err(EvidenceError::Invalid("noncanonical controller root")),
        }
    }
    Ok(())
}

/// Compare the complete Root-owned tree's path, mode, ownership and bytes to
/// one outside digest. Extra files, symlinks, hardlinks, mutable files and
/// changed bytes fail closed. This is an inspection result, not proof that a
/// future child actually executed these bytes.
pub fn verify_controller_tree(
    root: &Path,
    expected_digest: &str,
) -> Result<VerifiedControllerTree> {
    if !cfg!(target_os = "linux") || !is_sha256(expected_digest) {
        return Err(EvidenceError::Invalid(
            "Linux controller and outside SHA-256 pin required",
        ));
    }
    root_owned_ancestry(root)?;
    let inventory = inventory_tree(root, TreeKind::Controller)?;
    if inventory.digest != expected_digest {
        return Err(EvidenceError::Invalid(
            "controller tree differs from outside digest",
        ));
    }
    Ok(VerifiedControllerTree {
        root: root.to_owned(),
        digest: inventory.digest,
        entries: inventory.entries,
        bytes: inventory.bytes,
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use rustix::process::geteuid;

    #[test]
    fn ordinary_user_cannot_claim_a_controller_tree() {
        if geteuid().as_raw() == 0 {
            return;
        }
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        assert!(verify_controller_tree(&root, &"0".repeat(64)).is_err());
    }

    #[test]
    fn optional_root_owned_fixture_requires_exact_tree_and_refuses_links() {
        let Some(base) = std::env::var_os("GAUNTLET_ROOT_OWNED_TREE_FIXTURE") else {
            return;
        };
        let base = PathBuf::from(base);
        let root = base.join("valid");
        let digest = inventory_tree(&root, TreeKind::Controller).unwrap().digest;
        let verified = verify_controller_tree(&root, &digest).unwrap();
        assert_eq!(verified.entries(), 1);
        assert!(verify_controller_tree(&root, &"0".repeat(64)).is_err());
        assert!(verify_controller_tree(&base.join("extra"), &digest).is_err());
        for name in ["symlink", "hardlink"] {
            assert!(inventory_tree(&base.join(name), TreeKind::Controller).is_err());
        }
    }
}
