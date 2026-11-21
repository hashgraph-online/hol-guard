//! The overlay layers one contained Linux run writes through.
//!
//! They live in a directory of their own so the whole set goes when the run
//! does, including the layers a linked worktree's shared `.git` needs.

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

/// Where an overlay's layers are made. Pinned rather than taken from the
/// environment: the kernel needs a filesystem that carries the extended
/// attributes an overlay's upper layer records whiteouts in.
const OVERLAY_PARENT: &str = "/tmp";

/// The overlay layers one contained Linux run writes through, removed when
/// dropped.
///
/// The kernel needs an overlay's upper and work directories on one
/// filesystem, so both are made inside a single owner-only directory. A
/// linked worktree's shared `.git` takes a second pair beside them, because
/// it is mounted as an overlay of its own.
pub(super) struct OverlayRoot {
    pub(super) path: PathBuf,
}

impl OverlayRoot {
    pub(super) fn create(linked: bool) -> Option<Self> {
        let template = Path::new(OVERLAY_PARENT).join("hol-guard-overlay-XXXXXX");
        let created = nix::unistd::mkdtemp(&template).ok()?;
        let Ok(path) = std::fs::canonicalize(&created) else {
            let _ = std::fs::remove_dir(&created);
            return None;
        };
        // One owner only: its drop removes the directory.
        let root = Self { path };
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(root.upper()).ok()?;
        builder.create(root.work()).ok()?;
        if linked {
            builder.create(root.path.join("shared")).ok()?;
            builder.create(root.shared_upper()).ok()?;
            builder.create(root.shared_work()).ok()?;
        }
        Some(root)
    }

    pub(super) fn upper(&self) -> PathBuf {
        self.path.join("upper")
    }

    pub(super) fn work(&self) -> PathBuf {
        self.path.join("work")
    }

    pub(super) fn shared_upper(&self) -> PathBuf {
        self.path.join("shared").join("upper")
    }

    pub(super) fn shared_work(&self) -> PathBuf {
        self.path.join("shared").join("work")
    }
}

impl Drop for OverlayRoot {
    fn drop(&mut self) {
        guard_command::restricted_pytest::remove_workspace_overlay_root(&self.path);
    }
}
