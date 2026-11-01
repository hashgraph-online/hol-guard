//! Shared protected-artifact checks; no acquisition, process launch or activation.
#![forbid(unsafe_code)]
mod paths;
mod python_snapshot;
mod python_tree;
pub use paths::{admit_name, private_child, private_directory};
pub use python_snapshot::VerifiedPythonSnapshot;
pub use python_tree::{
    check_python_binding, verify_python_binding, verify_python_tree, VerifiedPythonBundle,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
const MAX_FILES: usize = 8192;
const MAX_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallError {
    Cancelled,
    DeadlineExceeded,
    InputsInvalid,
    ArtifactUnreadable,
    ArtifactMismatch,
    ArchiveInvalid,
    WheelUnsupported,
    PythonArchiveUnsupported,
    EntryUnsafe,
    LimitExceeded,
    TreeMismatch,
    DestinationUnsafe,
    DestinationNotEmpty,
    WriteFailed,
    PlatformUnsupported,
}
impl InstallError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Cancelled => "cigar_install_cancelled",
            Self::DeadlineExceeded => "cigar_install_deadline_exceeded",
            Self::InputsInvalid => "cigar_install_inputs_invalid",
            Self::ArtifactUnreadable => "cigar_install_artifact_unreadable",
            Self::ArtifactMismatch => "cigar_install_artifact_mismatch",
            Self::ArchiveInvalid => "cigar_install_archive_invalid",
            Self::WheelUnsupported => "cigar_install_wheel_unsupported",
            Self::PythonArchiveUnsupported => "cigar_python_archive_unsupported",
            Self::EntryUnsafe => "cigar_install_entry_unsafe",
            Self::LimitExceeded => "cigar_install_limit_exceeded",
            Self::TreeMismatch => "cigar_install_tree_mismatch",
            Self::DestinationUnsafe => "cigar_install_destination_unsafe",
            Self::DestinationNotEmpty => "cigar_install_destination_not_empty",
            Self::WriteFailed => "cigar_install_write_failed",
            Self::PlatformUnsupported => "cigar_install_platform_unsupported",
        }
    }
}
impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for InstallError {}

pub struct PreparationControl {
    cancel: Arc<AtomicBool>,
    deadline: Instant,
}
impl PreparationControl {
    pub fn new(cancel: Arc<AtomicBool>, timeout: Duration) -> Result<Self, InstallError> {
        if timeout.is_zero() || timeout > Duration::from_secs(120) {
            return Err(InstallError::InputsInvalid);
        }
        Ok(Self {
            cancel,
            deadline: Instant::now() + timeout,
        })
    }
    pub fn remaining(&self) -> Result<Duration, InstallError> {
        self.checkpoint()?;
        Ok(self.deadline.saturating_duration_since(Instant::now()))
    }
    pub fn checkpoint(&self) -> Result<(), InstallError> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(InstallError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(InstallError::DeadlineExceeded);
        }
        Ok(())
    }
}
