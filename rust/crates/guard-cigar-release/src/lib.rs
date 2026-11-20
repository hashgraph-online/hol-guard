#![forbid(unsafe_code)]
//! CIGAR selection records, build identities and lifecycle data.
//! This crate does no I/O, process launch, installation or runtime activation.

mod binding;
mod identity;
mod initial_selection;
mod labels;
mod lifecycle;
mod lifecycle_selection;
mod lifecycle_selection_recovery;
mod types;
mod update_preferences;

pub use binding::ReleaseBinding;
pub use identity::{compare_builds, BuildChange};
pub use initial_selection::{InitialPhase, InitialRecovery, InitialSelection};
pub use lifecycle::{DataTransition, SwitchError};
pub use lifecycle_selection::{
    SelectionData, SelectionInstallation, SelectionOrigin, SelectionPhase, SelectionPointer,
    SelectionRecord, SelectionTransaction,
};
pub use lifecycle_selection_recovery::SelectionRecovery;
pub use types::*;
pub use update_preferences::{UpdateMode, UpdatePreferences};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseError {
    InvalidUpdatePreferences,
    InvalidVersion,
    InvalidIdentity,
    IdentityConflict,
}

impl ReleaseError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidUpdatePreferences => "cigar_update_preferences_invalid",
            Self::InvalidVersion => "cigar_release_version_invalid",
            Self::InvalidIdentity => "cigar_build_identity_invalid",
            Self::IdentityConflict => "cigar_build_identity_conflict",
        }
    }
}

impl std::fmt::Display for ReleaseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}
impl std::error::Error for ReleaseError {}

#[cfg(test)]
mod initial_selection_tests;
#[cfg(test)]
mod label_tests;
#[cfg(test)]
mod lifecycle_selection_tests;
#[cfg(test)]
mod update_preferences_tests;
