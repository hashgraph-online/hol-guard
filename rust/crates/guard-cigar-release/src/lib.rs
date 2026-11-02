#![forbid(unsafe_code)]
//! CIGAR release identities and authenticated compatibility data.
//! This crate does no I/O, process launch, installation or runtime activation.
//! A version label, upstream release or signed catalog is not a Guard approval.

mod artifact_identity;
mod binding;
mod catalog;
mod identity;
mod interpreter_build;
mod labels;
pub use interpreter_build::{InterpreterBuild, ResolvedInterpreterBuild};
mod interpreter_binding;
pub use interpreter_binding::InterpreterBinding;
mod interpreter_receipt;
pub use interpreter_receipt::{
    seal_interpreter_receipt, verify_interpreter_receipt, InstalledInterpreterReceipt,
    SealedInterpreterReceipt, VerifiedInterpreterReceipt,
};
mod installation;
mod lifecycle;
mod update_preferences;
pub use update_preferences::{UpdateMode, UpdatePreferences};
mod initial_selection;
pub use initial_selection::{InitialPhase, InitialRecovery, InitialSelection};
#[cfg(test)]
mod initial_selection_tests;
mod lifecycle_selection;
mod lifecycle_selection_recovery;
pub use lifecycle_selection::{
    SelectionData, SelectionInstallation, SelectionOrigin, SelectionPhase, SelectionPointer,
    SelectionRecord, SelectionTransaction,
};
pub use lifecycle_selection_recovery::SelectionRecovery;
mod python;
mod source;
mod strict_json;
mod types;

pub use binding::{legacy_candidate_profile, LegacyCandidate, ReleaseBinding};
pub use catalog::{CatalogCheckpoint, CatalogTrust, ResolvedRelease, TrustedCatalog, TrustedKey};
pub use identity::{compare_builds, BuildChange};
pub use installation::{
    seal_installation_receipt, verify_installation_receipt, InstalledReleaseReceipt,
    SealedInstallationReceipt, VerifiedInstallationReceipt,
};
pub use lifecycle::{DataTransition, RecoveryAction, SwitchError, SwitchJournal, SwitchPhase};
pub use types::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseError {
    TooLarge,
    InvalidCatalog,
    InvalidUpdatePreferences,
    InvalidVersion,
    InvalidIdentity,
    IdentityConflict,
    DuplicateIdentity,
    UnsupportedSchema,
    UnknownKey,
    KeyUnavailable,
    InvalidSignature,
    Expired,
    Replay,
    Equivocation,
    BuildUnknown,
    BuildWithdrawn,
    PlatformUnavailable,
    AdapterUpdateRequired,
    GuardUpdateRequired,
    CandidateRequiresEnrollment,
    FeatureUnqualified,
    DependencyLockMissing,
    PreviewDisabled,
    PythonVersionRequired,
    InstallationReceiptInvalid,
    InstallationReceiptUnauthenticated,
    InstallationContextMismatch,
}

impl ReleaseError {
    pub fn code(self) -> &'static str {
        match self {
            Self::TooLarge => "cigar_catalog_too_large",
            Self::InvalidCatalog => "cigar_catalog_invalid",
            Self::InvalidUpdatePreferences => "cigar_update_preferences_invalid",
            Self::InvalidVersion => "cigar_release_version_invalid",
            Self::InvalidIdentity => "cigar_build_identity_invalid",
            Self::IdentityConflict => "cigar_build_identity_conflict",
            Self::DuplicateIdentity => "cigar_catalog_duplicate_identity",
            Self::UnsupportedSchema => "cigar_catalog_schema_unsupported",
            Self::UnknownKey => "cigar_catalog_trust_unavailable",
            Self::KeyUnavailable => "cigar_catalog_key_unavailable",
            Self::InvalidSignature => "cigar_catalog_signature_invalid",
            Self::Expired => "cigar_catalog_expired",
            Self::Replay => "cigar_catalog_replayed",
            Self::Equivocation => "cigar_catalog_revision_conflict",
            Self::BuildUnknown => "cigar_build_unknown",
            Self::BuildWithdrawn => "cigar_build_withdrawn",
            Self::PlatformUnavailable => "cigar_build_platform_unavailable",
            Self::AdapterUpdateRequired => "cigar_adapter_update_required",
            Self::GuardUpdateRequired => "cigar_guard_update_required",
            Self::CandidateRequiresEnrollment => "cigar_candidate_requires_enrollment",
            Self::FeatureUnqualified => "cigar_feature_unqualified",
            Self::DependencyLockMissing => "cigar_dependency_lock_missing",
            Self::PreviewDisabled => "cigar_preview_disabled",
            Self::PythonVersionRequired => "cigar_python_version_required",
            Self::InstallationReceiptInvalid => "cigar_installation_receipt_invalid",
            Self::InstallationReceiptUnauthenticated => {
                "cigar_installation_receipt_unauthenticated"
            }
            Self::InstallationContextMismatch => "cigar_installation_context_mismatch",
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
mod artifact_identity_tests;
#[cfg(test)]
mod binding_tests;
#[cfg(test)]
mod installation_tests;
#[cfg(test)]
mod interpreter_receipt_tests;
#[cfg(test)]
mod label_tests;
#[cfg(test)]
mod lifecycle_selection_tests;
#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod update_preferences_tests;
