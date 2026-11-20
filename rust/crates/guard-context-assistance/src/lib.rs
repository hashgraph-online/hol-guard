#![forbid(unsafe_code)]

//! Optional CIGAR control plane, isolated from synchronous hook decisions.

mod actor;
mod artifacts;
mod broker;
mod broker_doctor;
mod broker_execution_doctor;
mod broker_persistence_doctor;
mod broker_storage;
mod config;
mod evidence_cache;
mod freshness;
mod graph;
mod interpreter;
mod process;
mod release;
mod restrictions;
mod runtime;
mod source;

pub use actor::{Quiescence, RuntimeActivity, RuntimeActor};
pub use artifacts::{BundleApproval, RuntimeSelection};
pub use broker::EphemeralReviewedNotes;
pub use broker::{
    BrokerAnswerClaim, BrokerAnswerPolicy, BrokerBoundExecution, BrokerClaimReview,
    BrokerClientHandle, BrokerDomainHandle, BrokerExecutionHandoff, BrokerExecutionReview,
    BrokerProposal, BrokerReviewVerdict, BrokerRevision, BrokerSubmission, RetainedBrokerContext,
};
pub use broker_storage::BrokerStorage;
pub use config::{
    ConfigError, ContextAssistanceConfig, Features, Limits, ResourceProfile, Sources, Storage,
    StorageMode,
};
pub use evidence_cache::{
    DataCompatibility, EvidenceCache, EvidenceCacheHealth, EvidenceCacheLocation,
    EvidenceCacheSummary, EvidenceErasureScope, EvidenceGenerationStore, EvidencePreparation,
    EvidenceScope, EvidenceScopeErasure, EvidenceScopeOwner, EvidenceSlot,
    EvidenceUpgradeInventory, EvidenceUpgradePlan, EvidenceUpgradeProducer,
    EvidenceUpgradeStrategy, PreparedEvidenceGeneration, SavedNotes, VerifiedNoteTransfer,
};
pub use freshness::{ContextEpoch, ContextFence};
pub use graph::{
    ContextBrief, ContextDocument, ContextExcerpt, RetainedContext, ViewHandle, WorkspaceHandle,
};
pub use interpreter::InterpreterFacts;
pub use restrictions::{restrict_config, restrict_value};
pub use runtime::{
    builtin_approval, builtin_interpreter, builtin_platform, builtin_selection, RuntimeError,
    RuntimeStatus, VerifiedRuntime, BUILTIN_APPROVAL_SCHEMA,
};
pub use source::{AdmittedFile, SourceRoot};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod restriction_tests;
