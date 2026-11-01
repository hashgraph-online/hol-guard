#![forbid(unsafe_code)]

//! Optional CIGAR control plane, isolated from synchronous hook decisions.
//! Interpreter eligibility alone is not package verification or execution authority.

mod actor;
mod artifacts;
mod private_python;
pub use private_python::PrivatePythonSelection;
mod broker;
mod broker_doctor;
mod broker_execution_doctor;
mod broker_persistence_doctor;
mod broker_storage;
mod config;
#[cfg(unix)]
mod evidence_cache;
mod freshness;
mod graph;
mod interpreter;
mod interpreter_probe;
mod process;
mod release;
mod restrictions;
mod runtime;
mod source;

pub use actor::{Quiescence, RuntimeActivity, RuntimeActor};
pub use artifacts::{inspect_bundle, inspect_release_bundle, BundleApproval, RuntimeSelection};
#[cfg(unix)]
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
#[cfg(unix)]
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
pub use interpreter::{check_interpreter, InterpreterFacts, UnavailableReason};
pub use interpreter_probe::{
    probe_interpreter_cancellable, probe_private_interpreter_cancellable, VerifiedInterpreter,
};
pub use restrictions::{restrict_config, restrict_value};
pub use runtime::{RuntimeError, RuntimeStatus, VerifiedRuntime};
pub use source::{AdmittedFile, SourceRoot};

// Historical fixture identity only; production resolves the bundled catalog.
#[cfg(test)]
pub(crate) const CIGAR_VERSION: &str = "0.14.1";
pub const CIGAR_PROTOCOL: &str = "cigar.context-worker.v1";

#[cfg(test)]
mod tests;

#[cfg(test)]
mod restriction_tests;
