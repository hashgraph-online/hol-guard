//! Native port of `effect_decision.py` — the effect-decision plane.
//!
//! `evaluate_effect_decision` composes the maximum action floor from every
//! `DecisionFactor` and `UncertaintyKind`, emits an auditable `DecisionReason`
//! set, and derives the `FinalDisposition`. This module reproduces the Python
//! semantics byte-for-byte: enum values are the Python str-enum values, reason
//! ordering is `_reason_key`, factor ordering is `semantic_key`, and the
//! disposition lattice is `_disposition`.
use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

/// Effect-decision contract schema version (mirrors EFFECT_DECISION_SCHEMA_VERSION).
pub const EFFECT_DECISION_SCHEMA_VERSION: &str = "1.1.0";
/// Effect-contract schema version (mirrors EFFECT_CONTRACT_SCHEMA_VERSION).
pub const EFFECT_CONTRACT_SCHEMA_VERSION: &str = "1.0.0";

/// `_REASON_CODE` (effect_decision.py:28) — stable lowercase factor identifier.
static REASON_CODE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$").unwrap());

/// `_REFERENCE` (effect_decision.py:29) — `scheme:path` canonical reference.
static REFERENCE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9_-]*:[a-z0-9][a-z0-9._/-]*$").unwrap());

/// `_SHA256` (effect_decision.py:30) — lowercase SHA-256 hex digest.
static SHA256: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9a-f]{64}$").unwrap());

/// Canonical action lattice rank (mirrors `action_lattice.GUARD_ACTION_SEVERITY`).
///
/// `GuardAction` is a string literal in Python; we model it as a serde string
/// enum with the exact wire values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuardAction {
    Allow,
    Warn,
    Review,
    RequireReapproval,
    SandboxRequired,
    Block,
}

impl GuardAction {
    pub const fn severity(self) -> u8 {
        match self {
            GuardAction::Allow => 0,
            GuardAction::Warn => 1,
            GuardAction::Review => 2,
            GuardAction::RequireReapproval => 3,
            GuardAction::SandboxRequired => 4,
            GuardAction::Block => 5,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            GuardAction::Allow => "allow",
            GuardAction::Warn => "warn",
            GuardAction::Review => "review",
            GuardAction::RequireReapproval => "require-reapproval",
            GuardAction::SandboxRequired => "sandbox-required",
            GuardAction::Block => "block",
        }
    }
}

/// `most_restrictive_guard_action`: the max-severity action, "review" if empty.
pub fn maximum_action_floor<'a>(floors: impl IntoIterator<Item = &'a GuardAction>) -> GuardAction {
    floors
        .into_iter()
        .copied()
        .max_by_key(|a| a.severity())
        .unwrap_or(GuardAction::Review)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProofRoute {
    Verified,
    Contained,
    WorkflowAuthorized,
}

impl ProofRoute {
    pub const fn as_str(self) -> &'static str {
        match self {
            ProofRoute::Verified => "verified",
            ProofRoute::Contained => "contained",
            ProofRoute::WorkflowAuthorized => "workflow-authorized",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProofRequirement {
    OperationAndTargets,
    WorkspaceIdentity,
    RepositoryIdentity,
    RemoteResourceIdentity,
    WorkingDirectoryIdentity,
    ExecutableIdentity,
    LaunchChain,
    DependencyProvenance,
    ConfigurationIdentity,
    ShellDataFlow,
    ParserConfidence,
    ExpectedEffects,
    ContainmentIdentity,
    CapabilityConstraints,
}

impl ProofRequirement {
    pub const fn as_str(self) -> &'static str {
        match self {
            ProofRequirement::OperationAndTargets => "operation-and-targets",
            ProofRequirement::WorkspaceIdentity => "workspace-identity",
            ProofRequirement::RepositoryIdentity => "repository-identity",
            ProofRequirement::RemoteResourceIdentity => "remote-resource-identity",
            ProofRequirement::WorkingDirectoryIdentity => "working-directory-identity",
            ProofRequirement::ExecutableIdentity => "executable-identity",
            ProofRequirement::LaunchChain => "launch-chain",
            ProofRequirement::DependencyProvenance => "dependency-provenance",
            ProofRequirement::ConfigurationIdentity => "configuration-identity",
            ProofRequirement::ShellDataFlow => "shell-data-flow",
            ProofRequirement::ParserConfidence => "parser-confidence",
            ProofRequirement::ExpectedEffects => "expected-effects",
            ProofRequirement::ContainmentIdentity => "containment-identity",
            ProofRequirement::CapabilityConstraints => "capability-constraints",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UncertaintyKind {
    PartialParse,
    DynamicInput,
    UnsupportedInput,
    MalformedInput,
    ParserBudgetExhausted,
    MatcherFailure,
    ParserFailure,
    UnresolvedLaunchIdentity,
    UnknownEffect,
    DegradedContainment,
    ProtectionHealthDegraded,
    PolicyVersionMismatch,
    MalformedBoundaryVersion,
    UnknownBoundaryVersion,
    RollbackBoundaryVersion,
}

impl UncertaintyKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            UncertaintyKind::PartialParse => "partial-parse",
            UncertaintyKind::DynamicInput => "dynamic-input",
            UncertaintyKind::UnsupportedInput => "unsupported-input",
            UncertaintyKind::MalformedInput => "malformed-input",
            UncertaintyKind::ParserBudgetExhausted => "parser-budget-exhausted",
            UncertaintyKind::MatcherFailure => "matcher-failure",
            UncertaintyKind::ParserFailure => "parser-failure",
            UncertaintyKind::UnresolvedLaunchIdentity => "unresolved-launch-identity",
            UncertaintyKind::UnknownEffect => "unknown-effect",
            UncertaintyKind::DegradedContainment => "degraded-containment",
            UncertaintyKind::ProtectionHealthDegraded => "protection-health-degraded",
            UncertaintyKind::PolicyVersionMismatch => "policy-version-mismatch",
            UncertaintyKind::MalformedBoundaryVersion => "malformed-boundary-version",
            UncertaintyKind::UnknownBoundaryVersion => "unknown-boundary-version",
            UncertaintyKind::RollbackBoundaryVersion => "rollback-boundary-version",
        }
    }

    /// `UNCERTAINTY_FLOOR[kind]` (effect_contract.py:151).
    pub const fn floor(self) -> GuardAction {
        match self {
            UncertaintyKind::PartialParse
            | UncertaintyKind::DynamicInput
            | UncertaintyKind::UnsupportedInput
            | UncertaintyKind::MalformedInput => GuardAction::Review,
            UncertaintyKind::ParserBudgetExhausted
            | UncertaintyKind::UnresolvedLaunchIdentity
            | UncertaintyKind::UnknownEffect => GuardAction::RequireReapproval,
            UncertaintyKind::MatcherFailure
            | UncertaintyKind::ParserFailure
            | UncertaintyKind::DegradedContainment
            | UncertaintyKind::ProtectionHealthDegraded
            | UncertaintyKind::PolicyVersionMismatch
            | UncertaintyKind::MalformedBoundaryVersion
            | UncertaintyKind::UnknownBoundaryVersion
            | UncertaintyKind::RollbackBoundaryVersion => GuardAction::Block,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionFactorSource {
    Effect,
    Match,
    Policy,
    Containment,
    Authorization,
    Assurance,
    Control,
}

impl DecisionFactorSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            DecisionFactorSource::Effect => "effect",
            DecisionFactorSource::Match => "match",
            DecisionFactorSource::Policy => "policy",
            DecisionFactorSource::Containment => "containment",
            DecisionFactorSource::Authorization => "authorization",
            DecisionFactorSource::Assurance => "assurance",
            DecisionFactorSource::Control => "control",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectKind {
    WorkspaceOrPublicRead,
    SensitiveRead,
    WorkspaceWrite,
    ExternalFilesystemWrite,
    ProcessExecution,
    NetworkRead,
    NetworkWrite,
    RemoteStateRead,
    RemoteStateMutation,
    PermissionOrAccessChange,
    CredentialOrSecretOperation,
    SystemOrPrivilegeOperation,
    PackageOrSourceInstallation,
    DestructiveOrIrreversibleOperation,
    GuardControlOperation,
}

impl EffectKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            EffectKind::WorkspaceOrPublicRead => "workspace-or-public-read",
            EffectKind::SensitiveRead => "sensitive-read",
            EffectKind::WorkspaceWrite => "workspace-write",
            EffectKind::ExternalFilesystemWrite => "external-filesystem-write",
            EffectKind::ProcessExecution => "process-execution",
            EffectKind::NetworkRead => "network-read",
            EffectKind::NetworkWrite => "network-write",
            EffectKind::RemoteStateRead => "remote-state-read",
            EffectKind::RemoteStateMutation => "remote-state-mutation",
            EffectKind::PermissionOrAccessChange => "permission-or-access-change",
            EffectKind::CredentialOrSecretOperation => "credential-or-secret-operation",
            EffectKind::SystemOrPrivilegeOperation => "system-or-privilege-operation",
            EffectKind::PackageOrSourceInstallation => "package-or-source-installation",
            EffectKind::DestructiveOrIrreversibleOperation => {
                "destructive-or-irreversible-operation"
            }
            EffectKind::GuardControlOperation => "guard-control-operation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectTargetScope {
    PublicResource,
    Workspace,
    SensitiveLocal,
    ExternalLocal,
    NetworkEndpoint,
    RemoteResource,
    System,
    Guard,
    Unknown,
}

impl EffectTargetScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            EffectTargetScope::PublicResource => "public-resource",
            EffectTargetScope::Workspace => "workspace",
            EffectTargetScope::SensitiveLocal => "sensitive-local",
            EffectTargetScope::ExternalLocal => "external-local",
            EffectTargetScope::NetworkEndpoint => "network-endpoint",
            EffectTargetScope::RemoteResource => "remote-resource",
            EffectTargetScope::System => "system",
            EffectTargetScope::Guard => "guard",
            EffectTargetScope::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectReversibility {
    Reversible,
    TriviallyRecoverable,
    RecoverableWithReview,
    Irreversible,
    Unknown,
}

impl EffectReversibility {
    pub const fn as_str(self) -> &'static str {
        match self {
            EffectReversibility::Reversible => "reversible",
            EffectReversibility::TriviallyRecoverable => "trivially-recoverable",
            EffectReversibility::RecoverableWithReview => "recoverable-with-review",
            EffectReversibility::Irreversible => "irreversible",
            EffectReversibility::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectBlastRadius {
    SingleResource,
    Workspace,
    MultipleResources,
    SystemWide,
    Catastrophic,
    Unknown,
}

impl EffectBlastRadius {
    pub const fn as_str(self) -> &'static str {
        match self {
            EffectBlastRadius::SingleResource => "single-resource",
            EffectBlastRadius::Workspace => "workspace",
            EffectBlastRadius::MultipleResources => "multiple-resources",
            EffectBlastRadius::SystemWide => "system-wide",
            EffectBlastRadius::Catastrophic => "catastrophic",
            EffectBlastRadius::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectEvidenceSource {
    Parser,
    Extension,
    LaunchIdentity,
    Manifest,
    Lockfile,
    Configuration,
    Policy,
    Containment,
    Capability,
    Runtime,
}

impl EffectEvidenceSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            EffectEvidenceSource::Parser => "parser",
            EffectEvidenceSource::Extension => "extension",
            EffectEvidenceSource::LaunchIdentity => "launch-identity",
            EffectEvidenceSource::Manifest => "manifest",
            EffectEvidenceSource::Lockfile => "lockfile",
            EffectEvidenceSource::Configuration => "configuration",
            EffectEvidenceSource::Policy => "policy",
            EffectEvidenceSource::Containment => "containment",
            EffectEvidenceSource::Capability => "capability",
            EffectEvidenceSource::Runtime => "runtime",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectConfidence {
    Exact,
    Strong,
    Partial,
    Dynamic,
    Unknown,
}

impl EffectConfidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            EffectConfidence::Exact => "exact",
            EffectConfidence::Strong => "strong",
            EffectConfidence::Partial => "partial",
            EffectConfidence::Dynamic => "dynamic",
            EffectConfidence::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContainmentRequirement {
    None,
    Eligible,
    Required,
    NotEligible,
}

impl ContainmentRequirement {
    pub const fn as_str(self) -> &'static str {
        match self {
            ContainmentRequirement::None => "none",
            ContainmentRequirement::Eligible => "eligible",
            ContainmentRequirement::Required => "required",
            ContainmentRequirement::NotEligible => "not-eligible",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FinalDisposition {
    SilentVerified,
    SilentContained,
    WorkflowAuthorized,
    Warn,
    Review,
    RequireReapproval,
    SandboxRequired,
    Block,
}

impl FinalDisposition {
    /// `FinalDisposition(action)` coercion: maps each non-silent action value.
    pub const fn from_action(action: GuardAction) -> Option<FinalDisposition> {
        match action {
            GuardAction::Allow => None, // resolved via proof route below
            GuardAction::Warn => Some(FinalDisposition::Warn),
            GuardAction::Review => Some(FinalDisposition::Review),
            GuardAction::RequireReapproval => Some(FinalDisposition::RequireReapproval),
            GuardAction::SandboxRequired => Some(FinalDisposition::SandboxRequired),
            GuardAction::Block => Some(FinalDisposition::Block),
        }
    }
    /// Python `.value` — the wire disposition string.
    pub const fn as_str(self) -> &'static str {
        match self {
            FinalDisposition::SilentVerified => "silent-verified",
            FinalDisposition::SilentContained => "silent-contained",
            FinalDisposition::WorkflowAuthorized => "workflow-authorized",
            FinalDisposition::Warn => "warn",
            FinalDisposition::Review => "review",
            FinalDisposition::RequireReapproval => "require-reapproval",
            FinalDisposition::SandboxRequired => "sandbox-required",
            FinalDisposition::Block => "block",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DecisionBasis {
    pub action_floor: GuardAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_route: Option<ProofRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PositiveProof {
    pub route: ProofRoute,
    pub binding_digest: String,
    pub satisfied_requirements: Vec<ProofRequirement>,
    #[serde(default)]
    pub enforced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EffectAssessment {
    pub kind: EffectKind,
    pub target_scope: EffectTargetScope,
    pub reversibility: EffectReversibility,
    pub blast_radius: EffectBlastRadius,
    pub evidence_source: EffectEvidenceSource,
    pub confidence: EffectConfidence,
    pub containment: ContainmentRequirement,
    pub proof_requirements: Vec<ProofRequirement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uncertainty_reasons: Vec<UncertaintyKind>,
    #[serde(default = "default_contract_schema")]
    pub schema_version: String,
}

fn default_contract_schema() -> String {
    EFFECT_CONTRACT_SCHEMA_VERSION.to_owned()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DecisionFactor {
    pub source: DecisionFactorSource,
    pub reason_code: String,
    pub basis: DecisionBasis,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assessment: Option<EffectAssessment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<PositiveProof>,
}

impl DecisionFactor {
    /// `_assessment_key` (effect_decision.py): 11-tuple, empty for None.
    fn assessment_key(assessment: Option<&EffectAssessment>) -> Vec<String> {
        match assessment {
            None => vec![String::new(); 11],
            Some(a) => vec![
                a.kind.as_str().to_owned(),
                a.target_scope.as_str().to_owned(),
                a.reversibility.as_str().to_owned(),
                a.blast_radius.as_str().to_owned(),
                a.evidence_source.as_str().to_owned(),
                a.confidence.as_str().to_owned(),
                a.containment.as_str().to_owned(),
                sorted_join(&a.proof_requirements, ProofRequirement::as_str),
                sorted_join(&a.uncertainty_reasons, UncertaintyKind::as_str),
                a.schema_version.clone(),
                "assessment".to_owned(),
            ],
        }
    }

    /// `_proof_key` (effect_decision.py): 4-tuple, empty for None.
    fn proof_key(proof: Option<&PositiveProof>) -> Vec<String> {
        match proof {
            None => vec![String::new(); 4],
            Some(p) => vec![
                p.route.as_str().to_owned(),
                p.binding_digest.clone(),
                sorted_join(&p.satisfied_requirements, ProofRequirement::as_str),
                if p.enforced {
                    "enforced"
                } else {
                    "not-enforced"
                }
                .to_owned(),
            ],
        }
    }

    /// `semantic_key` (effect_decision.py:148): deterministic sort key.
    pub fn semantic_key(&self) -> Vec<String> {
        let mut key = vec![
            self.segment_ref.clone().unwrap_or_default(),
            self.operation_ref.clone().unwrap_or_default(),
            self.producer_ref.clone().unwrap_or_default(),
            self.evidence_digest.clone().unwrap_or_default(),
            self.source.as_str().to_owned(),
            self.reason_code.clone(),
            self.basis.action_floor.as_str().to_owned(),
            self.basis
                .proof_route
                .map(ProofRoute::as_str)
                .unwrap_or("")
                .to_owned(),
        ];
        key.extend(Self::assessment_key(self.assessment.as_ref()));
        key.extend(Self::proof_key(self.proof.as_ref()));
        key
    }
}

/// Sorted, comma-joined enum values — mirrors `",".join(sorted(item.value ...))`.
fn sorted_join<T: Copy>(items: &[T], as_str: impl Fn(T) -> &'static str) -> String {
    let mut values: Vec<&'static str> = items.iter().map(|&i| as_str(i)).collect();
    values.sort_unstable();
    values.join(",")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DecisionReason {
    pub source: DecisionFactorSource,
    pub reason_code: String,
    pub action_floor: GuardAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_ref: Option<String>,
}

impl DecisionReason {
    /// `_reason_key` (effect_decision.py:278): (segment_ref, operation_ref,
    /// source.value, reason_code, severity_rank).
    fn reason_key(&self) -> (String, String, &'static str, String, u8) {
        (
            self.segment_ref.clone().unwrap_or_default(),
            self.operation_ref.clone().unwrap_or_default(),
            self.source.as_str(),
            self.reason_code.clone(),
            self.action_floor.severity(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EffectDecisionRequest {
    pub factors: Vec<DecisionFactor>,
    #[serde(default)]
    pub uncertainties: Vec<UncertaintyKind>,
    #[serde(default = "default_decision_schema")]
    pub schema_version: String,
}

fn default_decision_schema() -> String {
    EFFECT_DECISION_SCHEMA_VERSION.to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EffectDecision {
    pub action: GuardAction,
    pub disposition: FinalDisposition,
    pub controlling_reasons: Vec<DecisionReason>,
    pub reasons: Vec<DecisionReason>,
    pub proof_routes: Vec<ProofRoute>,
    pub schema_version: String,
}

/// `evaluate_effect_decision` (effect_decision.py:203).
///
/// Reproduces: reasons = factors→floor + request uncertainties→UNCERTAINTY_FLOOR
/// + per-assessment uncertainties (EFFECT source); sort by `_reason_key`;
///   `maximum_action_floor`; `controlling` = reasons at max severity;
///   `proof_routes` = {proof.route for positive proofs}; `_disposition`.
///
/// The request must already satisfy the Python `__post_init__` invariants
/// (factors sorted by `semantic_key`, no duplicate keys, deduped sorted
/// uncertainties); serde deserialization + `prepare` enforces this.
pub fn evaluate_effect_decision(
    request: &EffectDecisionRequest,
) -> Result<EffectDecision, &'static str> {
    if request.schema_version != EFFECT_DECISION_SCHEMA_VERSION {
        return Err("unsupported effect decision schema version");
    }
    // `__post_init__` invariants (effect_decision.py:100-190, effect_contract.py
    // :125-130/:185-217) — fail-closed: any request Python would reject is an
    // error here rather than a silently-accepted degenerate request.
    validate_request(request)?;
    // Python __post_init__ orders factors by semantic_key and uncertainties by
    // value; we sort copies to match regardless of wire order.
    let mut factors = request.factors.clone();
    factors.sort_by_cached_key(DecisionFactor::semantic_key);
    let mut uncertainties = request.uncertainties.clone();
    uncertainties.sort_by_key(|u| u.as_str());

    let mut reasons: Vec<DecisionReason> = Vec::new();
    for item in &factors {
        reasons.push(DecisionReason {
            source: item.source,
            reason_code: item.reason_code.clone(),
            action_floor: item.basis.action_floor,
            segment_ref: item.segment_ref.clone(),
            operation_ref: item.operation_ref.clone(),
        });
    }
    for uncertainty in &uncertainties {
        reasons.push(DecisionReason {
            source: DecisionFactorSource::Policy,
            reason_code: format!("uncertainty.{}", uncertainty.as_str()),
            action_floor: uncertainty.floor(),
            segment_ref: None,
            operation_ref: None,
        });
    }
    for factor in &factors {
        if let Some(assessment) = &factor.assessment {
            for uncertainty in &assessment.uncertainty_reasons {
                reasons.push(DecisionReason {
                    source: DecisionFactorSource::Effect,
                    reason_code: format!("uncertainty.{}", uncertainty.as_str()),
                    action_floor: uncertainty.floor(),
                    segment_ref: factor.segment_ref.clone(),
                    operation_ref: factor.operation_ref.clone(),
                });
            }
        }
    }
    reasons.sort_by_cached_key(DecisionReason::reason_key);

    let action = maximum_action_floor(reasons.iter().map(|r| &r.action_floor));
    let max_severity = action.severity();
    let controlling_reasons: Vec<DecisionReason> = reasons
        .iter()
        .filter(|r| r.action_floor.severity() == max_severity)
        .cloned()
        .collect();

    let proof_routes: BTreeSet<ProofRoute> = factors
        .iter()
        .filter_map(|f| f.proof.as_ref().map(|p| p.route))
        .collect();
    // Preserve a stable sorted order (enum Ord = declaration order, matching
    // Python's set→sorted-by-value in to_dict consumers).
    let proof_routes: Vec<ProofRoute> = proof_routes.into_iter().collect();

    let disposition = disposition(action, &proof_routes);

    Ok(EffectDecision {
        action,
        disposition,
        controlling_reasons,
        reasons,
        proof_routes,
        schema_version: EFFECT_DECISION_SCHEMA_VERSION.to_owned(),
    })
}

/// `_disposition` (effect_decision.py:288).
fn disposition(action: GuardAction, routes: &[ProofRoute]) -> FinalDisposition {
    if action == GuardAction::Allow {
        if routes.contains(&ProofRoute::WorkflowAuthorized) {
            return FinalDisposition::WorkflowAuthorized;
        }
        if routes.contains(&ProofRoute::Contained) {
            return FinalDisposition::SilentContained;
        }
        return FinalDisposition::SilentVerified;
    }
    FinalDisposition::from_action(action).unwrap_or(FinalDisposition::Review)
}

/// Request-level `__post_init__` invariants (effect_decision.py:181-190):
/// deduped uncertainties, no duplicate factor `semantic_key`s, per-factor
/// `__post_init__`.
fn validate_request(request: &EffectDecisionRequest) -> Result<(), &'static str> {
    // uncertainties deduped (sorted by value → adjacent-equal check is exact).
    let mut sorted_unc: Vec<&str> = request.uncertainties.iter().map(|u| u.as_str()).collect();
    sorted_unc.sort_unstable();
    if sorted_unc.windows(2).any(|w| w[0] == w[1]) {
        return Err("uncertainties cannot contain duplicates");
    }
    let mut seen_keys = std::collections::HashSet::new();
    for factor in &request.factors {
        validate_factor(factor)?;
        // Duplicate semantic_key rejection (effect_decision.py:185-186).
        if !seen_keys.insert(factor.semantic_key()) {
            return Err("duplicate decision factors are not allowed");
        }
    }
    Ok(())
}

/// `DecisionBasis.__post_init__` (effect_contract.py:125-130): floors below
/// `review` require a positive proof route.
fn validate_basis(basis: &DecisionBasis) -> Result<(), &'static str> {
    if basis.action_floor.severity() < GuardAction::Review.severity() && basis.proof_route.is_none()
    {
        return Err("permissive action floors require a positive proof route");
    }
    Ok(())
}

/// `PositiveProof.__post_init__` (effect_decision.py:64-83): sha256 binding
/// digest; CONTAINED ⇒ enforced + CONTAINMENT_IDENTITY; enforced ⇒ CONTAINED.
fn validate_proof(proof: &PositiveProof) -> Result<(), &'static str> {
    if !SHA256.is_match(&proof.binding_digest) {
        return Err("binding_digest must be a lowercase SHA-256 digest");
    }
    if proof.route == ProofRoute::Contained {
        if !proof.enforced {
            return Err("contained proof must be enforced");
        }
        if !proof
            .satisfied_requirements
            .contains(&ProofRequirement::ContainmentIdentity)
        {
            return Err("contained proof must bind containment identity");
        }
    } else if proof.enforced {
        return Err("only contained proof may claim enforcement");
    }
    Ok(())
}

/// `EffectAssessment.__post_init__` (effect_contract.py:185-217): confidence /
/// uncertainty / unknown-dimension / containment cross-invariants + contract
/// schema version.
fn validate_assessment(assessment: &EffectAssessment) -> Result<(), &'static str> {
    if assessment.schema_version != EFFECT_CONTRACT_SCHEMA_VERSION {
        return Err("unsupported effect contract schema version");
    }
    let uncertain = matches!(
        assessment.confidence,
        EffectConfidence::Partial | EffectConfidence::Dynamic | EffectConfidence::Unknown
    );
    if uncertain && assessment.uncertainty_reasons.is_empty() {
        return Err("partial, dynamic, and unknown effects require an uncertainty reason");
    }
    if assessment.confidence == EffectConfidence::Exact
        && !assessment.uncertainty_reasons.is_empty()
    {
        return Err("exact effects cannot carry uncertainty reasons");
    }
    let has_unknown_dimension = assessment.target_scope == EffectTargetScope::Unknown
        || assessment.reversibility == EffectReversibility::Unknown
        || assessment.blast_radius == EffectBlastRadius::Unknown;
    if has_unknown_dimension
        && (assessment.confidence == EffectConfidence::Exact
            || assessment.uncertainty_reasons.is_empty())
    {
        return Err("unknown effect dimensions require non-exact confidence and typed uncertainty");
    }
    if assessment.containment == ContainmentRequirement::Required
        && !assessment
            .proof_requirements
            .contains(&ProofRequirement::ContainmentIdentity)
    {
        return Err("required containment must bind containment identity");
    }
    Ok(())
}

/// `DecisionFactor.__post_init__` (effect_decision.py:100-145): identifier
/// patterns, basis validity, and proof↔assessment cross-invariants.
fn validate_factor(factor: &DecisionFactor) -> Result<(), &'static str> {
    if !REASON_CODE.is_match(&factor.reason_code) {
        return Err("reason_code must be a stable lowercase identifier");
    }
    validate_basis(&factor.basis)?;
    for reference in [
        factor.segment_ref.as_deref(),
        factor.operation_ref.as_deref(),
        factor.producer_ref.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !REFERENCE.is_match(reference) {
            return Err("reference must be a canonical reference");
        }
    }
    if let Some(digest) = factor.evidence_digest.as_deref() {
        if !SHA256.is_match(digest) {
            return Err("evidence_digest must be a lowercase SHA-256 digest");
        }
    }
    // EFFECT-source ⇔ assessment gating (effect_decision.py:121-124).
    if factor.source == DecisionFactorSource::Effect && factor.assessment.is_none() {
        return Err("effect factors require an assessment");
    }
    if factor.source != DecisionFactorSource::Effect && factor.assessment.is_some() {
        return Err("only effect factors may carry an assessment");
    }
    if let Some(assessment) = &factor.assessment {
        validate_assessment(assessment)?;
    }
    if let Some(proof) = &factor.proof {
        validate_proof(proof)?;
    }
    // proof_route ⇄ proof exact-match (effect_decision.py:127-131).
    match (&factor.basis.proof_route, &factor.proof) {
        (None, Some(_)) => return Err("proof requires a matching proof route"),
        (Some(route), Some(proof)) if proof.route != *route => {
            return Err("permissive basis requires proof on the exact route");
        }
        (Some(_), None) => return Err("permissive basis requires proof on the exact route"),
        _ => {}
    }
    if let (Some(proof), Some(assessment)) = (&factor.proof, &factor.assessment) {
        // proof.satisfied_requirements must cover assessment.proof_requirements.
        let missing = assessment
            .proof_requirements
            .iter()
            .any(|req| !proof.satisfied_requirements.contains(req));
        if missing {
            return Err("proof does not satisfy every effect requirement");
        }
        if proof.route == ProofRoute::Contained
            && !matches!(
                assessment.containment,
                ContainmentRequirement::Eligible | ContainmentRequirement::Required
            )
        {
            return Err("contained proof is incompatible with the effect containment requirement");
        }
        if assessment.containment == ContainmentRequirement::Required
            && proof.route != ProofRoute::Contained
        {
            return Err("containment-required effects require contained proof");
        }
    }
    Ok(())
}

/// `_reason_to_dict` (command_decision_adapter.py:231): one DecisionReason →
/// the exact wire dict, with `segment_ref`/`operation_ref` emitted as `null`.
fn reason_to_payload(reason: &DecisionReason) -> Value {
    json!({
        "source": reason.source.as_str(),
        "reason_code": reason.reason_code,
        "action_floor": reason.action_floor.as_str(),
        "segment_ref": reason.segment_ref,
        "operation_ref": reason.operation_ref,
    })
}

/// `effect_decision_to_dict` (command_decision_adapter.py:223) — the exact
/// `decision_plane` dict embedded in `CompositeCommandEvaluation.to_dict()`.
pub fn effect_decision_to_payload(decision: &EffectDecision) -> Value {
    let mut proof_routes: Vec<&str> = decision.proof_routes.iter().map(|r| r.as_str()).collect();
    proof_routes.sort_unstable();
    let mut payload = Map::new();
    payload.insert(
        "schema_version".to_owned(),
        Value::String(decision.schema_version.clone()),
    );
    payload.insert(
        "action".to_owned(),
        Value::String(decision.action.as_str().to_owned()),
    );
    payload.insert(
        "disposition".to_owned(),
        Value::String(decision.disposition.as_str().to_owned()),
    );
    payload.insert(
        "proof_routes".to_owned(),
        Value::Array(proof_routes.into_iter().map(Value::from).collect()),
    );
    payload.insert(
        "controlling_reasons".to_owned(),
        Value::Array(
            decision
                .controlling_reasons
                .iter()
                .map(reason_to_payload)
                .collect(),
        ),
    );
    payload.insert(
        "reasons".to_owned(),
        Value::Array(decision.reasons.iter().map(reason_to_payload).collect()),
    );
    Value::Object(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn factor(source: DecisionFactorSource, code: &str, floor: GuardAction) -> DecisionFactor {
        DecisionFactor {
            source,
            reason_code: code.to_owned(),
            basis: DecisionBasis {
                action_floor: floor,
                proof_route: if floor.severity() < GuardAction::Review.severity() {
                    Some(ProofRoute::Verified)
                } else {
                    None
                },
            },
            segment_ref: None,
            operation_ref: None,
            producer_ref: None,
            evidence_digest: None,
            assessment: None,
            proof: None,
        }
    }

    /// Permissive-floor factor with a matching Verified proof (satisfies the
    /// `proof_route == proof.route` invariant for allow/warn floors).
    fn verified_factor(
        source: DecisionFactorSource,
        code: &str,
        floor: GuardAction,
    ) -> DecisionFactor {
        let mut f = factor(source, code, floor);
        f.proof = Some(PositiveProof {
            route: f
                .basis
                .proof_route
                .expect("permissive factor must set proof_route"),
            binding_digest: "b".repeat(64),
            satisfied_requirements: vec![],
            enforced: false,
        });
        f
    }

    #[test]
    fn max_floor_composes_across_factors_and_uncertainties() {
        let req = EffectDecisionRequest {
            factors: vec![
                factor(DecisionFactorSource::Match, "a", GuardAction::Review),
                verified_factor(DecisionFactorSource::Policy, "b", GuardAction::Allow),
            ],
            uncertainties: vec![UncertaintyKind::MatcherFailure], // floor = block
            schema_version: EFFECT_DECISION_SCHEMA_VERSION.to_owned(),
        };
        let decision = evaluate_effect_decision(&req).unwrap();
        assert_eq!(decision.action, GuardAction::Block);
        assert_eq!(decision.disposition, FinalDisposition::Block);
    }

    #[test]
    fn allow_with_workflow_proof_disposes_workflow_authorized() {
        let mut f = factor(DecisionFactorSource::Match, "ok", GuardAction::Allow);
        f.basis.proof_route = Some(ProofRoute::WorkflowAuthorized);
        f.proof = Some(PositiveProof {
            route: ProofRoute::WorkflowAuthorized,
            binding_digest: "a".repeat(64),
            satisfied_requirements: vec![],
            enforced: false,
        });
        let req = EffectDecisionRequest {
            factors: vec![f],
            uncertainties: vec![],
            schema_version: EFFECT_DECISION_SCHEMA_VERSION.to_owned(),
        };
        let decision = evaluate_effect_decision(&req).unwrap();
        assert_eq!(decision.action, GuardAction::Allow);
        assert_eq!(decision.disposition, FinalDisposition::WorkflowAuthorized);
        assert_eq!(decision.proof_routes, vec![ProofRoute::WorkflowAuthorized]);
    }

    #[test]
    fn assessment_uncertainty_raises_effect_reason() {
        let mut f = factor(DecisionFactorSource::Effect, "e", GuardAction::Review);
        f.assessment = Some(EffectAssessment {
            kind: EffectKind::SensitiveRead,
            target_scope: EffectTargetScope::SensitiveLocal,
            reversibility: EffectReversibility::Reversible,
            blast_radius: EffectBlastRadius::SingleResource,
            evidence_source: EffectEvidenceSource::Parser,
            confidence: EffectConfidence::Partial,
            containment: ContainmentRequirement::None,
            proof_requirements: vec![],
            uncertainty_reasons: vec![UncertaintyKind::ParserFailure], // block
            schema_version: EFFECT_CONTRACT_SCHEMA_VERSION.to_owned(),
        });
        let req = EffectDecisionRequest {
            factors: vec![f],
            uncertainties: vec![],
            schema_version: EFFECT_DECISION_SCHEMA_VERSION.to_owned(),
        };
        let decision = evaluate_effect_decision(&req).unwrap();
        assert_eq!(decision.action, GuardAction::Block);
        assert!(decision
            .reasons
            .iter()
            .any(|r| r.source == DecisionFactorSource::Effect
                && r.reason_code == "uncertainty.parser-failure"));
    }

    fn request(
        factors: Vec<DecisionFactor>,
        uncertainties: Vec<UncertaintyKind>,
    ) -> EffectDecisionRequest {
        EffectDecisionRequest {
            factors,
            uncertainties,
            schema_version: EFFECT_DECISION_SCHEMA_VERSION.to_owned(),
        }
    }

    #[test]
    fn rejects_permissive_floor_without_proof_route() {
        // DecisionBasis.__post_init__: floor < review requires proof_route.
        let mut f = factor(DecisionFactorSource::Match, "ok", GuardAction::Warn);
        f.basis.proof_route = None;
        assert!(evaluate_effect_decision(&request(vec![f], vec![])).is_err());
    }

    #[test]
    fn rejects_noncanonical_reason_code() {
        let f = factor(
            DecisionFactorSource::Match,
            "Not_A Code!",
            GuardAction::Review,
        );
        assert!(evaluate_effect_decision(&request(vec![f], vec![])).is_err());
    }

    #[test]
    fn rejects_duplicate_factor_semantic_keys() {
        let f = || {
            factor(
                DecisionFactorSource::Match,
                "same-code",
                GuardAction::Review,
            )
        };
        assert!(evaluate_effect_decision(&request(vec![f(), f()], vec![])).is_err());
    }

    #[test]
    fn rejects_contained_proof_without_enforcement() {
        let mut f = factor(DecisionFactorSource::Match, "ok", GuardAction::Allow);
        f.proof = Some(PositiveProof {
            route: ProofRoute::Contained,
            binding_digest: "b".repeat(64),
            satisfied_requirements: vec![ProofRequirement::ContainmentIdentity],
            enforced: false, // CONTAINED must be enforced
        });
        assert!(evaluate_effect_decision(&request(vec![f], vec![])).is_err());
    }

    #[test]
    fn rejects_exact_assessment_carrying_uncertainty() {
        let mut f = factor(DecisionFactorSource::Effect, "e", GuardAction::Review);
        f.assessment = Some(EffectAssessment {
            kind: EffectKind::SensitiveRead,
            target_scope: EffectTargetScope::SensitiveLocal,
            reversibility: EffectReversibility::Reversible,
            blast_radius: EffectBlastRadius::SingleResource,
            evidence_source: EffectEvidenceSource::Parser,
            confidence: EffectConfidence::Exact,
            containment: ContainmentRequirement::None,
            proof_requirements: vec![],
            uncertainty_reasons: vec![UncertaintyKind::ParserFailure],
            schema_version: EFFECT_CONTRACT_SCHEMA_VERSION.to_owned(),
        });
        assert!(evaluate_effect_decision(&request(vec![f], vec![])).is_err());
    }

    #[test]
    fn payload_emits_null_refs_and_exact_key_set() {
        let req = request(
            vec![factor(
                DecisionFactorSource::Match,
                "ok",
                GuardAction::Review,
            )],
            vec![],
        );
        let decision = evaluate_effect_decision(&req).unwrap();
        let payload = effect_decision_to_payload(&decision);
        // `effect_decision_to_dict` key set (command_decision_adapter.py:224-231).
        let obj = payload.as_object().unwrap();
        assert_eq!(
            obj.keys().cloned().collect::<BTreeSet<_>>(),
            [
                "schema_version",
                "action",
                "disposition",
                "proof_routes",
                "controlling_reasons",
                "reasons"
            ]
            .iter()
            .map(|s| s.to_string())
            .collect::<BTreeSet<_>>(),
        );
        // `_reason_to_dict`: segment_ref/operation_ref serialize as null (not omitted).
        let reason = &obj["reasons"][0];
        assert!(reason["segment_ref"].is_null());
        assert!(reason["operation_ref"].is_null());
        let reason_keys: BTreeSet<String> = reason.as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            reason_keys,
            [
                "source",
                "reason_code",
                "action_floor",
                "segment_ref",
                "operation_ref"
            ]
            .iter()
            .map(|s| s.to_string())
            .collect::<BTreeSet<_>>(),
        );
    }
}
