//! Native port of the verified-read decisions in `runtime/verified_read_execution.py`
//! and `runtime/verified_github_reads.py`.
//!
//! Both modules built a `DecisionFactor` in Python and composed it through the
//! local effect lattice. That composition is the verdict that lets a verified
//! read execute silently, so it belongs on this side: the lattice already lives
//! here, and a second caller of it in Python is a second place a verified read
//! can be declared allowed.
//!
//! The factors themselves are fixed in shape. Only the proof's binding digest
//! varies, plus the workspace read's operation id, so the builders take those
//! and nothing else; everything that decided the classification already
//! happened when the proof was produced.

use crate::effect_decision::{
    evaluate_effect_decision, ContainmentRequirement, DecisionBasis, DecisionFactor,
    DecisionFactorSource, EffectAssessment, EffectBlastRadius, EffectConfidence, EffectDecision,
    EffectDecisionRequest, EffectEvidenceSource, EffectKind, EffectReversibility,
    EffectTargetScope, GuardAction, PositiveProof, ProofRequirement, ProofRoute,
    EFFECT_CONTRACT_SCHEMA_VERSION, EFFECT_DECISION_SCHEMA_VERSION,
};

/// `verified_read_execution._REQUIREMENTS` (:45).
const WORKSPACE_READ_REQUIREMENTS: &[ProofRequirement] = &[
    ProofRequirement::OperationAndTargets,
    ProofRequirement::WorkspaceIdentity,
    ProofRequirement::RepositoryIdentity,
    ProofRequirement::WorkingDirectoryIdentity,
    ProofRequirement::ConfigurationIdentity,
    ProofRequirement::ShellDataFlow,
    ProofRequirement::ParserConfidence,
    ProofRequirement::ExpectedEffects,
];

/// `verified_github_reads._REQUIREMENTS` (:54).
const GITHUB_READ_REQUIREMENTS: &[ProofRequirement] = &[
    ProofRequirement::OperationAndTargets,
    ProofRequirement::RemoteResourceIdentity,
    ProofRequirement::ConfigurationIdentity,
    ProofRequirement::ShellDataFlow,
    ProofRequirement::ParserConfidence,
    ProofRequirement::ExpectedEffects,
];

/// The operation ref every verified GitHub read carries
/// (`verified_github_reads._decision` :280).
const GITHUB_READ_OPERATION_REF: &str = "operation:github-public-pull-request-view";

/// `verified_read_execution._decision` (:417).
pub fn verified_workspace_read_decision(
    operation_id: &str,
    binding_digest: &str,
) -> Result<EffectDecision, &'static str> {
    let proof = proof(binding_digest, WORKSPACE_READ_REQUIREMENTS);
    let factor = DecisionFactor {
        source: DecisionFactorSource::Effect,
        reason_code: "verified-workspace-read".to_owned(),
        basis: DecisionBasis {
            action_floor: GuardAction::Allow,
            proof_route: Some(ProofRoute::Verified),
        },
        segment_ref: None,
        operation_ref: Some(format!("operation:{operation_id}")),
        producer_ref: Some("executor:verified-read-v1".to_owned()),
        evidence_digest: Some(proof.binding_digest.clone()),
        assessment: Some(EffectAssessment {
            kind: EffectKind::WorkspaceOrPublicRead,
            target_scope: EffectTargetScope::Workspace,
            reversibility: EffectReversibility::TriviallyRecoverable,
            blast_radius: EffectBlastRadius::Workspace,
            evidence_source: EffectEvidenceSource::Runtime,
            confidence: EffectConfidence::Exact,
            containment: ContainmentRequirement::None,
            proof_requirements: WORKSPACE_READ_REQUIREMENTS.to_vec(),
            uncertainty_reasons: Vec::new(),
            schema_version: EFFECT_CONTRACT_SCHEMA_VERSION.to_owned(),
        }),
        proof: Some(proof),
    };
    evaluate_effect_decision(&request(vec![factor]))
}

/// `verified_github_reads._decision` (:276). One factor per effect kind, both
/// bound to the same proof.
pub fn verified_github_read_decision(binding_digest: &str) -> Result<EffectDecision, &'static str> {
    let factors = [EffectKind::NetworkRead, EffectKind::RemoteStateRead]
        .into_iter()
        .map(|kind| {
            let proof = proof(binding_digest, GITHUB_READ_REQUIREMENTS);
            DecisionFactor {
                source: DecisionFactorSource::Effect,
                reason_code: format!("verified-{}", kind.as_str()),
                basis: DecisionBasis {
                    action_floor: GuardAction::Allow,
                    proof_route: Some(ProofRoute::Verified),
                },
                segment_ref: None,
                operation_ref: Some(GITHUB_READ_OPERATION_REF.to_owned()),
                producer_ref: Some("executor:verified-github-read-v1".to_owned()),
                evidence_digest: Some(proof.binding_digest.clone()),
                assessment: Some(EffectAssessment {
                    kind,
                    target_scope: EffectTargetScope::RemoteResource,
                    reversibility: EffectReversibility::Reversible,
                    blast_radius: EffectBlastRadius::SingleResource,
                    evidence_source: EffectEvidenceSource::Runtime,
                    confidence: EffectConfidence::Exact,
                    containment: ContainmentRequirement::None,
                    proof_requirements: GITHUB_READ_REQUIREMENTS.to_vec(),
                    uncertainty_reasons: Vec::new(),
                    schema_version: EFFECT_CONTRACT_SCHEMA_VERSION.to_owned(),
                }),
                proof: Some(proof),
            }
        })
        .collect();
    evaluate_effect_decision(&request(factors))
}

/// Both callers pass `PositiveProof(ProofRoute.VERIFIED, digest, requirements)`,
/// which leaves `enforced` at the Python dataclass default of `False`.
fn proof(binding_digest: &str, requirements: &[ProofRequirement]) -> PositiveProof {
    PositiveProof {
        route: ProofRoute::Verified,
        binding_digest: binding_digest.to_owned(),
        satisfied_requirements: requirements.to_vec(),
        enforced: false,
    }
}

fn request(factors: Vec<DecisionFactor>) -> EffectDecisionRequest {
    EffectDecisionRequest {
        factors,
        uncertainties: Vec::new(),
        schema_version: EFFECT_DECISION_SCHEMA_VERSION.to_owned(),
    }
}
