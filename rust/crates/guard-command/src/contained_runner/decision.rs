//! Proof, decision and result assembly shared by the contained runners.
//!
//! Faithful port of `containment_execution_support.py`.

use serde_json::{json, Value};

use super::contract::{Attestation, Request};
use super::exec::execute_contained;
use super::health::{contained_positive_proof, current_health, now_micros};
use crate::effect_decision::{
    effect_decision_to_payload, evaluate_effect_decision, ContainmentRequirement, DecisionBasis,
    DecisionFactor, DecisionFactorSource, EffectAssessment, EffectBlastRadius, EffectConfidence,
    EffectDecision, EffectDecisionRequest, EffectEvidenceSource, EffectKind, EffectReversibility,
    EffectTargetScope, FinalDisposition, GuardAction, PositiveProof, ProofRequirement, ProofRoute,
    EFFECT_CONTRACT_SCHEMA_VERSION, EFFECT_DECISION_SCHEMA_VERSION,
};

pub(crate) const EXECUTION_PROOF_REQUIREMENTS: [ProofRequirement; 7] = [
    ProofRequirement::OperationAndTargets,
    ProofRequirement::WorkspaceIdentity,
    ProofRequirement::WorkingDirectoryIdentity,
    ProofRequirement::ExecutableIdentity,
    ProofRequirement::LaunchChain,
    ProofRequirement::ParserConfidence,
    ProofRequirement::ExpectedEffects,
];

/// One contained execution with the proof and decision that admit it.
#[derive(Debug, Clone)]
pub(crate) struct ContainedOutcome {
    pub(crate) exit_code: i32,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) attestation: Attestation,
    pub(crate) proof: PositiveProof,
    pub(crate) decision: EffectDecision,
    pub(crate) operation_id: String,
}

impl ContainedOutcome {
    pub(crate) fn to_value(&self) -> Result<Value, String> {
        let attestation = &self.attestation;
        Ok(json!({
            "attestation": {
                "exit_code": self.exit_code,
                "backend": attestation.backend.as_str(),
                "backend_digest": attestation.backend_digest,
                "request_digest": attestation.request_digest,
                "policy_digest": attestation.policy_digest,
                "launch_digest": attestation.launch_digest,
                "executable_digest": attestation.executable_digest,
                "enforced": attestation.enforced,
                "failure": null,
            },
            "decision": effect_decision_to_payload(&self.decision),
            "proof": serde_json::to_value(&self.proof).map_err(|error| error.to_string())?,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "operation_id": self.operation_id,
        }))
    }
}

/// How a runner judges a finished process.
pub(crate) enum ExitPolicy {
    /// Any exit status is a completed enforced run (test and lint runners).
    AnyExit,
    /// Only a zero exit counts (type checks).
    ZeroExit,
}

pub(crate) struct DecisionLabels<'a> {
    pub(crate) operation_id: &'a str,
    pub(crate) producer_ref: &'a str,
    pub(crate) reason_code: Option<&'a str>,
}

/// Run the request once under enforced containment and mint its decision.
pub(crate) fn execute_and_decide(
    request: &Request,
    timeout_seconds: f64,
    exit_policy: ExitPolicy,
    labels: &DecisionLabels,
) -> Result<ContainedOutcome, String> {
    // Fail closed before running anything when containment is unhealthy.
    current_health()?;
    let result = execute_contained(request, timeout_seconds)?;
    // A long run can outlive the probe that admitted it; take the proof
    // against current health (re-probed in-process when stale) so a completed
    // contained run is not discarded as `containment_probe_stale`.
    let (health, fingerprint) = current_health()?;
    let exit_code = match (result.enforced(), result.exit_code, exit_policy) {
        (true, Some(code), ExitPolicy::AnyExit) => code,
        (true, Some(0), ExitPolicy::ZeroExit) => 0,
        _ => return Err("contained execution was not enforced or did not complete".to_owned()),
    };
    let proof = contained_positive_proof(
        &result.attestation,
        request,
        &health,
        &EXECUTION_PROOF_REQUIREMENTS,
        now_micros(),
        &fingerprint,
    )?;
    let decision = contained_process_effect_decision(&proof, labels)?;
    if decision.disposition != FinalDisposition::SilentContained {
        return Err("decision did not admit silent contained execution".to_owned());
    }
    Ok(ContainedOutcome {
        exit_code,
        stdout: result.stdout,
        stderr: result.stderr,
        attestation: result.attestation,
        proof,
        decision,
        operation_id: labels.operation_id.to_owned(),
    })
}

/// Evaluate a contained process-execution effect for one local runner.
pub(crate) fn contained_process_effect_decision(
    proof: &PositiveProof,
    labels: &DecisionLabels,
) -> Result<EffectDecision, String> {
    let mut requirements = EXECUTION_PROOF_REQUIREMENTS.to_vec();
    requirements.push(ProofRequirement::ContainmentIdentity);
    let assessment = EffectAssessment {
        kind: EffectKind::ProcessExecution,
        target_scope: EffectTargetScope::Workspace,
        reversibility: EffectReversibility::TriviallyRecoverable,
        blast_radius: EffectBlastRadius::Workspace,
        evidence_source: EffectEvidenceSource::Containment,
        confidence: EffectConfidence::Strong,
        containment: ContainmentRequirement::Required,
        proof_requirements: requirements,
        uncertainty_reasons: Vec::new(),
        schema_version: EFFECT_CONTRACT_SCHEMA_VERSION.to_owned(),
    };
    let reason_code = labels.reason_code.map_or_else(
        || format!("routine-{}-contained", labels.operation_id),
        str::to_owned,
    );
    let factor = DecisionFactor {
        source: DecisionFactorSource::Effect,
        reason_code,
        basis: DecisionBasis {
            action_floor: GuardAction::Allow,
            proof_route: Some(ProofRoute::Contained),
        },
        segment_ref: None,
        operation_ref: Some(format!("operation:{}", labels.operation_id)),
        producer_ref: Some(labels.producer_ref.to_owned()),
        evidence_digest: Some(proof.binding_digest.clone()),
        assessment: Some(assessment),
        proof: Some(proof.clone()),
    };
    evaluate_effect_decision(&EffectDecisionRequest {
        factors: vec![factor],
        uncertainties: Vec::new(),
        schema_version: EFFECT_DECISION_SCHEMA_VERSION.to_owned(),
    })
    .map_err(|error| format!("{error:?}"))
}
