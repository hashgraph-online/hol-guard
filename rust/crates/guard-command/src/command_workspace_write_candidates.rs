//! Rust port of `runtime/command_workspace_write_candidates.py`.
//!
//! On the native path `command.redirects` and `command.embedded_commands`
//! are always empty (`canonical_command.rs::from_v1`). Consequences:
//! - `_symlink_write_through` requires `len(redirects) == 1` → unreachable,
//!   so the symlink-block branch and `redirect.operator`/`redirect.target`
//!   reads are dead and are not ported.
//! - `_plain_command`'s `not command.redirects` is a tautology → `_plain`
//!   reduces to `_exact`.
//! - `_exact`'s `not command.embedded_commands` is a tautology → omitted.

use crate::canonical_command::CanonicalCommand;
use crate::effect_decision::{
    ContainmentRequirement, DecisionBasis, DecisionFactor, DecisionFactorSource, EffectAssessment,
    EffectBlastRadius, EffectConfidence, EffectEvidenceSource, EffectKind, EffectReversibility,
    EffectTargetScope, GuardAction, ProofRequirement,
};
use crate::CommandSegmentV1;

#[allow(dead_code)]
pub const WORKSPACE_WRITE_CANDIDATE_VERSION: &str = "guard.workspace-write-candidate.v1";

/// `workspace_write_candidate_factors` (:26).
///
/// The `_symlink_write_through` block branch is dead on the native path
/// (no redirects); only the contained-operation review factor is reachable.
pub fn workspace_write_candidate_factors(command: &CanonicalCommand) -> Vec<DecisionFactor> {
    let operation = match workspace_write_candidate_operation(command) {
        Some(op) => op,
        None => return Vec::new(),
    };
    let kind = if operation == "patch-check" {
        EffectKind::ProcessExecution
    } else {
        EffectKind::WorkspaceWrite
    };
    vec![DecisionFactor {
        source: DecisionFactorSource::Effect,
        reason_code: "contained-workspace-write-proof-required".to_owned(),
        basis: DecisionBasis {
            action_floor: GuardAction::Review,
            proof_route: None,
        },
        segment_ref: None,
        operation_ref: Some(format!("operation:{operation}")),
        producer_ref: Some("policy:workspace-write-candidate-v1".to_owned()),
        evidence_digest: None,
        assessment: Some(EffectAssessment {
            kind,
            target_scope: EffectTargetScope::Workspace,
            reversibility: EffectReversibility::Reversible,
            blast_radius: EffectBlastRadius::Workspace,
            evidence_source: EffectEvidenceSource::Parser,
            confidence: EffectConfidence::Strong,
            containment: ContainmentRequirement::Required,
            proof_requirements: vec![
                ProofRequirement::OperationAndTargets,
                ProofRequirement::WorkspaceIdentity,
                ProofRequirement::ExecutableIdentity,
                ProofRequirement::ShellDataFlow,
                ProofRequirement::ExpectedEffects,
                ProofRequirement::ContainmentIdentity,
            ],
            uncertainty_reasons: Vec::new(),
            schema_version: crate::effect_decision::EFFECT_CONTRACT_SCHEMA_VERSION.to_owned(),
        }),
        proof: None,
    }]
}

/// `workspace_write_candidate_operation` (:88).
pub fn workspace_write_candidate_operation(command: &CanonicalCommand) -> Option<&'static str> {
    if !plain_command(command) || command.segments.is_empty() {
        return None;
    }
    let operation: &CommandSegmentV1 = if command.segments.len() == 1 {
        &command.segments[0]
    } else if command.segments.len() == 2 {
        let directory = &command.segments[0];
        if name(directory) != "cd"
            || directory.arguments.len() != 1
            || !plain_value(&directory.arguments[0])
        {
            return None;
        }
        &command.segments[1]
    } else {
        return None;
    };
    let op_name = name(operation);
    let args = operation.arguments.as_slice();
    if op_name == "git"
        && args.len() == 3
        && args[..2] == ["apply", "--check"]
        && plain_value(&args[2])
    {
        return Some("patch-check");
    }
    if op_name == "git" && args.len() == 2 && args[0] == "apply" && plain_value(&args[1]) {
        return Some("patch-apply");
    }
    if op_name == "ruff" && args.len() == 2 && args[0] == "format" && plain_value(&args[1]) {
        return Some("format-write");
    }
    if op_name == "cp" && args.len() == 2 && args.iter().all(|v| plain_value(v)) {
        return Some("copy-generated");
    }
    None
}

/// `_plain_command` (:132) — `_exact` (redirects always empty natively).
fn plain_command(command: &CanonicalCommand) -> bool {
    exact_command(command)
}

/// `_exact_command` (:136).
fn exact_command(command: &CanonicalCommand) -> bool {
    !command.segments.is_empty()
        && command.confidence == "exact"
        && command.uncertainty_reason.is_none()
        && command.dialect == "posix"
        && command.transport == "shell_string"
        && command.wrapper_chain.is_empty()
        // `not command.embedded_commands` — always empty on the native path.
        && command.segments.iter().all(|segment| {
            segment.execution_context.starts_with("top:")
                && segment.wrapper_chain.is_empty()
                && segment.environment_names.is_empty()
                && !segment.path_overridden
        })
}

/// `_name` (:156): `Path(segment.executable or "").name.lower()`.
fn name(segment: &CommandSegmentV1) -> String {
    let exe = segment.executable.as_deref().unwrap_or("");
    exe.rsplit('/').next().unwrap_or(exe).to_lowercase()
}

/// `_plain_value` (:160).
fn plain_value(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value
            .chars()
            .any(|c| matches!(c, '$' | '`' | '<' | '>' | '|' | ';' | '&' | '\0'))
}
