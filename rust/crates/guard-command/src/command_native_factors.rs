//! Native authority and explicit-permission factors for command policy
//! (`runtime/command_native_factors.py`).

use std::collections::BTreeSet;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::canonical_command::CanonicalCommand;
use crate::effect_decision::{
    DecisionBasis, DecisionFactor, DecisionFactorSource, GuardAction, PositiveProof,
    ProofRequirement, ProofRoute,
};
use crate::extension_control::ExtensionControlLayer;
use crate::github_capability_contract::github_capability_contract;
use crate::github_command_capabilities::classify_github_cli;

/// Authority evidence bound into explicit-permission proofs
/// (`ExtensionControlDecisionEvidence.revision` / `.effective_digest`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityEvidence {
    pub revision: u64,
    pub effective_digest: String,
}

fn canonical_digest(value: &Value) -> String {
    let mut bytes = Vec::new();
    // Inputs are strings, booleans, integers, and arrays/objects of those.
    let _ = guard_contracts::write_canonical_json(value, &mut bytes);
    format!("{:x}", Sha256::digest(&bytes))
}

fn minimum_action_is(value: &Value, expected: &str) -> bool {
    value.get("minimum_action").and_then(Value::as_str) == Some(expected)
}

/// `_native_classification_factors`: carry native hard blocks, reapproval, and
/// benign proof into host policy composition.
pub fn native_classification_factors(
    value: &Value,
    command: &CanonicalCommand,
    allow_benign_proof: bool,
) -> Vec<DecisionFactor> {
    if !value.is_object() {
        return Vec::new();
    }
    let blocked = minimum_action_is(value, "block");
    let requires_reapproval = minimum_action_is(value, "require-reapproval");
    let reapproval_reason = if value.get("reason_code").and_then(Value::as_str)
        == Some("native_privileged_wrapper_reapproval")
    {
        "native.privileged-wrapper-reapproval"
    } else {
        "native.classification-reapproval"
    };
    let explicitly_benign = allow_benign_proof
        && command.confidence == "exact"
        && minimum_action_is(value, "allow")
        && value.get("explicitly_benign") == Some(&Value::Bool(true));
    if !(blocked || requires_reapproval || explicitly_benign) {
        return Vec::new();
    }
    let digest = canonical_digest(&json!({
        "schema": "guard.native-classification-projection.v1",
        "command_security_identity": command.security_identity,
        "command_extensions": value.get("command_extensions").cloned().unwrap_or(Value::Null),
        "minimum_action": if blocked {
            "block"
        } else if requires_reapproval {
            "require-reapproval"
        } else {
            "allow"
        },
        "explicitly_benign": explicitly_benign,
    }));
    let mut factor = DecisionFactor {
        source: DecisionFactorSource::Assurance,
        reason_code: String::new(),
        basis: DecisionBasis {
            action_floor: GuardAction::Allow,
            proof_route: None,
        },
        segment_ref: None,
        operation_ref: None,
        producer_ref: Some("native:command-classification".to_owned()),
        evidence_digest: Some(digest.clone()),
        assessment: None,
        proof: None,
    };
    if blocked {
        factor.reason_code = "native.classification-block".to_owned();
        factor.basis.action_floor = GuardAction::Block;
    } else if requires_reapproval {
        factor.reason_code = reapproval_reason.to_owned();
        factor.basis.action_floor = GuardAction::RequireReapproval;
    } else {
        factor.reason_code = "native.explicit-benign".to_owned();
        factor.basis.proof_route = Some(ProofRoute::Verified);
        factor.proof = Some(PositiveProof {
            route: ProofRoute::Verified,
            binding_digest: digest,
            satisfied_requirements: vec![
                ProofRequirement::ConfigurationIdentity,
                ProofRequirement::ParserConfidence,
            ],
            enforced: false,
        });
    }
    vec![factor]
}

/// `_explicit_permission_allow_factors`.
pub fn explicit_permission_allow_factors(
    command: &CanonicalCommand,
    layers: &[ExtensionControlLayer],
    permission_ids: &BTreeSet<String>,
    authority_evidence: Option<&AuthorityEvidence>,
) -> Vec<DecisionFactor> {
    if command.confidence != "exact" || permission_ids.is_empty() {
        return Vec::new();
    }
    let mut ordered: Vec<&ExtensionControlLayer> = layers.iter().collect();
    ordered.sort_by_key(|layer| layer.kind.as_str());
    let canonical_layers: Vec<Value> = ordered
        .into_iter()
        .map(|layer| {
            let mut controls: Vec<_> = layer.controls.iter().collect();
            controls.sort_by(|a, b| {
                (a.target.kind.as_str(), a.target.target_id.as_str())
                    .cmp(&(b.target.kind.as_str(), b.target.target_id.as_str()))
            });
            json!({
                "kind": layer.kind.as_str(),
                "catalog_digest": layer.catalog_digest,
                "global_lockdown": layer.global_lockdown,
                "controls": controls
                    .iter()
                    .map(|control| json!({
                        "kind": control.target.kind.as_str(),
                        "target_id": control.target.target_id,
                        "state": control.state.as_str(),
                    }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    let authority = authority_evidence.map(|evidence| {
        json!({"revision": evidence.revision, "effective_digest": evidence.effective_digest})
    });
    permission_ids
        .iter()
        .map(|permission_id| {
            let binding_digest = canonical_digest(&json!({
                "command_security_identity": command.security_identity,
                "permission_id": permission_id,
                "layers": canonical_layers,
                "authority": authority,
            }));
            DecisionFactor {
                source: DecisionFactorSource::Control,
                reason_code: "control.explicitly-enabled-permission".to_owned(),
                basis: DecisionBasis {
                    action_floor: GuardAction::Allow,
                    proof_route: Some(ProofRoute::Verified),
                },
                segment_ref: None,
                operation_ref: None,
                producer_ref: Some(format!("control:{permission_id}")),
                evidence_digest: Some(binding_digest.clone()),
                assessment: None,
                proof: Some(PositiveProof {
                    route: ProofRoute::Verified,
                    binding_digest,
                    satisfied_requirements: vec![
                        ProofRequirement::ConfigurationIdentity,
                        ProofRequirement::ParserConfidence,
                        ProofRequirement::CapabilityConstraints,
                    ],
                    enforced: false,
                }),
            }
        })
        .collect()
}

/// `_direct_github_permission_ids`: catalog permissions for exact GitHub
/// capabilities without matcher rules.
pub fn direct_github_permission_ids(command: &CanonicalCommand) -> BTreeSet<String> {
    let mut permission_ids = BTreeSet::new();
    for segment in &command.segments {
        let executable = segment
            .executable
            .as_deref()
            .unwrap_or("")
            .replace('\\', "/")
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_lowercase();
        if executable.strip_suffix(".exe").unwrap_or(&executable) != "gh" {
            continue;
        }
        for capability in &classify_github_cli(&segment.arguments).capabilities {
            permission_ids.insert(
                github_capability_contract(*capability)
                    .permission_id
                    .clone(),
            );
        }
    }
    permission_ids
}
