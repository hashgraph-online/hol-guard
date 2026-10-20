//! Oracle payloads recorded from the retired Python `evaluate_effect_decision`
//! on the factors `verified_read_execution._decision` and
//! `verified_github_reads._decision` built, before either caller moved here.

use serde_json::json;

use crate::effect_decision::effect_decision_to_payload;
use crate::verified_read_decision::{
    verified_github_read_decision, verified_workspace_read_decision,
};

const WORKSPACE_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GITHUB_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn workspace_read_matches_python_payload() {
    let decision = verified_workspace_read_decision("op-123", WORKSPACE_DIGEST).expect("decision");
    let reason = json!({
        "action_floor": "allow",
        "operation_ref": "operation:op-123",
        "reason_code": "verified-workspace-read",
        "segment_ref": null,
        "source": "effect",
    });
    assert_eq!(
        effect_decision_to_payload(&decision),
        json!({
            "action": "allow",
            "controlling_reasons": [reason.clone()],
            "disposition": "silent-verified",
            "proof_routes": ["verified"],
            "reasons": [reason],
            "schema_version": "1.1.0",
        })
    );
}

#[test]
fn github_read_matches_python_payload() {
    let decision = verified_github_read_decision(GITHUB_DIGEST).expect("decision");
    let network = json!({
        "action_floor": "allow",
        "operation_ref": "operation:github-public-pull-request-view",
        "reason_code": "verified-network-read",
        "segment_ref": null,
        "source": "effect",
    });
    let remote = json!({
        "action_floor": "allow",
        "operation_ref": "operation:github-public-pull-request-view",
        "reason_code": "verified-remote-state-read",
        "segment_ref": null,
        "source": "effect",
    });
    assert_eq!(
        effect_decision_to_payload(&decision),
        json!({
            "action": "allow",
            "controlling_reasons": [network.clone(), remote.clone()],
            "disposition": "silent-verified",
            "proof_routes": ["verified"],
            "reasons": [network, remote],
            "schema_version": "1.1.0",
        })
    );
}

#[test]
fn workspace_read_carries_the_operation_id_it_was_given() {
    let decision = verified_workspace_read_decision("op-zzz", WORKSPACE_DIGEST).expect("decision");
    assert_eq!(
        decision.reasons[0].operation_ref.as_deref(),
        Some("operation:op-zzz")
    );
}

#[test]
fn a_non_sha256_binding_digest_is_refused() {
    // The proof's `__post_init__` check: a digest the host did not produce by
    // framing cannot stand in for one that it did.
    assert!(verified_workspace_read_decision("op-123", "not-a-digest").is_err());
    assert!(verified_github_read_decision("").is_err());
}

#[test]
fn both_github_factors_bind_to_the_same_proof() {
    let decision = verified_github_read_decision(GITHUB_DIGEST).expect("decision");
    assert_eq!(decision.proof_routes.len(), 1);
    assert_eq!(decision.reasons.len(), 2);
}
