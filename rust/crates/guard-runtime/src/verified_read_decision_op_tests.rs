use super::*;

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn github_request() -> VerifiedReadDecisionRequestV1 {
    VerifiedReadDecisionRequestV1 {
        schema: VERIFIED_READ_DECISION_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
        binding_digest: DIGEST.to_owned(),
        read: VerifiedReadDecisionKindV1::GithubPublicRead {},
    }
}

fn decode(request: &VerifiedReadDecisionRequestV1) -> VerifiedReadDecisionResultV1 {
    serde_json::from_slice(&evaluate_verified_read_decision(request).unwrap()).unwrap()
}

#[test]
fn a_github_read_yields_both_python_reasons() {
    let result = decode(&github_request());
    assert_eq!(result.status, "ok");
    assert_eq!(result.code, "ok");
    let decision = result.decision.expect("decision");
    assert_eq!(decision["action"], "allow");
    assert_eq!(decision["disposition"], "silent-verified");
    assert_eq!(decision["proof_routes"], serde_json::json!(["verified"]));
    assert_eq!(decision["reasons"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        decision["reasons"][0]["reason_code"],
        "verified-network-read"
    );
    assert_eq!(
        decision["reasons"][1]["reason_code"],
        "verified-remote-state-read"
    );
    assert_eq!(
        decision["reasons"][1]["operation_ref"],
        "operation:github-public-pull-request-view"
    );
}

/// The workspace read composes its decision inside the execute op, so the only
/// kind this op takes is the GitHub one. A request naming the retired workspace
/// kind has to be refused by the contract rather than decided here.
#[test]
fn a_workspace_kind_is_no_longer_a_request_this_op_accepts() {
    let wire = serde_json::json!({
        "schema": VERIFIED_READ_DECISION_REQUEST_SCHEMA,
        "request_id": "req-1",
        "binding_digest": DIGEST,
        "read": {"kind": "workspace", "operation_id": "op-123"},
    });
    assert!(serde_json::from_value::<VerifiedReadDecisionRequestV1>(wire).is_err());
}

/// The digest binds the reply to the request Python sent, so it has to be the
/// one `_canonical_request_sha256` computes over the same dict.
#[test]
fn the_request_digest_matches_the_python_canonical_form() {
    assert_eq!(
        decode(&github_request()).request_sha256,
        "90061f5a4178cf057663791601b05abe0450d94475e6abbaadf2b5bad95ffc74"
    );
}

#[test]
fn a_foreign_schema_fails_closed_and_still_binds_the_reply() {
    let mut request = github_request();
    request.schema = "guard-verified-read-decision-request.v0".to_owned();
    let result = decode(&request);
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_verified_read_decision_schema_mismatch");
    assert!(result.decision.is_none());
    assert_eq!(result.request_id, "req-1");
    assert_eq!(result.request_sha256.len(), 64);
}

#[test]
fn an_oversized_request_fails_closed() {
    let request = VerifiedReadDecisionRequestV1 {
        request_id: "a".repeat(VERIFIED_READ_DECISION_MAX_REQUEST_BYTES + 1),
        ..github_request()
    };
    let result = decode(&request);
    assert_eq!(result.status, "error");
    assert_eq!(
        result.code,
        "native_verified_read_decision_request_too_large"
    );
    assert!(result.decision.is_none());
}

/// A digest the executor did not produce has to fail rather than yield a silent
/// allow.
#[test]
fn a_bad_digest_fails_closed() {
    let request = VerifiedReadDecisionRequestV1 {
        binding_digest: "not-a-digest".to_owned(),
        ..github_request()
    };
    let result = decode(&request);
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_verified_read_decision_invalid");
    assert!(result.decision.is_none());
}
