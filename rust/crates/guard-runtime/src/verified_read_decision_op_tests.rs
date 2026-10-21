use super::*;

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn workspace_request() -> VerifiedReadDecisionRequestV1 {
    VerifiedReadDecisionRequestV1 {
        schema: VERIFIED_READ_DECISION_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
        binding_digest: DIGEST.to_owned(),
        read: VerifiedReadDecisionKindV1::Workspace {
            operation_id: "op-123".to_owned(),
        },
    }
}

fn decode(request: &VerifiedReadDecisionRequestV1) -> VerifiedReadDecisionResultV1 {
    serde_json::from_slice(&evaluate_verified_read_decision(request).unwrap()).unwrap()
}

#[test]
fn a_workspace_read_yields_the_python_decision() {
    let result = decode(&workspace_request());
    assert_eq!(result.status, "ok");
    assert_eq!(result.code, "ok");
    let decision = result.decision.expect("decision");
    assert_eq!(decision["action"], "allow");
    assert_eq!(decision["disposition"], "silent-verified");
    assert_eq!(decision["proof_routes"], serde_json::json!(["verified"]));
    assert_eq!(decision["reasons"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        decision["reasons"][0]["reason_code"],
        "verified-workspace-read"
    );
    assert_eq!(decision["reasons"][0]["operation_ref"], "operation:op-123");
}

#[test]
fn a_github_read_yields_both_python_reasons() {
    let request = VerifiedReadDecisionRequestV1 {
        read: VerifiedReadDecisionKindV1::GithubPublicRead {},
        ..workspace_request()
    };
    let decision = decode(&request).decision.expect("decision");
    assert_eq!(decision["disposition"], "silent-verified");
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

/// The digest binds the reply to the request Python sent, so it has to be the
/// one `_canonical_request_sha256` computes over the same dict.
#[test]
fn the_request_digest_matches_the_python_canonical_form() {
    assert_eq!(
        decode(&workspace_request()).request_sha256,
        "453e0f67029dc743c6ac871325e8222e527f865115a6ef3f77c7dc676830ac5b"
    );
}

#[test]
fn a_foreign_schema_fails_closed_and_still_binds_the_reply() {
    let mut request = workspace_request();
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
        read: VerifiedReadDecisionKindV1::Workspace {
            operation_id: "a".repeat(VERIFIED_READ_DECISION_MAX_REQUEST_BYTES + 1),
        },
        ..workspace_request()
    };
    let result = decode(&request);
    assert_eq!(result.status, "error");
    assert_eq!(
        result.code,
        "native_verified_read_decision_request_too_large"
    );
    assert!(result.decision.is_none());
}

/// A digest the executor did not produce, and an operation the decision would
/// not be attached to, both have to fail rather than yield a silent allow.
#[test]
fn a_bad_digest_or_empty_operation_fails_closed() {
    let bad_digest = VerifiedReadDecisionRequestV1 {
        binding_digest: "not-a-digest".to_owned(),
        ..workspace_request()
    };
    let no_operation = VerifiedReadDecisionRequestV1 {
        read: VerifiedReadDecisionKindV1::Workspace {
            operation_id: String::new(),
        },
        ..workspace_request()
    };
    for request in [bad_digest, no_operation] {
        let result = decode(&request);
        assert_eq!(result.status, "error");
        assert_eq!(result.code, "native_verified_read_decision_invalid");
        assert!(result.decision.is_none());
    }
}
