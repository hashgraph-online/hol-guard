use super::*;

use serde_json::json;

fn request() -> ToolActionRequestIdentityRequestV1 {
    ToolActionRequestIdentityRequestV1 {
        schema: TOOL_ACTION_REQUEST_IDENTITY_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
        harness: "codex".to_owned(),
        source_scope: "project".to_owned(),
        normalized_tool_name: "shell".to_owned(),
        command_text: "npm install left-pad".to_owned(),
        action_class: "package_install".to_owned(),
        shell_execution_context_hash: None,
        interpreter_executable_identities: Vec::new(),
        script_read_identity_sha256: None,
        restricted_profile_version: None,
        pytest_config_identity_sha256: None,
    }
}

fn decode(request: &ToolActionRequestIdentityRequestV1) -> ToolActionRequestIdentityResultV1 {
    serde_json::from_slice(&evaluate_tool_action_request_identity(request).unwrap()).unwrap()
}

#[test]
fn a_well_formed_request_yields_the_python_artifact_id() {
    let req = request();
    let result = decode(&req);
    assert_eq!(result.status, "ok");
    assert_eq!(result.code, "ok");
    assert_eq!(result.request_id, "req-1");
    assert_eq!(
        result.artifact_id.as_deref(),
        Some(
            "codex:project:tool-action:\
             eb1b99795c6bca333d21943b4f502ee7d4d79b05226b08de85823fec068b7d2a"
        )
    );
}

/// The digest binds the reply to the request Python sent, so it has to be the
/// one `_canonical_request_sha256` computes over the same dict.
#[test]
fn the_request_digest_matches_the_python_canonical_form() {
    assert_eq!(
        decode(&request()).request_sha256,
        "712b969fe8d921fa024456cf4a5f1543faaa82135d86d67fb241d9be6fd4d96c"
    );
}

#[test]
fn optional_identities_reach_the_fingerprint() {
    let req = ToolActionRequestIdentityRequestV1 {
        harness: "claude".to_owned(),
        source_scope: "global".to_owned(),
        shell_execution_context_hash: Some("a".repeat(64)),
        interpreter_executable_identities: vec![
            json!({"path": "/usr/bin/python3", "status": "resolved", "sha256": "b".repeat(64)}),
            json!({"path": null, "status": "ambiguous"}),
        ],
        script_read_identity_sha256: Some("c".repeat(64)),
        restricted_profile_version: Some("2.1.0".to_owned()),
        pytest_config_identity_sha256: Some("d".repeat(64)),
        ..request()
    };
    assert_eq!(
        decode(&req).artifact_id.as_deref(),
        Some(
            "claude:global:tool-action:\
             f25b683fb2e5498012f0f2051766c38fa8edc47e9377230daa6d4fcd4a264842"
        )
    );
}

#[test]
fn a_foreign_schema_fails_closed_and_still_binds_the_reply() {
    let mut req = request();
    req.schema = "guard-tool-action-request-identity-request.v0".to_owned();
    let result = decode(&req);
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_tool_action_identity_schema_mismatch");
    assert!(result.artifact_id.is_none());
    assert_eq!(result.request_id, "req-1");
    assert_eq!(result.request_sha256.len(), 64);
}

#[test]
fn an_oversized_request_fails_closed() {
    let req = ToolActionRequestIdentityRequestV1 {
        command_text: "a".repeat(TOOL_ACTION_REQUEST_IDENTITY_MAX_REQUEST_BYTES + 1),
        ..request()
    };
    let result = decode(&req);
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_tool_action_identity_request_too_large");
    assert!(result.artifact_id.is_none());
}

#[test]
fn an_empty_harness_or_scope_fails_closed() {
    for req in [
        ToolActionRequestIdentityRequestV1 {
            harness: String::new(),
            ..request()
        },
        ToolActionRequestIdentityRequestV1 {
            source_scope: String::new(),
            ..request()
        },
    ] {
        let result = decode(&req);
        assert_eq!(result.status, "error");
        assert_eq!(result.code, "native_tool_action_identity_invalid");
        assert!(result.artifact_id.is_none());
    }
}
