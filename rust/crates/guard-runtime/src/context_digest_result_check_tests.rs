//! Parity of the result-contract gate with the Python decoder it replaced.
//!
//! The vectors were recorded from the Python transport's `_decode_result` over
//! the semantic rejections the resident now owns; each case carries the verdict
//! Python reached, and the gate must reach the same one.

use super::*;
use guard_contracts::ContextDigestKindV1;
use serde_json::json;

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/context_digest_result_check_vectors.json"
));

#[test]
fn gate_matches_recorded_python_verdicts() {
    let corpus: Value = serde_json::from_str(VECTORS).expect("vectors must parse");
    let cases = corpus["cases"].as_array().expect("cases must be a list");
    assert!(cases.len() > 50, "corpus unexpectedly small");
    let mut rejected = 0;
    for case in cases {
        let kind = case["kind"].as_str().expect("kind");
        let verdict = check_result(kind, &case["payload"]).is_ok();
        let expected = case["accepted"].as_bool().expect("accepted");
        assert_eq!(verdict, expected, "case {}", case["name"]);
        rejected += usize::from(!expected);
    }
    assert!(rejected > 25, "corpus must exercise rejections");
}

#[test]
fn every_kind_name_is_a_contract_tag() {
    let names = [
        "build_approval_context_token",
        "validate_approval_context_tokens",
        "configured_environment_hash",
        "configured_headers_hash",
        "launch_argv_digest",
        "canonical_sha256",
        "opaque_material_digest",
        "mcp_redact_json",
        "mcp_launch_environment",
        "package_execution_context_from_evidence",
        "package_execution_context_from_scanner_evidence",
        "custom_extension_continuity",
        "managed_controls_policy_fields",
        "local_cli_identity",
        "package_json_scripts",
        "local_cli_identify",
        "custom_extension_suggestion",
        "claude_guard_question",
        "memory_pattern",
        "mcp_server_identity",
        "mcp_tool_identity",
        "browser_mcp",
        "runtime_executable_identity",
        "runtime_launch_identity",
        "runtime_launch_identity_matches",
        "runtime_launch_identity_projection",
        "mcp_tool_catalog_fingerprint",
        "runtime_hook_approval_context",
        "generic_hook_approval_context",
    ];
    for name in names {
        // A bare tag may or may not be a complete request; it is only ever
        // wrong when the contract does not know the tag at all.
        if let Err(error) = serde_json::from_value::<ContextDigestKindV1>(json!({ "kind": name })) {
            assert!(
                !error.to_string().contains("unknown variant"),
                "{name} is not a contract tag: {error}"
            );
        }
    }
}

#[test]
fn kind_name_follows_the_request_tag() {
    let request: ContextDigestKindV1 = serde_json::from_value(json!({
        "kind": "canonical_sha256", "material": {"a": 1}, "prefix": null
    }))
    .expect("canonical request");
    assert_eq!(kind_name(&request), "canonical_sha256");
    let request: ContextDigestKindV1 = serde_json::from_value(json!({
        "kind": "launch_argv_digest", "argv": ["x"]
    }))
    .expect("argv request");
    assert_eq!(kind_name(&request), "launch_argv_digest");
}

#[test]
fn resident_answer_that_breaks_the_contract_never_encodes() {
    assert_eq!(
        check_result("canonical_sha256", &json!({"status": "ok", "code": "ok"})),
        Err(ERR_RESULT_INVALID)
    );
    assert_eq!(
        check_result("canonical_sha256", &json!([1])),
        Err(ERR_RESULT_INVALID)
    );
}
