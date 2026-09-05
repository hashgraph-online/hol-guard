use super::*;

static EDGE_FIXTURE_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn write_fixture_file(path: &std::path::Path, bytes: &[u8]) {
    #[cfg(windows)]
    {
        use std::io::Write;
        let private_root = path.parent().unwrap_or(path);
        let mut file = crate::resident_state::private_file(path, true, private_root).unwrap();
        file.write_all(bytes).unwrap();
    }
    #[cfg(not(windows))]
    std::fs::write(path, bytes).unwrap();
}

fn envelope(event: &str, payload: Value) -> GuardHookEnvelopeV2 {
    let digest = "a".repeat(64);
    let guard_home = std::env::temp_dir().join(format!(
        "hol-guard-native-edge-generation-test-{}-{}",
        std::process::id(),
        EDGE_FIXTURE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    #[cfg(windows)]
    let guard_home = crate::resident_state::ensure_private_directory(&guard_home, true)
        .expect("create edge generation fixture");
    #[cfg(not(windows))]
    std::fs::create_dir_all(&guard_home).expect("create edge generation fixture");
    let generation_path = guard_home.join("native-policy-generation.json");
    write_fixture_file(
        &generation_path,
        &serde_json::to_vec(&serde_json::json!({
            "schema": "hol-guard-native-policy-generation.v1",
            "generation": 1,
            "policy_digest": digest.clone(),
        }))
        .expect("encode edge generation fixture"),
    );
    GuardHookEnvelopeV2 {
        schema: GUARD_HOOK_ENVELOPE_V2_SCHEMA.to_owned(),
        request_id: Some("edge-test".to_owned()),
        harness: "Claude".to_owned(),
        event: event.to_owned(),
        raw_payload: payload,
        deadline_budget_ms: Some(100),
        policy_generation: 1,
        policy_snapshot: serde_json::json!({
            "schema": "hol-guard-native-policy.v1",
            "generation": 1,
            "policy_digest": digest,
            "config_digest": "b".repeat(64),
            "rule_digest": guard_rule_contract::rule_digest(),
            "mode": "enforce"
        }),
        source: guard_contracts::GuardHookSourceMetadataV2 {
            cwd: Some("/workspace".to_owned()),
            home_dir: "/home/test".to_owned(),
            guard_home: guard_home.to_string_lossy().into_owned(),
            source_ref_external_allowed: false,
        },
    }
}

fn evaluate_isolated(envelope: GuardHookEnvelopeV2) -> Result<Vec<u8>, String> {
    let guard_home = std::path::PathBuf::from(&envelope.source.guard_home);
    let result = validate_envelope_shape(&envelope)
        .and_then(|_| evaluate_validated_envelope(envelope, None));
    std::fs::remove_dir_all(guard_home).expect("remove edge generation fixture");
    result
}

#[test]
fn normalizes_harness_event_and_extracts_pretool_command() {
    let bytes = evaluate_isolated(envelope(
        "pre_tool_use",
        serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_input": {"command": "pwd"}
        }),
    ))
    .unwrap();
    let result: GuardHookEdgeResultV2 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result.harness, "claude-code");
    assert_eq!(result.event_name, "PreToolUse");
    assert_eq!(result.result["minimum_action"], "allow");
    assert_eq!(
        result.receipt.schema,
        "guard-native-hook-decision-receipt.v1"
    );
    assert_eq!(result.receipt.authority, "rust");
    assert_eq!(result.receipt.event_name, "PreToolUse");
    assert_eq!(result.receipt.decision, "allow");
    assert_eq!(result.receipt.decision_id.len(), 64);
    assert!(result.receipt.runtime_identity.is_none());
    let encoded = serde_json::to_value(result.receipt).unwrap();
    assert!(encoded.get("raw_payload").is_none());
    assert!(encoded.get("command").is_none());
}

#[test]
fn rejects_declared_and_payload_event_mismatch() {
    let error = evaluate_isolated(envelope(
        "PreToolUse",
        serde_json::json!({"hook_event_name": "PostToolUse"}),
    ))
    .unwrap_err();
    assert_eq!(error, "native_hook_event_mismatch");
}

#[test]
fn rejects_conflicting_payload_event_aliases() {
    let error = evaluate_isolated(envelope(
        "PreToolUse",
        serde_json::json!({
            "event": "PreToolUse",
            "hook_event_name": "PostToolUse",
            "tool_input": {"command": "pwd"}
        }),
    ))
    .unwrap_err();
    assert_eq!(error, "native_hook_event_mismatch");
}

#[test]
fn rejects_unknown_harness_before_command_evaluation() {
    let mut request = envelope(
        "PreToolUse",
        serde_json::json!({"tool_input": {"command": "pwd"}}),
    );
    request.harness = "unknown-agent".to_owned();
    let error = evaluate_isolated(request).unwrap_err();
    assert_eq!(error, "native_hook_harness_unsupported");
}

#[test]
fn request_digest_excludes_deadline_and_json_field_order() {
    let mut first = envelope(
        "PreToolUse",
        serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_input": {"command": "pwd", "timeout": 10}
        }),
    );
    first.request_id = None;
    let mut second = first.clone();
    second.deadline_budget_ms = Some(9_999_999);
    second.raw_payload = serde_json::json!({
        "tool_input": {"timeout": 10, "command": "pwd"},
        "eventName": "pre_tool_use"
    });
    let (_, first_digest) = request_identity(&first).unwrap();
    let (_, second_digest) = request_identity(&second).unwrap();
    assert_eq!(first_digest, second_digest);
}

#[test]
fn request_digest_excludes_root_adapter_timestamps_but_binds_nested_arguments() {
    let mut first = envelope(
        "PreToolUse",
        serde_json::json!({
            "hook_event_name": "PreToolUse",
            "timestamp": 100,
            "tool_input": {"command": "deploy", "timestamp": 10}
        }),
    );
    first.request_id = None;
    let mut second = first.clone();
    second.raw_payload = serde_json::json!({
        "eventName": "pre_tool_use",
        "timestamp": 200,
        "tool_input": {"command": "deploy", "timestamp": 11}
    });
    let (_, first_digest) = request_identity(&first).unwrap();
    let (_, second_digest) = request_identity(&second).unwrap();
    assert_ne!(first_digest, second_digest);

    second.raw_payload["tool_input"]["timestamp"] = serde_json::json!(10);
    let (_, stable_digest) = request_identity(&second).unwrap();
    assert_eq!(first_digest, stable_digest);
}

#[test]
fn rejects_malformed_source_reference_before_review() {
    let error = evaluate_isolated(envelope(
        "PostToolUse",
        serde_json::json!({"guard_source_ref": {"path": 1}}),
    ))
    .unwrap_err();
    assert_eq!(error, "native_hook_source_ref_invalid");
}

#[test]
fn evaluates_complete_cursor_file_envelope_as_native_generic_result() {
    let bytes = evaluate_isolated(envelope(
        "beforeReadFile",
        serde_json::json!({
            "event": "beforeReadFile",
            "toolName": "read_file",
            "toolInput": {"file_path": "README.md"}
        }),
    ))
    .unwrap();
    let result: GuardHookEdgeResultV2 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result.event_name, "PreToolUse");
    assert_eq!(result.result["schema"], "guard-pre-tool-result.v1");
    assert_eq!(result.result["authority"], "rust");
    assert_eq!(result.result["action"]["action_type"], "file_read");
    assert_eq!(result.result["minimum_action"], "review");
    assert!(result.result.get("raw_payload").is_none());
}

#[test]
fn evaluates_generic_pretool_for_supported_harness_aliases() {
    for (harness, expected) in [
        ("Claude", "claude-code"),
        ("Codex", "codex"),
        ("Cline", "cline"),
        ("Cursor", "cursor"),
        ("Copilot", "copilot"),
        ("Grok", "grok"),
        ("Z-Code", "zcode"),
    ] {
        let mut request = envelope(
            "PreToolUse",
            serde_json::json!({
                "hook_event_name": "PreToolUse",
                "toolName": "read_file",
                "toolInput": {"file_path": "README.md"}
            }),
        );
        request.harness = harness.to_owned();
        let bytes = evaluate_isolated(request).unwrap();
        let result: GuardHookEdgeResultV2 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result.harness, expected);
        assert_eq!(result.result["action"]["harness"], expected);
        assert_eq!(result.result["action"]["action_type"], "file_read");
        assert_eq!(result.result["minimum_action"], "review");
    }
}

#[test]
fn unknown_and_ambiguous_pretool_payloads_never_receive_an_allow_floor() {
    let unknown = evaluate_isolated(envelope(
        "PreToolUse",
        serde_json::json!({"toolName": "future_tool", "opaque": true}),
    ))
    .unwrap();
    let unknown_result: GuardHookEdgeResultV2 = serde_json::from_slice(&unknown).unwrap();
    assert_eq!(unknown_result.result["minimum_action"], "review");

    let ambiguous = evaluate_isolated(envelope(
        "PreToolUse",
        serde_json::json!({"command": "pwd", "cmd": "whoami"}),
    ))
    .unwrap();
    let ambiguous_result: GuardHookEdgeResultV2 = serde_json::from_slice(&ambiguous).unwrap();
    assert_eq!(ambiguous_result.result["minimum_action"], "block");
    assert_eq!(
        ambiguous_result.result["reason_code"],
        "native_pre_tool_ambiguous_payload"
    );
}
