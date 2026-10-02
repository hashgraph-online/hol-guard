use super::*;

#[test]
fn pi_retry_identity_ignores_call_id_but_binds_arguments_and_session() {
    for harness in ["pi", "omp"] {
        let mut first = envelope(
            "PreToolUse",
            serde_json::json!({
                "tool_name": "eval",
                "tool_call_id": "first-call",
                "session_id": "session-one",
                "tool_input": {"code": "1 + 1", "tool_call_id": "argument-id"}
            }),
        );
        first.harness = harness.to_owned();
        let mut retry = first.clone();
        retry.raw_payload["tool_call_id"] = serde_json::json!("retry-call");
        assert_eq!(
            request_identity(&first).unwrap().1,
            request_identity(&retry).unwrap().1
        );
        for (field, value) in [
            ("session_id", serde_json::json!("session-two")),
            (
                "tool_input",
                serde_json::json!({"code": "2 + 2", "tool_call_id": "argument-id"}),
            ),
        ] {
            let mut changed = retry.clone();
            changed.raw_payload[field] = value;
            assert_ne!(
                request_identity(&first).unwrap().1,
                request_identity(&changed).unwrap().1
            );
        }
        retry.raw_payload["tool_input"]["tool_call_id"] = serde_json::json!("different-argument");
        assert_ne!(
            request_identity(&first).unwrap().1,
            request_identity(&retry).unwrap().1
        );
    }
}

#[test]
fn pi_retry_without_session_keeps_transport_identity() {
    for harness in ["pi", "omp"] {
        for session in [serde_json::Value::Null, serde_json::json!("")] {
            let mut first = envelope(
                "PreToolUse",
                serde_json::json!({
                    "tool_name": "eval", "tool_call_id": "first-call",
                    "tool_input": {"code": "1 + 1"}
                }),
            );
            first.harness = harness.to_owned();
            if !session.is_null() {
                first.raw_payload["session_id"] = session;
            }
            let mut retry = first.clone();
            retry.raw_payload["tool_call_id"] = serde_json::json!("retry-call");
            assert_ne!(
                request_identity(&first).unwrap().1,
                request_identity(&retry).unwrap().1
            );
        }
    }
}

#[test]
fn pi_retry_identity_matches_shared_python_fixture_vectors() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/fixtures/pi-retry-identity-vectors.json"
    )))
    .unwrap();
    for vector in vectors.as_array().unwrap() {
        let mut before = envelope("PreToolUse", vector["before"].clone());
        before.harness = vector["harness"].as_str().unwrap().to_owned();
        let mut after = before.clone();
        after.raw_payload = vector["after"].clone();
        assert_eq!(
            request_identity(&before).unwrap().1 == request_identity(&after).unwrap().1,
            vector["same_identity"].as_bool().unwrap(),
            "{}",
            vector["name"]
        );
    }
}

#[test]
fn execution_intent_digest_excludes_policy_refresh() {
    let first = envelope(
        "PreToolUse",
        serde_json::json!({
            "tool_name": "read",
            "tool_input": {"path": "README.md"}
        }),
    );
    let mut refreshed = first.clone();
    refreshed.policy_generation = 2;
    refreshed.policy_snapshot["generation"] = serde_json::json!(2);
    refreshed.policy_snapshot["policy_digest"] = serde_json::json!("c".repeat(64));
    refreshed.policy_snapshot["rule_digest"] = serde_json::json!("d".repeat(64));
    refreshed.policy_snapshot["runtime_identity"] = serde_json::json!("runtime-two");
    assert_eq!(
        execution_intent_digest(&first).unwrap(),
        execution_intent_digest(&refreshed).unwrap()
    );
    assert_ne!(
        request_identity(&first).unwrap().1,
        request_identity(&refreshed).unwrap().1
    );
}

#[test]
fn execution_intent_same_session_call_id_is_harness_scoped() {
    for harness in ["pi", "omp"] {
        let mut first = envelope(
            "PreToolUse",
            serde_json::json!({
                "tool_name": "eval",
                "tool_call_id": "first-call",
                "session_id": "session-one",
                "tool_input": {"code": "1 + 1"}
            }),
        );
        first.harness = harness.to_owned();
        let mut retry = first.clone();
        retry.raw_payload["tool_call_id"] = serde_json::json!("retry-call");
        assert_eq!(
            execution_intent_digest(&first).unwrap(),
            execution_intent_digest(&retry).unwrap()
        );
    }
    let mut first = envelope(
        "PreToolUse",
        serde_json::json!({
            "tool_name": "eval",
            "tool_call_id": "first-call",
            "session_id": "session-one",
            "tool_input": {"code": "1 + 1"}
        }),
    );
    first.harness = "claude-code".to_owned();
    let mut retry = first.clone();
    retry.raw_payload["tool_call_id"] = serde_json::json!("retry-call");
    assert_ne!(
        execution_intent_digest(&first).unwrap(),
        execution_intent_digest(&retry).unwrap()
    );
}

#[test]
fn execution_intent_digest_binds_cwd_session_arguments_and_target() {
    let first = {
        let mut value = envelope(
            "PreToolUse",
            serde_json::json!({
                "tool_name": "run",
                "tool_call_id": "call-one",
                "session_id": "session-one",
                "target": "workspace-one",
                "tool_input": {"command": "deploy", "path": "one"}
            }),
        );
        value.harness = "pi".to_owned();
        value
    };
    let baseline = execution_intent_digest(&first).unwrap();
    let mut changed = first.clone();
    changed.source.cwd = Some("/different-workspace".to_owned());
    assert_ne!(baseline, execution_intent_digest(&changed).unwrap());
    let mut changed = first.clone();
    changed.raw_payload["session_id"] = serde_json::json!("session-two");
    assert_ne!(baseline, execution_intent_digest(&changed).unwrap());
    let mut changed = first.clone();
    changed.raw_payload["tool_input"]["command"] = serde_json::json!("destroy");
    assert_ne!(baseline, execution_intent_digest(&changed).unwrap());
    let mut changed = first.clone();
    changed.raw_payload["target"] = serde_json::json!("workspace-two");
    assert_ne!(baseline, execution_intent_digest(&changed).unwrap());
}

#[test]
fn execution_intent_digest_keeps_call_id_without_session() {
    for harness in ["pi", "omp"] {
        for session in [serde_json::Value::Null, serde_json::json!("")] {
            let mut first = envelope(
                "PreToolUse",
                serde_json::json!({
                    "tool_name": "eval",
                    "tool_call_id": "first-call",
                    "tool_input": {"code": "1 + 1"}
                }),
            );
            first.harness = harness.to_owned();
            first.raw_payload["session_id"] = session;
            let mut retry = first.clone();
            retry.raw_payload["tool_call_id"] = serde_json::json!("retry-call");
            assert_ne!(
                execution_intent_digest(&first).unwrap(),
                execution_intent_digest(&retry).unwrap()
            );
        }
    }
}
