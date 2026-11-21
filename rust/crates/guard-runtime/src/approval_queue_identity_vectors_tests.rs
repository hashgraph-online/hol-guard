//! Parity vectors recorded from the retired Python queue-identity helpers
//! (`normalize_command_identity`, `_build_action_identity`,
//! `_build_queue_group_id`): every case carries the narrowed wire item and the
//! identity the Python produced.

use guard_contracts::{
    ApprovalQueueIdentityItemV1, ApprovalQueueIdentityRequestV1,
    APPROVAL_QUEUE_IDENTITY_REQUEST_SCHEMA,
};
use serde_json::{json, Value};

use super::{evaluate, normalize_command_identity};
use crate::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/approval_queue_identity_vectors.json.gz");

fn request(items: Vec<ApprovalQueueIdentityItemV1>) -> ApprovalQueueIdentityRequestV1 {
    ApprovalQueueIdentityRequestV1 {
        schema: APPROVAL_QUEUE_IDENTITY_REQUEST_SCHEMA.to_owned(),
        request_id: "vector".to_owned(),
        items,
    }
}

#[test]
fn identities_match_the_retired_python() {
    let vectors = gunzip_json(VECTORS);
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(cases.len() > 5000);
    for (index, case) in cases.iter().enumerate() {
        let item: ApprovalQueueIdentityItemV1 = serde_json::from_value(case["wire"].clone())
            .unwrap_or_else(|error| panic!("case {index}: {error}"));
        let actual =
            evaluate(&request(vec![item])).unwrap_or_else(|code| panic!("case {index}: {code}"));
        assert_eq!(
            actual["items"][0], case["expected"]["item"],
            "case {index}: {}",
            case["wire"]
        );
    }
}

#[test]
fn command_normalisation_matches_the_retired_python() {
    let vectors = gunzip_json(VECTORS);
    for (index, case) in vectors["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .enumerate()
    {
        let command = case["command"].as_str().expect("command");
        assert_eq!(
            normalize_command_identity(command),
            case["expected"].as_str().expect("expected"),
            "command {index}: {command:?}"
        );
    }
}

#[test]
fn a_batch_is_identified_in_request_order() {
    let item = |target: &str| ApprovalQueueIdentityItemV1 {
        launch_target: Some(target.to_owned()),
        harness: "codex".to_owned(),
        artifact_id: "a1".to_owned(),
        ..Default::default()
    };
    let result = evaluate(&request(vec![item("ls --port 3000"), item("pwd")])).expect("ok");
    assert_eq!(result["items"][0]["identity_key"], "ls <port-flag>");
    assert_eq!(result["items"][1]["identity_key"], "pwd");
}

#[test]
fn non_scalar_browser_intent_fields_are_rejected() {
    let item = ApprovalQueueIdentityItemV1 {
        harness: "codex".to_owned(),
        artifact_id: "a1".to_owned(),
        browser_intent: Some(json!({"intent": ["list"]})),
        ..Default::default()
    };
    assert!(evaluate(&request(vec![item])).is_err());
}

#[test]
fn a_non_object_envelope_is_rejected() {
    let item = ApprovalQueueIdentityItemV1 {
        harness: "codex".to_owned(),
        artifact_id: "a1".to_owned(),
        envelope: Some(Value::String("not-an-object".to_owned())),
        ..Default::default()
    };
    assert!(evaluate(&request(vec![item])).is_err());
}

#[test]
fn a_retry_through_a_new_codex_bridge_keeps_the_action_identity() {
    let item = |pid: u64, command: &str| ApprovalQueueIdentityItemV1 {
        harness: "codex".to_owned(),
        artifact_id: "codex:project:bash".to_owned(),
        envelope: Some(json!({
            "action_type": "shell",
            "tool_name": "Bash",
            "command": command,
            "raw_payload_redacted": {
                "tool_name": "Bash",
                "guard_codex_browser_wait_process": {"pid": pid, "startToken": format!("start-{pid}")},
                "guard_codex_browser_wait_timeout_seconds": 300,
            },
        })),
        ..Default::default()
    };
    let result = evaluate(&request(vec![
        item(101, "curl https://example.test"),
        item(202, "curl https://example.test"),
        item(303, "curl https://other.example.test"),
    ]))
    .expect("ok");
    let items = &result["items"];
    for key in ["action_identity", "queue_group_id"] {
        assert!(items[0][key].is_string(), "{key}");
        assert_eq!(items[0][key], items[1][key], "{key}");
        assert_ne!(items[0][key], items[2][key], "{key}");
    }
}
