//! The approval request `ReviewRequest` builds for a paused native review.

use guard_command::hook_adapter_value::OValue;
use guard_contracts::HOOK_ADAPTER_REQUEST_SCHEMA;
use serde_json::{json, Value};

const TOKEN: &str = "guard-approval-context:v1:abc";
const RECEIPTS: &str = include_str!("../../testdata/guard_store/native_receipt_vectors.json");
#[cfg(unix)]
const DAEMON_REQUESTS: &str =
    include_str!("../../testdata/hook_direct_review/review_request_vectors.json");

fn tagged(value: &Value) -> Value {
    crate::hook_direct::saved_decision::review_request::tagged(value)
}

fn query(payload: Value, workspace: Option<&str>, review: Value) -> Value {
    let mut query = json!({
        "kind": "review_request",
        "envelope": {
            "harness": "claude-code",
            "event_name": "PreToolUse",
            "payload": tagged(&payload),
            "workspace": workspace,
            "home_dir": "/home/u",
            "devin_project_dir": null,
            "path_env": null,
            "host": {"tilde_home": "/home/u", "default_home": "/home/u", "cwd": "/work"},
        },
        "result": {"decision": "review", "reason": "Review this command."},
        "native_receipt": null,
        "request_id": "req1",
        "approval_center_url": "http://127.0.0.1:4781/approvals",
        "guard_home": "/home/u/.hol-guard",
        "review_binding": "binding-1",
        "exact_token": TOKEN,
        "once_only_reason": null,
        "queue_group_id": null,
        "bound_bash": null,
    });
    for (key, value) in review.as_object().unwrap() {
        query[key] = value.clone();
    }
    query
}

fn answer(query: Value) -> Value {
    let request = json!({
        "operation": "hook_adapter",
        "request": {"schema": HOOK_ADAPTER_REQUEST_SCHEMA, "request_id": "req-adapter", "query": query},
    });
    let bytes =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn request(query: Value) -> Value {
    let reply = answer(query);
    assert_eq!(reply["status"], "ok", "{reply}");
    let decoded = OValue::from_wire(&reply["payload"]).unwrap();
    serde_json::from_str(&decoded.compact_json()).unwrap()
}

fn shell(command: &str) -> Value {
    json!({"tool_name": " Bash ", "tool_input": {"command": command}})
}

#[test]
fn a_command_review_binds_its_retry_and_exact_action() {
    let request = request(query(shell("npm test"), Some("/work"), json!({})));
    assert_eq!(request["request_id"], "req1");
    assert_eq!(request["artifact_id"], "claude-code:native-pretool:Bash");
    assert_eq!(request["artifact_name"], "Bash");
    assert_eq!(request["artifact_hash"], "binding-1");
    assert_eq!(request["artifact_type"], "tool_call");
    assert_eq!(request["source_scope"], "project");
    assert_eq!(request["config_path"], "/work");
    assert_eq!(request["workspace"], "/work");
    assert_eq!(request["launch_target"], "npm test");
    assert_eq!(request["raw_command_text"], "npm test");
    assert_eq!(request["risk_summary"], "Review this command.");
    assert_eq!(request["changed_fields"], json!(["native_pre_tool"]));
    assert_eq!(
        request["review_command"],
        "hol-guard approvals approve req1"
    );
    assert_eq!(
        request["approval_url"],
        "http://127.0.0.1:4781/approvals/requests/req1"
    );
    let envelope = &request["action_envelope_json"];
    assert_eq!(envelope["pre_execution_result"], "review");
    assert_eq!(envelope["exact_context_token"], TOKEN);
    assert!(envelope.get("exact_identity_kind").is_none());
    assert!(envelope.get("once_only_reason").is_none());
}

#[test]
fn a_tool_review_outside_a_workspace_is_scoped_to_the_harness() {
    let payload = json!({"tool_name": "Read", "tool_input": {"file_path": "  /etc/hosts  "}});
    let request = request(query(
        payload,
        None,
        json!({"review_binding": "", "result": {"decision": "review", "reason": ""}}),
    ));
    assert_eq!(request["source_scope"], "harness");
    assert_eq!(request["config_path"], "/home/u/.hol-guard");
    assert_eq!(request["workspace"], Value::Null);
    assert_eq!(request["artifact_hash"], "req1");
    assert_eq!(request["launch_target"], "/etc/hosts");
    assert_eq!(request["raw_command_text"], Value::Null);
    assert_eq!(
        request["risk_summary"],
        "HOL Guard requires review before this action can execute."
    );
    assert_eq!(
        request["action_envelope_json"]["exact_identity_kind"],
        "tool-target"
    );
}

#[test]
fn a_once_only_review_says_why_and_joins_its_connector_group() {
    let request = request(query(
        shell("acme deploy"),
        Some("/work"),
        json!({"exact_token": null, "once_only_reason": "unstable", "queue_group_id": "connector:acme"}),
    ));
    let envelope = &request["action_envelope_json"];
    assert!(envelope.get("exact_context_token").is_none());
    assert_eq!(envelope["once_only_reason"], "unstable");
    assert_eq!(request["queue_group_id"], "connector:acme");
}

#[test]
fn a_bound_script_review_carries_its_descriptor_and_lineage_group() {
    let lineage = json!({"lineage_id": "lin-1", "artifact_hash": TOKEN});
    let request = request(query(
        shell("./run.sh"),
        Some("/work"),
        json!({
            "queue_group_id": "connector:ignored",
            "bound_bash": {"subject": {"schema": "guard.bash-subject.v1"}, "review_lineage": lineage},
        }),
    ));
    assert_eq!(
        request["artifact_id"],
        "native-bash-owner:native-pretool:v3"
    );
    assert_eq!(request["artifact_type"], "native_bash_request");
    assert_eq!(request["queue_group_id"], "native-bash-review:lin-1");
    assert!(request["risk_summary"]
        .as_str()
        .unwrap()
        .ends_with("a new user request is separate."));
    let descriptor = &request["action_envelope_json"]["native_bash"];
    assert_eq!(descriptor["schema"], "guard-native-bash-review.v4");
    assert_eq!(descriptor["artifact_hash"], TOKEN);
    assert_eq!(descriptor["review_lineage"], lineage);
}

/// A recorded receipt; the named scenario's first.
fn receipt(scenario: &str) -> Value {
    let vectors: Value = serde_json::from_str(RECEIPTS).unwrap();
    let scenario = vectors["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == scenario)
        .unwrap();
    serde_json::from_str(scenario["receipt_texts"][0].as_str().unwrap()).unwrap()
}

fn envelope(receipt: Value) -> Value {
    let result = json!({
        "decision": "review",
        "reason": "r",
        "command_extensions": {"observations": [{"extension_id": "command.acme", "effective_segment_indexes": [0]}]},
    });
    let request = request(query(
        shell("acme status"),
        Some("/work"),
        json!({"native_receipt": receipt, "result": result}),
    ));
    request["action_envelope_json"].clone()
}

#[test]
fn an_authenticated_receipt_and_command_category_reach_the_envelope() {
    let receipt = receipt("post_tool_every_optional_field");
    let envelope = envelope(receipt.clone());
    assert_eq!(envelope["native_origin_receipt"], receipt);
    assert_eq!(envelope["command_category"], "command.acme");
}

#[test]
fn an_unauthenticated_or_forged_receipt_stays_out_of_the_envelope() {
    let mut forged = receipt("post_tool_every_optional_field");
    forged["decision"] = json!("allow");
    for receipt in [
        receipt("pre_tool_minimal"),
        forged,
        json!({"origin_authentication": "a"}),
    ] {
        let envelope = envelope(receipt);
        assert!(
            envelope.get("native_origin_receipt").is_none(),
            "{envelope}"
        );
        assert_eq!(envelope["command_category"], "command.acme");
    }
}

#[test]
fn a_malformed_review_is_a_typed_rejection() {
    for review in [
        json!({"result": {"decision": "review", "reason": 3}}),
        json!({"bound_bash": {"subject": {}, "review_lineage": {}}}),
    ] {
        let reply = answer(query(shell("npm test"), Some("/work"), review));
        assert_eq!(reply["status"], "error");
        assert_eq!(reply["code"], "native_hook_adapter_review_invalid");
    }
}

/// The fields `ReviewRequest` sets, against the requests the retired daemon
/// builder persisted for the same pause. The recorder accepted any receipt,
/// while the resident authenticates it (pinned above), so the synthetic
/// receipt's envelope copy is left out of the comparison. The recorder also
/// stubbed the adapter's review envelope (`envelope`), which the adapter's own
/// parity vectors pin, so only the keys the builder adds or changes on top of
/// that stub are compared. The vectors were recorded where
/// `os.path.expanduser` reads `HOME`.
#[cfg(unix)]
#[test]
fn requests_match_the_retired_daemon_builder() {
    let document: Value = serde_json::from_str(DAEMON_REQUESTS).unwrap();
    for vector in document["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let mut envelope = vector["query"].clone();
        envelope["payload"] = tagged(&vector["payload"]);
        let query = json!({
            "kind": "review_request",
            "envelope": envelope,
            "result": vector["result"],
            "native_receipt": vector["receipt"],
            "request_id": vector["request_id"],
            "approval_center_url": vector["approval_center_url"],
            "guard_home": "/home/agent/.hol-guard",
            "review_binding": vector["review_binding"],
            "exact_token": vector["exact"]["token"],
            "once_only_reason": vector["exact"]["once_only"],
            "queue_group_id": null,
            "bound_bash": null,
        });
        let mut built = request(query);
        let mut expected = vector["request"].clone();
        for request in [&mut built, &mut expected] {
            request["action_envelope_json"]
                .as_object_mut()
                .unwrap()
                .remove("native_origin_receipt");
        }
        let stub = vector["envelope"].as_object().unwrap();
        let built_envelope = built["action_envelope_json"].as_object().unwrap();
        let expected_envelope = expected["action_envelope_json"].as_object().unwrap();
        let mut built_keys: Vec<_> = built_envelope.keys().collect();
        let mut expected_keys: Vec<_> = expected_envelope.keys().collect();
        built_keys.sort();
        expected_keys.sort();
        assert_eq!(built_keys, expected_keys, "{name}: envelope keys");
        for (key, value) in expected_envelope {
            if stub.get(key) != Some(value) {
                assert_eq!(&built_envelope[key], value, "{name}: envelope {key}");
            }
        }
        let fields = built.as_object().unwrap();
        assert_eq!(fields.len(), 19, "{name}");
        for (key, value) in fields {
            if key != "action_envelope_json" {
                assert_eq!(value, &expected[key], "{name}: {key}");
            }
        }
    }
}
