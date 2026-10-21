//! Parity vectors recorded from the retired Python persist decision
//! (`_persist_claude_native_permission_policy` and its runtime-artifact
//! wrapper, frozen in `scripts/ci/record_native_permission_persist_vectors.py`),
//! replayed through the resident `hook_decide` operation, plus the stored
//! hashes a saved approval is looked up by, pinned as literals.

use guard_contracts::{
    HOOK_DECISION_NATIVE_PERMISSION_PERSIST_FEATURE, HOOK_DECISION_REQUEST_SCHEMA,
};
use serde_json::{json, Value};

use crate::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] =
    include_bytes!("../tests/fixtures/native_permission_persist_vectors.json.gz");

/// A well-formed approval-context token is stored exactly as given.
const WELL_FORMED_TOKEN: &str = "guard-approval-context:v1:eyJjYXBhYmlsaXRpZXMiOiIwOTcxNjBmMzZjNWY1ZTEwNDE4NzU4YzBkOGQ1ZjhjMWUzZTc2YTMwMmU5YTdkMWZmNWFmMjljYThiM2JhYzg1IiwiY29udGVudCI6ImQ5OTQ2NTU5NzQ1MGIxODQ4MzU4ZjNlNjY3MjBjNjQ2ZjdhMzFkODQ4MTVmNjk4NDU3NDVmOTY2YzY0MDhjODAiLCJpZGVudGl0eSI6ImM5ZWEzN2I4NGJhMTBjMzlhYTg5MDg3ODE4NjMyNTE5MzNmNjBhYjY1ZTEzMjVjNTZiYTk4YzY5NzY1ZWJkYjIiLCJwb2xpY3kiOiI3YzA5NGM1YTRkMjgyODVlYzg3NTI3MTI1NWY2NzIzZWVlZWY3YjhmNjgzZjA2NmU4OGZjOTQyOTEwYzUwMGIyIiwic2FuZGJveCI6IjRlNWU0ZWYwY2Y4YTIwZDk2MThkNzY2MzRkMzdlYmU0NGNkODk1NzA3MGEyZjAyYzcwYTkyMTExODQzYjAzZjMiLCJ2ZXJzaW9uIjoxfQ";
/// `sha256("claude-code:runtime:tool-action:abc123")`: a legacy hash for a
/// command with no recorded location or text.
const LEGACY_EXACT_KEY: &str =
    "runtime-exact:44869672e5a90ec571e6ba62a2aec9cded44bdf7a09b4d477a679f972b70a534";
/// The same command bound to its config path, scope, text and wrapper chain.
const LEGACY_EXACT_KEY_WITH_CONTEXT: &str =
    "runtime-exact:7ee804454b012f82e91b2fbd4b5471f53c41c1fb9d6ad108a3625a22f01e79bc";
const TOOL_ACTION_ID: &str = "claude-code:runtime:tool-action:abc123";

fn reply(inputs: &Value) -> Option<Value> {
    let request = json!({
        "operation": "hook_decide",
        "request": {
            "schema": HOOK_DECISION_REQUEST_SCHEMA,
            "request_id": "req-native-permission-persist",
            "query": {"kind": "native_permission_persist_plan", "inputs": inputs},
        }
    });
    let out =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .ok()?;
    serde_json::from_slice(&out).ok()
}

fn plan(inputs: &Value) -> Value {
    let reply = reply(inputs).expect("hook decision op should answer");
    assert_eq!(reply["status"], "ok", "{reply}");
    reply["payload"].clone()
}

fn rejected(inputs: &Value) -> bool {
    match reply(inputs) {
        None => true,
        Some(reply) => reply["status"] == "error",
    }
}

fn error_code(inputs: &Value) -> String {
    let reply = reply(inputs).expect("hook decision op should answer");
    assert_eq!(reply["status"], "error", "{reply}");
    reply["code"].as_str().unwrap().to_owned()
}

fn inputs(artifact_hash: &str) -> Value {
    json!({
        "artifact_id": TOOL_ACTION_ID,
        "artifact_hash": artifact_hash,
        "artifact_type": "tool_action_request",
        "config_path": null,
        "source_scope": null,
        "raw_command_text": null,
        "wrapper_chain": null,
        "action": "allow",
        "reason": "native approval",
        "source": "claude-native-approval",
        "authoritative_action": null,
        "tilde_home": "/home/recorder",
    })
}

#[test]
fn matches_python_persist_vectors() {
    let vectors = gunzip_json(VECTORS);
    let vectors = vectors.as_array().unwrap();
    assert!(vectors.len() > 2_700);
    for vector in vectors {
        // Path vectors record POSIX `pathlib` behaviour.
        if cfg!(windows) && vector["flavor"] == "posix" {
            continue;
        }
        let facts = &vector["inputs"];
        let payload = plan(facts);
        assert_eq!(payload["kind"], "native_permission_persist_plan", "{facts}");
        for (key, expected) in vector["plan"].as_object().unwrap() {
            assert_eq!(&payload[key], expected, "{facts}: {key}");
        }
    }
}

#[test]
fn well_formed_token_is_stored_as_given() {
    let payload = plan(&inputs(WELL_FORMED_TOKEN));
    assert_eq!(payload["stored_artifact_hash"], WELL_FORMED_TOKEN);
    assert_eq!(payload["policy_action"], "allow");
}

#[test]
fn legacy_hash_is_stored_as_the_exact_key() {
    let payload = plan(&inputs("hash-native"));
    assert_eq!(payload["stored_artifact_hash"], LEGACY_EXACT_KEY);
    assert_eq!(payload["events"].as_array().unwrap().len(), 1);
}

#[test]
fn legacy_hash_with_context_is_stored_as_the_exact_key_with_context() {
    let mut facts = inputs("hash-native");
    facts["config_path"] = json!("/repo/.claude/settings.json");
    facts["source_scope"] = json!("project");
    facts["raw_command_text"] = json!("git status");
    facts["wrapper_chain"] = json!(["bash", "-lc"]);
    let payload = plan(&facts);
    assert_eq!(
        payload["stored_artifact_hash"],
        LEGACY_EXACT_KEY_WITH_CONTEXT
    );
}

#[test]
fn malformed_token_falls_back_to_the_exact_key() {
    let mut malformed = WELL_FORMED_TOKEN.to_owned();
    malformed.push('=');
    let payload = plan(&inputs(&malformed));
    assert_eq!(payload["stored_artifact_hash"], LEGACY_EXACT_KEY);
}

#[test]
fn retained_policy_writes_no_policy_row() {
    let mut facts = inputs("hash-native");
    facts["authoritative_action"] = json!("warn");
    let payload = plan(&facts);
    assert_eq!(payload["stored_artifact_hash"], Value::Null);
    assert_eq!(payload["policy_action"], Value::Null);
    assert_eq!(payload["inventory_approved"], true);
    assert_eq!(
        payload["events"],
        json!([{
            "name": "claude/native_permission_current_policy_retained",
            "before_policy": false,
            "payload": {
                "artifact_id": TOOL_ACTION_ID,
                "artifact_hash": "hash-native",
                "native_action": "allow",
                "authoritative_action": "warn",
            },
        }])
    );
}

#[test]
fn feature_is_advertised() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&HOOK_DECISION_NATIVE_PERMISSION_PERSIST_FEATURE));
}

#[test]
fn malformed_inputs_fail_closed() {
    let facts = inputs("hash-native");
    let mut unknown_action = facts.clone();
    unknown_action["authoritative_action"] = json!("permit");
    assert!(rejected(&unknown_action));
    let mut extra = facts.clone();
    extra["permission_mode"] = json!("default");
    assert!(rejected(&extra));
    let mut missing = facts.clone();
    missing.as_object_mut().unwrap().remove("artifact_id");
    assert!(rejected(&missing));
    let mut wrong_type = facts;
    wrong_type["reason"] = json!(7);
    assert!(rejected(&wrong_type));
}

#[test]
fn a_config_path_that_cannot_be_expanded_fails_closed() {
    let mut other_user = inputs("hash-native");
    other_user["config_path"] = json!("~someone/.claude/settings.json");
    assert_eq!(
        error_code(&other_user),
        "native_hook_decision_context_path_unsupported"
    );
    let mut no_home = inputs("hash-native");
    no_home["config_path"] = json!("~/.claude/settings.json");
    no_home["tilde_home"] = Value::Null;
    assert_eq!(
        error_code(&no_home),
        "native_hook_decision_context_path_unsupported"
    );
}
