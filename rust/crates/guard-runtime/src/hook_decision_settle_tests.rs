//! Parity vectors recorded from the retired Python Copilot settle logic
//! (`run_native_copilot_pretool` / `run_native_copilot_permission_request`),
//! replayed through the resident `hook_decide` operation.

use guard_contracts::HOOK_DECISION_REQUEST_SCHEMA;
use serde_json::{json, Value};

use super::{copilot_hook_reason, join_hook_reason};
use crate::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/hook_copilot_settle_vectors.json.gz");

fn settle(inputs: &Value) -> Value {
    let request = json!({
        "operation": "hook_decide",
        "request": {
            "schema": HOOK_DECISION_REQUEST_SCHEMA,
            "request_id": "req-copilot",
            "query": {"kind": "copilot_settle", "inputs": inputs},
        }
    });
    let out =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .expect("hook decision op should answer");
    let reply: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(reply["status"], "ok", "{reply}");
    reply["payload"].clone()
}

#[test]
fn matches_python_copilot_vectors() {
    let document = gunzip_json(VECTORS);
    let vectors = document["vectors"].as_array().unwrap();
    assert!(vectors.len() > 500);
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let mut inputs = vector["inputs"].clone();
        let acked = inputs
            .as_object_mut()
            .unwrap()
            .remove("acked_recording_only");
        let mut payload = settle(&inputs);
        assert_eq!(payload["kind"], "copilot_settle", "{name}");
        if vector["needs_acked_snapshot"].as_bool().unwrap() {
            assert_eq!(
                payload["needs_facts"],
                json!(["acked_recording_only"]),
                "{name}"
            );
            assert!(payload["plan"].is_null(), "{name}");
            inputs["acked_recording_only"] = acked.expect("recorded acked fact");
            payload = settle(&inputs);
        }
        assert_eq!(payload["needs_facts"], json!([]), "{name}");
        let plan = &payload["plan"];
        let expected = &vector["expected"];
        for key in ["effects", "exit_code", "approval_reuse", "scanner_evidence"] {
            assert_eq!(plan[key], expected[key], "{name}: {key}");
        }
    }
}

#[test]
fn unknown_stage_is_rejected() {
    let document = gunzip_json(VECTORS);
    let mut inputs = document["vectors"][0]["inputs"].clone();
    inputs["stage"] = json!("post_tool_use");
    let request = json!({
        "operation": "hook_decide",
        "request": {
            "schema": HOOK_DECISION_REQUEST_SCHEMA,
            "request_id": "req-copilot",
            "query": {"kind": "copilot_settle", "inputs": inputs},
        }
    });
    let out =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .unwrap();
    let reply: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(reply["status"], "error");
    assert_eq!(reply["code"], "native_hook_decision_stage_invalid");
}

#[test]
fn hook_reason_keeps_the_tokenized_link() {
    let link =
        "Open HOL Guard to approve or keep this blocked: https://g.test/a#guard-token=abc.def";
    let plain = "Open HOL Guard to approve or keep this blocked: https://g.test/a";
    assert_eq!(join_hook_reason(&[plain, link]), link);
    assert_eq!(
        join_hook_reason(&["  ", ""]),
        "HOL Guard flagged this tool call for review."
    );
    assert_eq!(join_hook_reason(&["a", " a ", "b"]), "a b");
    assert_eq!(
        copilot_hook_reason(&["Guard stopped it.", "fs.write"]),
        "HOL Guard stopped it. fs.write Approve it in HOL Guard, then retry."
    );
}
