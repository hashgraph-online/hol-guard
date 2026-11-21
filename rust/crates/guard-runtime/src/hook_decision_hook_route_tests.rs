//! Parity vectors recorded from the retired Python pipeline ladder
//! (`run_native_hook_pipeline`, frozen in `scripts/ci/record_hook_route_vectors.py`),
//! replayed through the resident `hook_decide` operation.

use guard_contracts::{HOOK_DECISION_HOOK_ROUTE_FEATURE, HOOK_DECISION_REQUEST_SCHEMA};
use serde_json::{json, Value};

use crate::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/hook_route_vectors.json.gz");

/// Handlers that answer every hook they run for; a plan ends at the first.
const TERMINAL: [&str; 6] = [
    "passthrough",
    "copilot_pretool",
    "claude_permission_request",
    "claude_permission_prompt",
    "claude_stop",
    "generic_flow",
];
/// Terminal handlers that settle their own verdict, so the artifact and
/// generic flows are not reached after them.
const SELF_SETTLING: [&str; 5] = [
    "passthrough",
    "copilot_pretool",
    "claude_permission_request",
    "claude_permission_prompt",
    "claude_stop",
];

fn reply(inputs: &Value) -> Option<Value> {
    let request = json!({
        "operation": "hook_decide",
        "request": {
            "schema": HOOK_DECISION_REQUEST_SCHEMA,
            "request_id": "req-hook-route",
            "query": {"kind": "hook_route", "inputs": inputs},
        }
    });
    let out =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .ok()?;
    serde_json::from_slice(&out).ok()
}

fn route(inputs: &Value) -> Value {
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

fn plan_of(payload: &Value) -> Vec<&str> {
    payload["plan"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| step.as_str().unwrap())
        .collect()
}

#[test]
fn matches_python_pipeline_ladder_vectors() {
    let vectors = gunzip_json(VECTORS);
    let vectors = vectors.as_array().unwrap();
    assert!(vectors.len() >= 600);
    for vector in vectors {
        let facts = &vector["facts"];
        let payload = route(facts);
        assert_eq!(payload["kind"], "hook_route", "{facts}");
        for (key, expected) in vector["route"].as_object().unwrap() {
            assert_eq!(&payload[key], expected, "{facts}: {key}");
        }
    }
}

/// Only a Devin or Zcode permission request is answered with no decision, and
/// every other plan runs the native edge, ends in a handler that always
/// answers and either settles its own verdict or reaches the artifact and
/// generic flows that offer Allow once and Always allow. A tool or prompt
/// event is never routed on without the edge outage check.
#[test]
fn every_route_keeps_the_review_path_and_fails_closed() {
    let vectors = gunzip_json(VECTORS);
    let (mut passthrough, mut reviewed) = (0_usize, 0_usize);
    for vector in vectors.as_array().unwrap() {
        let facts = &vector["facts"];
        let payload = route(facts);
        let plan = plan_of(&payload);
        let last = *plan.last().unwrap();
        assert!(TERMINAL.contains(&last), "{facts}: ends in {last}");
        assert_eq!(
            plan.iter().filter(|step| TERMINAL.contains(step)).count(),
            1,
            "{facts}: {plan:?}"
        );
        let mut unique = plan.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), plan.len(), "{facts}: {plan:?}");
        if plan == ["passthrough"] {
            assert_eq!(facts["invoked_event"], "PermissionRequest", "{facts}");
            assert!(matches!(
                facts["canonical_harness"].as_str().unwrap(),
                "devin" | "zcode"
            ));
            passthrough += 1;
            continue;
        }
        assert!(plan.contains(&"native_edge"), "{facts}: {plan:?}");
        assert!(plan.contains(&"containment"), "{facts}: {plan:?}");
        let event = payload["event_name"].as_str().unwrap();
        if matches!(event, "PreToolUse" | "PostToolUse" | "UserPromptSubmit") {
            let edge = plan.iter().position(|step| *step == "native_edge");
            let outage = plan.iter().position(|step| *step == "edge_unavailable");
            assert!(outage > edge, "{facts}: {plan:?}");
        }
        if SELF_SETTLING.contains(&last) {
            assert!(!plan.contains(&"generic_flow"), "{facts}: {plan:?}");
        } else {
            assert_eq!(&plan[plan.len() - 2..], ["artifact_flow", "generic_flow"]);
            reviewed += 1;
        }
    }
    assert!(passthrough > 20);
    assert!(reviewed > 300);
}

/// The Claude permission handlers and turn stop answer for Claude only; no
/// other harness's hook is ever routed to them.
#[test]
fn claude_handlers_are_planned_for_claude_only() {
    let vectors = gunzip_json(VECTORS);
    for vector in vectors.as_array().unwrap() {
        let facts = &vector["facts"];
        let payload = route(facts);
        let plan = plan_of(&payload);
        if plan.iter().any(|step| step.starts_with("claude_")) {
            assert_eq!(
                facts["canonical_harness"], "claude-code",
                "{facts}: {plan:?}"
            );
        }
    }
}

#[test]
fn feature_is_advertised() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&HOOK_DECISION_HOOK_ROUTE_FEATURE));
}

#[test]
fn malformed_inputs_fail_closed() {
    let vectors = gunzip_json(VECTORS);
    let facts = vectors[0]["facts"].clone();
    let mut empty_harness = facts.clone();
    empty_harness["canonical_harness"] = json!("");
    assert!(rejected(&empty_harness));
    let mut empty_event = facts.clone();
    empty_event["runtime_event"] = json!("");
    assert!(rejected(&empty_event));
    let mut wrong_type = facts.clone();
    wrong_type["copilot_tool_call_present"] = json!("yes");
    assert!(rejected(&wrong_type));
    let mut extra = facts.clone();
    extra["edge_result_present"] = json!(true);
    assert!(rejected(&extra));
    let mut missing = facts;
    missing.as_object_mut().unwrap().remove("invoked_event");
    assert!(rejected(&missing));
}
