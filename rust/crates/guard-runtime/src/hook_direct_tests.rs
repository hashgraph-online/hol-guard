use super::{evaluate, HookDirectRequestV1};
use crate::policy_store::policy_store_direct_lane::tests::{
    allowing_fixture, binding, fixture, push, write_current_ack, Fixture,
};
use serde_json::{json, Value};
use std::fs;

const HOME: &str = "/home/guard";

fn edge(decision: &str, minimum_action: &str) -> Vec<u8> {
    pre_edge(json!({ "decision": decision, "minimum_action": minimum_action }))
}

fn pre_edge(result: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "guard-hook-edge-result.v2",
        "event_name": "PreToolUse",
        "result": result,
        "harness_response": {},
    }))
    .unwrap()
}

fn post_edge(result: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "guard-hook-edge-result.v2",
        "event_name": "PostToolUse",
        "result": result,
        "harness_response": {},
    }))
    .unwrap()
}

struct Lane {
    fixture: Fixture,
    workspace: String,
}

fn lane(label: &str, extra: Value) -> Lane {
    open_lane(label, extra, false)
}

fn allowing_lane(label: &str, extra: Value) -> Lane {
    open_lane(label, extra, true)
}

fn open_lane(label: &str, extra: Value, allow_policy: bool) -> Lane {
    let fixture = if allow_policy {
        allowing_fixture(&format!("hook-direct-{label}"))
    } else {
        fixture(&format!("hook-direct-{label}"))
    };
    let directory = fixture.root.join("repo");
    fs::create_dir_all(&directory).unwrap();
    let workspace = fs::canonicalize(&directory)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let mut bound = binding(&fixture, &workspace);
    bound["home_dir"] = json!(HOME);
    bound["harness_postures"] = json!({});
    bound["local_cli_block_rules"] = json!(false);
    bound["evidence_drain"] = json!(true);
    for (key, value) in extra.as_object().unwrap() {
        bound[key] = value.clone();
    }
    push(&fixture, Some(bound)).unwrap();
    write_current_ack(&fixture);
    Lane { fixture, workspace }
}

fn run(lane: &Lane, payload: Value) -> Value {
    run_as(lane, "codex", Some(HOME), payload)
}

fn run_as(lane: &Lane, harness: &str, home_dir: Option<&str>, payload: Value) -> Value {
    let request = HookDirectRequestV1 {
        harness: harness.to_owned(),
        guard_home: lane.fixture.root.to_str().unwrap().to_owned(),
        home_dir: home_dir.map(str::to_owned),
        workspace: None,
        deadline_budget_ms: None,
        payload,
    };
    serde_json::from_slice(&evaluate(request, &lane.fixture.store).unwrap()).unwrap()
}

/// A shell command the edge allows outright.
fn allowed_payload(lane: &Lane) -> Value {
    json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "pwd" },
        "cwd": lane.workspace,
    })
}

fn deferred(result: &Value) -> &str {
    assert_eq!(result["schema"], "guard-hook-direct-result.v1");
    assert_eq!(result["outcome"], "defer", "{result}");
    result["reason"].as_str().unwrap()
}

/// A package script run in `lane`'s workspace: a command that launches a
/// local CLI a custom rule can name.
fn package_script_payload(lane: &Lane) -> Value {
    fs::write(
        std::path::Path::new(&lane.workspace).join("package.json"),
        br#"{"name": "demo", "scripts": {"build": "tsc"}}"#,
    )
    .unwrap();
    json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "npm run build" },
        "cwd": lane.workspace,
    })
}

/// The next evidence page, after acknowledging `acked`, a page drained before.
fn drain(lane: &Lane, acked: Option<&Value>) -> Value {
    let request = crate::hook_direct_evidence::HookDirectEvidenceDrainRequestV1 {
        guard_home: lane.fixture.root.to_str().unwrap().to_owned(),
        max_records: None,
        ack_through: acked.and_then(|page| page["through"].as_u64()),
        ack_epoch: acked.and_then(|page| page["epoch"].as_str().map(str::to_owned)),
    };
    let page =
        crate::hook_direct_evidence::drain(&request, lane.fixture.store.direct_evidence()).unwrap();
    serde_json::from_slice(&page).unwrap()
}

/// A shell command that already ran.
fn post_tool_payload(lane: &Lane) -> Value {
    json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "pwd" },
        "tool_response": { "stdout": "/repo", "exit_code": 0 },
        "cwd": lane.workspace,
    })
}

fn prompt_payload(lane: &Lane) -> Value {
    json!({
        "hook_event_name": "UserPromptSubmit",
        "prompt": "List the files in this repository.",
        "cwd": lane.workspace,
    })
}

#[path = "hook_direct_event_shape_tests.rs"]
mod event_shape;

#[path = "hook_direct_edge_tests.rs"]
mod edge_answers;

#[path = "hook_direct_binding_tests.rs"]
mod binding_defer;

#[path = "hook_direct_rules_tests.rs"]
mod custom_rules;

#[path = "hook_direct_evidence_drain_tests.rs"]
mod evidence_drain;

#[path = "hook_direct_prompt_tests.rs"]
mod prompts;

#[path = "hook_direct_lifecycle_tests.rs"]
mod lifecycle;

#[path = "hook_direct_counters_evaluate_tests.rs"]
mod counters;

#[path = "hook_direct_pi_tests.rs"]
mod pi_lane;

#[path = "hook_direct_cursor_tests.rs"]
mod cursor_observer;
