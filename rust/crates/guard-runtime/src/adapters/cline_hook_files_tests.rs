//! Replays the hook files and health verdicts the original Python produced,
//! and pins the argument refusals.

use serde_json::{json, Value};

use super::cline_hook_files::dispatch;
use super::runner_authority_op::ERR_INVALID;

const VECTORS: &str = include_str!("../../testdata/cline/cline_hook_files_vectors.json");

fn vectors() -> Value {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    assert_eq!(document["schema"], "guard-cline-hook-files-vectors.v1");
    document
}

fn cases(section: &str) -> Vec<Value> {
    vectors()[section].as_array().expect("cases").clone()
}

fn with_op(args: &Value, op: &str) -> Value {
    let mut request = args.clone();
    request["op"] = json!(op);
    request
}

#[test]
fn every_recorded_render_replays() {
    let cases = cases("render");
    assert_eq!(cases.len(), 6);
    for case in cases {
        let answer = dispatch(&with_op(&case["args"], "render")).expect("renders");
        assert_eq!(
            answer,
            json!({ "files": case["files"] }),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn only_the_windows_pretool_launcher_cancels() {
    for case in cases("render") {
        let answer = dispatch(&with_op(&case["args"], "render")).expect("renders");
        let windows = case["args"]["windows"].as_bool().expect("windows");
        for (event, files) in answer["files"].as_object().expect("files") {
            let launcher = files["launcher"].as_str().expect("launcher");
            assert!(launcher.contains("HOL_GUARD_MANAGED_CLINE_HOOK_V1"));
            assert_eq!(
                launcher.contains("cancel=$true"),
                windows && event == "PreToolUse"
            );
            assert_eq!(launcher.starts_with("#!/bin/sh\n"), !windows);
        }
    }
}

/// Applies the canary the way the caller does: it runs only when the answer
/// asks for it, and the hooks are ready only when it passes.
fn with_canary(answer: &Value, canary_ok: bool) -> (Value, bool) {
    let mut verdict = answer["state"].clone();
    let canary = answer["canary"].as_bool().expect("canary");
    if canary {
        let ready = verdict["ready"].as_bool().expect("ready") && canary_ok;
        verdict["synthetic_canary_ok"] = json!(canary_ok);
        verdict["ready"] = json!(ready);
    }
    (verdict, canary)
}

#[test]
fn every_recorded_state_replays_for_each_canary_outcome() {
    let cases = cases("state");
    assert_eq!(cases.len(), 23);
    for case in cases {
        let answer = dispatch(&with_op(&case["args"], "state")).expect("state");
        for (label, canary_ok) in [("canary_ok", true), ("canary_failed", false)] {
            let (verdict, canary) = with_canary(&answer, canary_ok);
            assert_eq!(canary, case["canary_called"], "{}", case["name"]);
            assert_eq!(verdict, case["verdicts"][label], "{} {label}", case["name"]);
        }
    }
}

fn healthy_state() -> Value {
    with_op(&cases("state")[0]["args"], "state")
}

#[test]
fn a_proof_that_is_not_an_object_is_present_but_never_live() {
    let mut request = healthy_state();
    request["proofs"]["PreToolUse"] = json!("[1, 2]");
    request["proofs"]["PostToolUse"] = json!("null");
    let answer = dispatch(&request).expect("state");
    for (key, event) in [
        ("live_pretool_proof", "PreToolUse"),
        ("live_posttool_proof", "PostToolUse"),
    ] {
        assert_eq!(
            answer["state"][key],
            json!({"present": true, "fresh": false, "live": false, "event": event, "outcome": null})
        );
    }
    assert_eq!(answer["state"]["ready"], false);
}

#[test]
fn non_standard_or_infinite_proof_timestamps_are_never_fresh() {
    let mut request = healthy_state();
    request["proofs"]["PreToolUse"] =
        json!("{\"timestamp\": -Infinity, \"source\": \"cline\", \"outcome\": \"blocked\"}");
    request["proofs"]["PostToolUse"] =
        json!("{\"timestamp\": -1e400, \"source\": \"cline\", \"outcome\": \"observed\"}");
    let answer = dispatch(&request).expect("state");
    assert_eq!(answer["state"]["live_pretool_proof"]["present"], false);
    assert_eq!(answer["state"]["live_posttool_proof"]["fresh"], false);
    assert_eq!(answer["state"]["pretool_blocking_proven"], false);
    assert_eq!(answer["state"]["ready"], false);
}

#[test]
fn malformed_render_arguments_are_refused() {
    let base = with_op(&cases("render")[0]["args"], "render");
    let mut refused = Vec::new();
    for (key, value) in [
        ("windows", json!("false")),
        ("runtime", Value::Null),
        ("guard_cli", json!("python")),
        ("guard_cli", json!(["python", 7])),
        ("adapter_state", json!(["/state"])),
        ("events", json!([])),
    ] {
        let mut request = base.clone();
        request[key] = value;
        refused.push(request);
    }
    let mut extra = base.clone();
    extra["unexpected"] = json!(true);
    refused.push(extra);
    let mut missing = base.clone();
    missing.as_object_mut().expect("object").remove("runtime");
    refused.push(missing);
    let mut unknown_event = base.clone();
    unknown_event["events"]["Unknown"] = json!({"worker": "/w", "proof": "/p"});
    refused.push(unknown_event);
    let mut absent_event = base.clone();
    absent_event["events"]
        .as_object_mut()
        .expect("events")
        .remove("TaskError");
    refused.push(absent_event);
    let mut bad_paths = base.clone();
    bad_paths["events"]["PreToolUse"] = json!({"worker": "/w"});
    refused.push(bad_paths);
    let mut extra_path = base.clone();
    extra_path["events"]["PreToolUse"]["slot"] = json!("x");
    refused.push(extra_path);
    for request in refused {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}

#[test]
fn malformed_state_arguments_are_refused() {
    let base = healthy_state();
    let mut refused = Vec::new();
    for (pointer, value) in [
        ("/now", json!("1800000000")),
        ("/state_text", json!({})),
        ("/launchers/PreToolUse", json!({"sha256": "x"})),
        (
            "/launchers/PreToolUse",
            json!({"sha256": "x", "managed": "yes"}),
        ),
        ("/workers/TaskStart", json!({"sha256": 7, "managed": true})),
        ("/workers/TaskStart", json!("x")),
        ("/proofs/PreToolUse", json!(7)),
    ] {
        let mut request = base.clone();
        *request.pointer_mut(pointer).expect("pointer") = value;
        refused.push(request);
    }
    for (key, inner) in [("launchers", "TaskError"), ("workers", "PostToolUse")] {
        let mut request = base.clone();
        request[key].as_object_mut().expect(key).remove(inner);
        refused.push(request);
    }
    let mut extra_proof = base.clone();
    extra_proof["proofs"]["TaskStart"] = Value::Null;
    refused.push(extra_proof);
    let mut extra = base.clone();
    extra["unexpected"] = json!(true);
    refused.push(extra);
    let mut missing = base.clone();
    missing.as_object_mut().expect("object").remove("now");
    refused.push(missing);
    for request in refused {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}

#[test]
fn unknown_ops_and_non_object_arguments_are_refused() {
    assert_eq!(dispatch(&json!([])), Err(ERR_INVALID));
    assert_eq!(dispatch(&json!({"op": "write"})), Err(ERR_INVALID));
    assert_eq!(dispatch(&json!({})), Err(ERR_INVALID));
}
