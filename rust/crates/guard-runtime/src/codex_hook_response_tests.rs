//! Parity with the Python Codex hook bridge, recorded before the port.

use serde_json::Value;

use super::*;
use crate::hook_env_stamp::dumps;
use crate::pyjson::parse_mapping_lone_surrogates;

const VECTORS: &str = include_str!("../testdata/codex_hook_bridge/vectors.json");

fn vectors(section: &str) -> Vec<Value> {
    let all: Value = serde_json::from_str(VECTORS).unwrap();
    all[section].as_array().unwrap().clone()
}

fn entries(text: &str) -> Vec<(String, PyVal)> {
    match parse_mapping_lone_surrogates(text).ok().unwrap().value {
        PyVal::Dict(entries) => entries,
        other => panic!("not an object: {other:?}"),
    }
}

#[test]
fn responses_are_shaped_as_python_shapes_them() {
    let cases = vectors("shape");
    assert!(cases.len() > 100);
    for case in cases {
        let response = case["response"].as_str().unwrap();
        let event = case["event"].as_str().unwrap();
        let mut rendered = String::new();
        dumps(
            &codex_hook_response(&entries(response), event),
            true,
            false,
            &mut rendered,
        );
        assert_eq!(
            rendered,
            case["expected"].as_str().unwrap(),
            "{event} {response}"
        );
    }
}

#[test]
fn fail_closed_matches_python() {
    for case in vectors("fail_closed") {
        let event = case["event"].as_str().unwrap();
        assert_eq!(
            fail_closed(event),
            case["expected"].as_str().unwrap(),
            "{event:?}"
        );
    }
}

#[test]
fn event_names_match_python() {
    for case in vectors("event_names") {
        let payload = case["payload"].as_str().unwrap();
        assert_eq!(
            runtime_hook_event_name(&entries(payload)),
            case["expected"].as_str().unwrap(),
            "{payload}"
        );
    }
}

#[test]
fn approval_aliases_never_reach_the_hook_response() {
    let response = r#"{"policy_action": "review",
      "reason_code": "native_pre_tool_review",
      "reason": "Open HOL Guard: https://example.test/a?sig=x.",
      "approval_url": "https://example.test/a",
      "approval_request_id": "req-native-codex-bridge",
      "primary_approval_url": "https://example.test/a",
      "guardApprovalUrl": "https://example.test/a",
      "approval_requests": [{"request_id": "req-native-codex-bridge"}],
      "guard_transition_observation": {"probe_id": "p-1"},
      "hookSpecificOutput": {"hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": "Open HOL Guard: https://example.test/a?sig=x."}}"#;
    let mut rendered = String::new();
    dumps(
        &codex_hook_response(&entries(response), PRE_TOOL_USE),
        true,
        false,
        &mut rendered,
    );
    for alias in [
        "approval_url",
        "approval_request_id",
        "primary_approval_url",
        "guardApprovalUrl",
        "approval_requests",
        "policy_action",
        "reason_code",
        "guard_transition_observation",
    ] {
        assert!(!rendered.contains(alias), "{alias} leaked: {rendered}");
    }
    assert!(rendered.contains("permissionDecisionReason"), "{rendered}");
}

#[test]
fn a_policy_deny_overrides_an_updated_input_allow() {
    // A contained-sink rewrite answers `allow` with `updatedInput`. A policy
    // deny must still win, and the rewritten input must not reach the hook.
    let response = r#"{"policy_action": "deny",
      "hookSpecificOutput": {"hookEventName": "PreToolUse",
        "permissionDecision": "allow",
        "updatedInput": {"command": "true"}}}"#;
    let mut rendered = String::new();
    dumps(
        &codex_hook_response(&entries(response), PRE_TOOL_USE),
        true,
        false,
        &mut rendered,
    );
    let shaped: Value = serde_json::from_str(&rendered).unwrap();
    let output = &shaped["hookSpecificOutput"];
    assert_eq!(output["permissionDecision"], "deny", "{rendered}");
    assert!(output.get("updatedInput").is_none(), "{rendered}");
}
