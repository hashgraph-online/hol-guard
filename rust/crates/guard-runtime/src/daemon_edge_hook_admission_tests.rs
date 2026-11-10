use serde_json::{json, Map, Value};

use super::*;

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

#[test]
fn events_normalize_to_the_four_the_daemon_tells_apart() {
    let event = |payload: Value| runtime_event(&object(payload));
    assert_eq!(event(json!({})), "PreToolUse");
    assert_eq!(
        event(json!({"event": "before_shell_execution"})),
        "PreToolUse"
    );
    assert_eq!(
        event(json!({"hookEventName": "after-read-file"})),
        "PostToolUse"
    );
    assert_eq!(
        event(json!({"hook_name": "permission_request_v2"})),
        "PermissionRequest"
    );
    assert_eq!(
        event(json!({"event": " ", "hook_event_name": "prompt"})),
        "UserPromptSubmit"
    );
    assert_eq!(event(json!({"event": "SessionStart"})), "SessionStart");
}

#[test]
fn the_reply_event_is_spelled_as_the_hook_sent_it() {
    let event = |payload: Value| reply_event(&object(payload));
    assert_eq!(event(json!({"event": "x"})), "x");
    assert_eq!(
        event(json!({"hook_event_name": 3, "event": "x"})),
        "PreToolUse"
    );
    assert_eq!(event(json!({"hook_event_name": " y "})), "y");
}

#[test]
fn decisions_take_the_first_lane() {
    assert_eq!(lane("PreToolUse"), "decision");
    assert_eq!(lane("UserPromptSubmit"), "decision");
    assert_eq!(lane("PostToolUse"), "content-security");
}

#[test]
fn hints_are_taken_out_of_the_payload() {
    let mut payload = object(json!({"guard_remaining_ms": 1500, "a": 1}));
    assert_eq!(take_hint(&mut payload), (Some(1.5), false));
    assert!(!payload.contains_key("guard_remaining_ms"));
    let mut payload = object(json!({"guard_remaining_seconds": true}));
    assert_eq!(take_hint(&mut payload), (None, false));
    assert_eq!(take_hint(&mut Map::new()), (None, true));
}

#[test]
fn deadlines_stay_inside_the_admission_window() {
    assert!((expires_at(100.0, None, true, false) - 102.75).abs() < 1e-9);
    assert!((expires_at(100.0, Some(9.0), false, false) - 103.0).abs() < 1e-9);
    assert!((expires_at(100.0, Some(0.0), false, false) - 100.1).abs() < 1e-9);
    assert!((expires_at(100.0, None, true, true) - 109.75).abs() < 1e-9);
    assert!((expires_at(100.0, Some(2.0), false, true) - 101.75).abs() < 1e-9);
}

#[test]
fn the_client_key_digests_workspace_and_session() {
    let payload = object(json!({"session_id": "", "thread_id": "t"}));
    let key = client_key(&payload, Some("/w"));
    assert_eq!(key.len(), 32);
    assert_ne!(key, client_key(&payload, None));
    assert_eq!(
        key,
        client_key(&object(json!({"thread_id": "t"})), Some("/w"))
    );
}

#[test]
fn only_exec_command_names_a_workdir() {
    let named = |payload: Value| exec_workdir(&object(payload));
    assert_eq!(
        named(json!({"tool_name": " Exec_Command ", "tool_input": {"workdir": "/w"}})),
        (true, Some("/w".to_owned()))
    );
    assert_eq!(
        named(json!({"tool_name": "exec_command", "tool_input": {"workdir": 1}})),
        (true, None)
    );
    assert_eq!(
        named(json!({"tool_name": "bash", "tool_input": {"workdir": "/w"}})),
        (false, None)
    );
}

#[test]
fn truthiness_follows_python() {
    assert!(!truthy(None));
    assert!(!truthy(Some(&json!(""))));
    assert!(!truthy(Some(&json!(0))));
    assert!(truthy(Some(&json!("/w"))));
}

#[test]
fn a_workspace_rejection_is_reported_as_the_workspace() {
    let directories = Directories {
        verdicts: vec![
            json!({"parameter": "workspace-query", "trusted": false, "reason": "r"}),
            json!({"parameter": "home", "trusted": true, "path": "/h"}),
        ],
        unavailable: None,
    };
    assert_eq!(directories.require("home"), Ok(Some("/h".to_owned())));
    assert_eq!(directories.require("guard-home"), Ok(None));
    assert_eq!(
        directories.require("workspace-query"),
        Err(Rejection {
            parameter: "workspace".to_owned(),
            reason: "r".to_owned(),
        })
    );
    let unavailable = Directories {
        verdicts: Vec::new(),
        unavailable: Some("guard-home".to_owned()),
    };
    assert_eq!(
        unavailable
            .require("home")
            .map_err(|rejection| rejection.reason),
        Err(DIRECTORY_TRUST_UNAVAILABLE.to_owned())
    );
}

#[test]
fn nothing_named_settles_to_nothing() {
    let directories = Directories::settle("/g", "/h", &[("home", None, None)]);
    assert_eq!(directories.require("home"), Ok(None));
}

#[test]
fn a_payload_reference_needs_version_one_a_path_and_a_digest() {
    let digest = "A".repeat(64);
    let read = |reference: Value| {
        let payload = json!({ "guard_payload_ref": reference });
        payload_reference(payload.as_object().unwrap_or_else(|| unreachable!()))
    };
    assert_eq!(
        payload_reference(&Map::new()),
        Ok(None),
        "an inline payload names no reference"
    );
    assert_eq!(read(json!("not-an-object")), Ok(None));
    assert_eq!(
        read(json!({"version": 1, "path": "/tmp/p", "sha256": digest})),
        Ok(Some("/tmp/p".to_owned()))
    );
    assert_eq!(read(json!({"version": 1})), Err(()));
    assert_eq!(
        read(json!({"version": 2, "path": "/tmp/p", "sha256": digest})),
        Err(())
    );
    assert_eq!(
        read(json!({"version": 1, "path": "/tmp/p", "sha256": "abc"})),
        Err(())
    );
    assert_eq!(
        read(json!({"version": 1, "path": "/tmp/p", "sha256": "z".repeat(64)})),
        Err(())
    );
}
