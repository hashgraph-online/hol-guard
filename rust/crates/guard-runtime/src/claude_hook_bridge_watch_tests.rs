//! Watch posture on the native Claude hook bridge: a review that cannot
//! complete lets the action through only where Watch applies, and a daemon's
//! passthrough for an app Guard does not manage is not a malformed answer.

use std::io::Cursor;

use serde_json::{json, Value};

use super::*;
use crate::claude_hook_bridge::hook_response;
use crate::claude_hook_bridge_fixture::{closed_port, home_with_daemon, Exchange, GuardHome};

const PRE_TOOL_USE: &str =
    r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}"#;
const PERMISSION_REQUEST: &str = r#"{"hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"echo ok"}}"#;
const UNMANAGED: &str = r#"{"continue":true,"reason_code":"harness_not_managed"}"#;

fn config_for(home: &GuardHome) -> String {
    json!({
        "state_path": home.state_path.to_str().unwrap(),
        "fallback_daemon_url": format!("http://127.0.0.1:{}", closed_port()),
        "query": format!("guard-home={}", home.home_text().replace('/', "%2F")),
        "fallback_command": ["/bin/sh", "-c", "exit 3"],
        "recovery_command": [],
    })
    .to_string()
}

fn respond(home: &GuardHome, input: &str) -> Value {
    let text = hook_response(
        &config_for(home),
        &mut Cursor::new(input.as_bytes().to_vec()),
    )
    .expect("hook response");
    serde_json::from_str(&text).expect("hook JSON")
}

fn configure(home: &GuardHome, toml: &str) {
    std::fs::write(home.home.join("config.toml"), toml).unwrap();
}

fn decision(response: &Value) -> &str {
    response["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or_default()
}

fn failure_log(home: &GuardHome) -> String {
    std::fs::read_to_string(home.home.join(FAILURE_LOG)).unwrap_or_default()
}

#[test]
fn config_reads_watch_from_the_baseline_or_the_harness_override() {
    let config = |posture: &str, mode: &str, overrides: Value| json!({"protection_posture": posture, "mode": mode, "harness_postures": overrides});
    assert!(config_is_watch(&config("watch", "observe", json!({}))));
    assert!(config_is_watch(&config("protected", "observe", json!({}))));
    assert!(config_is_watch(&config(
        "protected",
        "prompt",
        json!({"claude-code": "watch"})
    )));
    assert!(!config_is_watch(&config("protected", "prompt", json!({}))));
    assert!(!config_is_watch(&config(
        "extra_careful",
        "enforce",
        json!({"cursor": "watch"})
    )));
    // An enforcing override beats a machine-wide Watch.
    assert!(!config_is_watch(&config(
        "watch",
        "observe",
        json!({"claude-code": "protected"})
    )));
    // Nothing unreadable reads as Watch.
    assert!(!config_is_watch(&json!({})));
    assert!(!config_is_watch(
        &json!({"protection_posture": 7, "mode": null})
    ));
}

#[test]
fn watch_lets_an_action_through_when_the_daemon_answer_is_malformed() {
    let (home, daemon) = home_with_daemon(
        "watch-malformed",
        vec![Exchange::Hook(200, "not json".to_owned())],
    );
    configure(&home, "protection_posture = \"watch\"\n");
    let response = respond(&home, PRE_TOOL_USE);
    assert_eq!(decision(&response), "allow", "{response}");
    assert_eq!(response["reason_code"], "watch_native_review_unavailable");
    let reason = response["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(
        reason.contains("daemon returned malformed hook JSON"),
        "{reason}"
    );
    let log = failure_log(&home);
    assert!(log.contains("hook_bridge_watch_fail_open"), "{log}");
    assert!(log.contains("daemon returned malformed hook JSON"), "{log}");
    daemon.join().unwrap();
}

#[test]
fn watch_lets_an_action_through_when_the_daemon_is_unavailable_or_absent() {
    let (home, daemon) = home_with_daemon(
        "watch-unavailable",
        vec![Exchange::Hook(503, "unavailable".to_owned())],
    );
    configure(&home, "protection_posture = \"watch\"\n");
    assert_eq!(decision(&respond(&home, PRE_TOOL_USE)), "allow");
    daemon.join().unwrap();

    let absent = GuardHome::new("watch-absent");
    configure(&absent, "protection_posture = \"watch\"\n");
    std::fs::remove_file(absent.home.join("daemon-discovery-key")).unwrap();
    assert_eq!(decision(&respond(&absent, PRE_TOOL_USE)), "allow");
}

#[test]
fn a_harness_override_puts_claude_code_in_watch_under_an_enforcing_baseline() {
    let (home, daemon) =
        home_with_daemon("watch-override", vec![Exchange::Hook(200, "{}".to_owned())]);
    configure(&home, "[harness_postures]\nclaude-code = \"watch\"\n");
    assert_eq!(decision(&respond(&home, PRE_TOOL_USE)), "allow");
    daemon.join().unwrap();
}

#[test]
fn watch_defers_a_permission_request_to_the_claude_dialog_and_grants_nothing() {
    let (home, daemon) =
        home_with_daemon("watch-permission", vec![Exchange::Hook(200, "".to_owned())]);
    configure(&home, "protection_posture = \"watch\"\n");
    let response = respond(&home, PERMISSION_REQUEST);
    assert_eq!(response["guard_permission_passthrough"], true, "{response}");
    assert!(response["hookSpecificOutput"].get("decision").is_none());
    daemon.join().unwrap();
}

#[test]
fn enforcement_still_denies_a_malformed_daemon_answer() {
    for (label, toml) in [
        ("enforce-default", ""),
        ("enforce-protected", "protection_posture = \"protected\"\n"),
        (
            "enforce-override",
            "protection_posture = \"watch\"\n[harness_postures]\nclaude-code = \"extra_careful\"\n",
        ),
    ] {
        let (home, daemon) =
            home_with_daemon(label, vec![Exchange::Hook(200, "not json".to_owned())]);
        configure(&home, toml);
        let response = respond(&home, PRE_TOOL_USE);
        assert_eq!(decision(&response), "deny", "{label}: {response}");
        assert!(
            response["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains("could not complete native review"),
            "{label}"
        );
        assert_eq!(failure_log(&home), "", "{label}");
        daemon.join().unwrap();
    }
}

#[test]
fn enforcement_still_denies_when_the_daemon_is_unavailable() {
    let (home, daemon) = home_with_daemon(
        "enforce-unavailable",
        vec![Exchange::Hook(503, "unavailable".to_owned())],
    );
    assert_eq!(decision(&respond(&home, PRE_TOOL_USE)), "deny");
    daemon.join().unwrap();
}

#[test]
fn a_daemon_passthrough_for_an_unmanaged_app_is_not_malformed() {
    for event in [PRE_TOOL_USE, PERMISSION_REQUEST] {
        let (home, daemon) =
            home_with_daemon("unmanaged", vec![Exchange::Hook(200, UNMANAGED.to_owned())]);
        let response = respond(&home, event);
        assert_eq!(response, serde_json::from_str::<Value>(UNMANAGED).unwrap());
        daemon.join().unwrap();
    }
}

#[test]
fn an_unmanaged_passthrough_with_anything_more_is_still_malformed() {
    for body in [
        r#"{"continue":true,"reason_code":"harness_not_managed","extra":1}"#,
        r#"{"continue":false,"reason_code":"harness_not_managed"}"#,
        r#"{"continue":true,"reason_code":"something_else"}"#,
    ] {
        let (home, daemon) = home_with_daemon(
            "unmanaged-extra",
            vec![Exchange::Hook(200, body.to_owned())],
        );
        assert_eq!(decision(&respond(&home, PRE_TOOL_USE)), "deny", "{body}");
        daemon.join().unwrap();
    }
}
