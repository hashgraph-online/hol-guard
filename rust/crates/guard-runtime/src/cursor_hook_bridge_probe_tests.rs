//! Cursor's silent `preToolUse` probe for `Shell`: the rewritten command
//! when the daemon routed the call into the contained sink, else a plain
//! allow, whatever the daemon answered.

use std::time::Duration;

use serde_json::Value;

use super::super::daemon_tests::ask;
use super::super::{prepared_request, respond, Client};
use super::rewritten;
use crate::claude_hook_bridge_fixture::{closed_port, write_private, GuardHome};
use crate::cursor_hook_bridge_response::ALLOW_STDOUT;

const PROBE: &[u8] = br#"{"hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"npx vitest run a.test.ts","cwd":"/nonexistent-cursor-cwd"},"cwd":"/nonexistent-cursor-cwd"}"#;
const SHELL: &[u8] =
    br#"{"hook_event_name":"beforeShellExecution","command":"ls","cwd":"/nonexistent-cursor-cwd"}"#;
const ROUTED: &str = r#"{"policy_action": "allow", "reason_code": "native_contained_execution_routed", "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow", "updatedInput": {"command": "'/py' -m codex_plugin_scanner.cli guard execute-contained-test --harness cursor", "cwd": "/w", "timeout": 1.5e3}}}"#;

fn allowed() -> Option<(String, i32)> {
    Some((ALLOW_STDOUT.to_owned(), 0))
}

#[test]
fn only_cursors_shell_pretooluse_is_a_probe() {
    let client = Client {
        guard_home: "/g".to_owned(),
        home: Some("/h".to_owned()),
        recovery_command: Vec::new(),
        event: "preToolUse".to_owned(),
        deadline: std::time::Instant::now() + Duration::from_secs(5),
    };
    assert!(prepared_request(&client, PROBE).unwrap().probe);
    assert!(!prepared_request(&client, SHELL).unwrap().probe);
    let write = br#"{"hook_event_name":"preToolUse","tool_name":"Write","tool_input":{"file_path":"/tmp/a"}}"#;
    assert!(!prepared_request(&client, write).unwrap().probe);
}

#[test]
fn a_routed_probe_answers_with_the_rewritten_command() {
    let (answered, request, _home) = ask("probe-routed", PROBE, 200, ROUTED);
    let (stdout, code) = answered.unwrap();
    assert_eq!(code, 0);
    assert!(request.target.starts_with("/v1/hooks/cursor?guard-home="));
    let printed: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(printed["permission"], "allow");
    assert_eq!(printed["updated_input"]["cwd"], "/w");
    assert!(printed["updated_input"]["command"]
        .as_str()
        .unwrap()
        .contains("execute-contained-test"));
    // `json.dumps(..., sort_keys=True)` as the client prints it.
    assert!(stdout.starts_with("{\"permission\": \"allow\", \"updated_input\": {\"command\": "));
    assert!(stdout.ends_with(", \"cwd\": \"/w\", \"timeout\": 1500.0}}\n"));
}

#[test]
fn every_other_daemon_answer_is_a_plain_allow() {
    let bodies: [(&str, u16, &str); 9] = [
        (
            "review",
            200,
            r#"{"policy_action":"review","reason":"Needs a look."}"#,
        ),
        ("block", 200, r#"{"policy_action":"block"}"#),
        ("sandbox", 200, r#"{"policy_action":"sandbox-required"}"#),
        ("allow", 200, r#"{"policy_action":"allow"}"#),
        (
            "unrouted-rewrite",
            200,
            r#"{"policy_action":"allow","reason_code":"other","hookSpecificOutput":{"updatedInput":{"command":"x"}}}"#,
        ),
        (
            "no-command",
            200,
            r#"{"policy_action":"allow","reason_code":"native_contained_execution_routed","hookSpecificOutput":{"updatedInput":{"cwd":"/w"}}}"#,
        ),
        ("server-error", 500, ROUTED),
        ("malformed", 200, "{"),
        ("list", 200, "[]"),
    ];
    for (label, status, body) in bodies {
        let (answered, _request, _home) = ask(label, PROBE, status, body);
        assert_eq!(answered, allowed(), "{label}");
    }
}

#[test]
fn a_body_the_client_cannot_print_is_a_plain_allow() {
    let routed = |extra: &str| {
        format!(
            r#"{{"policy_action":"allow","reason_code":"native_contained_execution_routed","hookSpecificOutput":{{"updatedInput":{{"command":"x"{extra}}}}}}}"#
        )
    };
    assert!(rewritten(&routed("")).is_some());
    for extra in [r#","n":NaN"#, r#","n":1e400"#, r#","s":"\ud800""#] {
        assert_eq!(rewritten(&routed(extra)), None, "{extra}");
    }
}

#[test]
fn a_probe_with_no_daemon_is_a_plain_allow_without_a_restart() {
    let home = GuardHome::new("cursor-probe-no-daemon");
    write_private(
        &home.state_path,
        &serde_json::json!({"host": "127.0.0.1", "port": closed_port()}).to_string(),
    );
    let client = Client {
        guard_home: home.home_text().to_owned(),
        home: Some("/h".to_owned()),
        // A restart would run this and fail the hook closed.
        recovery_command: vec!["/nonexistent-guard-recovery".to_owned()],
        event: "preToolUse".to_owned(),
        deadline: std::time::Instant::now() + Duration::from_secs(5),
    };
    assert_eq!(respond(&client, PROBE), allowed());
}
