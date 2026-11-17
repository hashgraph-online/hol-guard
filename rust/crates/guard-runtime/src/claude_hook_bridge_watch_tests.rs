//! A Claude hook whose daemon does not answer continues when the signed
//! posture proves the harness is in Watch, and is denied otherwise.

use std::io::Cursor;

use serde_json::{json, Value};

use crate::claude_hook_bridge::hook_response;
use crate::claude_hook_bridge_fixture::{closed_port, GuardHome};
use crate::claude_hook_bridge_harness::current_cursor_run;
use crate::hook_watch_posture::tests::sign_postures;

const PRE_TOOL_USE: &str =
    r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push"}}"#;
const PERMISSION_REQUEST: &str = r#"{"hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"git push"}}"#;

/// A home whose daemon is down: its state names a closed port, and there is
/// no recovery command to bring it back.
fn down_daemon(label: &str) -> (GuardHome, String) {
    let home = GuardHome::new(label);
    home.write_state(&home.state(closed_port()));
    let config = json!({
        "state_path": home.state_path.to_str().unwrap(),
        "fallback_daemon_url": format!("http://127.0.0.1:{}", closed_port()),
        "query": format!("guard-home={}", home.home_text().replace('/', "%2F")),
        "fallback_command": ["/bin/sh", "-c", "exit 3"],
        "recovery_command": [],
    })
    .to_string();
    (home, config)
}

fn respond(config: &str, input: &str) -> String {
    hook_response(config, &mut Cursor::new(input.as_bytes().to_vec())).expect("hook response")
}

fn denied(output: &str) -> bool {
    let payload: Value = serde_json::from_str(output).expect("hook JSON");
    payload["hookSpecificOutput"]["permissionDecision"] == "deny"
        || payload["hookSpecificOutput"]["decision"]["behavior"] == "deny"
}

fn running_inside_cursor() -> bool {
    if current_cursor_run().is_some() {
        eprintln!("skipped: this test process runs inside Cursor");
        return true;
    }
    false
}

#[test]
fn a_watch_harness_continues_while_its_daemon_is_down() {
    if running_inside_cursor() {
        return;
    }
    let (home, config) = down_daemon("watch-down");
    sign_postures(&home.home, "enforce", &[("claude-code", "watch")]);
    for event in [PRE_TOOL_USE, PERMISSION_REQUEST] {
        assert_eq!(respond(&config, event), "{}", "{event}");
    }
}

#[test]
fn a_global_watch_continues_while_the_daemon_is_down() {
    if running_inside_cursor() {
        return;
    }
    let (home, config) = down_daemon("global-watch-down");
    sign_postures(&home.home, "observe", &[]);
    assert_eq!(respond(&config, PRE_TOOL_USE), "{}");
}

#[test]
fn an_enforced_harness_is_still_denied_while_its_daemon_is_down() {
    if running_inside_cursor() {
        return;
    }
    for (label, mode, postures) in [
        (
            "protected-down",
            "enforce",
            vec![("claude-code", "protected")],
        ),
        ("other-watch-down", "enforce", vec![("cursor", "watch")]),
        (
            "override-down",
            "observe",
            vec![("claude-code", "extra_careful")],
        ),
    ] {
        let (home, config) = down_daemon(label);
        sign_postures(&home.home, mode, &postures);
        for event in [PRE_TOOL_USE, PERMISSION_REQUEST] {
            let output = respond(&config, event);
            assert!(denied(&output), "{label}: {output}");
        }
    }
}

#[test]
fn an_unproven_watch_is_still_denied_while_the_daemon_is_down() {
    if running_inside_cursor() {
        return;
    }
    let (_home, config) = down_daemon("unsigned-down");
    // No signed posture at all, as before the daemon ever published one.
    let output = respond(&config, PRE_TOOL_USE);
    assert!(denied(&output), "{output}");
}
