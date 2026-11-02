use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use tempfile::TempDir;

use super::*;

const HOOK: &[u8] = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash"}"#;

fn prepared() -> Prepared {
    Prepared {
        data: String::from_utf8(HOOK.to_vec()).unwrap(),
        event_name: "PreToolUse".to_owned(),
        mapped: false,
        collision: false,
    }
}

fn failed() -> Route {
    Route::Fail {
        event_name: "PreToolUse".to_owned(),
        unmap: false,
    }
}

/// A newer bridge whose answer is what `body` prints.
fn bridge(directory: &TempDir, body: &str) -> PathBuf {
    let runtime = directory.path().join("hol-guard-runtime");
    fs::write(&runtime, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    runtime
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

#[test]
fn the_newer_bridge_answers_the_hook_with_this_bridges_command() {
    let directory = TempDir::new().unwrap();
    let successor = bridge(
        &directory,
        r#"printf '%s|%s|%s|%s|' "$HOL_GUARD_HOOK_HANDED_OFF" "$1" "$2" "$#"; cat; exit 2"#,
    );
    let python_argv = ["python3".to_owned(), "{\"harness\":\"zcode\"}".to_owned()];

    let route = handed_off(&successor, &prepared(), &python_argv, HOOK, soon());

    let stdout = format!(
        "1|bounded-hook-bridge|python3|3|{}",
        String::from_utf8(HOOK.to_vec()).unwrap()
    );
    assert_eq!(
        route,
        Some(Route::Respond {
            stdout,
            stderr: String::new(),
            exit_code: 2,
        })
    );
}

#[test]
fn a_newer_bridge_without_an_answer_in_time_fails_closed() {
    let directory = TempDir::new().unwrap();
    let successor = bridge(&directory, "exec sleep 30");
    let deadline = Instant::now() + Duration::from_millis(200);

    let route = handed_off(&successor, &prepared(), &[], HOOK, deadline);

    assert_eq!(route, Some(failed()));
}

#[test]
fn a_newer_bridge_that_cannot_start_leaves_the_hook_here() {
    let directory = TempDir::new().unwrap();
    let missing = directory.path().join("hol-guard-runtime");

    assert_eq!(handed_off(&missing, &prepared(), &[], HOOK, soon()), None);
}

#[test]
fn an_answer_this_bridge_cannot_write_fails_closed() {
    let unreadable = HandOff::Answered(vec![0xff, 0xfe], 0);

    assert_eq!(handed_off_route(&prepared(), unreadable), failed());
    assert_eq!(handed_off_route(&prepared(), HandOff::Failed), failed());
}
