//! Reading a Codex turn's sandbox from its session transcript.

use std::io::Write;

use super::*;
use crate::pyjson::parse_mapping_lone_surrogates;

fn context(turn_id: &str, policy: &str) -> String {
    format!(
        r#"{{"timestamp":"2026-11-03T10:00:00.000Z","type":"turn_context","payload":{{"turn_id":"{turn_id}","cwd":"/w","approval_policy":"on-request","sandbox_policy":{policy},"model":"m"}}}}"#
    )
}

const WORKSPACE_WRITE: &str = r#"{"type":"workspace-write","writable_roots":[],"network_access":false,"exclude_tmpdir_env_var":true,"exclude_slash_tmp":true}"#;
/// Codex's default workspace-write sandbox, which also writes `/tmp` and
/// `$TMPDIR`.
const SHARED_TMP: &str = r#"{"type":"workspace-write","writable_roots":[],"network_access":false,"exclude_tmpdir_env_var":false,"exclude_slash_tmp":false}"#;

/// A transcript holding `lines`, and a payload for `turn_id` that names it.
fn session(lines: &[String], turn_id: &str, input: &str) -> (tempfile::TempDir, PyVal) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("rollout.jsonl");
    let mut file = std::fs::File::create(&path).unwrap();
    for line in lines {
        writeln!(file, "{line}").unwrap();
    }
    let payload = hook_payload(path.to_str().unwrap(), turn_id, input);
    (directory, payload)
}

fn hook_payload(transcript: &str, turn_id: &str, input: &str) -> PyVal {
    parse_mapping_lone_surrogates(&payload_text(transcript, turn_id, input))
        .unwrap()
        .value
}

fn payload_text(transcript: &str, turn_id: &str, input: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": serde_json::from_str::<serde_json::Value>(input).unwrap(),
        "transcript_path": transcript,
        "turn_id": turn_id,
        "cwd": std::path::Path::new(transcript).parent(),
        "permission_mode": "bypassPermissions",
    })
    .to_string()
}

const COMMAND: &str = r#"{"command":"head -3 README.md"}"#;

#[test]
fn a_turn_in_codex_workspace_write_or_read_only_sandbox_is_read() {
    let (_directory, payload) = session(&[context("t2", WORKSPACE_WRITE)], "t2", COMMAND);
    assert_eq!(turn(&payload), Turn::WorkspaceWrite);
    let (_directory, payload) = session(&[context("t2", r#"{"type":"read-only"}"#)], "t2", COMMAND);
    assert_eq!(turn(&payload), Turn::ReadOnly);
}

#[test]
fn a_turn_whose_sandbox_reaches_the_network_or_writes_elsewhere_is_wider() {
    for policy in [
        r#"{"type":"workspace-write","network_access":true}"#,
        r#"{"type":"read-only","network_access":true}"#,
        r#"{"type":"workspace-write","writable_roots":["/Users/u"],"network_access":false}"#,
        r#"{"type":"workspace-write","writable_roots":"/","network_access":false}"#,
        SHARED_TMP,
        r#"{"type":"workspace-write","writable_roots":[],"network_access":false}"#,
        r#"{"type":"workspace-write","exclude_slash_tmp":true,"exclude_tmpdir_env_var":false}"#,
        r#"{"type":"workspace-write","exclude_slash_tmp":false,"exclude_tmpdir_env_var":true}"#,
    ] {
        let (_directory, payload) = session(&[context("t2", policy)], "t2", COMMAND);
        assert_eq!(turn(&payload), Turn::Wider, "{policy}");
    }
}

#[test]
fn a_workspace_write_turn_confines_only_the_workspace_profile() {
    for profile in [
        "workspace-contained-v1",
        "pytest-readonly-v2",
        "node-build-output-v1",
    ] {
        assert!(Turn::ReadOnly.confines(Some(profile)), "{profile}");
        assert!(!Turn::Wider.confines(Some(profile)), "{profile}");
        assert!(!Turn::Unknown.confines(Some(profile)), "{profile}");
    }
    assert!(Turn::WorkspaceWrite.confines(Some("workspace-contained-v1")));
    for profile in [
        Some("pytest-readonly-v2"),
        Some("python-eval-readonly-v1"),
        Some("node-build-output-v1"),
        None,
    ] {
        assert!(!Turn::WorkspaceWrite.confines(profile), "{profile:?}");
    }
}

#[test]
fn a_turn_without_codex_sandbox_is_unknown() {
    for policy in [
        r#"{"type":"danger-full-access"}"#,
        r#"{"type":"external-sandbox"}"#,
        r#""workspace-write""#,
        "null",
    ] {
        let (_directory, payload) = session(&[context("t2", policy)], "t2", COMMAND);
        assert_eq!(turn(&payload), Turn::Unknown, "{policy}");
    }
}

#[test]
fn only_the_hook_calls_own_turn_counts() {
    let lines = [
        context("t1", WORKSPACE_WRITE),
        context("t2", r#"{"type":"danger-full-access"}"#),
        r#"{"type":"event_msg","payload":{"type":"turn_context","turn_id":"t3"}}"#.to_owned(),
    ];
    let (_directory, payload) = session(&lines, "t2", COMMAND);
    assert_eq!(turn(&payload), Turn::Unknown);
    let (_directory, payload) = session(&lines, "t1", COMMAND);
    assert_eq!(turn(&payload), Turn::WorkspaceWrite);
    let (_directory, payload) = session(&lines, "t3", COMMAND);
    assert_eq!(turn(&payload), Turn::Unknown);
    let (_directory, payload) = session(&lines, "", COMMAND);
    assert_eq!(turn(&payload), Turn::Unknown);
}

#[test]
fn the_latest_context_for_the_turn_wins() {
    let lines = [
        context("t2", r#"{"type":"danger-full-access"}"#),
        context("t2", WORKSPACE_WRITE),
    ];
    let (_directory, payload) = session(&lines, "t2", COMMAND);
    assert_eq!(turn(&payload), Turn::WorkspaceWrite);
}

#[test]
fn a_call_that_asks_to_leave_the_sandbox_is_unknown() {
    for input in [
        r#"{"command":"ls","sandbox_permissions":"require_escalated"}"#,
        r#"{"command":"ls","with_escalated_permissions":true}"#,
    ] {
        let (_directory, payload) = session(&[context("t2", WORKSPACE_WRITE)], "t2", input);
        assert_eq!(turn(&payload), Turn::Unknown, "{input}");
    }
    let input = r#"{"command":"ls","sandbox_permissions":"use_default"}"#;
    let (_directory, payload) = session(&[context("t2", WORKSPACE_WRITE)], "t2", input);
    assert_eq!(turn(&payload), Turn::WorkspaceWrite);
    let camel = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "toolInput": {"command": "ls", "sandbox_permissions": "require_escalated"},
        "transcript_path": "/unused/rollout.jsonl",
        "turn_id": "t2",
    });
    let payload = parse_mapping_lone_surrogates(&camel.to_string())
        .unwrap()
        .value;
    assert!(escalated(&payload), "the camel-case input is read too");
}

#[test]
fn a_missing_relative_or_unreadable_transcript_is_unknown() {
    let (directory, _) = session(&[context("t2", WORKSPACE_WRITE)], "t2", COMMAND);
    for transcript in [
        directory
            .path()
            .join("missing.jsonl")
            .to_str()
            .unwrap()
            .to_owned(),
        "rollout.jsonl".to_owned(),
        directory.path().to_str().unwrap().to_owned(),
    ] {
        let payload = hook_payload(&transcript, "t2", COMMAND);
        assert_eq!(turn(&payload), Turn::Unknown, "{transcript}");
    }
}

#[cfg(unix)]
#[test]
fn a_symlinked_transcript_is_unknown() {
    let (directory, _) = session(&[context("t2", WORKSPACE_WRITE)], "t2", COMMAND);
    let link = directory.path().join("link.jsonl");
    std::os::unix::fs::symlink(directory.path().join("rollout.jsonl"), &link).unwrap();
    let payload = hook_payload(link.to_str().unwrap(), "t2", COMMAND);
    assert_eq!(turn(&payload), Turn::Unknown);
}

#[test]
fn a_turn_context_beyond_the_read_tail_is_unknown() {
    let filler = format!(
        r#"{{"type":"response_item","payload":"{}"}}"#,
        "x".repeat(1 << 20)
    );
    let mut lines = vec![context("t2", WORKSPACE_WRITE)];
    lines.extend(std::iter::repeat_n(filler, 9));
    let (_directory, payload) = session(&lines, "t2", COMMAND);
    assert_eq!(turn(&payload), Turn::Unknown);
    lines.drain(1..3);
    let (_directory, payload) = session(&lines, "t2", COMMAND);
    assert_eq!(turn(&payload), Turn::WorkspaceWrite);
}

#[cfg(target_os = "macos")]
#[test]
fn a_contained_call_in_codex_sandbox_runs_behind_the_sandbox_check() {
    use std::time::{Duration, Instant};

    use super::super::{settle, BridgeConfig, Prepared, Route, FIXED_CODEX_APPLIES};
    use crate::codex_hook_response::PRE_TOOL_USE;

    const DENY: &str = r#"{"policy_action":"sandbox-required","decision":"deny","reason_code":"native_workspace_containment_required","required_execution_profile":"workspace-contained-v1","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Run this inside the contained runner."}}"#;
    let config = BridgeConfig {
        state_path: "/g/daemon-state.json".to_owned(),
        query: "harness=codex&home=%2Fh".to_owned(),
        hook_timeouts: Vec::new(),
        start_command: Vec::new(),
        fallback_command: vec!["/opt/hol-guard".to_owned(), "hook".to_owned()],
    };
    const READ_ONLY_DENY: &str = r#"{"policy_action":"sandbox-required","decision":"deny","reason_code":"native_pytest_readonly_containment_required","required_execution_profile":"pytest-readonly-v2","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Run this inside the contained runner."}}"#;
    let (directory, _) = session(&[], "t2", COMMAND);
    let workspace = std::fs::canonicalize(directory.path()).unwrap();
    let transcript = workspace.join("rollout.jsonl");
    let answer = |policy: &str, deny: &str| {
        std::fs::write(&transcript, format!("{}\n", context("t2", policy))).unwrap();
        let prepared = Prepared {
            event_name: PRE_TOOL_USE.to_owned(),
            data: payload_text(transcript.to_str().unwrap(), "t2", COMMAND),
            timeout: Duration::from_secs(30),
        };
        FIXED_CODEX_APPLIES.with(|applies| applies.set(Some(true)));
        let deadline = Instant::now() + Duration::from_secs(5);
        let parsed = parse_mapping_lone_surrogates(deny).unwrap().value;
        let route = settle(&config, &prepared, parsed, false, deadline);
        FIXED_CODEX_APPLIES.with(|applies| applies.set(None));
        route
    };
    let check = shell_join(&[
        std::env::current_exe()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        "codex-sandbox-check".to_owned(),
        "--profile".to_owned(),
        "workspace-contained-v1".to_owned(),
        "--workspace".to_owned(),
        workspace.to_str().unwrap().to_owned(),
    ])
    .unwrap();
    let allowed = serde_json::json!({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow",
        "updatedInput": {"command": format!("{check} || exit 126\nhead -3 README.md")},
    }});
    let Route::Respond(output) = answer(WORKSPACE_WRITE, DENY) else {
        panic!("the bridge answers the call itself");
    };
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&output).unwrap(),
        allowed
    );
    let denied = Route::Respond(
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Run this inside the contained runner."}}"#
            .to_owned(),
    );
    assert_eq!(
        answer(r#"{"type":"workspace-write","network_access":true}"#, DENY),
        denied
    );
    assert_eq!(
        answer(SHARED_TMP, DENY),
        denied,
        "Codex's default sandbox writes /tmp and $TMPDIR"
    );
    assert_eq!(
        answer(WORKSPACE_WRITE, READ_ONLY_DENY),
        denied,
        "workspace-write would let a read-only profile write"
    );
}
