use super::*;
use crate::browser_session_store::BROWSER_SESSION_IDLE_SECONDS;
use guard_contracts::{
    PreToolActionTypeV1, PreToolActionV1, PreToolOperationV1, PRE_TOOL_ACTION_V1_SCHEMA,
};
use serde_json::json;

const NOW: i64 = 1_792_584_000;
const HARNESS: &str = "claude-code";

fn result(minimum_action: &str) -> PreToolResultV1 {
    PreToolResultV1 {
        schema: "guard-pre-tool-result.v1".into(),
        version: 1,
        authority: "rust".into(),
        action: PreToolActionV1 {
            schema: PRE_TOOL_ACTION_V1_SCHEMA.into(),
            version: 1,
            harness: HARNESS.into(),
            event: "PreToolUse".into(),
            action_type: PreToolActionTypeV1::Command,
            operation: PreToolOperationV1::Execute,
            bounded: true,
            sensitive_target: false,
        },
        decision: if matches!(minimum_action, "allow" | "warn") {
            "allow"
        } else {
            "deny"
        }
        .into(),
        policy_action: minimum_action.into(),
        minimum_action: minimum_action.into(),
        reason_code: "native_test".into(),
        reason: "native test".into(),
        explicitly_benign: minimum_action == "allow",
        command_extensions: None,
        prompt_risk_classes: Vec::new(),
    }
}

fn bash(session: &str, command: &str) -> Value {
    json!({
        "session_id": session,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
}

fn run(home: &Path, payload: &Value, minimum_action: &str) -> PreToolResultV1 {
    apply(home, HARNESS, payload, NOW, result(minimum_action))
}

const LAUNCH: &str =
    "chromium --headless --remote-debugging-port=9333 --user-data-dir=./profile about:blank";
const READ: &str = "curl -s http://127.0.0.1:9333/json/version";

#[test]
fn a_recorded_debugging_port_is_held_for_review() {
    let home = tempfile::tempdir().unwrap();
    let launch = run(home.path(), &bash("session-a", LAUNCH), "allow");
    assert_eq!(launch.minimum_action, "allow");
    assert_eq!(launch.reason_code, "native_test");

    let reached = run(home.path(), &bash("session-a", READ), "allow");
    assert_eq!(reached.minimum_action, "review");
    assert_eq!(reached.policy_action, "review");
    assert_eq!(reached.decision, "deny");
    assert!(!reached.explicitly_benign);
    assert_eq!(reached.reason_code, DEBUG_PORT_REVIEW);
    assert!(is_review_finding(&reached.reason_code));

    for command in [
        "curl -s localhost:9333/json",
        "curl -s 'http://[::1]:9333/json/list'",
        "wget -qO- http://localhost.:9333/json",
    ] {
        let reached = run(home.path(), &bash("session-a", command), "allow");
        assert_eq!(reached.reason_code, DEBUG_PORT_REVIEW, "{command}");
    }
}

#[test]
fn an_unrecorded_port_keeps_its_verdict() {
    let home = tempfile::tempdir().unwrap();
    run(home.path(), &bash("session-a", LAUNCH), "allow");

    let other_port = run(
        home.path(),
        &bash("session-a", "curl -s http://127.0.0.1:9334/json"),
        "allow",
    );
    assert_eq!(other_port.minimum_action, "allow");
    assert_eq!(other_port.reason_code, "native_test");

    // Another harness session never launched that browser.
    let other_session = run(home.path(), &bash("session-b", READ), "allow");
    assert_eq!(other_session.minimum_action, "allow");

    // A public host on the same port is not this machine.
    let public = run(
        home.path(),
        &bash("session-a", "curl -s https://example.test:9333/"),
        "allow",
    );
    assert_eq!(public.minimum_action, "allow");
}

#[test]
fn a_launch_and_read_in_one_call_is_held_without_a_store() {
    let home = tempfile::tempdir().unwrap();
    let missing = home.path().join("absent");
    let command = format!("{LAUNCH} & sleep 1; {READ}");
    let reached = run(&missing, &bash("session-a", &command), "allow");
    assert_eq!(reached.reason_code, DEBUG_PORT_REVIEW);
}

#[test]
fn the_overlay_only_raises() {
    let home = tempfile::tempdir().unwrap();
    run(home.path(), &bash("session-a", LAUNCH), "allow");
    let blocked = run(home.path(), &bash("session-a", READ), "block");
    assert_eq!(blocked.minimum_action, "block");
    assert_eq!(blocked.reason_code, "native_test");
    let reapproval = run(home.path(), &bash("session-a", READ), "require-reapproval");
    assert_eq!(reapproval.minimum_action, "require-reapproval");
    assert_eq!(reapproval.reason_code, "native_test");
    let review = run(home.path(), &bash("session-a", READ), "review");
    assert_eq!(review.minimum_action, "review");
    assert_eq!(review.reason_code, DEBUG_PORT_REVIEW);
}

#[test]
fn a_call_without_a_session_records_and_matches_nothing() {
    let home = tempfile::tempdir().unwrap();
    let mut launch = bash("session-a", LAUNCH);
    launch.as_object_mut().unwrap().remove("session_id");
    run(home.path(), &launch, "allow");
    assert!(!home.path().join(STORE_FILE_NAME).exists());
}

#[test]
fn debugging_port_flags_are_read_in_each_spelling() {
    assert_eq!(debugging_ports_in(LAUNCH), (vec![9333], false));
    assert_eq!(
        debugging_ports_in("chrome --remote-debugging-port 9444 --remote-debugging-port=\"9555\""),
        (vec![9444, 9555], false)
    );
    assert_eq!(
        debugging_ports_in("firefox -start-debugger-server 6080"),
        (vec![6080], false)
    );
    assert_eq!(
        debugging_ports_in("chrome --remote-debugging-port=0"),
        (Vec::<u16>::new(), false)
    );
    assert_eq!(
        debugging_ports_in("chrome --remote-debugging-pipe"),
        (Vec::<u16>::new(), false)
    );
}

fn many_launches(count: u16) -> String {
    (0..count)
        .map(|index| format!("chromium --remote-debugging-port={}", 10_000 + index))
        .collect::<Vec<_>>()
        .join(" ; ")
}

#[test]
fn naming_more_ports_than_a_session_keeps_is_reported() {
    let (ports, overflowed) = debugging_ports_in(&many_launches(16));
    assert_eq!(ports.len(), MAX_DEBUGGING_PORTS_PER_SESSION);
    assert!(!overflowed);
    let (ports, overflowed) = debugging_ports_in(&many_launches(17));
    assert_eq!(ports.len(), MAX_DEBUGGING_PORTS_PER_SESSION);
    assert!(overflowed);
}

#[test]
fn a_saturated_session_holds_every_loopback_port() {
    let home = tempfile::tempdir().unwrap();
    // The seventeenth port is not kept, so the call that names it is held on its own.
    let command = format!(
        "{} ; curl -s http://127.0.0.1:10016/json",
        many_launches(17)
    );
    let reached = run(home.path(), &bash("session-a", &command), "allow");
    assert_eq!(reached.reason_code, DEBUG_PORT_REVIEW);
    assert_eq!(reached.reason, SATURATED_REASON);

    // Later calls in the session find its store full and hold any loopback port.
    let later = run(
        home.path(),
        &bash("session-a", "curl -s http://127.0.0.1:10099/json"),
        "allow",
    );
    assert_eq!(later.reason_code, DEBUG_PORT_REVIEW);
    assert_eq!(later.reason, SATURATED_REASON);

    // Another session keeps its verdict.
    let other = run(
        home.path(),
        &bash("session-b", "curl -s http://127.0.0.1:10099/json"),
        "allow",
    );
    assert_eq!(other.minimum_action, "allow");
}

#[test]
fn driving_a_saturated_session_keeps_its_hold() {
    let home = tempfile::tempdir().unwrap();
    run(home.path(), &bash("session-a", &many_launches(17)), "allow");
    let step = BROWSER_SESSION_IDLE_SECONDS - 60;
    let mut now = NOW;
    for _ in 0..3 {
        now += step;
        let reached = apply(
            home.path(),
            HARNESS,
            &bash("session-a", "curl -s http://127.0.0.1:10016/json"),
            now,
            result("allow"),
        );
        assert_eq!(reached.reason, SATURATED_REASON);
    }
}

fn cursor_call(conversation: &str, command: &str) -> Value {
    json!({
        "conversation_id": conversation,
        "hook_event_name": "PreToolUse",
        "tool_name": "Shell",
        "tool_input": {"command": command},
    })
}

#[test]
fn cursor_sessions_are_read_from_the_conversation_id() {
    let home = tempfile::tempdir().unwrap();
    assert!(harness_session_digest("cursor", &cursor_call("conversation-a", LAUNCH)).is_some());
    // Other harnesses name their session `session_id` only.
    assert!(harness_session_digest(HARNESS, &cursor_call("conversation-a", LAUNCH)).is_none());

    let launch = apply(
        home.path(),
        "cursor",
        &cursor_call("conversation-a", LAUNCH),
        NOW,
        result("allow"),
    );
    assert_eq!(launch.minimum_action, "allow");
    let reached = apply(
        home.path(),
        "cursor",
        &cursor_call("conversation-a", READ),
        NOW,
        result("allow"),
    );
    assert_eq!(reached.reason_code, DEBUG_PORT_REVIEW);
    assert_eq!(reached.reason, DEBUG_PORT_REASON);
    let other = apply(
        home.path(),
        "cursor",
        &cursor_call("conversation-b", READ),
        NOW,
        result("allow"),
    );
    assert_eq!(other.minimum_action, "allow");
}

#[test]
fn driving_a_recorded_port_keeps_it_from_expiring() {
    let home = tempfile::tempdir().unwrap();
    run(home.path(), &bash("session-a", LAUNCH), "allow");
    let step = BROWSER_SESSION_IDLE_SECONDS - 60;
    let mut now = NOW;
    for _ in 0..3 {
        now += step;
        let reached = apply(
            home.path(),
            HARNESS,
            &bash("session-a", READ),
            now,
            result("allow"),
        );
        assert_eq!(reached.reason_code, DEBUG_PORT_REVIEW);
    }
    // Left idle past the window, the port is forgotten.
    now += BROWSER_SESSION_IDLE_SECONDS + 60;
    let idle = apply(
        home.path(),
        HARNESS,
        &bash("session-a", READ),
        now,
        result("allow"),
    );
    assert_eq!(idle.minimum_action, "allow");
}

#[test]
fn loopback_ports_are_read_from_every_local_host_form() {
    assert_eq!(loopback_port("http://127.0.0.1:9333/json"), Some(9333));
    assert_eq!(loopback_port("http://127.0.0.2:9333/"), Some(9333));
    assert_eq!(loopback_port("http://0.0.0.0:9333/"), Some(9333));
    assert_eq!(loopback_port("http://[::1]:9333/"), Some(9333));
    assert_eq!(loopback_port("http://[::ffff:127.0.0.1]:9333/"), Some(9333));
    assert_eq!(loopback_port("http://user@LOCALHOST:9333/"), Some(9333));
    assert_eq!(loopback_port("http://app.localhost/"), Some(80));
    assert_eq!(loopback_port("https://localhost/"), Some(443));
    for spelling in [
        "http://2130706433:9333/",
        "http://0x7f.0.0.1:9333/",
        "http://0x7F000001:9333/",
        "http://0177.0.0.1:9333/",
        "http://127.1:9333/",
        "http://127.0.1:9333/",
        "http://0:9333/",
    ] {
        assert_eq!(loopback_port(spelling), Some(9333), "{spelling}");
    }
    for spelling in [
        "http://2130706433.1:9333/",
        "http://0x80.0.0.1:9333/",
        "http://128.1:9333/",
        "http://08.0.0.1:9333/",
        "http://4294967296:9333/",
        "http://127.0.0.256:9333/",
        "http://127.0.0.1.1:9333/",
    ] {
        assert_eq!(loopback_port(spelling), None, "{spelling}");
    }
    assert_eq!(loopback_port("http://example.test:9333/"), None);
    assert_eq!(loopback_port("http://127.0.0.1.example.test:9333/"), None);
    assert_eq!(loopback_port("http://example.test\\@127.0.0.1:9333/"), None);
}

fn browser_navigate(session: Option<&str>, url: &str) -> Value {
    let mut payload = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "mcp__playwright__browser_navigate",
        "tool_input": {"url": url},
    });
    if let Some(session) = session {
        payload["session_id"] = json!(session);
    }
    payload
}

#[test]
fn a_tool_call_to_a_conventional_debugger_port_is_held() {
    let home = tempfile::tempdir().unwrap();
    for url in [
        "http://127.0.0.1:9222/json/version",
        "http://localhost:9229/json/list",
    ] {
        for session in [Some("session-a"), None] {
            let reached = run(home.path(), &browser_navigate(session, url), "allow");
            assert_eq!(reached.reason_code, DEBUG_PORT_REVIEW, "{url}");
            assert_eq!(reached.reason, CONVENTIONAL_PORT_REASON, "{url}");
            assert_eq!(reached.minimum_action, "review");
        }
    }
    // A dev server and a public host keep their verdict.
    for url in ["http://127.0.0.1:5173/", "https://example.test:9222/"] {
        let reached = run(
            home.path(),
            &browser_navigate(Some("session-a"), url),
            "allow",
        );
        assert_eq!(reached.minimum_action, "allow", "{url}");
    }
}

#[test]
fn a_tool_call_to_a_recorded_port_is_held() {
    let home = tempfile::tempdir().unwrap();
    run(home.path(), &bash("session-a", LAUNCH), "allow");
    let reached = run(
        home.path(),
        &browser_navigate(Some("session-a"), "http://127.0.0.1:9333/json"),
        "allow",
    );
    assert_eq!(reached.reason_code, DEBUG_PORT_REVIEW);
}
