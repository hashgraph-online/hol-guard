use super::*;
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
    assert_eq!(debugging_ports_in(LAUNCH), vec![9333]);
    assert_eq!(
        debugging_ports_in("chrome --remote-debugging-port 9444 --remote-debugging-port=\"9555\""),
        vec![9444, 9555]
    );
    assert_eq!(
        debugging_ports_in("firefox -start-debugger-server 6080"),
        vec![6080]
    );
    assert_eq!(
        debugging_ports_in("chrome --remote-debugging-port=0"),
        Vec::<u16>::new()
    );
    assert_eq!(
        debugging_ports_in("chrome --remote-debugging-pipe"),
        Vec::<u16>::new()
    );
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
    assert_eq!(loopback_port("http://example.test:9333/"), None);
    assert_eq!(loopback_port("http://127.0.0.1.example.test:9333/"), None);
    assert_eq!(loopback_port("http://example.test\\@127.0.0.1:9333/"), None);
}
