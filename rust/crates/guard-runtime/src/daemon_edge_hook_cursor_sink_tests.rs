use serde_json::{json, Map, Value};

use super::{names_sink, params};

fn payload(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(payload) => payload,
        _ => unreachable!(),
    }
}

fn sink_call(command: &str) -> Map<String, Value> {
    payload(json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Shell",
        "cursor_source_hook_event": "beforeShellExecution",
        "tool_input": {"command": command},
    }))
}

#[test]
fn only_a_cursor_before_shell_call_naming_a_sink_is_admitted_here() {
    let sink = sink_call("guard execute-contained-test --run abc");
    let native = sink_call("hol-guard contained-workspace-sink --run abc");
    assert_eq!(names_sink("cursor", "PreToolUse", &sink), !cfg!(windows));
    assert_eq!(names_sink("cursor", "PreToolUse", &native), !cfg!(windows));
    assert!(!names_sink("claude-code", "PreToolUse", &sink));
    assert!(!names_sink("cursor", "PostToolUse", &sink));
    assert!(!names_sink("cursor", "PreToolUse", &sink_call("ls -la")));
}

#[test]
fn a_probe_or_receipt_only_call_keeps_the_library_route() {
    let mut probe = sink_call("guard execute-contained-test");
    probe.remove("cursor_source_hook_event");
    probe.insert("cursor_route_probe".into(), Value::Bool(true));
    assert!(!names_sink("cursor", "PreToolUse", &probe));

    let mut other_source = sink_call("guard execute-contained-test");
    other_source.insert("cursor_source_hook_event".into(), json!("preToolUse"));
    assert!(!names_sink("cursor", "PreToolUse", &other_source));

    let mut receipt = sink_call("guard execute-contained-test");
    receipt.insert("guard_containment_receipt_only".into(), json!({"id": "r"}));
    assert!(!names_sink("cursor", "PreToolUse", &receipt));
    receipt.insert("guard_containment_receipt_only".into(), Value::Null);
    assert_eq!(names_sink("cursor", "PreToolUse", &receipt), !cfg!(windows));
}

#[test]
fn params_carry_the_sink_prefix_and_an_unstamped_caller() {
    let call = sink_call("guard execute-contained-test");
    let prefix = json!(["/usr/bin/python3", "-I", "-c", "boot"]);
    let built = params(&call, "/w", "/h", "/g", &prefix);
    assert_eq!(built["workspace"], "/w");
    assert_eq!(built["home_dir"], "/h");
    assert_eq!(built["guard_home"], "/g");
    assert_eq!(built["sink_command"], prefix);
    assert_eq!(built["native_sink"], true);
    assert_eq!(built["payload"]["guard_execution_environment"], Value::Null);
    assert_eq!(
        built["payload"]["tool_input"]["command"],
        "guard execute-contained-test"
    );

    let mut stamped = call.clone();
    stamped.insert(
        "guard_execution_environment".into(),
        json!({"pager": "less"}),
    );
    let built = params(&stamped, "/w", "/h", "/g", &prefix);
    assert_eq!(
        built["payload"]["guard_execution_environment"]["pager"],
        "less"
    );
}

#[test]
fn a_command_the_probe_never_wrote_is_not_admitted() {
    let built = params(
        &sink_call("guard execute-contained-test --run unknown"),
        "/nonexistent-workspace",
        "/nonexistent-home",
        "/nonexistent-guard",
        &json!(["/usr/bin/python3", "-I", "-c", "boot"]),
    );
    let answer = crate::hook_direct::cursor::daemon_answer(&built)
        .ok()
        .flatten();
    assert!(answer.is_none());
}
