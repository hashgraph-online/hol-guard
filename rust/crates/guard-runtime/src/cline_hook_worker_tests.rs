use std::fs;
use std::path::Path;

use guard_command::hook_adapter_value::{parse_python_json, OMap, OValue};

use super::{
    answer, explicitly_allows, parse_config, parse_output, py_splitlines, Config, AMBIGUOUS,
    EVALUATION_UNAVAILABLE, INVALID, INVALID_DECISION, OVERSIZED, OVERSIZED_PRETOOL,
    TRANSPORT_UNAVAILABLE, UNPARSEABLE,
};

const ALLOWED: &str = "{\"cancel\":false,\"errorMessage\":\"\",\"contextModification\":\"\"}\n";

fn config(root: &Path, event: &str, transport: Option<&str>) -> Config {
    let state = root.join("adapter-state.json");
    if let Some(transport) = transport {
        fs::write(&state, format!("{{\"active_transport\": \"{transport}\"}}")).expect("state");
    }
    let text = serde_json::json!({
        "marker": "HOL_GUARD_MANAGED_CLINE_HOOK_V1",
        "schema": "cline-hook-worker.v1",
        "event": event,
        "guard": ["guard", "hook"],
        "proof": root.join("proofs").join("native.json"),
        "adapter_state": state,
    })
    .to_string();
    parse_config(text.as_bytes()).expect("config")
}

fn map(text: &str) -> OMap {
    match parse_python_json(text) {
        Ok(OValue::Map(map)) => map,
        other => panic!("not an object: {other:?}"),
    }
}

/// Runs the worker with each review answering `decision`, and returns its
/// answer and the payloads Guard was sent.
fn run(config: &Config, input: &str, decision: Option<&str>) -> (String, Vec<String>) {
    let mut sent = Vec::new();
    let answer = answer(config, input.as_bytes(), false, &mut |argv, payload| {
        assert_eq!(argv, ["guard", "hook"]);
        sent.push(payload.to_owned());
        decision.map(|text| text.as_bytes().to_vec())
    });
    (answer, sent)
}

fn proof_outcome(root: &Path) -> Option<String> {
    let text = fs::read_to_string(root.join("proofs").join("native.json")).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    assert_eq!(value["source"], "cline");
    assert_eq!(value["schema_version"], 1);
    assert!(value["timestamp"].as_f64().is_some_and(|stamp| stamp > 0.0));
    Some(value["outcome"].as_str()?.to_owned())
}

#[test]
fn reviews_each_command_of_a_run_commands_call() {
    let root = tempfile::tempdir().expect("tempdir");
    let config = config(root.path(), "PreToolUse", Some("hooks"));
    let input = r#"{"cwd": "  /work  ", "tool_call": {"id": "call-1", "name": "run_commands",
        "input": {"commands": "[\"ls\", {\"cmd\": \"pwd\"}, \"  \", 7]"}}}"#;

    let (answer, sent) = run(&config, input, Some("{\"decision\": \"allow\"}"));

    assert_eq!(answer, ALLOWED);
    assert_eq!(
        sent,
        [
            r#"{"hookName": "PreToolUse", "hook_event_name": "PreToolUse", "tool_call": {"id": "call-1", "name": "run_command", "input": {"command": "ls"}}, "cwd": "/work"}"#,
            r#"{"hookName": "PreToolUse", "hook_event_name": "PreToolUse", "tool_call": {"id": "call-1", "name": "run_command", "input": {"command": "pwd"}}, "cwd": "/work"}"#,
        ]
    );
    assert_eq!(proof_outcome(root.path()).as_deref(), Some("allowed"));
}

#[test]
fn reads_the_legacy_call_and_forwards_other_tools_whole() {
    let root = tempfile::tempdir().expect("tempdir");
    let config = config(root.path(), "PreToolUse", Some("hooks"));
    let legacy =
        r#"{"preToolUse": {"toolName": "run_commands", "parameters": {"command": "echo \u00e9"}}}"#;
    let (_, sent) = run(&config, legacy, Some("{\"decision\": \"allow\"}"));
    assert_eq!(
        sent,
        [
            r#"{"hookName": "PreToolUse", "hook_event_name": "PreToolUse", "tool_call": {"id": "", "name": "run_command", "input": {"command": "echo \u00e9"}}}"#
        ]
    );

    let other = r#"{"tool_call":{"name":"read_files","input":{"paths":[1.5,true]}}}"#;
    let (_, sent) = run(&config, other, Some("{\"decision\": \"allow\"}"));
    assert_eq!(
        sent,
        [r#"{"tool_call": {"name": "read_files", "input": {"paths": [1.5, true]}}}"#]
    );
}

#[test]
fn a_denial_stops_the_review_and_cancels_with_its_reason() {
    let root = tempfile::tempdir().expect("tempdir");
    let config = config(root.path(), "PreToolUse", Some("hooks"));
    let input = r#"{"tool_call": {"name": "run_commands", "input": {"commands": ["a", "b"]}}}"#;

    let (answer, sent) = run(
        &config,
        input,
        Some("noise\n{\"policy_action\": \"REVIEW\", \"reason\": \"  needs review \\u00e9 \"}\n"),
    );

    assert_eq!(sent.len(), 1);
    assert_eq!(
        answer,
        "{\"cancel\":true,\"errorMessage\":\"needs review \\u00e9\",\"contextModification\":\"needs review \\u00e9\"}\n"
    );
    assert_eq!(proof_outcome(root.path()).as_deref(), Some("blocked"));
}

#[test]
fn an_unplaceable_decision_is_withheld() {
    let root = tempfile::tempdir().expect("tempdir");
    let config = config(root.path(), "PreToolUse", Some("hooks"));
    let (answer, _) = run(&config, "{}", Some("{\"policy_action\": \"quarantine\"}"));
    assert_eq!(
        answer,
        format!("{{\"cancel\":true,\"errorMessage\":\"{AMBIGUOUS}\",\"contextModification\":\"{AMBIGUOUS}\"}}\n")
    );
}

#[test]
fn a_missing_or_unreadable_review_fails_closed() {
    let root = tempfile::tempdir().expect("tempdir");
    let config = config(root.path(), "PreToolUse", Some("hooks"));
    for (decision, message) in [
        (None, EVALUATION_UNAVAILABLE),
        (Some("not json"), INVALID_DECISION),
        (Some("[1]"), INVALID_DECISION),
        (Some("{\"decision\": NaN}"), INVALID_DECISION),
    ] {
        let (answer, _) = run(&config, "{}", decision);
        assert_eq!(
            answer,
            format!("{{\"cancel\":true,\"errorMessage\":\"{message}\",\"contextModification\":\"{message}\"}}\n")
        );
    }
    assert_eq!(proof_outcome(root.path()), None);
}

#[test]
fn observer_events_never_cancel() {
    let root = tempfile::tempdir().expect("tempdir");
    let config = config(root.path(), "PostToolUse", Some("hooks"));
    let input = r#"{"tool_call": {"name": "run_commands", "input": {"commands": ["a", "b"]}}}"#;

    let (answer, sent) = run(&config, input, Some("{\"blocked\": true}"));
    assert_eq!(sent.len(), 1);
    assert_eq!(
        answer,
        "{\"cancel\":false,\"contextModification\":\"HOL Guard blocked this action.\"}\n"
    );
    assert_eq!(proof_outcome(root.path()).as_deref(), Some("observed"));

    let (answer, _) = run(&config, "[]", None);
    assert_eq!(
        answer,
        format!(
            "{{\"cancel\":false,\"errorMessage\":\"\",\"contextModification\":\"{INVALID}\"}}\n"
        )
    );
}

#[test]
fn another_transport_passes_and_an_unknown_one_fails_closed() {
    let root = tempfile::tempdir().expect("tempdir");
    let unknown = config(root.path(), "PreToolUse", None);
    let (answer, sent) = run(&unknown, "{}", None);
    assert!(sent.is_empty());
    assert_eq!(
        answer,
        format!("{{\"cancel\":true,\"errorMessage\":\"{TRANSPORT_UNAVAILABLE}\",\"contextModification\":\"{TRANSPORT_UNAVAILABLE}\"}}\n")
    );

    let plugin = config(root.path(), "PreToolUse", Some("plugin"));
    let (answer, sent) = run(&plugin, "{}", None);
    assert!(sent.is_empty());
    assert_eq!(answer, ALLOWED);
}

#[test]
fn the_canary_skips_the_transport_and_the_proof() {
    let root = tempfile::tempdir().expect("tempdir");
    let config = config(root.path(), "PreToolUse", None);
    let answer = answer(&config, b"{}", true, &mut |_, _| {
        Some(b"{\"decision\": \"allow\"}".to_vec())
    });
    assert_eq!(answer, ALLOWED);
    assert_eq!(proof_outcome(root.path()), None);
}

#[test]
fn refuses_requests_it_cannot_read_safely() {
    let root = tempfile::tempdir().expect("tempdir");
    let config = config(root.path(), "PreToolUse", Some("hooks"));
    let deep = format!("{}1{}", "[".repeat(47), "]".repeat(47));
    let deep = format!("{{\"a\": {deep}}}");
    let fits = format!("{{\"a\": {}1{}}}", "[".repeat(46), "]".repeat(46));
    let large = format!(
        "{{\"tool_call\": {{\"input\": \"{}\"}}}}",
        "x".repeat(64 * 1024)
    );
    let cases: [(&[u8], &str); 6] = [
        (&[b' '; 256 * 1024 + 1], OVERSIZED),
        (b"\xff", UNPARSEABLE),
        (b"{", UNPARSEABLE),
        (b"{\"a\": \"\\ud800\"}", INVALID),
        (deep.as_bytes(), INVALID),
        (large.as_bytes(), OVERSIZED_PRETOOL),
    ];
    for (input, message) in cases {
        let answer = answer(&config, input, false, &mut |_, _| panic!("reviewed"));
        assert_eq!(
            answer,
            format!("{{\"cancel\":true,\"errorMessage\":\"{message}\",\"contextModification\":\"{message}\"}}\n")
        );
    }
    let (answer, _) = run(&config, &fits, Some("{\"decision\": \"allow\"}"));
    assert_eq!(answer, ALLOWED);
}

#[test]
fn reads_only_its_own_config() {
    let base = serde_json::json!({
        "marker": "HOL_GUARD_MANAGED_CLINE_HOOK_V1",
        "schema": "cline-hook-worker.v1",
        "event": "PreToolUse",
        "guard": ["guard"],
        "proof": "/home/proof.json",
        "adapter_state": "/home/state.json",
    });
    assert!(parse_config(base.to_string().as_bytes()).is_some());
    for (key, value) in [
        ("marker", serde_json::json!("other")),
        ("schema", serde_json::json!("cline-hook-worker.v2")),
        ("event", serde_json::json!("Notification")),
        ("guard", serde_json::json!([])),
        ("guard", serde_json::json!([""])),
        ("proof", serde_json::json!("proof.json")),
        ("adapter_state", serde_json::json!("state.json")),
        ("extra", serde_json::json!(1)),
    ] {
        let mut config = base.clone();
        config[key] = value;
        assert!(
            parse_config(config.to_string().as_bytes()).is_none(),
            "{key}"
        );
    }
}

#[test]
fn reads_the_last_decision_line() {
    let decision =
        parse_output("log line\r\n{\"decision\": \"deny\"}\u{2028}{bad\n  ").expect("decision");
    assert_eq!(decision.get_str("decision"), Some("deny"));
    assert!(parse_output("{\"a\": 1} trailing").is_none());
    assert_eq!(py_splitlines("a\r\nb\rc\u{85}d\n"), ["a", "b", "c", "d"]);
    assert_eq!(py_splitlines("\n\nb"), ["", "", "b"]);
}

#[test]
fn allows_only_a_decision_that_says_allow_everywhere() {
    for (text, allows) in [
        (r#"{"decision": "Allow"}"#, true),
        (r#"{"policy_action": "warn"}"#, true),
        (
            r#"{"hookSpecificOutput": {"permissionDecision": "allow"}}"#,
            true,
        ),
        (
            r#"{"hookSpecificOutput": {"decision": {"behavior": "allow"}}}"#,
            true,
        ),
        (r#"{}"#, false),
        (r#"{"decision": null}"#, false),
        (r#"{"decision": "allow", "policyAction": null}"#, false),
        (r#"{"decision": "allow", "policyAction": "sandbox"}"#, false),
        (
            r#"{"decision": "allow", "hookSpecificOutput": {"permissionDecision": "defer"}}"#,
            false,
        ),
        (r#"{"decision": "allow", "continue": false}"#, false),
        (
            r#"{"policy_action": "allow", "policyAction": "require-reapproval"}"#,
            false,
        ),
    ] {
        assert_eq!(explicitly_allows(&map(text)), allows, "{text}");
    }
}

#[cfg(unix)]
#[test]
fn review_reads_the_answer_of_a_real_process() {
    let argv = |script: &str| ["/bin/sh", "-c", script].map(str::to_owned);
    let answer = super::review(
        &argv("read line; printf '%s' \"$line\"; exit 3"),
        "{\"a\": 1}\n",
    );
    assert_eq!(answer.as_deref(), Some(b"{\"a\": 1}".as_slice()));
    assert_eq!(super::review(&argv("exit 0"), "x"), Some(Vec::new()));
    assert_eq!(super::review(&["/nonexistent/guard".to_owned()], "x"), None);
}
