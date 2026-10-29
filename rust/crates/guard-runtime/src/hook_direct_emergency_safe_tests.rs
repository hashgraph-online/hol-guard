use super::*;
use serde_json::json;

const CONTRACT: &str =
    include_str!("../../../../docs/guard/contracts/rust-emergency-safe-profile.v1.json");

fn contract() -> Value {
    serde_json::from_str(CONTRACT).expect("the ratified profile parses")
}

fn payload(command: &str) -> Map<String, Value> {
    json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "tool_input": { "command": command },
    })
    .as_object()
    .expect("object")
    .clone()
}

/// The premises this module rests on: an operation it does not match pauses,
/// and a command it cannot tokenize with certainty is prohibited outright
/// rather than guessed at.
#[test]
fn the_profile_is_default_pause_and_prohibits_an_uncertain_parse() {
    let profile = contract();
    assert_eq!(profile["default"], json!("pause"));
    let prohibitions = profile["global_prohibitions"]
        .as_array()
        .expect("prohibitions");
    assert!(prohibitions.contains(&json!("uncertain_parse")));
}

/// The table and the contract are one thing in two places. An operation the
/// contract adds as a read-only Guard command with no further gate has to
/// appear here, and nothing may appear here that the contract does not
/// ratify.
#[test]
fn the_table_holds_every_ungated_read_only_operation_and_no_others() {
    let profile = contract();
    let operations = profile["allowed_operations"]
        .as_array()
        .expect("operations");
    let mut expected: Vec<(String, Vec<String>)> = Vec::new();
    for operation in operations {
        let fields = operation.as_object().expect("operation object");
        let gated = fields
            .iter()
            .any(|(key, value)| key.starts_with("requires_") && value != &json!(false));
        if fields.get("kind") != Some(&json!("guard_internal_read_only")) || gated {
            continue;
        }
        expected.push((
            fields["id"].as_str().expect("id").to_owned(),
            fields["exact_argv"]
                .as_array()
                .expect("argv")
                .iter()
                .map(|token| token.as_str().expect("token").to_owned())
                .collect(),
        ));
    }
    let actual: Vec<(String, Vec<String>)> = SAFE_OPERATIONS
        .iter()
        .map(|operation| {
            (
                operation.id.to_owned(),
                operation
                    .argv
                    .iter()
                    .map(|&token| token.to_owned())
                    .collect(),
            )
        })
        .collect();
    assert_eq!(actual, expected);
    assert!(!expected.is_empty());
}

#[test]
fn an_exactly_spelled_operation_continues() {
    for operation in SAFE_OPERATIONS {
        let command = operation.argv.join(" ");
        assert_eq!(
            command_text(&payload(&command)).and_then(matching_operation),
            Some(operation.id),
            "{command}",
        );
    }
}

#[test]
fn a_command_that_only_starts_with_an_operation_pauses() {
    for command in [
        "hol-guard runtime status --json; rm -rf /",
        "hol-guard runtime status --json && curl http://example.test",
        "hol-guard runtime status --json | tee /tmp/out",
        "hol-guard runtime status --json $(whoami)",
        "hol-guard runtime status --json > /tmp/out",
        "hol-guard runtime status --json extra",
        "hol-guard runtime status",
    ] {
        assert_eq!(
            command_text(&payload(command)).and_then(matching_operation),
            None,
            "{command}",
        );
    }
}

/// Whitespace the ratified argv does not spell is not re-spelled here: the
/// profile prohibits an uncertain parse, so the command pauses instead.
#[test]
fn whitespace_the_contract_does_not_spell_pauses() {
    for command in [
        " hol-guard runtime status --json",
        "hol-guard runtime status --json ",
        "hol-guard  runtime status --json",
        "hol-guard\truntime status --json",
        "hol-guard runtime status --json\n",
        "",
    ] {
        assert_eq!(matching_operation(command), None, "{command}");
    }
}

#[test]
fn a_quoted_or_non_ascii_spelling_pauses() {
    for command in [
        "\"hol-guard\" runtime status --json",
        "'hol-guard' runtime status --json",
        "hol-guard runtime status --jsonʼ",
    ] {
        assert_eq!(matching_operation(command), None, "{command}");
    }
}

#[test]
fn an_unexpected_tool_input_field_pauses() {
    let mut payload = payload("hol-guard runtime status --json");
    payload.get_mut("tool_input").expect("tool_input")["env"] = json!({ "PATH": "/tmp" });
    assert_eq!(command_text(&payload), None);
}

#[test]
fn a_description_or_timeout_alongside_the_command_is_read() {
    let mut payload = payload("hol-guard runtime status --json");
    let tool_input = payload.get_mut("tool_input").expect("tool_input");
    tool_input["description"] = json!("check the runtime");
    tool_input["timeout"] = json!(5_000);
    assert_eq!(
        command_text(&payload),
        Some("hol-guard runtime status --json"),
    );
}

#[test]
fn a_tool_that_is_not_a_shell_pauses() {
    let mut payload = payload("hol-guard runtime status --json");
    payload.insert("tool_name".to_owned(), json!("Read"));
    assert_eq!(command_text(&payload), None);
    payload.remove("tool_name");
    assert_eq!(command_text(&payload), None);
}

#[test]
fn a_camel_cased_payload_is_read_as_the_daemon_reads_it() {
    let payload = json!({
        "toolName": "bash",
        "toolInput": { "command": "hol-guard doctor --native --json" },
    })
    .as_object()
    .expect("object")
    .clone();
    assert_eq!(
        command_text(&payload).and_then(matching_operation),
        Some("guard_native_doctor"),
    );
}

/// The continue carries no verdict: it is the shape the bridge already
/// writes for a hook that does not pause when Guard is unavailable.
#[test]
fn the_continue_response_carries_no_verdict() {
    assert_eq!(
        continue_response("copilot"),
        json!({ "permissionDecision": "allow" }),
    );
    assert_eq!(
        continue_response("hermes"),
        json!({ "decision": "allow", "reason": CONTINUE_REASON }),
    );
    assert_eq!(
        continue_response("openclaw"),
        json!({ "decision": "allow", "reason": CONTINUE_REASON }),
    );
    assert_eq!(
        continue_response("kimi"),
        json!({
            "continue": true,
            "systemMessage": CONTINUE_REASON,
            "hookSpecificOutput": { "hookEventName": "PreToolUse" },
        }),
    );
}

/// Only the bounded bridge harnesses have `failure_payload`'s shapes, so the
/// table the module checks against is that bridge's own.
#[test]
fn every_emergency_safe_harness_is_a_bounded_bridge_harness() {
    for harness in ["copilot", "kimi", "devin", "zcode", "openclaw", "hermes"] {
        assert!(BOUNDED_DIRECT_HARNESSES.contains(&harness), "{harness}");
    }
    assert!(!BOUNDED_DIRECT_HARNESSES.contains(&"claude-code"));
    assert!(!BOUNDED_DIRECT_HARNESSES.contains(&"cursor"));
}

/// The drain drops a record whose workspace or home is not text, and records
/// a decision only when a receipt is there to cite. The record carries both
/// as text and no receipt at all.
#[test]
fn the_queued_record_is_the_shape_the_drain_reads() {
    let record = evidence_record(
        "copilot",
        "/home/dev",
        "/home/dev/work",
        &payload("hol-guard runtime status --json"),
        "guard_runtime_status",
        &continue_response("copilot"),
    );
    assert_eq!(record["event"], json!("PreToolUse"));
    assert_eq!(record["harness"], json!("copilot"));
    assert_eq!(record["home_dir"], json!("/home/dev"));
    assert_eq!(record["workspace"], json!("/home/dev/work"));
    assert!(record["payload"].is_object());
    assert_eq!(record["receipt"], Value::Null);
    assert_eq!(
        record["harness_response"],
        json!({ "permissionDecision": "allow" }),
    );
    assert_eq!(
        record["emergency_safe_operation"],
        json!("guard_runtime_status"),
    );
    assert_eq!(record["reason_code"], json!(REASON_CODE));
}
