use serde_json::{json, Value};

use super::*;

const TWO: [&str; 4] = ["cursor", "devin", "kimi", "hermes"];
const ONE: [&str; 2] = ["opencode", "superagent"];
const ENVELOPE: [&str; 6] = ["codex", "claude-code", "copilot", "pi", "omp", "muse"];
const ACTIONS: [&str; 6] = [
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
];
const EVENTS: [Option<&str>; 5] = [
    Some("PreToolUse"),
    Some("UserPromptSubmit"),
    Some("PermissionRequest"),
    Some("PostToolUse"),
    None,
];
const UNKNOWN: [&str; 6] = ["quarantine-required", "", "BLOCK", "ask ", "deny", "0"];

fn ask(harness: &str, action: Value, event: Option<&str>, recording_only: bool) -> i32 {
    let request = json!({
        "harness": harness,
        "policy_action": action,
        "event_name": event,
        "recording_only": recording_only,
    });
    let answer = run_command(request.to_string().as_bytes()).expect("an answer");
    let answer: Value = serde_json::from_slice(&answer).expect("json");
    i32::try_from(answer["exit_code"].as_i64().expect("a code")).expect("an i32")
}

fn code(harness: &str, action: &str, event: Option<&str>) -> i32 {
    ask(harness, json!(action), event, false)
}

fn blocks(action: &str) -> bool {
    matches!(
        action,
        "review" | "require-reapproval" | "sandbox-required" | "block"
    )
}

#[test]
fn the_table_every_shared_harness_follows() {
    let preemptive = ["PreToolUse", "UserPromptSubmit", "PermissionRequest"];
    let others = ["unknown-harness", "some-future-harness"];
    for harness in TWO.iter().chain(&ONE).chain(&ENVELOPE).chain(&others) {
        for action in ACTIONS {
            for event in EVENTS {
                let blocked = blocks(action);
                let expected = if TWO.contains(harness) {
                    if blocked {
                        2
                    } else {
                        0
                    }
                } else if ENVELOPE.contains(harness) {
                    i32::from(blocked && !event.is_some_and(|e| preemptive.contains(&e)))
                } else {
                    i32::from(blocked)
                };
                assert_eq!(
                    code(harness, action, event),
                    expected,
                    "{harness}/{action}/{event:?}"
                );
            }
        }
    }
}

#[test]
fn an_unknown_action_takes_the_review_tier_in_every_harness() {
    for action in UNKNOWN {
        for harness in TWO
            .iter()
            .chain(&ONE)
            .chain(&ENVELOPE)
            .chain(&["grok", "zcode"])
        {
            for event in [Some("PreToolUse"), Some("PostToolUse")] {
                assert_eq!(
                    code(harness, action, event),
                    code(harness, "review", event),
                    "{harness}/{action:?}/{event:?}"
                );
            }
        }
        for harness in TWO.iter().chain(&["grok"]) {
            assert_eq!(code(harness, action, Some("PreToolUse")), 2);
        }
        for harness in ONE.iter().chain(&["some-future-harness"]) {
            assert_eq!(code(harness, action, Some("PostToolUse")), 1);
        }
        for harness in ENVELOPE {
            assert_eq!(code(harness, action, Some("PreToolUse")), 0);
            assert_eq!(code(harness, action, Some("PostToolUse")), 1);
        }
        assert_eq!(code("zcode", action, Some("PreToolUse")), 0);
        assert_eq!(code("zcode", action, Some("PostToolUse")), 2);
    }
}

#[test]
fn a_non_string_action_never_reads_as_allow() {
    let values = [
        Value::Null,
        json!(7),
        json!({"policy_action": "allow"}),
        json!(["allow"]),
    ];
    for harness in [
        "cursor",
        "opencode",
        "codex",
        "grok",
        "zcode",
        "some-future-harness",
    ] {
        for value in &values {
            assert_eq!(
                ask(harness, value.clone(), Some("PostToolUse"), false),
                code(harness, "review", Some("PostToolUse")),
                "{harness}/{value}"
            );
        }
    }
}

#[test]
fn the_legacy_ask_alias_resolves_to_review() {
    for harness in ["cursor", "opencode", "codex", "grok", "zcode"] {
        for event in [Some("PreToolUse"), Some("PostToolUse")] {
            assert_eq!(
                code(harness, "ask", event),
                code(harness, "review", event),
                "{harness}/{event:?}"
            );
        }
    }
}

#[test]
fn grok_blocks_with_two_unless_the_guard_home_records_protection_off() {
    for action in ["review", "require-reapproval", "sandbox-required", "block"] {
        assert_eq!(code("grok", action, None), 2, "{action}");
        assert_eq!(ask("grok", json!(action), None, true), 0, "{action}");
    }
    assert_eq!(code("grok", "allow", None), 0);
    assert_eq!(code("grok", "warn", None), 0);
    assert_eq!(ask("grok", json!("block"), Some("PostToolUse"), false), 2);
}

#[test]
fn a_review_tier_zcode_pre_tool_use_exits_zero_so_zcode_opens_its_prompt() {
    for event in ["PreToolUse", "pre_tool_use", "pre-tool-use"] {
        for action in ["review", "require-reapproval"] {
            assert_eq!(code("zcode", action, Some(event)), 0, "{action}/{event}");
        }
        for action in ["block", "sandbox-required"] {
            assert_eq!(code("zcode", action, Some(event)), 2, "{action}/{event}");
        }
        assert_eq!(code("zcode", "allow", Some(event)), 0);
    }
    for action in ["review", "block"] {
        assert_eq!(code("zcode", action, Some("UserPromptSubmit")), 2);
    }
    // No event names the default, PreToolUse.
    assert_eq!(code("zcode", "review", None), 0);
}

#[test]
fn the_muse_envelope_table() {
    assert_eq!(code("muse", "block", Some("PreToolUse")), 0);
    assert_eq!(code("muse", "block", Some("UserPromptSubmit")), 0);
    assert_eq!(code("muse", "block", Some("PostToolUse")), 1);
    assert_eq!(code("muse", "allow", Some("PreToolUse")), 0);
}

#[test]
fn a_malformed_request_is_refused() {
    assert_eq!(
        run_command(&b"{}"[..]).unwrap_err(),
        "hook_exit_code_request_invalid"
    );
    let huge = vec![b' '; 20 * 1024];
    assert_eq!(
        run_command(huge.as_slice()).unwrap_err(),
        "hook_exit_code_request_too_large"
    );
}
