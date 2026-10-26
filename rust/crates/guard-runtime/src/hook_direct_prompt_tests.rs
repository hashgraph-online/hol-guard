use super::{drain, lane, post_edge, prompt_payload, run, run_as, HOME};
use crate::hook_direct::{prompt_answer, HookDirectDefer};
use serde_json::{json, Value};

#[test]
fn a_prompt_answer_needs_its_receipt() {
    let reviewed = |receipt: Value| {
        serde_json::to_vec(&json!({
            "schema": "guard-hook-edge-result.v2",
            "event_name": "UserPromptSubmit",
            "result": { "decision": "block", "minimum_action": "block" },
            "harness_response": {},
            "receipt": receipt,
        }))
        .unwrap()
    };
    assert!(prompt_answer(&reviewed(json!({ "decision_id": "d" })), false).is_ok());
    assert_eq!(
        prompt_answer(&reviewed(Value::Null), false),
        Err(HookDirectDefer::EdgeFailed)
    );
    assert_eq!(
        prompt_answer(&post_edge(json!({})), false),
        Err(HookDirectDefer::EdgeFailed)
    );
}

#[test]
fn only_a_prompt_the_daemon_restyles_carries_its_notice() {
    let reviewed = |action: &str| {
        serde_json::to_vec(&json!({
            "schema": "guard-hook-edge-result.v2",
            "event_name": "UserPromptSubmit",
            "result": {
                "decision": "block",
                "minimum_action": action,
                "reason": "Synthetic prompt reason",
            },
            "harness_response": { "hookSpecificOutput": { "hookEventName": "UserPromptSubmit" } },
            "receipt": { "decision_id": "d" },
        }))
        .unwrap()
    };
    for action in ["require-reapproval", "block", "sandbox-required"] {
        let noticed = prompt_answer(&reviewed(action), true).unwrap();
        assert!(
            noticed["harness_response"]["systemMessage"].is_string(),
            "{action}: {noticed}"
        );
        let plain = prompt_answer(&reviewed(action), false).unwrap();
        assert!(
            plain["harness_response"].get("systemMessage").is_none(),
            "{action}"
        );
    }
    let briefed = prompt_answer(&reviewed("require-reapproval"), true).unwrap();
    assert!(briefed["harness_response"]["hookSpecificOutput"]["additionalContext"].is_string());
    for action in ["allow", "warn", "review", ""] {
        let answered = prompt_answer(&reviewed(action), true).unwrap();
        assert!(
            answered["harness_response"].get("systemMessage").is_none(),
            "{action}"
        );
    }
}

#[test]
fn a_codex_prompt_is_answered_in_either_posture() {
    for (label, extra) in [
        ("prompt", json!({})),
        (
            "prompt-watch",
            json!({ "harness_postures": { "codex": "watch" } }),
        ),
        ("prompt-rules", json!({ "local_cli_block_rules": true })),
    ] {
        let reviewed = lane(label, extra);
        let result = run(&reviewed, prompt_payload(&reviewed));
        assert_eq!(result["outcome"], "answer", "{label}: {result}");
        assert_eq!(result["edge"]["event_name"], "UserPromptSubmit", "{label}");
        let page = drain(&reviewed, None);
        let record = &page["records"][0];
        assert_eq!(record["event"], "UserPromptSubmit", "{label}");
        assert_eq!(record["receipt"], result["edge"]["receipt"], "{label}");
    }
}

/// The Grok bridge asks with the time left stamped as the daemon receives
/// it, before the daemon's readiness check.
#[test]
fn a_grok_prompt_the_bridge_prepared_is_answered_in_either_posture() {
    for (label, extra) in [
        ("grok-prompt", json!({})),
        (
            "grok-prompt-watch",
            json!({ "harness_postures": { "grok": "watch" } }),
        ),
    ] {
        let reviewed = lane(label, extra);
        let mut payload = prompt_payload(&reviewed);
        payload["guard_remaining_ms"] = json!(4_000);
        let result = run_as(&reviewed, "grok", Some(HOME), payload);
        assert_eq!(result["outcome"], "answer", "{label}: {result}");
        assert_eq!(result["edge"]["event_name"], "UserPromptSubmit", "{label}");
        let page = drain(&reviewed, None);
        let record = &page["records"][0];
        assert_eq!(record["harness"], "grok", "{label}");
        assert_eq!(record["event"], "UserPromptSubmit", "{label}");
        assert_eq!(record["receipt"], result["edge"]["receipt"], "{label}");
        assert_eq!(
            record["harness_response"], result["edge"]["harness_response"],
            "{label}"
        );
    }
}

#[test]
fn a_claude_code_prompt_without_a_notice_is_answered_in_either_posture() {
    for (label, extra) in [
        ("prompt-claude", json!({})),
        (
            "prompt-claude-watch",
            json!({ "harness_postures": { "claude-code": "watch" } }),
        ),
    ] {
        let reviewed = lane(label, extra);
        let result = run_as(&reviewed, "claude-code", None, prompt_payload(&reviewed));
        assert_eq!(result["outcome"], "answer", "{label}: {result}");
        let page = drain(&reviewed, None);
        assert_eq!(page["records"][0]["harness"], "claude-code", "{label}");
    }
}
