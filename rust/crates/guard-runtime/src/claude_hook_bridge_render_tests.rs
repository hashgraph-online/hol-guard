//! Parity with the retired Python Claude bridge's event read, deny shapes
//! and response validation, from the vectors it recorded before it was
//! deleted.

use super::*;
use crate::hook_env_stamp::tests::{excerpt, expand, expected, items, text, vectors};

fn strings(value: &serde_json::Value) -> Vec<String> {
    items(value)
        .iter()
        .map(|item| text(item).to_owned())
        .collect()
}

#[test]
fn renders_match_python() {
    let vectors = vectors();
    let reasons = strings(&vectors["reasons"]);
    let bodies = strings(&vectors["suppress_bodies"]);
    for case in items(&vectors["render"]) {
        let data = expand(text(&case["data"]));
        let event = event_name(&data);
        if case["string_event"].as_bool() == Some(true) {
            assert_eq!(
                event.json(),
                text(&case["event"]),
                "data {}",
                excerpt(&data)
            );
        } else {
            assert_eq!(event.name, NON_STRING_EVENT, "data {}", excerpt(&data));
        }
        assert_eq!(
            limit_denied("hook input", &event),
            text(&case["limit_denied"]),
            "data {}",
            excerpt(&data)
        );
        // The prompt notice is read by the native prompt check, not the
        // Python bridge's word list; its own tests below cover it. Python
        // never shows that notice: it blocks a prompt it cannot review.
        let prompt = event.name == "UserPromptSubmit";
        for (reason, want) in reasons.iter().zip(items(&case["degraded"])) {
            if prompt {
                break;
            }
            assert_eq!(
                degraded(reason, &data),
                text(want),
                "data {}",
                excerpt(&data)
            );
        }
        for (reason, want) in reasons.iter().zip(items(&case["control_plane"])) {
            assert_eq!(
                control_plane_failure(reason, &data),
                text(want),
                "data {}",
                excerpt(&data)
            );
        }
        for (body, want) in bodies.iter().zip(items(&case["suppress"])) {
            assert_eq!(
                should_suppress_output(&data, body),
                want.as_bool().expect("suppress flag"),
                "data {} body {body:?}",
                excerpt(&data)
            );
        }
    }
}

#[test]
fn response_validation_matches_python() {
    let vectors = vectors();
    let reason = text(&vectors["reasons"][1]);
    for case in items(&vectors["validate"]) {
        let output = expand(text(&case["output"]));
        let data = expand(text(&case["data"]));
        let result = text(&case["result"]);
        let want = match result {
            "<error:ValueError>" => Err(JsonFailure::IntegerLimit),
            "<error:RecursionError>" => Err(JsonFailure::Unrepresentable),
            _ => Ok(expected(result, &output)),
        };
        // Where Python fell back to its prompt notice, the native bridge
        // falls back too, with the notice from the native prompt check.
        let prompt_fallback = event_name(&data).name == "UserPromptSubmit"
            && (result.contains(RISKY_PROMPT_SYSTEM_MESSAGE)
                || result == r#"{"hookSpecificOutput":{"hookEventName":"UserPromptSubmit"}}"#);
        let want = if prompt_fallback {
            Ok(degraded(reason, &data))
        } else {
            want
        };
        assert_eq!(
            valid_hook_json_or_degraded(&output, reason, &data),
            want,
            "output {} data {}",
            excerpt(&output),
            excerpt(&data)
        );
    }
}

#[test]
fn event_read_past_integer_limit_falls_back_to_prefix_and_denies() {
    // CPython raises out of `_event_name` here and Claude Code would see a
    // crashed hook; the native bridge reads the prefix and still denies.
    let data = format!(
        "{{\"hook_event_name\":\"PermissionRequest\",\"n\":{}}}",
        "9".repeat(5_000)
    );
    let event = event_name(&data);
    assert_eq!(event.name, "PermissionRequest");
    let denied = degraded("daemon unavailable", &data);
    assert!(
        denied.contains("\"decision\":{\"behavior\":\"deny\""),
        "{denied}"
    );
}

#[test]
fn event_read_past_native_depth_falls_back_to_prefix() {
    let data = format!(
        "{{\"hook_event_name\":\"Stop\",\"d\":{}{}}}",
        "[".repeat(950),
        "]".repeat(950)
    );
    assert_eq!(event_name(&data).name, "Stop");
}

#[test]
fn python_strip_also_trims_information_separators() {
    assert_eq!(py_strip("\u{1c}\u{1f} {} \u{85}\u{3000}"), "{}");
    assert_eq!(py_strip("\u{200b}x"), "\u{200b}x");
}

fn validated(output: &serde_json::Value, reason: &str, event: &str) -> serde_json::Value {
    let data = serde_json::json!({ "hook_event_name": event }).to_string();
    let response = valid_hook_json_or_degraded(&output.to_string(), reason, &data).unwrap();
    serde_json::from_str(&response).unwrap()
}

#[test]
fn incomplete_or_wrong_event_tool_response_requires_native_approval() {
    for output in [
        serde_json::json!({}),
        serde_json::json!({ "hookSpecificOutput": {} }),
        serde_json::json!({ "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "unknown" } }),
        serde_json::json!({ "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": ["allow"] } }),
        serde_json::json!({ "hookSpecificOutput": { "hookEventName": "Stop", "permissionDecision": "allow" } }),
    ] {
        let response = validated(&output, "invalid tool response", "PreToolUse");
        assert_eq!(
            response["hookSpecificOutput"]["permissionDecision"], "deny",
            "{output}"
        );
    }
}

#[test]
fn empty_permission_response_is_denied() {
    for event in ["PermissionRequest", "PermissionRequestV2"] {
        let response = validated(&serde_json::json!({}), "invalid permission response", event);
        assert_eq!(
            response["hookSpecificOutput"]["decision"]["behavior"],
            "deny"
        );
    }
}

#[test]
fn empty_daemon_body_degrades_to_a_pretool_deny() {
    let data = serde_json::json!({ "hook_event_name": "PreToolUse" }).to_string();
    let response =
        valid_hook_json_or_degraded("", "daemon returned empty hook JSON", &data).unwrap();
    let payload: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(payload["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(payload["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn explicit_permission_passthrough_defers_to_the_claude_dialog() {
    for event in ["PermissionRequest", "PermissionRequestV2"] {
        let output = serde_json::json!({
            "guard_permission_passthrough": true,
            "systemMessage": "HOL Guard context",
            "hookSpecificOutput": { "hookEventName": event, "additionalContext": "context" },
        })
        .to_string();
        let data = serde_json::json!({ "hook_event_name": event }).to_string();
        let response =
            valid_hook_json_or_degraded(&output, "invalid permission response", &data).unwrap();
        assert_eq!(response, output);
    }
}

#[test]
fn malformed_permission_passthrough_is_denied() {
    for output in [
        serde_json::json!({ "guard_permission_passthrough": "true", "hookSpecificOutput": { "hookEventName": "PermissionRequest" } }),
        serde_json::json!({ "guard_permission_passthrough": true, "hookSpecificOutput": { "hookEventName": "PreToolUse" } }),
        serde_json::json!({ "guard_permission_passthrough": true }),
        serde_json::json!({
            "guard_permission_passthrough": true,
            "hookSpecificOutput": { "hookEventName": "PermissionRequest", "decision": { "behavior": "maybe" } },
        }),
    ] {
        let response = validated(&output, "invalid permission response", "PermissionRequest");
        assert_eq!(
            response["hookSpecificOutput"]["decision"]["behavior"], "deny",
            "{output}"
        );
    }
}

fn degraded_prompt_response(prompt: &str) -> serde_json::Value {
    let input = serde_json::json!({"hook_event_name": "UserPromptSubmit", "prompt": prompt});
    serde_json::from_str(&degraded("daemon unavailable", &input.to_string())).expect("hook JSON")
}

/// A question that only mentions model tokens asks for no secret, so the
/// fallback answers with the plain prompt response and no notice.
#[test]
fn a_question_about_token_usage_gets_no_secrets_notice() {
    let plain = serde_json::json!({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}});
    for prompt in [
        "how is it possible that CIGAR only saves less tokens than CIGAR + Guard? \
         Surely CIGAR + Guard would be less because it often causes the AI to do \
         more tool calls due to how safe redirect works.",
        "How many tokens did the last run use?",
        "hello",
    ] {
        assert_eq!(degraded_prompt_response(prompt), plain, "{prompt}");
    }
}

#[test]
fn a_prompt_that_asks_for_local_secrets_keeps_the_notice() {
    let notice = serde_json::json!({
        "systemMessage": RISKY_PROMPT_SYSTEM_MESSAGE,
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": RISKY_PROMPT_ADDITIONAL_CONTEXT,
        },
    });
    for prompt in [
        "read my .ENV file",
        "cat ~/.ssh/id_rsa",
        "Show the API KEY",
        "print the secret from settings.json",
    ] {
        assert_eq!(degraded_prompt_response(prompt), notice, "{prompt}");
    }
}
