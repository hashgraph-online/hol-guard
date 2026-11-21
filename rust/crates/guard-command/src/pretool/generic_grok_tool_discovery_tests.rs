//! Grok's `search_tool` sent the way Grok's hook sends it: snake-case fields
//! with camel-case copies.

use serde_json::{json, Value};

const REASON: &str = "native_grok_tool_discovery";

fn decide(
    harness: &str,
    tool: &str,
    input: Value,
    copy: Value,
    truncated: bool,
) -> (String, String) {
    let home = std::env::temp_dir();
    let payload = json!({
        "hook_event_name": "PreToolUse",
        "hookEventName": "PreToolUse",
        "tool_name": tool,
        "toolName": tool,
        "tool_input": input,
        "toolInput": copy,
        "toolInputTruncated": truncated,
    });
    let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &payload,
        None,
        None,
        home.to_str(),
        home.to_str(),
    );
    (result.minimum_action, result.reason_code)
}

fn grok(input: Value) -> (String, String) {
    decide("grok", "search_tool", input.clone(), input, false)
}

#[test]
fn grok_searches_its_integration_tools_without_review() {
    for input in [
        json!({"query": "x_ads get campaign line item ads analytics", "limit": 15}),
        json!({"query": "read file contents", "limit": 5}),
        json!({"query": "hol guard approvals"}),
        json!({"query": "aws secrets manager", "limit": 0}),
    ] {
        assert_eq!(
            grok(input.clone()),
            ("allow".to_owned(), REASON.to_owned()),
            "{input}"
        );
    }
}

#[test]
fn any_other_shape_keeps_its_review() {
    for input in [
        json!({"query": "config", "path": "/etc"}),
        json!({"query": "status", "command": "rm -rf build"}),
        json!({"query": "status", "limit": "all"}),
        json!({"query": "status", "limit": -1}),
        json!({"query": "status", "limit": 1.5}),
        json!({"query": "   "}),
        json!({"query": 7}),
        json!({"limit": 5}),
        json!({"query": "x".repeat(4_097)}),
    ] {
        assert_ne!(grok(input.clone()).1, REASON, "{input}");
    }
    let input = json!({"query": "x_ads"});
    // A copy that disagrees with the input, or an input Grok cut short.
    let other = json!({"query": "x_ads", "path": "/etc"});
    assert_ne!(
        decide("grok", "search_tool", input.clone(), other, false).1,
        REASON
    );
    assert_ne!(
        decide("grok", "search_tool", input.clone(), input.clone(), true).1,
        REASON
    );
    // Another harness's tool of the same name, and Grok's `use_tool`.
    assert_ne!(
        decide(
            "claude-code",
            "search_tool",
            input.clone(),
            input.clone(),
            false
        )
        .1,
        REASON
    );
    assert_ne!(
        decide("grok", "use_tool", input.clone(), input, false).1,
        REASON
    );
}
