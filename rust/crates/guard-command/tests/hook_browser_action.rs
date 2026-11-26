//! BP-T025: harness built-in browser tools produce a `BrowserActionV2` through the driver matcher,
//! and the envelope keeps its `network_request` label as the fallback.

use std::path::Path;

use guard_command::browser_action_project::{BrowserProjection, BrowserUnclassifiedReason};
use guard_command::browser_first_party_drivers::{
    COMPUTER_USE_DRIVER_ID, HARNESS_BUILTINS_DRIVER_ID,
};
use guard_command::hook_adapter_browser::hook_browser_action;
use guard_command::hook_adapter_envelope::{
    normalize_harness_envelope, EnvelopeRequest, IntentSummary,
};
use guard_command::hook_adapter_paths::PathEnv;
use guard_command::hook_adapter_value::{parse_python_json, OMap, OValue};
use guard_contracts::{BrowserIntentV1, BrowserVerbV1};
use serde_json::{json, Value};

fn payload_map(payload: &Value) -> OMap {
    parse_python_json(&payload.to_string())
        .expect("payload json")
        .as_map()
        .expect("payload map")
        .clone()
}

fn request<'a>(harness: &'a str, payload: &'a OMap) -> EnvelopeRequest<'a> {
    EnvelopeRequest {
        harness,
        event_name: "PreToolUse",
        payload,
        workspace: Some("/srv/project"),
        home_dir: Some("/home/user"),
        devin_project_dir: None,
        env: PathEnv::default(),
    }
}

/// A hook payload in the harness's own shape.
fn payload(harness: &str, tool: &str, input: &Value) -> OMap {
    if harness == "cline" {
        let parameters: serde_json::Map<String, Value> = input
            .as_object()
            .expect("input object")
            .iter()
            .map(|(key, value)| {
                let text = match value {
                    Value::String(text) => text.clone(),
                    other => other.to_string(),
                };
                (key.clone(), Value::String(text))
            })
            .collect();
        return payload_map(&json!({
            "clineVersion": "",
            "hookName": "tool_call",
            "timestamp": "2026-01-01T00:00:00Z",
            "taskId": "t1",
            "workspaceRoots": ["/srv/project"],
            "tool_call": {"id": "c1", "name": tool, "input": input},
            "preToolUse": {"toolName": tool, "parameters": parameters},
        }));
    }
    payload_map(&json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": input,
    }))
}

fn projection(harness: &str, tool: &str, input: Value) -> Option<BrowserProjection> {
    let payload = payload(harness, tool, &input);
    hook_browser_action(&request(harness, &payload)).expect("payload prepares")
}

fn action_type(harness: &str, tool: &str, input: Value) -> String {
    let payload = payload(harness, tool, &input);
    let mut provider =
        |_: &str, _: Option<&Path>, _: Option<&Path>| -> Option<IntentSummary> { None };
    normalize_harness_envelope(&request(harness, &payload), &mut provider)
        .expect("envelope")
        .get("action_type")
        .and_then(OValue::as_str)
        .expect("action_type")
        .to_owned()
}

#[test]
fn harness_built_in_browser_tools_project_a_browser_action() {
    for harness in ["cline", "cursor"] {
        for (tool, input, verb, intent) in [
            (
                "browser_action",
                json!({"action": "launch", "url": "https://example.com/docs"}),
                BrowserVerbV1::Navigate,
                BrowserIntentV1::Navigation,
            ),
            (
                "browser_action",
                json!({"action": "click", "coordinate": "120,40"}),
                BrowserVerbV1::Click,
                BrowserIntentV1::Interact,
            ),
            (
                "browser_action",
                json!({"action": "type", "text": "hello"}),
                BrowserVerbV1::Type,
                BrowserIntentV1::Interact,
            ),
            (
                "browser_action",
                json!({"action": "scroll_down"}),
                BrowserVerbV1::Scroll,
                BrowserIntentV1::Inspect,
            ),
            (
                "open_url",
                json!({"url": "https://example.com/"}),
                BrowserVerbV1::Navigate,
                BrowserIntentV1::Navigation,
            ),
            (
                "visit_url",
                json!({"url": "https://example.com/"}),
                BrowserVerbV1::Navigate,
                BrowserIntentV1::Navigation,
            ),
            (
                "browser",
                json!({"action": "open", "targetUrl": "https://example.com/"}),
                BrowserVerbV1::Navigate,
                BrowserIntentV1::Navigation,
            ),
            (
                "browser",
                json!({"action": "act", "request": {"kind": "click", "ref": "e1"}}),
                BrowserVerbV1::Other,
                BrowserIntentV1::Privileged,
            ),
        ] {
            let label = format!("{harness} {tool} {input}");
            let Some(BrowserProjection::Classified(action)) =
                projection(harness, tool, input.clone())
            else {
                panic!("{label} is classified");
            };
            assert_eq!(action.driver.id, HARNESS_BUILTINS_DRIVER_ID, "{label}");
            assert_eq!(action.verb, verb, "{label}");
            assert_eq!(action.intent, intent, "{label}");
            assert_eq!(
                action_type(harness, tool, input),
                "network_request",
                "{label}: the envelope keeps its network fallback"
            );
        }
    }
}

#[test]
fn a_navigation_carries_its_target_origin() {
    for harness in ["cline", "cursor"] {
        let Some(BrowserProjection::Classified(action)) = projection(
            harness,
            "browser_action",
            json!({"action": "launch", "url": "https://example.com/docs?q=1"}),
        ) else {
            panic!("{harness} launch is classified");
        };
        assert_eq!(
            action.target.origin.as_deref(),
            Some("https://example.com"),
            "{harness}"
        );
    }
}

#[test]
fn an_unlisted_action_keeps_only_the_network_fallback() {
    for harness in ["cline", "cursor"] {
        let projected = projection(harness, "browser_action", json!({"action": "zoom"}));
        assert!(
            matches!(
                projected,
                Some(BrowserProjection::Unclassified {
                    reason: BrowserUnclassifiedReason::CaseNotListed,
                    ..
                })
            ),
            "{harness}: {projected:?}"
        );
        assert_eq!(
            action_type(harness, "browser_action", json!({"action": "zoom"})),
            "network_request"
        );
    }
}

#[test]
fn a_network_tool_no_profile_names_has_no_browser_action() {
    for harness in ["cline", "cursor"] {
        assert_eq!(
            projection(harness, "web_fetch", json!({"url": "https://example.com/"})),
            None,
            "{harness}"
        );
        assert_eq!(
            action_type(harness, "web_fetch", json!({"url": "https://example.com/"})),
            "network_request"
        );
    }
}

#[test]
fn a_harness_computer_tool_matches_the_computer_use_profile() {
    let Some(BrowserProjection::Classified(action)) = projection(
        "claude-code",
        "computer",
        json!({"action": "left_click", "coordinate": [10, 10]}),
    ) else {
        panic!("computer left_click is classified");
    };
    assert_eq!(action.driver.id, COMPUTER_USE_DRIVER_ID);
    assert_eq!(action.verb, BrowserVerbV1::Click);
}

#[test]
fn a_tool_no_profile_names_has_no_browser_action() {
    assert_eq!(
        projection("cursor", "read_file", json!({"path": "README.md"})),
        None
    );
}

#[test]
fn a_cline_mcp_browser_call_keeps_its_server_identity() {
    let Some(BrowserProjection::Classified(action)) = projection(
        "cline",
        "use_mcp_tool",
        json!({
            "server_name": "playwright",
            "tool_name": "browser_navigate",
            "arguments": {"url": "https://example.com/"},
        }),
    ) else {
        panic!("a Cline Playwright navigate is classified");
    };
    assert_eq!(action.driver.id, "browser.playwright-mcp");
    assert_eq!(action.verb, BrowserVerbV1::Navigate);
    assert_eq!(action.target.origin.as_deref(), Some("https://example.com"));
}
