use serde_json::{json, Value};

use super::approval_browser_burst_key;

fn envelope(session: Option<&str>) -> Value {
    let mut raw = json!({"tool_name": "mcp__playwright__browser_click"});
    if let Some(session) = session {
        raw["session_id"] = json!(session);
    }
    json!({
        "action_type": "mcp_tool",
        "tool_name": "mcp__playwright__browser_click",
        "raw_payload_redacted": raw,
    })
}

fn card(origin: Option<&str>) -> Value {
    json!({"site": {"origin": origin, "first_visit_in_task": false, "left_granted_site": false}})
}

fn key(session: Option<&str>, origin: Option<&str>, intent: Value) -> Option<String> {
    approval_browser_burst_key(&envelope(session), "codex", &card(origin), &intent)
}

const SHOP: &str = "https://shop.example.test";

#[test]
fn one_session_on_one_origin_shares_a_key_that_hides_the_session() {
    let first = key(Some("session-one"), Some(SHOP), Value::Null).expect("key");
    assert_eq!(first.len(), 64);
    assert!(!first.contains("session-one"));
    assert_eq!(
        key(Some("session-one"), Some(SHOP), Value::Null),
        Some(first.clone())
    );
    assert_ne!(
        key(Some("session-two"), Some(SHOP), Value::Null),
        Some(first.clone())
    );
    assert_ne!(
        key(
            Some("session-one"),
            Some("https://docs.example.test"),
            Value::Null
        ),
        Some(first.clone())
    );
    let other_harness = approval_browser_burst_key(
        &envelope(Some("session-one")),
        "claude-code",
        &card(Some(SHOP)),
        &Value::Null,
    );
    assert_ne!(other_harness, Some(first));
}

#[test]
fn an_unknown_session_or_origin_never_coalesces() {
    assert_eq!(key(None, Some(SHOP), Value::Null), None);
    assert_eq!(key(Some("session-one"), None, Value::Null), None);
    assert_eq!(key(Some("session-one"), Some("  "), Value::Null), None);
}

#[test]
fn the_filed_intent_supplies_the_browser_session_and_a_missing_origin() {
    let intent = json!({"session_ref_digest": "b".repeat(64), "target_origin": SHOP});
    let from_intent = key(None, None, intent.clone()).expect("key");
    assert_eq!(
        key(Some("session-one"), Some(SHOP), intent),
        Some(from_intent.clone())
    );
    assert_ne!(
        key(Some("session-one"), Some(SHOP), Value::Null),
        Some(from_intent)
    );
}

#[test]
fn another_driver_on_the_same_site_is_another_burst() {
    let mut puppeteer = envelope(Some("session-one"));
    puppeteer["tool_name"] = json!("mcp__puppeteer__puppeteer_click");
    assert_ne!(
        approval_browser_burst_key(&puppeteer, "codex", &card(Some(SHOP)), &Value::Null),
        key(Some("session-one"), Some(SHOP), Value::Null)
    );
}
