use serde_json::{json, Value};

/// The card with no provider cache.
fn approval_browser_card(envelope: &Value, harness: &str) -> Option<Value> {
    super::approval_browser_card(envelope, harness, &|_| Vec::new())
}

fn hook_envelope(tool: &str, input: Value) -> Value {
    json!({
        "action_type": "mcp_tool",
        "tool_name": format!("mcp__playwright__{tool}"),
        "raw_payload_redacted": {"tool_name": format!("mcp__playwright__{tool}"), "tool_input": input},
    })
}

#[test]
fn a_listed_navigation_gets_a_card_that_names_the_site() {
    let card = approval_browser_card(
        &hook_envelope(
            "browser_navigate",
            json!({"url": "https://shop.example.test/cart"}),
        ),
        "claude-code",
    )
    .expect("card");
    assert_eq!(
        card["headline"],
        "Claude Code wants to open shop.example.test"
    );
    assert_eq!(card["verb"], "navigate");
    assert_eq!(card["site"]["origin"], "https://shop.example.test");
    assert_eq!(card["profile_line"], "unknown");
    assert_eq!(
        card["choices"],
        json!(["allow_once", "always_allow", "deny"])
    );
}

#[test]
fn typed_text_reaches_the_card_only_as_its_kind_and_length() {
    let card = approval_browser_card(
        &hook_envelope(
            "browser_type",
            json!({"element": "Search box", "text": "blue shoes", "ref": "e12"}),
        ),
        "codex",
    )
    .expect("card");
    assert_eq!(
        card["headline"],
        "Codex wants to type into a form in the browser"
    );
    assert_eq!(card["detail"]["element_preview"], "Search box");
    assert_eq!(card["detail"]["input_kind"], "text");
    assert_eq!(card["detail"]["input_length"], 10);
    assert_eq!(card["detail"]["input_masked"], false);
    assert!(!card.to_string().contains("blue shoes"));
}

#[test]
fn a_redacted_value_is_masked_and_names_no_length() {
    let card = approval_browser_card(
        &hook_envelope(
            "browser_type",
            json!({"element": "Account code", "text": "[redacted]"}),
        ),
        "claude-code",
    )
    .expect("card");
    assert_eq!(card["detail"]["input_masked"], true);
    assert_eq!(card["detail"]["input_length"], Value::Null);
}

#[test]
fn an_asterisk_mask_or_a_cut_short_value_names_no_length() {
    let long = format!("{}\u{2026}", "a".repeat(239));
    for text in [
        "*****",
        "sk-*****",
        "Bearer *****",
        "HLG-******",
        long.as_str(),
    ] {
        let card = approval_browser_card(
            &hook_envelope(
                "browser_type",
                json!({"element": "Account code", "text": text}),
            ),
            "claude-code",
        )
        .expect("card");
        assert_eq!(card["detail"]["input_masked"], true, "{text}");
        assert_eq!(card["detail"]["input_length"], Value::Null, "{text}");
    }
}

#[test]
fn server_and_tool_fields_and_json_text_input_are_read() {
    let envelope = json!({
        "action_type": "mcp_tool",
        "mcp_server": "playwright",
        "mcp_tool": "browser_navigate",
        "raw_payload_redacted": {"arguments": "{\"url\":\"http://localhost:4173/\"}"},
    });
    let card = approval_browser_card(&envelope, "cursor").expect("card");
    assert_eq!(card["headline"], "Cursor wants to open localhost:4173");
}

#[test]
fn calls_no_profile_classifies_have_no_card() {
    assert!(approval_browser_card(
        &hook_envelope("browser_not_a_listed_tool", json!({})),
        "claude-code"
    )
    .is_none());
    let unrelated = json!({
        "action_type": "mcp_tool",
        "tool_name": "mcp__example-notes__create_note",
        "raw_payload_redacted": {"tool_input": {"title": "x"}},
    });
    assert!(approval_browser_card(&unrelated, "claude-code").is_none());
    assert!(approval_browser_card(&json!({"action_type": "shell"}), "claude-code").is_none());
    assert!(approval_browser_card(&Value::Null, "claude-code").is_none());
}

#[test]
fn an_unknown_harness_is_named_generically() {
    let card = approval_browser_card(
        &hook_envelope("browser_take_screenshot", json!({})),
        "example-harness",
    )
    .expect("card");
    assert_eq!(
        card["headline"],
        "The agent wants to take a screenshot in the browser"
    );
}
