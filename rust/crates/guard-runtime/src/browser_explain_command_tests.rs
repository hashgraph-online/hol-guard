use serde_json::{json, Value};

use super::run_command;

const PLAYWRIGHT: &str = "browser.playwright-mcp";

fn explain(request: Value) -> Value {
    run_command(&serde_json::to_vec(&request).unwrap())
}

#[test]
fn a_read_only_tool_is_classified_allowed_and_grant_eligible() {
    let answer = explain(json!({"driver": PLAYWRIGHT, "tool": "browser_snapshot"}));
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert_eq!(answer["driver"]["server"], json!("playwright"));
    assert_eq!(answer["action"]["operation"], json!("browser_snapshot"));
    assert_eq!(answer["action"]["intent"], json!("browser.inspect"));
    assert_eq!(answer["unclassified"], Value::Null);
    // The default `warn` action shows a notice and never stops the call.
    assert_eq!(answer["decision"]["action"], json!("warn"), "{answer}");
    assert_eq!(answer["grant"]["eligible"], json!(true));
    assert_eq!(answer["grant"]["category"], json!("browser_inspection"));
}

#[test]
fn script_evaluation_is_stopped_and_never_grant_eligible() {
    let answer = explain(json!({
        "driver": PLAYWRIGHT,
        "tool": "browser_evaluate",
        "arguments": {"function": "() => document.cookie"},
    }));
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert_eq!(answer["action"]["operation"], json!("browser_evaluate"));
    let action = answer["decision"]["action"].as_str().unwrap();
    assert!(!matches!(action, "allow" | "warn"), "{answer}");
    assert_eq!(answer["grant"]["eligible"], json!(false));
}

#[test]
fn a_tool_the_profile_does_not_list_is_unclassified() {
    let answer = explain(json!({"driver": PLAYWRIGHT, "tool": "browser_teleport"}));
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert_eq!(answer["action"], Value::Null);
    assert_eq!(answer["unclassified"], json!("tool_not_listed"));
    assert_eq!(answer["grant"]["eligible"], json!(false));
}

#[test]
fn an_unknown_driver_is_refused_with_the_shipped_ids() {
    let answer = explain(json!({"driver": "browser.example-pilot", "tool": "open"}));
    assert_eq!(answer["ok"], json!(false));
    assert_eq!(answer["error"]["code"], json!("driver_unknown"));
    let known = answer["drivers"].as_array().unwrap();
    assert!(known.contains(&json!(PLAYWRIGHT)), "{answer}");
}

#[test]
fn malformed_requests_are_refused() {
    for (request, code) in [
        (
            json!({"driver": PLAYWRIGHT, "tool": "browser_snapshot", "arguments": [1]}),
            "arguments_invalid",
        ),
        (json!({"driver": PLAYWRIGHT, "tool": "  "}), "tool_missing"),
        (
            json!({"driver": PLAYWRIGHT, "tool": "browser_snapshot", "extra": 1}),
            "request_invalid",
        ),
    ] {
        let answer = explain(request);
        assert_eq!(answer["ok"], json!(false));
        assert_eq!(answer["error"]["code"], json!(code), "{answer}");
    }
    assert_eq!(
        run_command(b"not json")["error"]["code"],
        json!("request_invalid")
    );
}
