//! The daemon's fail-closed replies agree with the Rust renderer.
//!
//! When the resident cannot render a hook response in time, the Python daemon
//! answers from `guard/contracts/hook-fail-closed-envelopes.v1.json` instead.
//! Those replies only help if each harness reads them as the same deny the
//! Rust renderer would have sent, so every PreToolUse and prompt envelope here
//! is held to the shape `pre_tool` and `prompt` give that harness. A harness
//! whose renderer moves to a new envelope fails this test until the contract
//! moves with it.

use guard_command::hook_responses::{hermes, pre_tool, prompt, Object};
use serde_json::{json, Value};

const CONTRACT: &str = include_str!(
    "../../../../src/codex_plugin_scanner/guard/contracts/hook-fail-closed-envelopes.v1.json"
);
const SCHEMA: &str = "hol-guard.hook-fail-closed-envelopes.v1";
const KINDS: [&str; 5] = ["pre_tool", "permission", "prompt", "lifecycle", "unmanaged"];
const PLACEHOLDERS: [&str; 3] = ["$reason", "$reason_code", "$event_name"];
const HARNESSES: [&str; 15] = [
    "claude-code",
    "codex",
    "cursor",
    "copilot",
    "gemini",
    "kimi",
    "devin",
    "zcode",
    "cline",
    "opencode",
    "pi",
    "omp",
    "grok",
    "hermes",
    "openclaw",
];
const REASON: &str = "Copying .env needs a fresh approval.";
const REASON_CODE: &str = "native_policy_reapproval_required";

fn contract() -> Object {
    let document: Value = serde_json::from_str(CONTRACT).expect("contract parses");
    let document = document.as_object().expect("contract is an object").clone();
    assert_eq!(document["schema"], SCHEMA);
    document
}

fn envelopes(kind: &str) -> Object {
    contract()["envelopes"][kind]
        .as_object()
        .unwrap_or_else(|| panic!("{kind} envelopes"))
        .clone()
}

fn fill(template: &Value, values: &[(&str, &str)]) -> Value {
    match template {
        Value::String(text) => values
            .iter()
            .find(|(placeholder, _)| *placeholder == text.as_str())
            .map_or_else(|| template.clone(), |(_, value)| json!(value)),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), fill(value, values)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(|item| fill(item, values)).collect()),
        _ => template.clone(),
    }
}

fn envelope(kind: &str, harness: &str, values: &[(&str, &str)]) -> Object {
    let table = envelopes(kind);
    let template = table.get(harness).unwrap_or(&table["*"]);
    fill(template, values)
        .as_object()
        .unwrap_or_else(|| panic!("{kind}/{harness} envelope is an object"))
        .clone()
}

fn strings(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::String(text) if text.starts_with('$') => found.push(text.clone()),
        Value::Object(map) => map.values().for_each(|item| strings(item, found)),
        Value::Array(items) => items.iter().for_each(|item| strings(item, found)),
        _ => {}
    }
}

#[test]
fn every_kind_has_a_default_and_only_known_placeholders() {
    for kind in KINDS {
        let table = envelopes(kind);
        assert!(table.contains_key("*"), "{kind} has no default envelope");
        for (harness, template) in &table {
            let mut found = Vec::new();
            strings(template, &mut found);
            for placeholder in found {
                assert!(
                    PLACEHOLDERS.contains(&placeholder.as_str()),
                    "{kind}/{harness} uses unknown placeholder {placeholder}"
                );
                assert!(
                    placeholder != "$event_name" || kind == "lifecycle",
                    "{kind}/{harness} names the event outside a lifecycle reply"
                );
            }
        }
    }
}

#[test]
fn every_event_maps_to_a_declared_kind() {
    let document = contract();
    for section in ["events", "event_prefixes"] {
        for (event, kind) in document[section].as_object().expect(section) {
            assert!(
                KINDS.contains(&kind.as_str().unwrap_or_default()),
                "{section}/{event} maps to an undeclared kind"
            );
        }
    }
}

#[test]
fn pre_tool_envelopes_deny_the_way_the_renderer_does() {
    let verdict: Object = serde_json::from_value(json!({
        "decision": "deny",
        "minimum_action": "block",
        "policy_action": "block",
        "reason": REASON,
        "reason_code": REASON_CODE,
    }))
    .unwrap();
    let values = [("$reason", REASON), ("$reason_code", REASON_CODE)];
    for harness in HARNESSES {
        let rendered = pre_tool(harness, &verdict);
        let fixed = envelope("pre_tool", harness, &values);
        assert_eq!(fixed["policy_action"], "block", "{harness}");
        assert_eq!(fixed["reason_code"], REASON_CODE, "{harness}");
        assert_eq!(
            hermes::policy_from_response(&fixed),
            ("block".to_owned(), REASON.to_owned()),
            "{harness} must read as a block"
        );
        if rendered.contains_key("decision") {
            assert!(
                fixed.contains_key("decision"),
                "{harness} drops the decision the renderer sends"
            );
        }
        // The fixed reply may omit renderer fields, but every field it does
        // send must carry the renderer's value.
        for (key, value) in &fixed {
            if let Some(expected) = rendered.get(key) {
                assert_eq!(value, expected, "pre_tool/{harness} {key}");
            }
        }
    }
}

#[test]
fn prompt_envelopes_keep_what_the_renderer_sends() {
    let code = "native_prompt_unavailable";
    let verdict: Object = serde_json::from_value(json!({
        "decision": "block",
        "minimum_action": "block",
        "reason": REASON,
        "reason_code": code,
    }))
    .unwrap();
    for harness in HARNESSES {
        let rendered = prompt(harness, &verdict);
        let fixed = envelope("prompt", harness, &[("$reason", REASON)]);
        for (key, value) in &fixed {
            if key == "hookSpecificOutput" {
                assert_eq!(
                    value["hookEventName"], rendered[key]["hookEventName"],
                    "prompt/{harness} hook event"
                );
            } else {
                assert_eq!(Some(value), rendered.get(key), "prompt/{harness} {key}");
            }
        }
    }
}

fn values(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::String(text) => found.push(text.to_ascii_lowercase()),
        Value::Bool(flag) => found.push(flag.to_string()),
        Value::Object(map) => map.values().for_each(|item| values(item, found)),
        Value::Array(items) => items.iter().for_each(|item| values(item, found)),
        _ => {}
    }
}

#[test]
fn permission_envelopes_always_deny() {
    let values_in = [("$reason", REASON), ("$reason_code", REASON_CODE)];
    let table = envelopes("permission");
    for harness in table.keys() {
        let fixed = envelope("permission", harness, &values_in);
        let behavior = fixed
            .get("behavior")
            .or_else(|| {
                fixed
                    .get("hookSpecificOutput")
                    .and_then(|output| output["decision"].get("behavior"))
            })
            .and_then(Value::as_str);
        let decision = fixed.get("decision").and_then(Value::as_str);
        assert!(
            behavior == Some("deny") || matches!(decision, Some("deny" | "block")),
            "permission/{harness} must deny"
        );
        assert_eq!(fixed["reason_code"], REASON_CODE, "permission/{harness}");
        let mut found = Vec::new();
        values(&Value::Object(fixed.clone()), &mut found);
        assert!(
            found.contains(&REASON.to_ascii_lowercase()),
            "permission/{harness} drops the reason"
        );
        assert!(
            !found.iter().any(|value| value == "allow"),
            "permission/{harness} allows"
        );
    }
}

#[test]
fn lifecycle_and_unmanaged_envelopes_never_stop_the_harness() {
    let values_in = [
        ("$reason", REASON),
        ("$reason_code", REASON_CODE),
        ("$event_name", "SessionStart"),
    ];
    for kind in ["lifecycle", "unmanaged"] {
        for harness in envelopes(kind).keys() {
            let mut found = Vec::new();
            values(
                &Value::Object(envelope(kind, harness, &values_in)),
                &mut found,
            );
            assert!(
                !found
                    .iter()
                    .any(|value| matches!(value.as_str(), "deny" | "block" | "ask" | "false")),
                "{kind}/{harness} stops the harness"
            );
        }
    }
}
