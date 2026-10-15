//! The view parsed once per binding answers what a fresh parse answers.

use super::*;
use serde_json::json;

fn view(mode: &str) -> Value {
    json!({
        "schema": VIEW_SCHEMA,
        "harnesses": {
            "codex": {
                "config": {"mode": mode},
                "hash_config": {"mode": mode},
                "receipt_redaction_level": "partial",
            },
            "cursor": {"config": {}, "hash_config": {}},
        },
        "extension_layers": [],
    })
}

fn bound(view: Option<Value>) -> Arc<DirectLaneBinding> {
    let mut binding = DirectLaneBinding::empty_for_tests();
    binding.mcp_relay = view;
    Arc::new(binding)
}

#[test]
fn a_bound_view_answers_as_a_fresh_parse_for_every_call() {
    let mut unlayered = view("enforce");
    unlayered["extension_layers"] = Value::Null;
    let mut renamed = view("enforce");
    renamed["schema"] = json!("guard-mcp-relay-view.v2");
    let views = [
        Some(view("enforce")),
        Some(view("observe")),
        Some(unlayered),
        Some(renamed),
        Some(json!({"schema": VIEW_SCHEMA})),
        None,
    ];
    for candidate in views {
        let binding = bound(candidate.clone());
        // Twice each, so the second read comes from the parsed binding.
        for _ in 0..2 {
            for harness in ["codex", "cursor", "copilot"] {
                assert_eq!(
                    bound_harness_view(&binding, harness),
                    harness_view(candidate.as_ref(), harness),
                    "{candidate:?} {harness}"
                );
            }
        }
    }
}

#[test]
fn a_new_binding_is_parsed_afresh() {
    let enforcing = bound(Some(view("enforce")));
    let observing = bound(Some(view("observe")));
    for _ in 0..2 {
        assert_eq!(
            bound_harness_view(&enforcing, "codex").unwrap().mode,
            "enforce"
        );
        assert_eq!(
            bound_harness_view(&observing, "codex").unwrap().mode,
            "observe"
        );
    }
    // A binding replaced after the last one was dropped is still its own.
    drop(enforcing);
    let replaced = bound(None);
    assert_eq!(bound_harness_view(&replaced, "codex"), Err(VIEW_MISSING));
}
