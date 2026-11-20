//! Replays the Grok user-config vectors recorded from the original tomlkit
//! merge (see `testdata/grok/record_grok_user_config_vectors.py`). Merged
//! text, ownership state and error messages come from Python, never from Rust
//! output. Documents in a layout the byte-exact editor handles must match
//! byte for byte; the rest are merged by the semantic editor and must parse
//! to the same document with the same state.

use serde_json::{json, Value};
use toml::Table;

use crate::grok_user_config::{
    FOREIGN_HOOK_COMPAT_VENDORS, GROK_PRETOOL_HOOK_TIMEOUT_SECONDS, MANAGED_DENY_RULES,
    OBSERVE_HOOK_EVENTS, OBSERVE_HOOK_TIMEOUT_SECONDS,
};
use crate::runner_authority_op::{dispatch, KindResult, ERR_INVALID};

const VECTORS: &str = include_str!("../../../testdata/grok/user_config_vectors.json");
const INVALID_TOML: &str = "Grok config is not valid TOML.";

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn call(args: &Value) -> KindResult {
    dispatch("grok_user_config", args)
}

fn read(case: &Value, mode: &str) -> Value {
    json!({
        "existing_text": case["existing_text"],
        "mode": mode,
        "previous_state": case["previous_state"],
    })
}

fn merge(case: &Value, retired: &[Value]) -> Value {
    json!({
        "existing_text": case["existing_text"],
        "hook_command": case["hook_command"],
        "mode": "merge",
        "previous_state": case["previous_state"],
        "retired_commands": retired,
    })
}

fn same_text(exact: bool, got: &Value, want: &Value) -> bool {
    if exact {
        return got == want;
    }
    match (got.as_str(), want.as_str()) {
        (Some(left), Some(right)) => matches!(
            (left.parse::<Table>(), right.parse::<Table>()),
            (Ok(a), Ok(b)) if a == b
        ),
        _ => false,
    }
}

/// Every owned hook the merge asked the Python side about, then the merge
/// with the ones that side reported missing retired.
fn replay(case: &Value) -> Result<(), String> {
    let exact = case["layout"] == "exact";
    let expect = &case["expect"];
    if case["op"] == "remove" {
        let got = call(&read(case, "remove"))?;
        return if same_text(exact, &got["text"], &expect["text"]) {
            Ok(())
        } else {
            Err(format!("removed text differs: {got}"))
        };
    }
    let wanted_error = expect["error"].as_str().map(|text| {
        if text == "invalid_toml" {
            INVALID_TOML
        } else {
            text
        }
    });
    if wanted_error != Some(INVALID_TOML) {
        let asked = call(&read(case, "candidates"))?;
        if asked["commands"] != case["candidates"] {
            return Err(format!("candidates differ: {asked}"));
        }
    }
    let missing = case["missing"].as_array().cloned().unwrap_or_default();
    let retired: Vec<Value> = case["candidates"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|command| missing.contains(command))
        .cloned()
        .collect();
    let got = call(&merge(case, &retired))?;
    if let Some(message) = wanted_error {
        return if got == json!({ "error": message }) {
            Ok(())
        } else {
            Err(format!("expected error {message:?}, got {got}"))
        };
    }
    if !same_text(exact, &got["merged"], &expect["merged"]) {
        return Err(format!("merged text differs: {}", got["merged"]));
    }
    if got["state"] != expect["state"] {
        return Err(format!("state differs: {}", got["state"]));
    }
    Ok(())
}

#[test]
fn vectors_replay_exactly() {
    let document = vectors();
    let cases = document["cases"].as_array().unwrap();
    assert!(cases.len() > 300);
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|case| {
            let name = case["name"].as_str().unwrap_or("?");
            replay(case).err().map(|why| format!("{name}: {why}"))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} cases differ:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

#[test]
fn exact_and_semantic_layouts_are_both_covered() {
    let document = vectors();
    let layouts: Vec<&str> = document["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|case| case["layout"].as_str())
        .collect();
    assert!(layouts.iter().filter(|layout| **layout == "exact").count() > 200);
    assert!(
        layouts
            .iter()
            .filter(|layout| **layout == "semantic")
            .count()
            > 40
    );
}

#[test]
fn constants_match_the_recorded_python_values() {
    let document = vectors();
    let constants = &document["constants"];
    assert_eq!(constants["managed_deny_rules"], json!(MANAGED_DENY_RULES));
    assert_eq!(
        constants["compat_vendors"],
        json!(FOREIGN_HOOK_COMPAT_VENDORS)
    );
    assert_eq!(constants["observe_events"], json!(OBSERVE_HOOK_EVENTS));
    assert_eq!(
        constants["observe_timeout"],
        json!(OBSERVE_HOOK_TIMEOUT_SECONDS)
    );
    assert_eq!(
        constants["pretool_timeout"],
        json!(GROK_PRETOOL_HOOK_TIMEOUT_SECONDS)
    );
}

#[test]
fn merge_reports_a_rejected_document_as_an_error_answer() {
    let args = json!({
        "existing_text": "permission = 1\n",
        "hook_command": "guard hook",
        "mode": "merge",
        "previous_state": {},
        "retired_commands": [],
    });
    assert_eq!(
        call(&args),
        Ok(json!({ "error": "Grok permission must be a TOML table." }))
    );
}

#[test]
fn a_byte_order_mark_is_not_valid_toml() {
    let args =
        json!({ "existing_text": "\u{feff}[ui]\n", "mode": "candidates", "previous_state": {} });
    assert_eq!(call(&args), Ok(json!({ "error": INVALID_TOML })));
}

#[test]
fn malformed_requests_are_refused() {
    let refused = [
        json!("remove"),
        json!({}),
        json!({ "existing_text": "", "mode": "other", "previous_state": {} }),
        json!({ "existing_text": "", "mode": "remove" }),
        json!({ "existing_text": "", "previous_state": {} }),
        json!({ "mode": "remove", "previous_state": {} }),
        json!({ "existing_text": 1, "mode": "remove", "previous_state": {} }),
        json!({ "existing_text": "", "mode": 1, "previous_state": {} }),
        json!({ "existing_text": "", "mode": "remove", "previous_state": [] }),
        json!({ "existing_text": "", "mode": "candidates", "previous_state": null }),
        json!({ "existing_text": "", "mode": "remove", "previous_state": {}, "extra": true }),
        json!({ "existing_text": "", "mode": "remove", "previous_state": {}, "hook_command": "guard hook" }),
        json!({ "existing_text": "", "mode": "candidates", "previous_state": {}, "retired_commands": [] }),
        json!({ "existing_text": "", "mode": "merge", "previous_state": {}, "hook_command": "guard hook" }),
        json!({ "existing_text": "", "mode": "merge", "previous_state": {}, "retired_commands": [] }),
        json!({ "existing_text": "", "mode": "merge", "previous_state": {}, "hook_command": 1, "retired_commands": [] }),
        json!({ "existing_text": "", "mode": "merge", "previous_state": {}, "hook_command": "c", "retired_commands": "c" }),
        json!({ "existing_text": "", "mode": "merge", "previous_state": {}, "hook_command": "c", "retired_commands": ["c", 1] }),
        json!({ "existing_text": "", "mode": "merge", "previous_state": [], "hook_command": "c", "retired_commands": [] }),
    ];
    for args in &refused {
        assert_eq!(call(args), Err(ERR_INVALID), "{args}");
    }
    let valid = json!({
        "existing_text": "",
        "hook_command": "guard hook",
        "mode": "merge",
        "previous_state": {},
        "retired_commands": [],
    });
    assert!(call(&valid).is_ok());
}
