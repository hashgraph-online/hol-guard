//! Replays `codex_host_inventory_vectors.json`, recorded from the original
//! Python reply validation, through the native kind, and pins the list bounds
//! too large to record.

use serde_json::{json, Value};

use crate::codex_host_inventory::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const VECTORS: &str =
    include_str!("../testdata/codex_host_inventory/codex_host_inventory_vectors.json");
const SCHEMA: &str = "guard-codex-host-inventory-vectors.v1";

fn installed(apps: Value) -> Value {
    dispatch(&json!({ "installed": { "apps": apps } })).expect("installed")
}

fn page(ids: &[&str]) -> Value {
    let apps: Vec<Value> = ids
        .iter()
        .map(|id| json!({"id": id, "enabled": true, "callable": false}))
        .collect();
    installed(Value::Array(apps))["apps"].clone()
}

fn read(ids: &[&str], result: Value) -> Value {
    dispatch(&json!({ "page": page(ids), "read": result })).expect("read")
}

#[test]
fn replays_every_recorded_python_reply() {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    assert_eq!(document["schema"], json!(SCHEMA));
    let cases = document["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 165);
    for case in cases {
        let name = case["name"].as_str().expect("name");
        assert_eq!(
            dispatch(&case["request"]).as_ref(),
            Ok(&case["expect"]),
            "{name}"
        );
    }
}

#[test]
fn installed_apps_are_bounded() {
    let apps = |count: usize| -> Value {
        (0..count)
            .map(|index| json!({"id": format!("app_{index}"), "enabled": true, "callable": true}))
            .collect()
    };
    let answer = installed(apps(1000));
    assert_eq!(answer["apps"].as_array().map(Vec::len), Some(1000));
    assert_eq!(answer["apps"][999]["app_id"], json!("app_999"));
    assert_eq!(installed(apps(1001)), json!({"error": "codex_host_limit"}));
}

#[test]
fn tool_summaries_are_bounded_per_app() {
    let tools = |count: usize| -> Value {
        (0..count)
            .map(|index| json!({"name": format!("tool_{index}")}))
            .collect()
    };
    let reply = |count: usize| {
        json!({
            "apps": [{"id": "example", "name": "Example", "toolSummaries": tools(count)}],
            "missingAppIds": [],
        })
    };
    let answer = read(&["example"], reply(10_000));
    assert_eq!(answer["complete"], json!(true));
    assert_eq!(
        answer["apps"][0]["tools"].as_array().map(Vec::len),
        Some(10_000)
    );
    assert_eq!(
        read(&["example"], reply(10_001)),
        json!({"error": "codex_host_limit"})
    );
}

#[test]
fn identifiers_are_not_normalized_into_another_connection() {
    for value in [" example", "example\n", "example tool", "\u{0}example"] {
        let answer = installed(json!([{"id": value, "enabled": true, "callable": true}]));
        assert_eq!(answer, json!({"error": "codex_host_invalid"}), "{value:?}");
    }
}

#[test]
fn empty_display_descriptions_are_valid_but_annotations_are_not_authority() {
    let answer = read(
        &["example"],
        json!({
            "apps": [{
                "id": "example",
                "name": "Example",
                "tools": [{"name": "delete", "description": "", "isReadOnly": true, "isEnabled": true}],
            }],
            "missingAppIds": [],
        }),
    );
    assert_eq!(answer["complete"], json!(true));
    assert_eq!(
        answer["apps"][0]["tools"],
        json!([{"name": "delete", "title": null, "description": null}])
    );
    assert_eq!(answer["apps"][0]["callable"], json!(false));
}

#[test]
fn long_display_text_is_cut_by_characters() {
    let answer = read(
        &["example"],
        json!({
            "apps": [{
                "id": "example",
                "name": "Example",
                "toolSummaries": [{"name": "a", "title": "\u{e9}".repeat(700), "description": "d".repeat(9030)}],
            }],
            "missingAppIds": [],
        }),
    );
    let tool = &answer["apps"][0]["tools"][0];
    assert_eq!(
        tool["title"].as_str().map(|text| text.chars().count()),
        Some(512)
    );
    assert_eq!(tool["description"].as_str().map(str::len), Some(4000));
}

#[test]
fn refuses_malformed_requests() {
    let row = json!({"app_id": "example", "name": "example", "enabled": true, "callable": true, "tools": [], "metadata_available": false});
    let reply = json!({"apps": [], "missingAppIds": ["example"]});
    for request in [
        json!([]),
        json!({}),
        json!({"installed": []}),
        json!({"installed": {}, "page": []}),
        json!({"page": [row.clone()]}),
        json!({"page": [row.clone()], "read": []}),
        json!({"page": {"example": row.clone()}, "read": reply.clone()}),
        json!({"page": ["example"], "read": reply.clone()}),
        json!({"page": [{"app_id": 1}], "read": reply.clone()}),
        json!({"page": [row.clone(), row.clone()], "read": reply.clone()}),
        json!({"page": [row.clone()], "read": reply.clone(), "op": "read"}),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
    let answer = dispatch(&json!({"page": [row], "read": reply})).expect("read");
    assert_eq!(answer["complete"], json!(false));
}
