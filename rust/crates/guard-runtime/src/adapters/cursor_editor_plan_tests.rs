//! Replays `cursor_editor_plan_vectors.json`, recorded from the original
//! Python Cursor editor install, through the native kind.

use serde_json::{json, Value};

use crate::cursor_editor_plan::plan;
use crate::runner_authority_op::ERR_INVALID;

const VECTORS: &str = include_str!("../../testdata/cursor/cursor_editor_plan_vectors.json");
const SCHEMA: &str = "guard-cursor-editor-plan-vectors.v1";

fn request(servers: Value) -> Value {
    json!({
        "previous_origins": null,
        "observed": [],
        "managed": [],
        "servers": servers,
        "workspace": false,
    })
}

#[test]
fn replays_every_recorded_python_install() {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    assert_eq!(document["schema"], json!(SCHEMA));
    let cases = document["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 12);
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let answer = plan(&case["request"]);
        if case["expect"]["refused"] == json!(true) {
            assert_eq!(answer, Err(ERR_INVALID), "{name}");
        } else {
            assert_eq!(answer.as_ref(), Ok(&case["expect"]), "{name}");
        }
    }
}

#[test]
fn refuses_requests_with_missing_extra_or_mistyped_fields() {
    let mut missing = request(Value::Null);
    missing.as_object_mut().expect("object").remove("workspace");
    assert_eq!(plan(&missing), Err(ERR_INVALID));
    let mut extra = request(Value::Null);
    extra["op"] = json!("plan");
    assert_eq!(plan(&extra), Err(ERR_INVALID));
    let mut workspace = request(Value::Null);
    workspace["workspace"] = json!("yes");
    assert_eq!(plan(&workspace), Err(ERR_INVALID));
    let mut observed = request(Value::Null);
    observed["observed"] = json!([["a", "project"]]);
    assert_eq!(plan(&observed), Err(ERR_INVALID));
    let mut origins = request(Value::Null);
    origins["previous_origins"] = json!({"a": ["project", "p"]});
    assert_eq!(plan(&origins), Err(ERR_INVALID));
    assert_eq!(plan(&request(json!([["a", {}]]))), Err(ERR_INVALID));
    assert_eq!(plan(&request(json!([{"env": {}}]))), Err(ERR_INVALID));
    assert_eq!(plan(&json!([])), Err(ERR_INVALID));
}

#[test]
fn a_repeated_previous_origin_keeps_its_first_position_and_last_value() {
    let mut repeated = request(Value::Null);
    repeated["previous_origins"] = json!([["b", 1], ["a", 2], ["b", 3]]);
    let answer = plan(&repeated).expect("plan");
    assert_eq!(answer["origins"], json!([["b", 3], ["a", 2]]));
}

#[test]
fn guard_proxy_entries_are_named_by_their_index() {
    let servers = json!([
        {"command": "node", "args": ["server.js"]},
        {"command": "HOL-GUARD.exe", "args": ["mcp-relay", "py", "-m", "codex_plugin_scanner.cli", "guard", "mcp-proxy"]},
        {"command": "hol-guard", "args": ["guard", "cursor-mcp-proxy"]},
        null,
    ]);
    let answer = plan(&request(servers)).expect("plan");
    assert_eq!(answer["refresh"], json!([1, 2]));
    assert_eq!(answer["notes"].as_array().map(Vec::len), Some(2));
}
