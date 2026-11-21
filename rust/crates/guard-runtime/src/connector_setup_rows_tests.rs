use serde_json::{json, Value};

use super::dispatch;

fn rows(items: Value) -> Vec<Value> {
    let answer = dispatch(&json!({ "items": items })).expect("answer");
    answer["rows"].as_array().expect("rows").clone()
}

#[test]
fn a_listed_connector_becomes_one_row() {
    let found = rows(json!([{
        "cli_id": "local-cli.mcp-1",
        "name": "docs",
        "display_name": "Docs server",
        "surface": "mcp",
        "state": "allowed",
        "source_label": "Claude Code",
        "remote_origin": "",
        "declared_sources": ["claude", 3, "cursor"],
        "mcp_catalog": {"complete": true, "changes": {"added": [], "changed": []}},
    }]));
    assert_eq!(
        found,
        vec![json!({
            "cli_id": "local-cli.mcp-1",
            "name": "Docs server",
            "surface": "mcp",
            "state": "allowed",
            "source_label": "Claude Code",
            "remote_origin": null,
            "needs_setup": false,
            "declared_sources": ["claude", "cursor"],
        })]
    );
}

#[test]
fn an_unset_connector_is_shown_only_when_it_can_be_suggested() {
    let found = rows(json!([
        {"cli_id": "a", "name": "a", "surface": "cli", "state": "unset"},
        {"cli_id": "b", "name": "b", "surface": "cli", "state": "unset", "suggestable": true},
        {"cli_id": "c", "name": "c", "surface": "skill", "state": "unset", "suggestable": true},
        {"cli_id": "d", "name": "d", "surface": "skill"},
    ]));
    let ids: Vec<_> = found.iter().map(|row| row["cli_id"].clone()).collect();
    assert_eq!(ids, vec![json!("b"), json!("d")]);
    assert_eq!(found[0]["needs_setup"], json!(true));
    assert_eq!(found[1]["state"], json!("unset"));
    assert_eq!(found[1]["needs_setup"], json!(false));
}

#[test]
fn a_changed_or_incomplete_catalog_needs_setup() {
    let item = |catalog: Value| json!({"cli_id": "x", "name": "x", "surface": "mcp", "state": "allowed", "mcp_catalog": catalog});
    let needs = |catalog: Value| rows(json!([item(catalog)]))[0]["needs_setup"].clone();
    assert_eq!(needs(json!({"stale": true})), json!(true));
    assert_eq!(needs(json!({"complete": false})), json!(true));
    assert_eq!(needs(json!({"changes": {"added": ["t"]}})), json!(true));
    assert_eq!(needs(json!({"changes": {"changed": 1}})), json!(true));
    assert_eq!(
        needs(json!({"changes": {"added": "", "changed": {}}})),
        json!(false)
    );
    assert_eq!(needs(json!({"stale": "yes", "complete": 0})), json!(false));
    assert_eq!(needs(json!(["not", "a", "catalog"])), json!(false));
    let stale =
        json!([{"cli_id": "x", "name": "x", "surface": "cli", "state": "allowed", "stale": true}]);
    assert_eq!(rows(stale)[0]["needs_setup"], json!(true));
}

#[test]
fn a_connector_without_text_identity_has_no_row() {
    let found = rows(json!([
        {"name": "x", "surface": "mcp", "state": "allowed"},
        {"cli_id": "y", "display_name": 5, "name": "y", "surface": "mcp", "state": "allowed"},
        {"cli_id": "z", "display_name": "", "name": "zed", "surface": "mcp", "state": 7},
    ]));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["name"], json!("zed"));
    assert_eq!(found[0]["state"], json!("unset"));
}

#[test]
fn a_malformed_request_is_refused() {
    assert!(dispatch(&json!([])).is_err());
    assert!(dispatch(&json!({})).is_err());
    assert!(dispatch(&json!({"items": {}})).is_err());
    assert!(dispatch(&json!({"items": [1]})).is_err());
    assert!(dispatch(&json!({"items": [], "extra": 1})).is_err());
}
