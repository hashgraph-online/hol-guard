use serde_json::{json, Value};

use crate::browser_driver_builder_command::run_command;

fn run(request: Value) -> Value {
    run_command(&serde_json::to_vec(&request).unwrap())
}

fn drafted() -> Value {
    let document = json!({
        "tools": [
            {"name": "page_navigate", "inputSchema": {"properties": {"url": {}}}},
            {"name": "page_click", "inputSchema": {"properties": {"element": {}, "ref": {}}}},
            {"name": "run_script", "inputSchema": {"properties": {"expression": {}}}},
            {"name": "frobnicate"},
        ]
    });
    let result = run(json!({
        "op": "generate",
        "slug": "example-pilot",
        "server": "example-pilot",
        "document": document.to_string(),
    }));
    assert_eq!(result["ok"], true, "{result}");
    result
}

fn validate(result: &Value, rows: &Value) -> Value {
    run(json!({
        "op": "validate",
        "profile": result["profileText"],
        "gateRows": rows.to_string(),
    }))
}

fn row<'a>(rows: &'a [Value], id: &str) -> &'a Value {
    rows.iter()
        .find(|row| row["id"] == id)
        .unwrap_or_else(|| panic!("no row {id}"))
}

#[test]
fn a_routine_tool_is_allowed_under_a_site_grant_and_paused_without_one() {
    let result = drafted();
    let rows = result["gateRows"].as_array().unwrap();
    let stop = row(rows, "neg-browser-example-pilot-page_navigate");
    assert_eq!(stop["expect"], "block");
    assert_eq!(stop["state"], "none");
    assert_eq!(stop["server"], "example-pilot");
    assert_eq!(
        stop["arguments"],
        json!({"url": "https://docs.example.test/guide/configuration"})
    );
    let pair = row(rows, "browser-example-pilot-page_navigate-site-grant");
    assert_eq!(pair["expect"], "allow");
    assert_eq!(pair["state"], "site-grant");
    assert_eq!(pair["page"], "docs-article");
    let click = row(rows, "browser-example-pilot-page_click-site-grant");
    assert_eq!(
        click["arguments"],
        json!({"element": "Configuration", "ref": "e3"})
    );
}

#[test]
fn a_privileged_or_unclassified_tool_stays_paused_under_a_site_grant() {
    let result = drafted();
    let rows = result["gateRows"].as_array().unwrap();
    for tool in ["run_script", "frobnicate"] {
        let stop = row(
            rows,
            &format!("neg-browser-example-pilot-{tool}-site-grant"),
        );
        assert_eq!(stop["expect"], "block");
        assert_eq!(stop["state"], "site-grant");
        let pair = row(rows, &format!("browser-example-pilot-{tool}-saved-exact"));
        assert_eq!(pair["expect"], "allow");
        assert_eq!(pair["state"], "saved-exact");
    }
    assert!(rows
        .iter()
        .all(|row| row["id"] != "browser-example-pilot-run_script-site-grant"));
    assert_eq!(
        row(rows, "browser-example-pilot-run_script-saved-exact")["arguments"],
        json!({"expression": "() => document.title"})
    );
    assert_eq!(rows.len(), 8);
    assert!(result["gateRowsText"].as_str().unwrap().ends_with("]\n"));
}

#[test]
fn validate_accepts_the_drafted_rows_inside_a_gate_document() {
    let result = drafted();
    let mut cases = result["gateRows"].as_array().unwrap().clone();
    cases.push(json!({"id": "echo", "server": "echo-mcp", "tool": "echo", "arguments": {}, "expect": "allow"}));
    let validated = validate(&result, &json!({"version": 1, "mcp_cases": cases}));
    assert_eq!(validated["ok"], true, "{validated}");
    assert_eq!(validated["gateRows"], 8);
}

#[test]
fn validate_refuses_a_protect_row_without_its_benign_pair() {
    let result = drafted();
    let rows: Vec<Value> = result["gateRows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["id"] != "browser-example-pilot-run_script-saved-exact")
        .cloned()
        .collect();
    let refused = validate(&result, &json!(rows));
    assert_eq!(refused["ok"], false);
    assert_eq!(refused["error"]["code"], "gate_benign_pair_missing");
    assert_eq!(
        refused["error"]["items"],
        json!(["neg-browser-example-pilot-run_script-site-grant"])
    );

    let mut rows = result["gateRows"].as_array().unwrap().clone();
    for row in &mut rows {
        if row["tool"] == "page_click" {
            row["expect"] = json!("review");
        }
    }
    let refused = validate(&result, &json!(rows));
    assert_eq!(refused["error"]["code"], "gate_benign_pair_missing");
}

#[test]
fn validate_refuses_a_tool_without_a_row_and_a_row_for_an_unmapped_tool() {
    let result = drafted();
    let rows: Vec<Value> = result["gateRows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["tool"] != "frobnicate")
        .cloned()
        .collect();
    let refused = validate(&result, &json!(rows));
    assert_eq!(refused["error"]["code"], "gate_row_missing");
    assert_eq!(refused["error"]["items"], json!(["frobnicate"]));

    let mut rows = result["gateRows"].as_array().unwrap().clone();
    rows.push(json!({"id": "stray", "server": "example-pilot", "tool": "page_drop_table", "arguments": {}, "expect": "allow"}));
    let refused = validate(&result, &json!(rows));
    assert_eq!(refused["error"]["code"], "gate_row_tool_unknown");
    assert_eq!(refused["error"]["items"], json!(["stray"]));
}

#[test]
fn validate_refuses_missing_foreign_and_malformed_rows() {
    let result = drafted();
    let missing = run(json!({"op": "validate", "profile": result["profileText"]}));
    assert_eq!(missing["error"]["code"], "gate_rows_missing");

    let foreign = json!([{"id": "echo", "server": "echo-mcp", "tool": "echo", "arguments": {}, "expect": "allow"}]);
    assert_eq!(
        validate(&result, &foreign)["error"]["code"],
        "gate_rows_missing"
    );

    for bad in [
        json!("rows"),
        json!({"cases": []}),
        json!([{"id": "x", "server": "example-pilot", "tool": "page_click", "expect": "allow"}]),
        json!([{"id": "x", "server": "example-pilot", "tool": "page_click", "arguments": {}, "expect": "maybe"}]),
        json!([{"server": "example-pilot", "tool": "page_click", "arguments": {}, "expect": "allow"}]),
    ] {
        assert_eq!(
            validate(&result, &bad)["error"]["code"],
            "gate_rows_invalid",
            "{bad}"
        );
    }
    let not_json =
        run(json!({"op": "validate", "profile": result["profileText"], "gateRows": "{"}));
    assert_eq!(not_json["error"]["code"], "gate_rows_invalid");
}
