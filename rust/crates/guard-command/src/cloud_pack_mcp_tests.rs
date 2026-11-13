//! `remote-mcp` actions: provider argument names, `json` arguments and open
//! arguments.

use crate::cloud_pack::{pack_from_value, CloudActionPack};
use crate::cloud_pack_diff::diff;
use crate::cloud_pack_facts::extract;
use crate::cloud_pack_request::check_arguments;
use serde_json::{json, Value};

fn mcp_pack(arguments: Value, open: Option<Value>) -> Value {
    let mut action = json!({
        "actionId": "crm.records.update",
        "title": "Update a record",
        "link": {"tool": "updateSobjectRecord"},
        "executor": {"kind": "remote-mcp", "tool": "updateSobjectRecord"},
        "arguments": arguments,
        "facts": {"class": "update", "recordCount": {"const": 1}},
        "response": {"maxBytes": 4096, "fields": [{"name": "id", "value": {"from": "id"}}]},
        "safety": {"effect": "write", "requiredCapabilities": ["bounded-output", "egress-pinned"],
            "idempotency": "none", "scopes": ["api"], "maxItems": 1, "minIntervalMs": 500, "timeoutMs": 10000},
        "fixtures": [
            {"name": "a", "kind": "safe", "arguments": {"sobject-name": "Account", "id": "001", "body": {"Name": "x"}}, "expect": {}},
            {"name": "b", "kind": "risky", "arguments": {}, "expect": {"error": "missing_argument"}}
        ]
    });
    if let Some(open) = open {
        action["openArguments"] = open;
    }
    json!({
        "schema": "guard.cloud-action-pack.v1",
        "provider": {"id": "crm", "name": "CRM", "publisher": {"name": "HOL", "verified": true}},
        "hosts": ["mcp.crm.example"],
        "auth": {"mode": "oauth2", "scopes": ["api"]},
        "actions": [action]
    })
}

fn record_arguments() -> Value {
    json!({
        "sobject-name": {"type": "string", "required": true, "maxLength": 64},
        "id": {"type": "string", "required": true, "maxLength": 18},
        "body": {"type": "json", "required": true, "maxBytes": 64}
    })
}

fn parsed(value: Value) -> CloudActionPack {
    pack_from_value(value).expect("pack is valid")
}

fn refused(value: Value) -> &'static str {
    pack_from_value(value).expect_err("pack is refused").code
}

fn check(pack: &CloudActionPack, args: Value) -> Result<(), &'static str> {
    check_arguments(&pack.actions[0], &args)
        .map(|_| ())
        .map_err(|error| error.code)
}

#[test]
fn a_remote_mcp_argument_keeps_the_provider_name() {
    let pack = parsed(mcp_pack(record_arguments(), None));
    assert!(pack.actions[0].arguments.contains_key("sobject-name"));
    assert_eq!(
        check(&pack, json!({"sobject-name": "Account", "id": "001", "body": {"Name": "Acme"}})),
        Ok(())
    );
}

#[test]
fn an_http_argument_must_stay_snake_case() {
    let mut value = mcp_pack(json!({"sobjectName": {"type": "string", "required": true, "maxLength": 8}}), None);
    value["actions"][0]["executor"] = json!({"kind": "declarative-http", "request": {
        "method": "GET", "host": "mcp.crm.example", "path": "/v1/{sobjectName}", "maxPages": 1}});
    assert_eq!(refused(value), "cloud_pack_argument_name_invalid");
}

#[test]
fn a_json_argument_is_bounded_by_size() {
    let pack = parsed(mcp_pack(record_arguments(), None));
    let big = "x".repeat(80);
    assert_eq!(
        check(&pack, json!({"sobject-name": "Account", "id": "001", "body": {"Name": big}})),
        Err("invalid_argument")
    );
}

#[test]
fn a_json_argument_is_refused_outside_remote_mcp() {
    let mut value = mcp_pack(json!({"body": {"type": "json", "required": true, "maxBytes": 64}}), None);
    value["actions"][0]["executor"] = json!({"kind": "declarative-http", "request": {
        "method": "POST", "host": "mcp.crm.example", "path": "/v1/records", "maxPages": 1,
        "body": {"arg": "body"}}});
    assert_eq!(refused(value), "cloud_pack_argument_type_invalid");
}

#[test]
fn a_counted_json_argument_feeds_the_record_count() {
    let mut value = mcp_pack(
        json!({"pages": {"type": "json", "required": true, "maxBytes": 4096, "maxItems": 20}}),
        None,
    );
    value["actions"][0]["facts"]["recordCount"] = json!({"count": {"arguments": ["pages"]}});
    value["actions"][0]["fixtures"] = json!([
        {"name": "a", "kind": "safe", "arguments": {"pages": [{"id": "p1"}]}, "expect": {"facts": {"record_count": {"state": "known", "value": 1}}}},
        {"name": "b", "kind": "risky", "arguments": {"pages": {"id": "p1"}}, "expect": {"error": "invalid_argument"}}
    ]);
    let pack = parsed(value);
    let args = json!({"pages": [{"id": "p1"}, {"id": "p2"}, {"id": "p3"}]});
    let facts = serde_json::to_value(extract(&pack.actions[0], args.as_object().unwrap())).unwrap();
    assert_eq!(facts["record_count"], json!({"state": "known", "value": 3}));
    let too_many: Vec<Value> = (0..21).map(|n| json!({"id": n})).collect();
    assert_eq!(check(&pack, json!({"pages": too_many})), Err("invalid_argument"));
}

#[test]
fn undeclared_arguments_need_open_arguments() {
    let closed = parsed(mcp_pack(record_arguments(), None));
    let call = json!({"sobject-name": "Account", "id": "001", "body": {}, "cloudId": "c1"});
    assert_eq!(check(&closed, call.clone()), Err("unknown_argument"));
    let open = parsed(mcp_pack(record_arguments(), Some(json!({"maxBytes": 16}))));
    assert_eq!(check(&open, call), Ok(()));
    let large = json!({"sobject-name": "Account", "id": "001", "body": {}, "cloudId": "c".repeat(32)});
    assert_eq!(check(&open, large), Err("open_arguments_too_large"));
}

#[test]
fn open_arguments_are_refused_outside_remote_mcp() {
    let mut value = mcp_pack(json!({"name": {"type": "string", "required": true, "maxLength": 8}}), Some(json!({"maxBytes": 16})));
    value["actions"][0]["executor"] = json!({"kind": "declarative-http", "request": {
        "method": "GET", "host": "mcp.crm.example", "path": "/v1/{name}", "maxPages": 1}});
    assert_eq!(refused(value), "cloud_pack_open_arguments_invalid");
}

#[test]
fn opening_arguments_widens_a_pack() {
    let closed = parsed(mcp_pack(record_arguments(), None));
    let open = parsed(mcp_pack(record_arguments(), Some(json!({"maxBytes": 16}))));
    let change = diff(&closed, &open).unwrap();
    assert!(change.widening);
    assert!(change.changes.iter().any(|c| c.code == "open_arguments_changed"));
    assert!(!diff(&open, &closed).unwrap().widening);
}
