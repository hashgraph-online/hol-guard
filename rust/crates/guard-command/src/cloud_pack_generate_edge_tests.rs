//! `generate` edge cases: parameter overrides, servers, bodies, bounds and
//! names a draft must neither drop nor widen.

use crate::cloud_pack_cli::answer;
use serde_json::{json, Value};

fn reply(request: Value) -> Value {
    let reply = answer(request.to_string().as_bytes());
    assert_eq!(reply["ok"], json!(true), "{reply}");
    reply
}

fn openapi(paths: Value) -> Value {
    json!({
        "openapi": "3.1.0",
        "servers": [{ "url": "https://api.example.com/v1" }],
        "paths": paths,
    })
}

fn draft(document: Value) -> Value {
    reply(json!({ "op": "generate", "providerId": "shop", "openapi": document }))
}

fn actions(reply: &Value) -> Vec<Value> {
    reply["pack"]["actions"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn only(reply: &Value) -> Value {
    let list = actions(reply);
    assert_eq!(list.len(), 1, "{reply}");
    list[0].clone()
}

fn noted(reply: &Value, code: &str) -> bool {
    reply["notes"].to_string().contains(code)
}

fn int_schema(schema: Value) -> Value {
    let id =
        json!({ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } });
    let page = json!({ "name": "page", "in": "query", "schema": schema });
    draft(openapi(json!({ "/items/{id}": { "get": {
        "operationId": "getItem", "parameters": [id, page],
        "responses": { "200": { "description": "ok" } } } } })))
}

#[test]
fn an_operation_parameter_replaces_the_shared_one() {
    let reply = draft(openapi(json!({ "/pets/{petId}": {
        "parameters": [{ "name": "petId", "in": "path", "required": true, "schema": { "type": "string" } }],
        "get": {
            "operationId": "getPet",
            "parameters": [{ "name": "petId", "in": "path", "required": true,
                "schema": { "type": "integer", "minimum": 1, "maximum": 99 } }],
            "responses": { "200": { "description": "ok" } }
        }
    } })));
    let action = only(&reply);
    assert_eq!(
        action["arguments"]["pet_id"]["type"],
        json!("integer"),
        "{action}"
    );
    assert_eq!(
        action["executor"]["request"]["path"],
        json!("/v1/pets/{pet_id}")
    );
}

#[test]
fn a_boolean_path_parameter_skips_the_operation() {
    let reply = answer(
        json!({ "op": "generate", "providerId": "shop", "openapi": openapi(json!({ "/flags/{on}": { "get": {
            "operationId": "getFlag",
            "parameters": [{ "name": "on", "in": "path", "required": true, "schema": { "type": "boolean" } }],
            "responses": { "200": { "description": "ok" } }
        } } })) })
        .to_string()
        .as_bytes(),
    );
    assert_eq!(reply["ok"], json!(false), "{reply}");
}

#[test]
fn a_required_body_the_pack_cannot_send_skips_the_operation() {
    let body = |required: bool| {
        json!({ "required": required,
        "content": { "application/json": { "schema": { "type": "string" } } } })
    };
    let reply = draft(openapi(json!({
        "/notes": { "post": { "operationId": "createNote", "requestBody": body(true),
            "responses": { "201": { "description": "ok" } } } },
        "/drafts": { "post": { "operationId": "createDraft", "requestBody": body(false),
            "responses": { "201": { "description": "ok" } } } }
    })));
    let action = only(&reply);
    assert_eq!(action["actionId"], json!("shop.create_draft"));
    assert!(noted(&reply, "operation_skipped"));
}

#[test]
fn a_success_without_a_body_may_be_empty() {
    let reply = draft(openapi(json!({ "/pets/{id}": { "delete": {
        "operationId": "removePet",
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": { "204": { "description": "deleted" } }
    } } })));
    let response = &only(&reply)["response"];
    assert_eq!(response["emptyOk"], json!(true), "{response}");
}

#[test]
fn a_guessed_response_field_is_untrusted() {
    let reply = draft(openapi(json!({ "/pets": { "get": {
        "operationId": "listPets",
        "responses": { "200": { "description": "ok",
            "content": { "application/json": { "schema": { "type": "string" } } } } }
    } } })));
    let fields = &only(&reply)["response"]["fields"];
    assert_eq!(fields[0]["untrusted"], json!(true), "{fields}");
    assert!(noted(&reply, "response_fields_guessed"));
}

#[test]
fn an_operation_server_overrides_the_document_server() {
    let reply = draft(openapi(json!({ "/pets": {
        "get": { "operationId": "listPets", "responses": { "200": { "description": "ok" } } },
        "post": { "operationId": "addPet", "servers": [{ "url": "https://api.example.com/v2" }],
            "responses": { "201": { "description": "ok" } } }
    } })));
    let path = |id: &str| {
        actions(&reply)
            .into_iter()
            .find(|action| action["actionId"] == json!(id))
            .map(|action| action["executor"]["request"]["path"].clone())
    };
    assert_eq!(path("shop.list_pets"), Some(json!("/v1/pets")));
    assert_eq!(path("shop.add_pet"), Some(json!("/v2/pets")));
}

#[test]
fn the_first_https_server_is_used() {
    let mut document = openapi(json!({ "/pets": { "get": {
        "operationId": "listPets", "responses": { "200": { "description": "ok" } } } } }));
    document["servers"] = json!([
        { "url": "http://localhost:8080/v1" },
        { "url": "https://api.example.com/v3" }
    ]);
    let reply = draft(document);
    assert_eq!(reply["pack"]["hosts"], json!(["api.example.com"]));
    assert_eq!(
        only(&reply)["executor"]["request"]["path"],
        json!("/v3/pets")
    );
}

#[test]
fn a_relative_server_keeps_its_base_path_with_a_named_host() {
    let mut document = openapi(json!({ "/pets": { "get": {
        "operationId": "listPets", "responses": { "200": { "description": "ok" } } } } }));
    document["servers"] = json!([{ "url": "/api/v3" }]);
    let reply = reply(json!({ "op": "generate", "providerId": "shop",
        "host": "pets.example.com", "openapi": document }));
    assert_eq!(reply["pack"]["hosts"], json!(["pets.example.com"]));
    assert_eq!(
        only(&reply)["executor"]["request"]["path"],
        json!("/api/v3/pets")
    );
}

#[test]
fn integer_bounds_round_inward_and_honour_exclusive_forms() {
    let page = |schema: Value| only(&int_schema(schema))["arguments"]["page"].clone();
    let fractional = page(json!({ "type": "integer", "minimum": 1.5, "maximum": 9.5 }));
    assert_eq!(
        (fractional["minimum"].clone(), fractional["maximum"].clone()),
        (json!(2), json!(9))
    );
    let numeric =
        page(json!({ "type": "integer", "exclusiveMinimum": 0, "exclusiveMaximum": 100 }));
    assert_eq!(
        (numeric["minimum"].clone(), numeric["maximum"].clone()),
        (json!(1), json!(99))
    );
    let flags = page(
        json!({ "type": "integer", "minimum": 0, "exclusiveMinimum": true,
        "maximum": 10, "exclusiveMaximum": true }),
    );
    assert_eq!(
        (flags["minimum"].clone(), flags["maximum"].clone()),
        (json!(1), json!(9))
    );
}

#[test]
fn a_zero_bound_is_never_widened() {
    let reply = int_schema(json!({ "type": "string", "maxLength": 0 }));
    assert!(only(&reply)["arguments"].get("page").is_none());
    assert!(noted(&reply, "argument_skipped"));
}

#[test]
fn an_mcp_list_with_a_zero_bound_is_never_widened() {
    let tools = json!([{ "name": "tag_items", "inputSchema": { "type": "object",
        "required": ["tags"],
        "properties": { "tags": { "type": "array", "maxItems": 0, "items": { "type": "object" } },
            "note": { "type": "string" } } } }]);
    let reply = reply(json!({ "op": "generate", "providerId": "files",
        "host": "mcp.files.example", "authMode": "oauth2", "mcpTools": tools }));
    assert!(only(&reply)["arguments"].get("tags").is_none());
    assert!(noted(&reply, "required_argument_unsupported"));
}

/// A draft with `/status` beside `extra`, so the draft is never empty.
fn with_status(extra: Value) -> Value {
    let mut paths = json!({ "/status": { "get": { "operationId": "getStatus" } } });
    paths["/orders"] = extra;
    draft(openapi(paths))
}

fn action_ids(reply: &Value) -> Vec<String> {
    actions(reply)
        .iter()
        .filter_map(|action| action["actionId"].as_str().map(str::to_owned))
        .collect()
}

#[test]
fn an_operation_with_a_required_parameter_it_cannot_send_is_left_out() {
    let required_array = with_status(json!({ "get": { "operationId": "listOrders",
        "parameters": [{ "name": "ids", "in": "query", "required": true,
            "schema": { "type": "array", "items": { "type": "string" } } }] } }));
    assert_eq!(action_ids(&required_array).len(), 1, "{required_array}");
    assert!(noted(&required_array, "required_argument_unsupported"));
    let required_filter = with_status(json!({ "get": { "operationId": "listOrders",
        "parameters": [{ "name": "$filter", "in": "query", "required": true,
            "schema": { "type": "string" } }] } }));
    assert_eq!(action_ids(&required_filter).len(), 1, "{required_filter}");
    let optional_array = with_status(json!({ "get": { "operationId": "listOrders",
        "parameters": [{ "name": "ids", "in": "query",
            "schema": { "type": "array", "items": { "type": "string" } } }] } }));
    assert_eq!(action_ids(&optional_array).len(), 2, "{optional_array}");
}

#[test]
fn a_required_body_property_it_cannot_carry_leaves_the_operation_out() {
    let reply = with_status(json!({ "post": { "operationId": "createOrder",
        "requestBody": { "content": { "application/json": { "schema": {
            "type": "object", "required": ["lines"],
            "properties": { "lines": { "type": "array", "items": { "type": "object" } },
                "note": { "type": "string" } } } } } } } }));
    assert_eq!(action_ids(&reply).len(), 1, "{reply}");
    assert!(noted(&reply, "required_argument_unsupported"));
}

#[test]
fn a_custom_method_placeholder_is_renamed_with_its_verb_kept() {
    let reply = draft(openapi(json!({ "/files/{fileId}:copy": { "post": {
        "operationId": "copyFile",
        "parameters": [{ "name": "fileId", "in": "path", "required": true,
            "schema": { "type": "string" } }],
        "requestBody": { "content": { "application/json": { "schema": {
            "type": "object", "properties": { "name": { "type": "string" } } } } } } } } })));
    let action = only(&reply);
    assert_eq!(
        action["executor"]["request"]["path"],
        json!("/v1/files/{file_id}:copy"),
        "{action}"
    );
    assert!(action["arguments"].get("file_id").is_some(), "{action}");
}
