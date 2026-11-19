use crate::cloud_pack::pack_from_value;
use crate::cloud_pack_request::render;
use crate::cloud_pack_response::project;
use crate::cloud_pack_validate_request::{custom_method, path_placeholders};
use serde_json::{json, Value};

fn pack(path: &str) -> Value {
    json!({
        "schema": "guard.cloud-action-pack.v1",
        "provider": {"id": "docs", "name": "Docs", "publisher": {"name": "HOL", "verified": true}},
        "hosts": ["docs.example.com"],
        "auth": {"mode": "oauth2", "scopes": ["docs"]},
        "actions": [{
            "actionId": "docs.documents.update",
            "title": "Edit a document",
            "executor": {"kind": "declarative-http", "request": {
                "method": "POST", "host": "docs.example.com", "path": path, "maxPages": 1,
                "body": {"object": [{"name": "text", "value": {"arg": "text"}}]}
            }},
            "arguments": {
                "document_id": {"type": "string", "required": true, "maxLength": 64, "pattern": "^[A-Za-z0-9_:-]{1,64}$"},
                "text": {"type": "string", "required": true, "maxLength": 64}
            },
            "facts": {"class": "update"},
            "response": {"maxBytes": 4096, "fields": [{"name": "id", "value": {"from": "documentId"}}]},
            "safety": {"effect": "write", "requiredCapabilities": ["bounded-output", "egress-pinned"],
                "idempotency": "none", "scopes": ["docs"], "maxItems": 1, "minIntervalMs": 500, "timeoutMs": 10000},
            "fixtures": [
                {"name": "a", "kind": "safe", "arguments": {"document_id": "d1", "text": "x"}, "expect": {}},
                {"name": "b", "kind": "risky", "arguments": {}, "expect": {"error": "missing_argument"}}
            ]
        }]
    })
}

fn url(path: &str, document_id: &str) -> String {
    let pack = pack_from_value(pack(path)).unwrap();
    render(
        &pack.actions[0],
        &json!({"document_id": document_id, "text": "x"}),
    )
    .unwrap()
    .url
}

#[test]
fn a_custom_method_follows_a_placeholder() {
    assert_eq!(
        url("/v1/documents/{document_id}:batchUpdate", "d1"),
        "https://docs.example.com/v1/documents/d1:batchUpdate"
    );
}

#[test]
fn a_custom_method_follows_a_literal_segment() {
    assert_eq!(
        url("/v1/documents/{document_id}/values:batchClear", "d1"),
        "https://docs.example.com/v1/documents/d1/values:batchClear"
    );
}

#[test]
fn an_argument_cannot_add_its_own_custom_method() {
    // The pattern lets a colon through; the encoder must still escape it.
    assert_eq!(
        url("/v1/documents/{document_id}", "d1:delete"),
        "https://docs.example.com/v1/documents/d1%3Adelete"
    );
}

#[test]
fn malformed_custom_methods_are_refused() {
    for path in [
        "/v1/documents/{document_id}:",
        "/v1/documents/{document_id}:batch-update",
        "/v1/documents/{document_id}:a:b",
        "/v1/documents/:verb",
        "/v1/documents/{document_id*}:copy",
        "/v1/documents/{document_id}:{text}",
    ] {
        assert!(path_placeholders(path).is_none(), "{path}");
        let code = pack_from_value(pack(path)).unwrap_err().code;
        assert_eq!(code, "cloud_pack_request_path_invalid", "{path}");
    }
}

#[test]
fn custom_method_splits_only_a_trailing_alphabetic_verb() {
    assert_eq!(custom_method("files"), Some(("files", None)));
    assert_eq!(custom_method("{id}:copy"), Some(("{id}", Some("copy"))));
    assert_eq!(custom_method("{id}:copy2"), None);
    assert_eq!(custom_method(":copy"), None);
}

fn query_pack(query: Value, ids: Value, fields: Value) -> crate::cloud_pack::CloudActionPack {
    let mut raw = pack("/v1/documents/{document_id}");
    let action = &mut raw["actions"][0];
    action["executor"]["request"]["query"] = query;
    action["arguments"]["ids"] = ids;
    action["response"]["fields"] = fields;
    pack_from_value(raw).unwrap()
}

fn id_field() -> Value {
    json!([{"name": "id", "value": {"from": "documentId"}}])
}

#[test]
fn an_array_argument_repeats_its_query_parameter() {
    let ids = json!({"type": "array", "required": true, "minItems": 1, "maxItems": 10,
        "items": {"maxLength": 17, "pattern": "^rec[A-Za-z0-9]{1,14}$"}});
    let pack = query_pack(
        json!([{"name": "records[]", "value": {"arg": {"name": "ids"}}}]),
        ids,
        id_field(),
    );
    let rendered = render(
        &pack.actions[0],
        &json!({"document_id": "d1", "text": "x", "ids": ["recA", "recB&x=1"]}),
    );
    assert!(
        rendered.is_err(),
        "the item pattern still binds each element"
    );
    let rendered = render(
        &pack.actions[0],
        &json!({"document_id": "d1", "text": "x", "ids": ["recA", "recB"]}),
    )
    .unwrap();
    assert_eq!(
        rendered.url,
        "https://docs.example.com/v1/documents/d1?records%5B%5D=recA&records%5B%5D=recB"
    );
}

#[test]
fn an_odata_parameter_keeps_its_dollar_sign() {
    let ids = json!({"type": "integer", "required": false, "minimum": 1, "maximum": 50});
    let pack = query_pack(
        json!([{"name": "$top", "value": {"arg": {"name": "ids", "default": 10}}}]),
        ids,
        id_field(),
    );
    let rendered = render(&pack.actions[0], &json!({"document_id": "d1", "text": "x"})).unwrap();
    assert_eq!(
        rendered.url,
        "https://docs.example.com/v1/documents/d1?$top=10"
    );
}

#[test]
fn a_query_name_cannot_smuggle_a_second_dollar_or_separator() {
    let ids = json!({"type": "integer", "required": false, "minimum": 1, "maximum": 50});
    for name in ["$$top", "a$b", "$", "a&b", "a=b"] {
        let mut raw = pack("/v1/documents/{document_id}");
        raw["actions"][0]["executor"]["request"]["query"] =
            json!([{"name": name, "value": {"const": 1}}]);
        raw["actions"][0]["arguments"]["ids"] = ids.clone();
        assert!(pack_from_value(raw).is_err(), "{name}");
    }
}

#[test]
fn a_response_path_steps_into_arrays_by_canonical_index() {
    let ids = json!({"type": "integer", "required": false, "minimum": 1, "maximum": 50});
    let fields = json!([
        {"name": "first_role", "value": {"from": "roles.0"}},
        {"name": "leading_zero", "value": {"from": "roles.01"}},
        {"name": "out_of_range", "value": {"from": "roles.9"}},
        {"name": "rows", "value": {"list": {"from": "values", "maxItems": 5, "fields": [
            {"name": "a", "value": {"from": "0"}}, {"name": "b", "value": {"from": "1"}}
        ]}}}
    ]);
    let pack = query_pack(json!([]), ids, fields);
    let body = br#"{"roles":["read","write"],"values":[["Name","Qty"],["Bolts","40",{"x":1}]]}"#;
    let projected = project(&pack.actions[0], body).unwrap();
    assert_eq!(
        projected.data,
        json!({"first_role": "read", "rows": [{"a": "Name", "b": "Qty"}, {"a": "Bolts", "b": "40"}]})
    );
}
