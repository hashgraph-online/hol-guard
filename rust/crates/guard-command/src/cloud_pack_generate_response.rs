//! Draft response fields: the scalar top-level properties of a success
//! schema, every string marked untrusted until an author reviews it.

use crate::cloud_pack_generate::{snake, Draft, DEFAULT_ARRAY_ITEMS};
use serde_json::{json, Value};
use std::collections::BTreeSet;

const MAX_RESPONSE_FIELDS: usize = 64;

/// Projected response fields for a JSON Schema: scalar top-level properties,
/// or those of each item when the response is an array. A success that
/// carries no body (`204`) projects as an empty object instead of failing.
pub(crate) fn response(schema: Option<&Value>, empty_ok: bool, draft: &mut Draft, at: &str) -> Value {
    let fields = schema.and_then(|schema| {
        if schema.get("type").and_then(Value::as_str) == Some("array") {
            let items = scalar_fields(schema.get("items")?);
            (!items.is_empty()).then(|| {
                vec![json!({
                    "name": "items",
                    "value": { "list": { "from": "", "maxItems": DEFAULT_ARRAY_ITEMS, "fields": items } },
                })]
            })
        } else {
            Some(scalar_fields(schema)).filter(|fields| !fields.is_empty())
        }
    });
    let fields = fields.unwrap_or_else(|| {
        if !empty_ok {
            draft.note("response_fields_guessed", at);
        }
        // A guessed field is still provider text, so it starts untrusted too.
        vec![json!({ "name": "id", "value": { "from": "id" }, "untrusted": true })]
    });
    let mut response = json!({ "maxBytes": 65_536, "fields": fields });
    if empty_ok {
        response["emptyOk"] = json!(true);
    }
    response
}
fn scalar_fields(schema: &Value) -> Vec<Value> {
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut names = BTreeSet::new();
    let mut fields = Vec::new();
    for (key, property) in properties {
        let kind = property.get("type").and_then(Value::as_str);
        let scalar = matches!(kind, Some("string" | "integer" | "number" | "boolean"));
        let Some(name) = snake(key).filter(|name| !name.starts_with('_')) else {
            continue;
        };
        if !scalar || !response_key(key) || !names.insert(name.clone()) {
            continue;
        }
        let mut field = json!({ "name": name, "value": { "from": key } });
        if kind == Some("string") {
            // Provider text can carry instructions; mark it untrusted until reviewed.
            field["untrusted"] = json!(true);
        }
        fields.push(field);
        if fields.len() == MAX_RESPONSE_FIELDS {
            break;
        }
    }
    fields
}

fn response_key(key: &str) -> bool {
    (1..=64).contains(&key.len())
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'$' | b'@'))
}
