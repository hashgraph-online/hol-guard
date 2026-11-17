//! Response projection: keep only the fields a pack allowlists.
//!
//! The provider body is bounded by the action's `maxBytes` before parsing.
//! An action marked `emptyOk` accepts an empty success body as `{}`.
//! Every output field is copied from a declared path; anything else is
//! dropped. Scalar fields keep scalars only, so a provider cannot smuggle a
//! nested object through a field declared as text. Each field marked
//! untrusted or with a sensitivity label is reported by JSON pointer so the
//! host can wrap or redact it.

use crate::cloud_pack::{FieldSource, PackAction, ResponseField};
use guard_contracts::SensitivityV2;
use serde::Serialize;
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldLabel {
    pub pointer: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub untrusted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<SensitivityV2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Projection {
    pub data: Value,
    pub labels: Vec<FieldLabel>,
}

pub fn project(action: &PackAction, body: &[u8]) -> Result<Projection, &'static str> {
    if body.len() as u64 > action.response.max_bytes {
        return Err("response_too_large");
    }
    let parsed = if action.response.empty_ok && body.iter().all(u8::is_ascii_whitespace) {
        Value::Object(Map::new())
    } else {
        crate::cloud_action_canonical::parse_strict(body).map_err(|_| "response_json_invalid")?
    };
    let mut labels = Vec::new();
    let data = project_fields(&action.response.fields, &parsed, "", &mut labels)?;
    Ok(Projection {
        data: Value::Object(data),
        labels,
    })
}

fn lookup<'a>(node: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return Some(node);
    }
    let mut current = node;
    let mut rest = path;
    while !rest.is_empty() {
        // An OData annotation such as `@odata.nextLink` is one key that holds a
        // dot, so a step that starts with `@` takes the rest of the path.
        let (key, tail) = match rest.split_once('.') {
            Some(_) if rest.starts_with('@') => (rest, ""),
            Some((key, tail)) => (key, tail),
            None => (rest, ""),
        };
        current = match current {
            Value::Object(map) => map.get(key)?,
            Value::Array(items) => items.get(array_index(key)?)?,
            _ => return None,
        };
        rest = tail;
    }
    Some(current)
}

/// A path step into an array: a canonical decimal index (`0`, `12`, never `01`).
fn array_index(key: &str) -> Option<usize> {
    let canonical = key.len() <= 4
        && key.bytes().all(|b| b.is_ascii_digit())
        && (key == "0" || !key.starts_with('0'));
    canonical.then(|| key.parse().ok()).flatten()
}

fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

fn project_fields(
    fields: &[ResponseField],
    node: &Value,
    pointer: &str,
    labels: &mut Vec<FieldLabel>,
) -> Result<Map<String, Value>, &'static str> {
    let mut out = Map::new();
    for field in fields {
        let at = format!("{pointer}/{}", escape(&field.name));
        let value = match &field.value {
            FieldSource::From(path) => match lookup(node, path) {
                Some(
                    value @ (Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null),
                ) => value.clone(),
                _ => continue,
            },
            FieldSource::Exists(path) => {
                Value::Bool(lookup(node, path).is_some_and(|value| !value.is_null()))
            }
            FieldSource::List {
                from,
                max_items,
                fields,
            } => {
                let Some(Value::Array(items)) = lookup(node, from) else {
                    continue;
                };
                if items.len() > *max_items as usize {
                    return Err("response_list_too_long");
                }
                let mut list = Vec::with_capacity(items.len());
                for (index, item) in items.iter().enumerate() {
                    list.push(Value::Object(project_fields(
                        fields,
                        item,
                        &format!("{at}/{index}"),
                        labels,
                    )?));
                }
                Value::Array(list)
            }
            FieldSource::Object { from, fields } => {
                let Some(inner @ Value::Object(_)) = lookup(node, from) else {
                    continue;
                };
                Value::Object(project_fields(fields, inner, &at, labels)?)
            }
        };
        if field.untrusted || field.sensitivity.is_some() {
            labels.push(FieldLabel {
                pointer: at,
                untrusted: field.untrusted,
                sensitivity: field.sensitivity,
            });
        }
        out.insert(field.name.clone(), value);
    }
    Ok(out)
}
