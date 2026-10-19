//! Field names in the result schema of an Oh My Pi `task` call.
//!
//! A delegation brief may describe the shape of the answer it expects, such as
//! `{"outputSchema": {"properties": {"tokenFields": {"type": "array"}}}}`. The
//! property names are labels for the result, not credential-shaped arguments,
//! so the secret-read setting must not read them as a request for a secret. A
//! property that declares a literal value under a credential name, and any
//! credential-named key outside a schema, keep the ordinary review.

use super::{sensitive_key, MAX_FACT_DEPTH};
use serde_json::{Map, Value};

/// Keywords whose value maps a name to a schema.
const NAMED_SCHEMAS: &[&str] = &[
    "properties",
    "patternProperties",
    "$defs",
    "definitions",
    "dependentSchemas",
];
/// Keywords whose value is one schema or a list of schemas.
const NESTED_SCHEMAS: &[&str] = &[
    "items",
    "prefixItems",
    "additionalProperties",
    "contains",
    "not",
    "anyOf",
    "oneOf",
    "allOf",
    "if",
    "then",
    "else",
];
/// Keywords that carry a concrete value rather than a shape.
const LITERALS: &[&str] = &["default", "const", "enum", "examples", "example"];

/// The maps of a payload that are safe to scan for credential-shaped keys:
/// every map except the schema name maps of a recognized `task` call.
pub(super) fn without_schema_names<'a>(
    maps: &[&'a Map<String, Value>],
    payload: &'a Value,
    harness: &str,
) -> Vec<&'a Map<String, Value>> {
    let names = schema_name_maps(payload, harness);
    maps.iter()
        .copied()
        .filter(|record| !names.iter().any(|name| std::ptr::eq(*record, *name)))
        .collect()
}

fn schema_name_maps<'a>(payload: &'a Value, harness: &str) -> Vec<&'a Map<String, Value>> {
    let mut names = Vec::new();
    if harness != "omp" {
        return names;
    }
    let Some(envelope) = payload.as_object() else {
        return names;
    };
    if envelope.get("tool_name").and_then(Value::as_str) != Some("task") {
        return names;
    }
    let Some(input) = envelope.get("tool_input").and_then(Value::as_object) else {
        return names;
    };
    if let Some(schema) = input.get("outputSchema") {
        collect(schema, 0, &mut names);
    }
    for task in input
        .get("tasks")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
    {
        if let Some(schema) = task.get("outputSchema") {
            collect(schema, 0, &mut names);
        }
    }
    names
}

/// Walk only the keywords that hold schemas. Examples and defaults are data,
/// so a map that merely looks like a schema inside one is never collected.
fn collect<'a>(schema: &'a Value, depth: usize, names: &mut Vec<&'a Map<String, Value>>) {
    if depth > MAX_FACT_DEPTH {
        return;
    }
    match schema {
        Value::Array(items) => {
            for item in items {
                collect(item, depth.saturating_add(1), names);
            }
        }
        Value::Object(node) => {
            for (keyword, child) in node {
                if NAMED_SCHEMAS.contains(&keyword.as_str()) {
                    if let Value::Object(named) = child {
                        if labels_only(named, depth.saturating_add(1)) {
                            names.push(named);
                        }
                        for sub in named.values() {
                            collect(sub, depth.saturating_add(2), names);
                        }
                    }
                } else if NESTED_SCHEMAS.contains(&keyword.as_str()) {
                    collect(child, depth.saturating_add(1), names);
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// A name map is a set of labels only when each entry is a schema and no
/// credential-named entry carries a concrete value anywhere beneath it.
fn labels_only(named: &Map<String, Value>, depth: usize) -> bool {
    named.iter().all(|(name, schema)| {
        matches!(schema, Value::Object(_) | Value::Bool(_))
            && !(sensitive_key(name) && declares_literal(schema, depth))
    })
}

fn declares_literal(value: &Value, depth: usize) -> bool {
    if depth > MAX_FACT_DEPTH {
        return true;
    }
    match value {
        Value::Object(node) => node.iter().any(|(key, child)| {
            LITERALS.contains(&key.as_str())
                // Without resolving the referenced schema, a sensitive field
                // might hide a concrete credential in $defs/definitions.
                || matches!(key.as_str(), "$ref" | "$dynamicRef" | "$recursiveRef")
                || declares_literal(child, depth.saturating_add(1))
        }),
        Value::Array(items) => items
            .iter()
            .any(|child| declares_literal(child, depth.saturating_add(1))),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}
