//! Field names a delegated Oh My Pi result is described by and answered in.
//!
//! A delegation brief may describe the shape of the answer it expects, such as
//! `{"outputSchema": {"properties": {"tokenFields": {"type": "array"}}}}`. The
//! property names are labels for the result, not credential-shaped arguments,
//! so the secret-read setting must not read them as a request for a secret. A
//! property that declares a literal value under a credential name, and any
//! credential-named key outside a schema, keep the ordinary review.
//!
//! The answer the subtask hands back carries those same names, so a report of
//! `{"tokenMentions": "No, the README does not mention a token."}` must not be
//! read as a secret read either. Only a verified report qualifies, and only
//! its key names: the values keep every scan, and path selectors keep their
//! floor because they are read from the unfiltered maps.

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

/// The maps of a verified Oh My Pi result report, whose keys are the field
/// names the parent's schema asked the subtask to answer in.
///
/// The exemption applies only once the native authority has accepted the
/// report as plain task data and found every file reference readable, and only
/// alongside a full scan of the same bytes, so a credential in a value is
/// already caught. `native_omp_yield_metadata` carries that finding before the
/// call; after it, `report_verified` re-derives it from the input half of the
/// envelope and pairs it with the output scan's own allow. A name floor on top of that stops no attacker,
/// who would simply rename the field, while it reliably blocks an honest
/// schema-driven answer.
pub(super) fn without_result_labels<'a>(
    maps: &[&'a Map<String, Value>],
    payload: &'a Value,
    harness: &str,
    reason_code: &str,
) -> Vec<&'a Map<String, Value>> {
    let labels = result_label_maps(payload, harness, reason_code);
    maps.iter()
        .copied()
        .filter(|record| !labels.iter().any(|label| std::ptr::eq(*record, *label)))
        .collect()
}

fn result_label_maps<'a>(
    payload: &'a Value,
    harness: &str,
    reason_code: &str,
) -> Vec<&'a Map<String, Value>> {
    let mut labels = Vec::new();
    if harness != "omp" {
        return labels;
    }
    let Some(envelope) = payload.as_object() else {
        return labels;
    };
    if envelope.get("tool_name").and_then(Value::as_str) != Some("yield") {
        return labels;
    }
    if !report_verified(envelope, reason_code) {
        return labels;
    }
    let Some(input) = envelope.get("tool_input").and_then(Value::as_object) else {
        return labels;
    };
    if let Some(Value::Object(data)) = input.get("data") {
        collect_report_maps(data, 0, &mut labels);
    }
    // After the call the harness echoes its acknowledgement of the same
    // report. Its values carry the output scan's own allow, so its field
    // names are labels for the same reason the report's are.
    if reason_code != YIELD_METADATA_REASON {
        for key in ["tool_response", "toolResponse"] {
            if let Some(value) = envelope.get(key) {
                collect_report_value(value, 0, &mut labels);
            }
        }
    }
    labels
}

/// Whether this envelope is a verified Oh My Pi result report.
///
/// Before the call, the native reason code carries the proof: the authority
/// accepted the report as plain task data and found every file reference
/// readable. After the call, the proof is the full output scan plus the same
/// native authority run again over the input half of the envelope, so the
/// post-tool exemption rests on exactly the same finding as the pre-tool one.
fn report_verified(envelope: &Map<String, Value>, reason_code: &str) -> bool {
    if reason_code == YIELD_METADATA_REASON {
        return true;
    }
    if !matches!(
        reason_code,
        "output_scan_allow" | "source_full_scan_allow" | "output_empty_allow"
    ) {
        return false;
    }
    let input: Map<String, Value> = envelope
        .iter()
        .filter(|(key, _)| {
            !matches!(
                key.as_str(),
                "tool_response" | "toolResponse" | "toolResultPreview"
            )
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let result = guard_command::pretool::evaluate_pre_tool_envelope(
        "omp",
        "PreToolUse",
        &Value::Object(input),
    );
    result.decision == "allow" && result.reason_code == YIELD_METADATA_REASON
}

/// The PreToolUse reason code that proves a yield report was verified.
const YIELD_METADATA_REASON: &str = "native_omp_yield_metadata";

/// Only the report body. A map deeper than the fact budget is left scanned.
fn collect_report_maps<'a>(
    node: &'a Map<String, Value>,
    depth: usize,
    labels: &mut Vec<&'a Map<String, Value>>,
) {
    if depth > MAX_FACT_DEPTH {
        return;
    }
    labels.push(node);
    for value in node.values() {
        collect_report_value(value, depth.saturating_add(1), labels);
    }
}

fn collect_report_value<'a>(
    value: &'a Value,
    depth: usize,
    labels: &mut Vec<&'a Map<String, Value>>,
) {
    if depth > MAX_FACT_DEPTH {
        return;
    }
    match value {
        Value::Object(node) => collect_report_maps(node, depth, labels),
        Value::Array(items) => {
            for item in items {
                collect_report_value(item, depth.saturating_add(1), labels);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
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
