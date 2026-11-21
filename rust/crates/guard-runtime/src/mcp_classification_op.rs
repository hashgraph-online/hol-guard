//! `McpClassify` - resident op that describes the static evidence an MCP tool
//! declaration carries.
//!
//! Pure and bounded: the op reads field *names* from the declared schema and
//! the provider's annotation claims, never field values, descriptions,
//! defaults, URLs, enum members or the tool itself. Nothing it returns is a
//! safe/allow recommendation, a verified destination or an account binding.
//!
//! Reviewed provider mappings are deliberately exact. A prefix or a friendly
//! name cannot borrow a reviewed action's semantics, and a provider action
//! Guard has not inspected stays `unknown`.

use guard_contracts::{
    McpClassificationItemV1, McpClassificationRequestV1, McpClassificationResultV1,
    MCP_CLASSIFICATION_MAX_BYTES, MCP_CLASSIFICATION_MAX_ITEMS, MCP_CLASSIFICATION_REQUEST_SCHEMA,
    MCP_CLASSIFICATION_RESULT_SCHEMA, MCP_CLASSIFICATION_SCHEMA,
};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

use crate::package_authority_op::request_digest_with_limit;

/// Inspected hosted `tool_schemas` response, 2026-09-27. The mapping is an
/// advisory description of the provider's contract, not proof of behavior.
const REVIEWED: [(&str, [&str; 4]); 1] = [(
    "SLACK_SEARCH_MESSAGES",
    ["read", "private-content", "slack", "not-applicable"],
)];

const CONTENT_FIELDS: [&str; 7] = [
    "body",
    "content",
    "text",
    "message",
    "messages",
    "attachment",
    "attachments",
];
const DESTINATION_FIELDS: [&str; 8] = [
    "url",
    "uri",
    "endpoint",
    "webhook_url",
    "recipient",
    "recipients",
    "to",
    "email",
];
const EXECUTION_FIELDS: [&str; 4] = ["command", "script", "code", "shell_command"];
const SECRET_FIELDS: [&str; 6] = [
    "password",
    "token",
    "api_key",
    "secret",
    "credential",
    "credentials",
];
const HINT_KEYS: [&str; 4] = [
    "readOnlyHint",
    "destructiveHint",
    "openWorldHint",
    "idempotentHint",
];
/// An effect a `readOnlyHint` claim contradicts.
const WRITING_EFFECTS: [&str; 5] = ["write", "communicate", "delete", "administer", "execute"];

/// Traversal bounds. A declaration that exceeds any of them is described from
/// what was read so far and reported incomplete, never fetched or resolved.
const MAX_NODES: usize = 2048;
const MAX_DEPTH: usize = 16;
const MAX_CHILDREN: usize = 256;
const MAX_FIELD_NAME_CHARS: usize = 128;

pub(crate) fn evaluate_mcp_classification_request(
    request: &McpClassificationRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, MCP_CLASSIFICATION_MAX_BYTES)
        .map_err(|_| "native_mcp_classification_too_large".to_owned())?;
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code, None),
    };
    crate::encode_response(&McpClassificationResultV1 {
        schema: MCP_CLASSIFICATION_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

pub(crate) fn evaluate(request: &McpClassificationRequestV1) -> Result<Value, String> {
    if request.schema != MCP_CLASSIFICATION_REQUEST_SCHEMA {
        // A client naming another contract is asking for something this op
        // does not implement; describing its items anyway would answer a
        // question that was never asked.
        return Err("native_mcp_classification_schema_unsupported".to_owned());
    }
    if request.items.len() > MCP_CLASSIFICATION_MAX_ITEMS {
        return Err("native_mcp_classification_too_large".to_owned());
    }
    let classifications: Vec<Value> = request.items.iter().map(classify).collect();
    Ok(json!({ "classifications": classifications }))
}

fn reviewed_mapping(item: &McpClassificationItemV1) -> Option<[&'static str; 4]> {
    if item.provider.as_deref() != Some("composio") {
        return None;
    }
    REVIEWED
        .iter()
        .find(|(name, _)| *name == item.name)
        .map(|(_, mapping)| *mapping)
}

fn classify(item: &McpClassificationItemV1) -> Value {
    let mapping = reviewed_mapping(item);
    let [mut effect, mut data, mut destination, reversibility] =
        mapping.unwrap_or(["unknown", "unknown", "unknown", "unknown"]);
    let mut evidence: Vec<&str> = Vec::new();
    let mut warnings: Vec<&str> = Vec::new();
    if mapping.is_some() {
        evidence.push("reviewed-provider-mapping:v1");
    }
    let (fields, complete) = schema_fields(item.schema.as_ref());
    if intersects(&fields, &CONTENT_FIELDS) {
        if data == "unknown" {
            data = "content-possible";
        }
        evidence.push("schema:content-fields");
    }
    if intersects(&fields, &SECRET_FIELDS) {
        data = "credentials-possible";
        evidence.push("schema:credential-fields");
    }
    if intersects(&fields, &DESTINATION_FIELDS) {
        destination = "caller-selected";
        evidence.push("schema:destination-fields");
        warnings.push("external-transfer-possible");
    }
    if intersects(&fields, &EXECUTION_FIELDS) {
        effect = "execute";
        evidence.push("schema:execution-fields");
        warnings.push("arbitrary-execution-possible");
    }
    let claims = item.annotations.as_ref().and_then(Value::as_object);
    if HINT_KEYS.iter().any(|key| claim(claims, key).is_some()) {
        evidence.push("provider-annotations:unverified");
        if claim(claims, "readOnlyHint") == Some(true) && WRITING_EFFECTS.contains(&effect) {
            warnings.push("annotation-conflicts-with-evidence");
        }
        if claim(claims, "destructiveHint") == Some(true) {
            warnings.push("provider-claims-destructive");
        }
        // A benign claim cannot turn an unknown operation into read-only.
    }
    if !complete || !item.full_schema {
        warnings.push("schema-incomplete");
    }
    if effect == "unknown" {
        warnings.push("effect-unresolved");
    }
    json!({
        "schema_version": MCP_CLASSIFICATION_SCHEMA,
        "effect": effect,
        "data": data,
        "destination": destination,
        "reversibility": reversibility,
        "confidence": if mapping.is_some() && complete && item.full_schema {
            "reviewed-mapping"
        } else {
            "limited"
        },
        "evidence": evidence,
        "warnings": warnings,
        "advisory_only": true,
    })
}

/// A declared boolean claim. A non-boolean value is no claim at all.
fn claim(claims: Option<&Map<String, Value>>, key: &str) -> Option<bool> {
    claims?.get(key)?.as_bool()
}

fn intersects(fields: &BTreeSet<String>, names: &[&str]) -> bool {
    names.iter().any(|name| fields.contains(*name))
}

/// The case-folded property names a declaration mentions, and whether the whole
/// declaration was read.
///
/// Case folding matches the caller's own normalization: full Unicode folding,
/// so a fold-equivalent spelling of `token` is still a credential field.
fn schema_fields(schema: Option<&Value>) -> (BTreeSet<String>, bool) {
    let mut fields = BTreeSet::new();
    let Some(root @ Value::Object(_)) = schema else {
        return (fields, false);
    };
    let mut pending: Vec<(&Value, usize)> = vec![(root, 0)];
    let mut nodes = 0usize;
    while let Some((node, depth)) = pending.pop() {
        nodes += 1;
        if nodes > MAX_NODES || depth > MAX_DEPTH {
            return (fields, false);
        }
        let object = match node {
            Value::Array(items) => {
                if items.len() > MAX_CHILDREN {
                    return (fields, false);
                }
                for child in items {
                    pending.push((child, depth + 1));
                }
                continue;
            }
            Value::Object(object) => object,
            _ => continue,
        };
        if object.len() > MAX_CHILDREN {
            return (fields, false);
        }
        if let Some(Value::Object(properties)) = object.get("properties") {
            if properties.len() > MAX_CHILDREN {
                return (fields, false);
            }
            for (key, child) in properties {
                if key.chars().count() <= MAX_FIELD_NAME_CHARS {
                    fields.insert(caseless::default_case_fold_str(key));
                }
                pending.push((child, depth + 1));
            }
        }
        for key in [
            "items",
            "additionalProperties",
            "allOf",
            "anyOf",
            "oneOf",
            "$defs",
            "definitions",
        ] {
            let Some(child) = object.get(key) else {
                continue;
            };
            match child {
                Value::Object(definitions) if key == "$defs" || key == "definitions" => {
                    if definitions.len() > MAX_CHILDREN {
                        return (fields, false);
                    }
                    for value in definitions.values() {
                        pending.push((value, depth + 1));
                    }
                }
                Value::Object(_) | Value::Array(_) => pending.push((child, depth + 1)),
                _ => {}
            }
        }
        if object.contains_key("$ref") {
            // Resolving references or fetching remote schemas is outside this
            // bounded display classifier. Keep uncertainty explicit.
            return (fields, false);
        }
    }
    (fields, true)
}

#[cfg(test)]
#[path = "mcp_classification_op_tests.rs"]
mod tests;
