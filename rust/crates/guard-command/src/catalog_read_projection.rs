//! Snapshot projections for [`crate::catalog_read_model`]: explicit field
//! allowlists, source validation and one-time HTML-safe encoding. A missing
//! required field or an unbounded value fails the whole snapshot closed.

use std::collections::BTreeSet;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::catalog_read_query::hex_prefix;

const MAX_PERMISSIONS_PER_EXTENSION: usize = 512;
const MAX_RULES_PER_EXTENSION: usize = 4096;
const MAX_MCP_TOOLS_PER_EXTENSION: usize = 4096;
const MAX_STRING_CHARS: usize = 8192;
const MAX_VALUE_DEPTH: usize = 6;

/// Index summaries carry what list views filter, route and label by
/// (aliases, executables, description, ecosystems, action classes) so a list
/// never needs every detail.
const INDEX_FIELDS: &[&str] = &[
    "action_classes",
    "aliases",
    "description",
    "ecosystem_ids",
    "executables",
    "extension_id",
    "icon",
    "name",
    "permission_count",
    "publisher",
    "required",
    "risk_classes",
    "rule_count",
    "source",
    "trust_class",
    "version",
];
const DETAIL_FIELDS: &[&str] = &[
    "action_classes",
    "aliases",
    "conflicts",
    "delegated_protection",
    "dependencies",
    "description",
    "ecosystem_ids",
    "executables",
    "extension_id",
    "icon",
    "name",
    "permission_count",
    "project_markers",
    "publisher",
    "reference_urls",
    "required",
    "risk_classes",
    "rule_count",
    "safer_alternatives",
    "schema_version",
    "source",
    "trust_class",
    "version",
];
/// Present only on some extensions (MCP surfaces); projected when present.
const OPTIONAL_DETAIL_FIELDS: &[&str] = &["mcp_launch", "surface"];
const OPTIONAL_INDEX_FIELDS: &[&str] = &["surface"];
/// Source fields projected elsewhere: `enabled`/`activation` become
/// `catalog_defaults`; collections are paged separately.
#[cfg(test)]
pub(crate) const EXTENSION_FIELDS_NOT_IN_DETAIL: &[&str] =
    &["activation", "enabled", "mcp_tools", "permissions", "rules"];
pub(crate) const PERMISSION_FIELDS: &[&str] = &[
    "action_classes",
    "baseline_floor",
    "configurable",
    "conflicts",
    "default_enabled",
    "dependencies",
    "deprecated",
    "description",
    "example_command",
    "extension_id",
    "family",
    "fixed_reason",
    "implementation_version",
    "implied_permissions",
    "introduced_version",
    "label",
    "permission_id",
    "replacement_permission_id",
    "risk_tier",
    "rule_ids",
    "safer_guidance",
    "schema_version",
    "typed_capabilities",
];
pub(crate) const RULE_FIELDS: &[&str] = &[
    "action_classes",
    "compatibility_fallback",
    "default_mode",
    "description",
    "family",
    "matcher_contract_digest",
    "matcher_kind",
    "risk_classes",
    "rule_id",
    "rule_version",
    "safe_variants",
    "safer_alternatives",
    "severity",
    "title",
];
pub(crate) const MCP_TOOL_FIELDS: &[&str] = &["name", "state"];

#[derive(Debug)]
pub(crate) struct ExtensionEntry {
    pub(crate) id: String,
    pub(crate) source: String,
    pub(crate) trust_class: String,
    pub(crate) surface: Option<String>,
    pub(crate) risk_classes: BTreeSet<String>,
    pub(crate) search_text: String,
    pub(crate) index_item: Box<[u8]>,
    pub(crate) detail: Box<[u8]>,
    pub(crate) permissions: Vec<Box<[u8]>>,
    pub(crate) rules: Vec<Box<[u8]>>,
    pub(crate) mcp_tools: Vec<Box<[u8]>>,
    /// Permission IDs in collection order, for catalog-wide uniqueness.
    pub(crate) permission_ids: Vec<String>,
    /// Lowercased search text per permission, aligned with `permissions`.
    pub(crate) permission_search: Vec<String>,
    /// Whether the source declares `mcp_tools`, so detail can mirror it exactly.
    pub(crate) has_mcp_tools: bool,
}

impl ExtensionEntry {
    pub(crate) fn encoded_bytes(&self) -> usize {
        let collection = |items: &[Box<[u8]>]| items.iter().map(|item| item.len()).sum::<usize>();
        self.index_item.len()
            + self.detail.len()
            + collection(&self.permissions)
            + collection(&self.rules)
            + collection(&self.mcp_tools)
            + self
                .permission_search
                .iter()
                .map(String::len)
                .sum::<usize>()
    }
}

pub(crate) fn extension_entry(value: &Value) -> Result<ExtensionEntry, &'static str> {
    let source = value
        .as_object()
        .ok_or("catalog_read_model_extension_shape")?;
    validate_value(value, 0)?;
    let text = |key: &str| -> Result<String, &'static str> {
        source
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or("catalog_read_model_extension_field")
    };
    let id = text("extension_id")?;
    let enabled = source
        .get("enabled")
        .and_then(Value::as_bool)
        .ok_or("catalog_read_model_extension_field")?;
    let activation = text("activation")?;
    let surface = match source.get("surface") {
        None | Some(Value::Null) => None,
        Some(Value::String(surface)) => Some(surface.clone()),
        Some(_) => return Err("catalog_read_model_extension_field"),
    };
    let strings = |key: &str| -> Vec<String> {
        source
            .get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    let permissions = collection(source, "permissions", "permission_id", PERMISSION_FIELDS)?;
    let (permission_ids, permission_search) =
        permission_search(source, &id, &text("name")?, &strings("executables"));
    let rules = collection(source, "rules", "rule_id", RULE_FIELDS)?;
    let has_mcp_tools = source.contains_key("mcp_tools");
    let mcp_tools = if has_mcp_tools {
        collection(source, "mcp_tools", "name", MCP_TOOL_FIELDS)?
    } else {
        Vec::new()
    };
    if permissions.len() > MAX_PERMISSIONS_PER_EXTENSION
        || rules.len() > MAX_RULES_PER_EXTENSION
        || mcp_tools.len() > MAX_MCP_TOOLS_PER_EXTENSION
    {
        return Err("catalog_read_model_collection_limit");
    }
    let canonical = serde_json::to_vec(value).map_err(|_| "catalog_read_model_encode")?;
    let revision = format!("er1-{}", hex_prefix(&Sha256::digest(&canonical), 32));
    let defaults = serde_json::json!({"enabled": enabled, "activation": activation});
    let mut index = project(source, INDEX_FIELDS, OPTIONAL_INDEX_FIELDS)?;
    index.insert("catalog_defaults".into(), defaults.clone());
    index.insert("content_revision".into(), Value::String(revision.clone()));
    let mut detail = project(source, DETAIL_FIELDS, OPTIONAL_DETAIL_FIELDS)?;
    detail.insert("catalog_defaults".into(), defaults);
    detail.insert("content_revision".into(), Value::String(revision));
    let mut search_parts = vec![id.clone(), text("name")?, text("description")?];
    search_parts.extend(
        source
            .get("publisher")
            .and_then(Value::as_str)
            .map(str::to_owned),
    );
    for key in ["aliases", "ecosystem_ids", "executables"] {
        search_parts.extend(strings(key));
    }
    Ok(ExtensionEntry {
        source: text("source")?,
        trust_class: text("trust_class")?,
        surface,
        risk_classes: strings("risk_classes").into_iter().collect(),
        search_text: search_parts.join("\n").to_lowercase(),
        index_item: encode(&Value::Object(index))?,
        detail: encode(&Value::Object(detail))?,
        permissions,
        rules,
        mcp_tools,
        permission_ids,
        permission_search,
        has_mcp_tools,
        id,
    })
}

/// Per-permission search text: the permission's label, example, permission
/// ID, description and family plus its extension's name, ID and executables.
/// Field order is irrelevant: queries match whitespace-free terms.
fn permission_search(
    source: &Map<String, Value>,
    extension_id: &str,
    extension_name: &str,
    executables: &[String],
) -> (Vec<String>, Vec<String>) {
    let extension_text = [extension_name, extension_id]
        .into_iter()
        .chain(executables.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join("\n");
    source
        .get("permissions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .map(|permission| {
            let field = |key: &str| permission.get(key).and_then(Value::as_str).unwrap_or("");
            let text = [
                field("label"),
                field("example_command"),
                field("permission_id"),
                field("description"),
                field("family"),
                &extension_text,
            ]
            .join("\n")
            .to_lowercase();
            (field("permission_id").to_owned(), text)
        })
        .unzip()
}

/// Items in source order (the order v1 consumers see); duplicate IDs fail closed.
fn collection(
    source: &Map<String, Value>,
    key: &str,
    id_key: &str,
    fields: &[&str],
) -> Result<Vec<Box<[u8]>>, &'static str> {
    let items = source
        .get(key)
        .and_then(Value::as_array)
        .ok_or("catalog_read_model_collection_shape")?;
    let mut seen = BTreeSet::new();
    items
        .iter()
        .map(|item| {
            let object = item
                .as_object()
                .ok_or("catalog_read_model_collection_shape")?;
            let id = object
                .get(id_key)
                .and_then(Value::as_str)
                .ok_or("catalog_read_model_collection_shape")?;
            if !seen.insert(id) {
                return Err("catalog_read_model_duplicate_collection_id");
            }
            encode(&Value::Object(project(object, fields, &[])?))
        })
        .collect()
}

/// Explicit allowlist projection; a missing required field fails closed.
fn project(
    source: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> Result<Map<String, Value>, &'static str> {
    let mut projected = Map::new();
    for field in required {
        let value = source
            .get(*field)
            .ok_or("catalog_read_model_projection_field_missing")?;
        projected.insert((*field).to_owned(), value.clone());
    }
    for field in optional {
        if let Some(value) = source.get(*field) {
            projected.insert((*field).to_owned(), value.clone());
        }
    }
    Ok(projected)
}

fn validate_value(value: &Value, depth: usize) -> Result<(), &'static str> {
    if depth > MAX_VALUE_DEPTH {
        return Err("catalog_read_model_value_depth");
    }
    match value {
        Value::String(text) if text.chars().count() > MAX_STRING_CHARS => {
            Err("catalog_read_model_string_limit")
        }
        Value::Array(items) => items
            .iter()
            .try_for_each(|item| validate_value(item, depth + 1)),
        Value::Object(object) => object
            .values()
            .try_for_each(|item| validate_value(item, depth + 1)),
        _ => Ok(()),
    }
}

/// Compact sorted-key JSON with the daemon's HTML-safe escaping applied, so
/// byte budgets measure exactly what is written.
fn encode(value: &Value) -> Result<Box<[u8]>, &'static str> {
    let raw = serde_json::to_vec(value).map_err(|_| "catalog_read_model_encode")?;
    Ok(escape_json_for_html(&raw).into_boxed_slice())
}

pub(crate) fn escape_json_for_html(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    for byte in raw {
        match byte {
            b'&' => out.extend_from_slice(b"\\u0026"),
            b'<' => out.extend_from_slice(b"\\u003c"),
            b'>' => out.extend_from_slice(b"\\u003e"),
            _ => out.push(*byte),
        }
    }
    out
}
