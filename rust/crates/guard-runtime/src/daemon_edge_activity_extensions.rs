//! `GET /v1/command-extensions` and `GET /v1/command-activity/diagnostics`,
//! answered from the packaged catalog as `command_extensions_page` and
//! `command_activity_diagnostics` answer them.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use super::cursor::{sign, verify};
use super::{bad_request, bounded_int, single_values, Parsed, HARNESSES, PROOF_LEVELS};
use super::{NativeReads, ReadConfig};

/// `COMMAND_EXTENSION_SCHEMA_VERSION`.
const EXTENSION_SCHEMA_VERSION: i64 = 2;
const EXTENSION_KEYS: &[&str] = &["limit", "cursor"];
const DIAGNOSTICS_SCHEMA_VERSION: &str = "guard.command-activity-diagnostics.v1";
/// `_ALLOWED_ERROR_CLASSES`.
const ERROR_CLASSES: &[&str] = &[
    "cursor_observer_verify_failed",
    "maintenance_failed",
    "post_record_failed",
    "pre_record_failed",
    "shadow_evaluation_failed",
];

/// The packaged catalog's extension records, sorted by id, or `None` when the
/// catalog cannot be read (the daemon then answers).
fn sorted_extensions() -> Option<Vec<&'static Value>> {
    let records = guard_command::native_command_catalog::packaged_catalog_records().ok()?;
    let mut extensions: Vec<&Value> = records.iter().collect();
    for record in &extensions {
        record.get("extension_id")?.as_str()?;
    }
    extensions.sort_by_key(|record| record["extension_id"].as_str().unwrap_or_default());
    Some(extensions)
}

/// `GET /v1/command-extensions`.
pub(in crate::daemon_edge) fn page(query: &str, config: &ReadConfig) -> Option<(u16, Value)> {
    match extensions_page(query, &config.token)? {
        Ok(body) => Some((200, body)),
        Err(code) => Some(bad_request(code)),
    }
}

fn extensions_page(query: &str, key: &[u8]) -> Parsed<Value> {
    let mut values = check!(single_values(query, EXTENSION_KEYS));
    let limit = check!(bounded_int(values.remove("limit"), 50));
    if !(1..=100).contains(&limit) {
        return Some(Err("limit_out_of_range"));
    }
    let after = match values.remove("cursor") {
        None => None,
        Some(cursor) => {
            let payload = check!(verify(&cursor, key));
            match (payload.get("kind"), payload.get("after")) {
                (Some(Value::String(kind)), Some(Value::String(after))) if kind == "extensions" => {
                    Some(after.clone())
                }
                _ => return Some(Err("invalid_cursor")),
            }
        }
    };
    let mut extensions = sorted_extensions()?;
    if let Some(after) = &after {
        // Python compares code points; Rust compares UTF-8 bytes, which order
        // the same way.
        extensions.retain(|record| record["extension_id"].as_str() > Some(after.as_str()));
    }
    let size = usize::try_from(limit).ok()?;
    let page = &extensions[..extensions.len().min(size)];
    let next_cursor = match page.last() {
        Some(last) if extensions.len() > size => {
            let id = last["extension_id"].as_str()?;
            Value::String(sign(&json!({"kind": "extensions", "after": id}), key)?)
        }
        _ => Value::Null,
    };
    let items = page
        .iter()
        .map(|record| extension_payload(record))
        .collect::<Option<Vec<_>>>()?;
    Some(Ok(json!({
        "schema_version": EXTENSION_SCHEMA_VERSION,
        "source": "built-in",
        "items": items,
        "next_cursor": next_cursor,
    })))
}

/// `_extension_payload`.
fn extension_payload(record: &Value) -> Option<Value> {
    let field = |name: &str| record.get(name).cloned();
    let rules = record.get("rules")?.as_array()?;
    let rule_payloads = rules
        .iter()
        .map(|rule| {
            let variant_ids = rule
                .get("safe_variants")?
                .as_array()?
                .iter()
                .map(|variant| variant.get("variant_id").cloned())
                .collect::<Option<Vec<_>>>()?;
            Some(json!({
                "rule_id": rule.get("rule_id")?,
                "title": rule.get("title")?,
                "description": rule.get("description")?,
                "severity": rule.get("severity")?,
                "risk_classes": rule.get("risk_classes")?,
                "action_classes": rule.get("action_classes")?,
                "default_mode": rule.get("default_mode")?,
                "safe_variant_ids": variant_ids,
                "compatibility_fallback": rule.get("compatibility_fallback")?,
            }))
        })
        .collect::<Option<Vec<_>>>()?;
    Some(json!({
        "extension_id": field("extension_id")?,
        "version": field("version")?,
        "name": field("name")?,
        "description": field("description")?,
        "enabled": true,
        "required": field("required")?,
        "source": field("source")?,
        "dependencies": field("dependencies")?,
        "conflicts": field("conflicts")?,
        "delegated_protection": field("delegated_protection")?,
        "action_classes": field("action_classes")?,
        "risk_classes": field("risk_classes")?,
        "rule_count": rules.len(),
        "rules": rule_payloads,
    }))
}

/// `_allowlists()`: the stable ids the diagnostics snapshot may name.
fn allowlists() -> Option<Value> {
    let extensions = sorted_extensions()?;
    let mut extension_ids = BTreeSet::new();
    let mut rule_ids = BTreeSet::new();
    for record in &extensions {
        extension_ids.insert(record["extension_id"].as_str()?);
        for rule in record.get("rules")?.as_array()? {
            rule_ids.insert(rule.get("rule_id")?.as_str()?);
        }
    }
    Some(json!({
        "harnesses": HARNESSES,
        "extension_ids": extension_ids,
        "rule_ids": rule_ids,
        "proof_levels": PROOF_LEVELS,
        "error_classes": ERROR_CLASSES,
    }))
}

/// `GET /v1/command-activity/diagnostics`.
pub(in crate::daemon_edge) fn diagnostics(
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value)> {
    let Value::Object(snapshot) =
        reads.store_call(config, "command_activity_diagnostics", allowlists()?)?
    else {
        return None;
    };
    let mut body = Map::new();
    body.insert("schema_version".into(), DIAGNOSTICS_SCHEMA_VERSION.into());
    body.insert(
        "schemas".into(),
        json!({
            "activity": "1.0.0",
            "api": super::API_SCHEMA_VERSION,
            "health": "1.0.0",
            "maintenance": "guard.command-activity-maintenance.v1",
            "shadow": "guard.command-shadow.v1",
        }),
    );
    // `{..., **payload}`: the snapshot's keys win.
    body.extend(snapshot);
    Some((200, Value::Object(body)))
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_activity_extensions_tests.rs"]
mod tests;
