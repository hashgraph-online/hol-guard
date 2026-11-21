//! Canonical tools/list boundary for MCP child traffic.
//!
//! Port of `runtime_mcp._canonical_tool_catalog_entry`,
//! `_normalized_tools_catalog_page`, and `_tool_catalog_fingerprint`. The raw
//! `tools` payload is attacker-controlled server output; every check below
//! mirrors the Python validator so the same payload fails closed here.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use guard_contracts::write_canonical_json_utf8;

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `_canonical_tool_catalog_entry` — normalize internal aliases while
/// retaining every advertised field. `name` is emitted last so the canonical
/// entry carries it back (Python re-adds it after the alias pass).
fn canonical_tool_catalog_entry(name: &str, definition: &Value) -> Value {
    let mut canonical = Map::with_capacity(8);
    if let Value::Object(obj) = definition {
        for (key, value) in obj {
            if key == "name" {
                continue;
            }
            canonical.insert(key.clone(), value.clone());
        }
    }
    // input_schema → inputSchema, output_schema → outputSchema (snake wins:
    // Python `setdefault` keeps the existing snake value when both spellings
    // are present, then deletes the snake key).
    for (snake, camel) in [
        ("input_schema", "inputSchema"),
        ("output_schema", "outputSchema"),
    ] {
        if let Some(snake_value) = canonical.get(snake).cloned() {
            canonical
                .entry(camel.to_string())
                .or_insert(snake_value.clone());
            canonical.remove(snake);
        }
    }
    canonical.insert("name".to_string(), Value::String(name.to_string()));
    Value::Object(canonical)
}

/// `_normalized_tools_catalog_page` — reject any malformed `tools` payload and
/// return the `name → entry` page (name key stripped) keyed by raw name.
///
/// `entries` arrives as ordered `[name, definition]` pairs because the raw
/// payload is a JSON array of objects; transport preserves order so duplicate
/// names are still visible for rejection.
///
/// Returns `None` on the same conditions the Python validator rejects:
/// non-dict item, non-string key, blank/non-trimmed name, duplicate name, or
/// an entry that fails canonical serialization (`allow_nan=False` → NaN).
pub fn normalized_tools_catalog_page(entries: &[(String, Value)]) -> Option<Map<String, Value>> {
    let mut page: Map<String, Value> = Map::with_capacity(entries.len());
    for (name, definition) in entries {
        let Value::Object(item) = definition else {
            return None;
        };
        // Python rejects any non-str key — JSON object keys are always
        // strings by construction, so this only needs the dict check above.
        if name.is_empty() || name != name.trim() {
            return None;
        }
        if page.contains_key(name) {
            return None;
        }
        let mut entry = Map::with_capacity(item.len());
        for (key, value) in item {
            entry.insert(key.clone(), value.clone());
        }
        let entry_value = Value::Object(entry);
        // Python serializes `_canonical_tool_catalog_entry` with
        // `allow_nan=False` and rejects the whole page when it can't be
        // serialized — the canonical writer fails on non-finite numbers the
        // same way.
        let mut probe = Vec::with_capacity(128);
        if write_canonical_json_utf8(
            &canonical_tool_catalog_entry(name, &entry_value),
            &mut probe,
        )
        .is_err()
        {
            return None;
        }
        page.insert(name.clone(), entry_value);
    }
    Some(page)
}

/// `_tool_catalog_fingerprint` — sha256 over the canonical-JSON document
/// `{"state", "tools" (sorted by name), "version"}`. Returns
/// `(digest, normalized_page)`; `digest` is `None` when the document can't be
/// canonically serialized (Python propagates `json.dumps`/`allow_nan=False`
/// `ValueError` — the caller surfaces that as a failure, so `None` lets the
/// binding distinguish it from transport loss).
///
/// `entries` are the raw `[name, definition]` pairs. Duplicate names collapse
/// the same way Python's `catalog[name]` map lookup would (later entry wins in
/// a dict) — page-normalization rejects duplicates before hashing, so any
/// duplicates reaching this point resolve by last-write.
pub fn tool_catalog_fingerprint(
    entries: &[(String, Value)],
    state: &str,
    version: &str,
) -> (Option<String>, Option<Map<String, Value>>) {
    // Python iterates `sorted(catalog)` on the name→definition map.
    let mut catalog: BTreeMap<String, Value> = BTreeMap::new();
    for (name, definition) in entries {
        catalog.insert(name.clone(), definition.clone());
    }
    let canonical_tools: Vec<Value> = catalog
        .iter()
        .map(|(name, def)| canonical_tool_catalog_entry(name, def))
        .collect();

    let mut document = Map::with_capacity(4);
    document.insert("state".to_string(), Value::String(state.to_string()));
    document.insert("tools".to_string(), Value::Array(canonical_tools));
    document.insert("version".to_string(), Value::String(version.to_string()));

    let mut material = Vec::with_capacity(512);
    let digest = if write_canonical_json_utf8(&Value::Object(document), &mut material).is_ok() {
        Some(sha256_hex(&material))
    } else {
        None
    };

    let page = normalized_tools_catalog_page(entries);
    (digest, page)
}
