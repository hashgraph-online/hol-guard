//! `fleet_aibom_rows`: the AIBOM-detected items fleet posture reports next to
//! the local inventory table.
//!
//! Guard writes an inventory table row only when it scans an artifact itself,
//! so machines protected through hooks keep an empty table while the AIBOM
//! collection sees every skill, MCP server, plugin and hook. Each collection
//! stores a compact copy of what it found and fleet posture reports the union
//! of both sources. Python holds the locks and the stored state; this module
//! decides the rows:
//!
//! - `remember` turns one collection into the rows to store, restoring each
//!   redacted path (`{home}/...`) to the absolute form the table uses, keeping
//!   when each item was first seen, and keeping the project rows of workspaces
//!   this collection did not scan.
//! - `union` names the stored rows the table does not already hold installed.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde_json::{json, Map, Value};

use crate::aibom_paths::py_join;
use crate::cloud_request_text::py_truthy;
use crate::guard_paths::python_realpath_lax;
use crate::guard_store_json::py_strip;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

use super::selection::{item_kind, normalized_timestamp, text_or_empty, HARNESS_IDS};

/// `MAX_AIBOM_ROWS`: one machine rarely carries more than a few hundred
/// items; the cap bounds the stored row.
const MAX_AIBOM_ROWS: usize = 5_000;
/// Rows or items one request may carry across all of its chunks.
const MAX_ENTRIES: usize = 50_000;
/// `ITEM_SOURCE_SCOPES`: the scopes an item id may name.
const ITEM_SOURCE_SCOPES: [&str; 7] = [
    "marketplace",
    "project",
    "workspace",
    "global",
    "user",
    "lockfile",
    "config",
];

fn is_project_scope(scope: Option<&str>) -> bool {
    matches!(scope, Some("project" | "workspace"))
}

/// A list the caller split into chunks the native request parser accepts:
/// each entry is a chunk (joined back in order) or a single value.
fn chunked(value: Option<&Value>) -> Result<Vec<&Value>, &'static str> {
    let mut entries = Vec::new();
    for entry in value.and_then(Value::as_array).ok_or(ERR_INVALID)? {
        match entry {
            Value::Array(chunk) => entries.extend(chunk),
            single => entries.push(single),
        }
        if entries.len() > MAX_ENTRIES {
            return Err(ERR_INVALID);
        }
    }
    Ok(entries)
}

fn optional_text<'a>(
    args: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, &'static str> {
    match args.get(key) {
        Some(Value::String(text)) => Ok(Some(text.as_str())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(ERR_INVALID),
    }
}

/// `os.path.realpath(path)` for an absolute path, the text itself otherwise.
fn path_identity(path: Option<&Value>) -> String {
    match path.and_then(Value::as_str) {
        Some(text) if !text.is_empty() => python_realpath_lax(Path::new(text)).map_or_else(
            |_| text.to_owned(),
            |real| real.to_string_lossy().into_owned(),
        ),
        _ => String::new(),
    }
}

/// `_row_key`: harness, contract kind, stripped name and path identity.
fn row_key(row: &Value) -> String {
    let kind = item_kind(&text_or_empty(row.get("artifact_type"))).unwrap_or("");
    let name = text_or_empty(row.get("artifact_name"));
    [
        text_or_empty(row.get("harness")),
        kind.to_owned(),
        py_strip(&name).to_owned(),
        path_identity(row.get("config_path")),
    ]
    .join("\0")
}

/// `_installed`: not removed, and `present` is not `0`, `False` or `"0"`.
fn installed(row: &Value) -> bool {
    if row.get("removed_at").is_some_and(py_truthy) {
        return false;
    }
    match row.get("present") {
        Some(Value::Bool(false)) => false,
        Some(Value::Number(number)) => number.as_f64() != Some(0.0),
        Some(Value::String(text)) => text != "0",
        _ => true,
    }
}

/// `_absolute_path`: the absolute path a redacted `configPath` came from,
/// when the collection's root for its prefix is known.
fn absolute_path(redacted: &str, home: Option<&str>, workspace: Option<&str>) -> String {
    for (prefix, root) in [("{home}/", home), ("{workspace}/", workspace)] {
        if let Some(rest) = redacted.strip_prefix(prefix) {
            return match root {
                Some(root) => py_join(Path::new(root), rest)
                    .to_string_lossy()
                    .into_owned(),
                None => redacted.to_owned(),
            };
        }
    }
    redacted.to_owned()
}

/// `_source_scope`: the scope the item id names, else where its file lives.
fn source_scope(
    item_id: &str,
    harness: &str,
    config_path: Option<&str>,
    workspace: Option<&str>,
) -> Option<&'static str> {
    let segments: Vec<&str> = item_id.split(':').collect();
    let inner = segments
        .get(1..segments.len().saturating_sub(1))
        .unwrap_or(&[]);
    let own_prefix = format!("{harness}-");
    for &segment in inner {
        let scope = segment.strip_prefix(own_prefix.as_str()).unwrap_or(segment);
        if let Some(known) = ITEM_SOURCE_SCOPES.iter().find(|known| **known == scope) {
            return Some(*known);
        }
    }
    let path = Path::new(config_path.filter(|path| !path.is_empty())?);
    if !path.is_absolute() {
        return None;
    }
    // Without a scanned workspace the collection only reads user-wide configuration.
    match workspace {
        Some(workspace) if path.starts_with(workspace) => Some("project"),
        _ => Some("global"),
    }
}

/// One reportable item of a collection, as a row to store.
struct ItemRow {
    snapshot: usize,
    item: usize,
    row: Map<String, Value>,
}

fn item_rows(
    snapshots: &[Value],
    home: Option<&str>,
    workspace: Option<&str>,
) -> Result<Vec<ItemRow>, &'static str> {
    let mut rows = Vec::new();
    for (snapshot_index, snapshot) in snapshots.iter().enumerate() {
        let snapshot = snapshot.as_object().ok_or(ERR_INVALID)?;
        let harness = snapshot
            .get("harness")
            .and_then(Value::as_str)
            .ok_or(ERR_INVALID)?;
        let items = chunked(snapshot.get("items"))?;
        let Some(seen_at) = normalized_timestamp(snapshot.get("generated_at")) else {
            continue;
        };
        if !HARNESS_IDS.contains(&harness) {
            continue;
        }
        for (item_index, item) in items.into_iter().enumerate() {
            // An explicit artifact type decides; the item kind only stands in
            // when there is none, so a type fleet posture does not report (a
            // Cline host, say) never becomes a plugin.
            let explicit = text_or_empty(item.get("artifact_type"));
            let artifact_type = if explicit.is_empty() {
                text_or_empty(item.get("item_kind"))
            } else {
                explicit
            };
            let raw_name = text_or_empty(item.get("name"));
            let name = py_strip(&raw_name);
            if item_kind(&artifact_type).is_none() || name.is_empty() {
                continue;
            }
            let config_path = item
                .get("config_path")
                .and_then(Value::as_str)
                .filter(|redacted| !redacted.is_empty())
                .map(|redacted| absolute_path(redacted, home, workspace));
            let item_id = text_or_empty(item.get("item_id"));
            let scope = source_scope(&item_id, harness, config_path.as_deref(), workspace);
            let row = json!({
                "artifact_type": artifact_type,
                "harness": harness,
                "artifact_name": name,
                "source_scope": scope,
                "config_path": config_path,
                "first_seen_at": seen_at,
                "last_seen_at": seen_at,
            });
            let Value::Object(row) = row else {
                return Err(ERR_INVALID);
            };
            rows.push(ItemRow {
                snapshot: snapshot_index,
                item: item_index,
                row,
            });
        }
    }
    Ok(rows)
}

/// `_replace_rows`: the collection's rows, then the previous project rows of
/// workspaces it did not scan. Each new row names the snapshot and item it
/// came from so the caller adds the fields it already holds.
fn remember(args: &Map<String, Value>) -> KindResult {
    let home = optional_text(args, "home")?;
    let workspace = optional_text(args, "workspace")?;
    let previous = chunked(args.get("previous"))?;
    let snapshots = args
        .get("snapshots")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    let mut first_seen: HashMap<String, Option<&Value>> = HashMap::new();
    for row in &previous {
        first_seen.insert(row_key(row), row.get("first_seen_at"));
    }
    let mut keys = HashSet::new();
    let mut rows = Vec::new();
    for mut entry in item_rows(snapshots, home, workspace)? {
        let key = row_key(&Value::Object(entry.row.clone()));
        if keys.contains(&key) || keys.len() >= MAX_AIBOM_ROWS {
            continue;
        }
        if let Some(earlier) = first_seen
            .get(&key)
            .and_then(|seen| normalized_timestamp(*seen))
        {
            entry
                .row
                .insert("first_seen_at".to_owned(), Value::from(earlier));
        }
        let scope = entry.row.get("source_scope").and_then(Value::as_str);
        if is_project_scope(scope) {
            entry
                .row
                .insert("collection_workspace".to_owned(), json!(workspace));
        }
        entry
            .row
            .insert("snapshot".to_owned(), Value::from(entry.snapshot));
        entry.row.insert("item".to_owned(), Value::from(entry.item));
        keys.insert(key);
        rows.push(Value::Object(entry.row));
    }
    let scanned = workspace.map_or(Value::Null, Value::from);
    let mut kept = Vec::new();
    for (index, row) in previous.iter().enumerate() {
        let kept_workspace = row.get("collection_workspace").unwrap_or(&Value::Null);
        let scope = row.get("source_scope").and_then(Value::as_str);
        if !is_project_scope(scope) || kept_workspace.is_null() || *kept_workspace == scanned {
            continue;
        }
        let key = row_key(row);
        if !keys.contains(&key) && keys.len() < MAX_AIBOM_ROWS {
            keys.insert(key);
            kept.push(index);
        }
    }
    Ok(json!({"rows": rows, "kept": kept}))
}

/// `fleet_inventory_rows`: the stored rows the table does not hold installed.
/// A row Guard marked removed does not hide the same item found installed again.
fn union(args: &Map<String, Value>) -> KindResult {
    let known: HashSet<String> = chunked(args.get("table"))?
        .into_iter()
        .filter(|row| installed(row))
        .map(row_key)
        .collect();
    let kept: Vec<usize> = chunked(args.get("stored"))?
        .into_iter()
        .enumerate()
        .filter(|(_, row)| !known.contains(&row_key(row)))
        .map(|(index, _)| index)
        .collect();
    Ok(json!({"kept": kept}))
}

pub(super) fn dispatch(args: &Map<String, Value>) -> KindResult {
    match args.get("op").and_then(Value::as_str) {
        Some("remember") => remember(args),
        Some("union") => union(args),
        _ => Err(ERR_INVALID),
    }
}

#[cfg(test)]
#[path = "fleet_posture_aibom_tests.rs"]
mod tests;
