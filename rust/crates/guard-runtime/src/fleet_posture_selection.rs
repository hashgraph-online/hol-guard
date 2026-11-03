//! Row selection and item shaping for `fleet_posture_inventory`: which local
//! inventory rows fleet posture reports, and their contract items.

use std::collections::{BTreeMap, HashSet};

use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::cloud_request_text::py_truthy;
use crate::guard_store_json::{py_prefix, py_str, py_strip};
use crate::guard_store_local_cli::parse_utc;
use crate::policy_bundle_time::micros_to_utc_isoformat;
use crate::runner_authority_op::ERR_INVALID;

const MAX_NAME_CHARS: usize = 200;

const HARNESS_IDS: [&str; 18] = [
    "antigravity",
    "claude-code",
    "cline",
    "codex",
    "copilot",
    "cursor",
    "devin",
    "gemini",
    "grok",
    "hermes",
    "kimi",
    "muse",
    "omp",
    "openclaw",
    "opencode",
    "paseo",
    "pi",
    "zcode",
];

fn item_kind(artifact_type: &str) -> Option<&'static str> {
    Some(match artifact_type {
        "skill" | "skill_file" => "skill",
        "mcp_server" => "mcp_server",
        "plugin" | "plugin-file" | "extension" => "plugin",
        "package" => "package",
        "hook" | "guard_hook" => "hook",
        _ => return None,
    })
}

fn item_source(scope: &str) -> &'static str {
    match scope {
        "marketplace" => "marketplace",
        "project" | "workspace" => "project",
        "global" | "user" => "user",
        "lockfile" => "lockfile",
        "config" => "config",
        _ => "unknown",
    }
}

/// `str(value or "")`.
fn text_or_empty(value: Option<&Value>) -> String {
    match value {
        Some(value) if py_truthy(value) => py_str(value).unwrap_or_default(),
        _ => String::new(),
    }
}

/// `iso(utc)`: whole seconds with a `Z` suffix.
pub(super) fn iso(micros: i64) -> Option<String> {
    micros_to_utc_isoformat(micros - micros.rem_euclid(1_000_000), "Z")
}

/// `parse_timestamp`: only strings parse.
pub(super) fn timestamp(value: Option<&Value>) -> Option<i64> {
    value.filter(|value| value.is_string()).and_then(parse_utc)
}

fn normalized_timestamp(value: Option<&Value>) -> Option<String> {
    iso(timestamp(value)?)
}

/// `normalized_hash`: a `sha256:` digest of 64 lowercase hex digits.
fn normalized_hash(value: Option<&Value>) -> Value {
    let Some(text) = value.and_then(Value::as_str) else {
        return Value::Null;
    };
    let lowered = py_strip(text).to_lowercase();
    let digits = lowered.strip_prefix("sha256:").unwrap_or(&lowered);
    if digits.len() == 64
        && digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Value::from(format!("sha256:{digits}"))
    } else {
        Value::Null
    }
}

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// `keyed_digest`: an HMAC under the per-install secret, so guessable paths
/// cannot be reversed by a dictionary search.
fn keyed_digest(key: &[u8], text: &str) -> Result<String, &'static str> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| ERR_INVALID)?;
    mac.update(text.as_bytes());
    Ok(format!(
        "sha256:{}",
        hex::encode(mac.finalize().into_bytes())
    ))
}

fn joined(item: &Map<String, Value>, parts: &[&str]) -> String {
    parts
        .iter()
        .map(|part| text_or_empty(item.get(*part)))
        .collect::<Vec<_>>()
        .join("\0")
}

fn item_key(item: &Map<String, Value>) -> String {
    sha256_hex(&joined(item, &["kind", "harness", "name", "pathHash"]))[..32].to_owned()
}

pub(super) fn item_fingerprint(item: &Map<String, Value>) -> String {
    sha256_hex(&joined(item, &["version", "hash", "source"]))[..16].to_owned()
}

/// `item_digest`: rows sorted lexicographically, as compact JSON.
pub(super) fn item_digest<'a>(items: impl Iterator<Item = &'a Map<String, Value>>) -> String {
    let mut rows: Vec<Vec<String>> = items
        .map(|item| {
            ["kind", "name", "version", "hash", "harness"]
                .iter()
                .map(|cell| match item.get(*cell) {
                    None | Some(Value::Null) => String::new(),
                    Some(value) => py_str(value).unwrap_or_default(),
                })
                .collect()
        })
        .collect();
    rows.sort();
    let text = serde_json::to_string(&rows).unwrap_or_default();
    format!("sha256:{}", sha256_hex(&text))
}

/// A row fleet posture reports, with its normalized fields.
pub(super) struct Reportable<'a> {
    pub(super) index: usize,
    row: &'a Map<String, Value>,
    pub(super) kind: &'static str,
    pub(super) harness: String,
    pub(super) name: String,
    pub(super) first_seen_at: String,
    pub(super) last_seen_at: String,
    pub(super) config_path: Option<String>,
}

fn not_present(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(flag)) => !flag,
        Some(Value::Number(number)) => number.as_f64() == Some(0.0),
        Some(Value::String(text)) => text == "0",
        _ => false,
    }
}

/// `reportable_inventory_rows`: installed, known kind and harness, named and
/// validly timestamped. Rows that map to the same kind, harness, name as sent
/// and config path collapse to the first one.
pub(super) fn reportable<'a>(rows: &[&'a Value]) -> Result<Vec<Reportable<'a>>, &'static str> {
    let mut seen = HashSet::new();
    let mut selected = Vec::new();
    for (index, row) in rows.iter().copied().enumerate() {
        let row = row.as_object().ok_or(ERR_INVALID)?;
        if row.get("removed_at").is_some_and(py_truthy) || not_present(row.get("present")) {
            continue;
        }
        let Some(kind) = item_kind(&text_or_empty(row.get("artifact_type"))) else {
            continue;
        };
        let harness = text_or_empty(row.get("harness"));
        let name = py_strip(&text_or_empty(row.get("artifact_name"))).to_owned();
        if !HARNESS_IDS.contains(&harness.as_str()) || name.is_empty() {
            continue;
        }
        let (Some(first_seen_at), Some(last_seen_at)) = (
            normalized_timestamp(row.get("first_seen_at")),
            normalized_timestamp(row.get("last_seen_at")),
        ) else {
            continue;
        };
        let config_path = row
            .get("config_path")
            .and_then(Value::as_str)
            .filter(|path| !path.is_empty())
            .map(str::to_owned);
        let identity = (
            kind,
            harness.clone(),
            py_prefix(&name, MAX_NAME_CHARS),
            config_path.clone().unwrap_or_default(),
        );
        if seen.insert(identity) {
            selected.push(Reportable {
                index,
                row,
                kind,
                harness,
                name,
                first_seen_at,
                last_seen_at,
                config_path,
            });
        }
    }
    Ok(selected)
}

/// `inventory_items`: contract items keyed and sorted by `item_key`.
pub(super) fn inventory_items(
    rows: &[&Value],
    key: &[u8],
) -> Result<BTreeMap<String, Map<String, Value>>, &'static str> {
    let mut items = BTreeMap::new();
    for selected in reportable(rows)? {
        let path_hash = match &selected.config_path {
            Some(path) => Value::from(keyed_digest(key, path)?),
            None => Value::Null,
        };
        let source = item_source(&text_or_empty(selected.row.get("source_scope")));
        let item: Map<String, Value> = [
            ("kind", Value::from(selected.kind)),
            (
                "name",
                Value::from(py_prefix(&selected.name, MAX_NAME_CHARS)),
            ),
            ("version", Value::Null),
            ("hash", normalized_hash(selected.row.get("artifact_hash"))),
            ("harness", Value::from(selected.harness)),
            ("source", Value::from(source)),
            ("pathHash", path_hash),
            ("firstSeenAt", Value::from(selected.first_seen_at)),
            ("lastSeenAt", Value::from(selected.last_seen_at)),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
        items.entry(item_key(&item)).or_insert(item);
    }
    Ok(items)
}
