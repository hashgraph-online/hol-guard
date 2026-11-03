//! `fleet_posture_inventory`: the inventory section of `fleet-posture/v1`
//! and the plan for sending it.
//!
//! Python collects the local inventory rows, the machine, client, tool and
//! policy sections. This module selects the rows fleet posture reports,
//! shapes them into contract items, plans the transmission against the last
//! snapshot Guard Cloud accepted, and fits the payload under its byte cap.
//!
//! Each send is planned against that snapshot: a first send, a requested
//! refresh or a weekly refresh goes out as `full` (or as a stream of deltas
//! when the inventory does not fit one request), everything else as a
//! `delta`. Building never writes state: the caller commits `next_state`
//! only after Guard Cloud accepted the request.

use std::collections::{BTreeMap, HashSet};

use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::cloud_request_text::py_truthy;
use crate::guard_store_json::{py_prefix, py_str, py_strip};
use crate::guard_store_local_cli::parse_utc;
use crate::policy_bundle_time::micros_to_utc_isoformat;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const SCHEMA_VERSION: &str = "fleet-posture/v1";
const MAX_ITEMS_PER_SYNC: usize = 250;
const MAX_TOOLS: usize = 32;
const MAX_ARTIFACT_COUNT: usize = 100_000;
const MAX_NAME_CHARS: usize = 200;
/// `FULL_REFRESH_AFTER`: a full inventory older than a week is resent.
const FULL_REFRESH_AFTER_MICROS: i64 = 7 * 24 * 60 * 60 * 1_000_000;
/// Rows one request may carry; the inventory table plus the AIBOM rows stay
/// far below this on any real machine.
const MAX_ROWS: usize = 50_000;

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
fn iso(micros: i64) -> Option<String> {
    micros_to_utc_isoformat(micros - micros.rem_euclid(1_000_000), "Z")
}

/// `parse_timestamp`: only strings parse.
fn timestamp(value: Option<&Value>) -> Option<i64> {
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

fn item_fingerprint(item: &Map<String, Value>) -> String {
    sha256_hex(&joined(item, &["version", "hash", "source"]))[..16].to_owned()
}

/// `item_digest`: rows sorted lexicographically, as compact JSON.
fn item_digest<'a>(items: impl Iterator<Item = &'a Map<String, Value>>) -> String {
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
struct Reportable<'a> {
    index: usize,
    row: &'a Map<String, Value>,
    kind: &'static str,
    harness: String,
    name: String,
    first_seen_at: String,
    last_seen_at: String,
    config_path: Option<String>,
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
fn reportable(rows: &[Value]) -> Result<Vec<Reportable<'_>>, &'static str> {
    let mut seen = HashSet::new();
    let mut selected = Vec::new();
    for (index, row) in rows.iter().enumerate() {
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
fn inventory_items(
    rows: &[Value],
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

fn tracked(item: &Map<String, Value>) -> Value {
    json!({
        "k": item.get("kind"),
        "n": item.get("name"),
        "h": item.get("harness"),
        "x": item.get("hash"),
        "f": item_fingerprint(item),
    })
}

fn field(value: &Value, key: &str) -> Value {
    value.get(key).cloned().unwrap_or(Value::Null)
}

/// What a removal entry can name: the contract carries no path hash.
fn identity(kind: Value, harness: Value, name: Value, hash: Value) -> String {
    Value::Array(vec![kind, harness, name, hash]).to_string()
}

struct Plan {
    mode: &'static str,
    items: Vec<Value>,
    removed: Vec<Value>,
    next_items: Map<String, Value>,
    /// A chunked full refresh still has items or removals left to send.
    streaming: bool,
    /// This send finished a full refresh.
    full_complete: bool,
}

struct Request<'a> {
    current: &'a BTreeMap<String, Map<String, Value>>,
    previous: Option<Map<String, Value>>,
    last: Option<&'a Map<String, Value>>,
    force_full: bool,
    detail: bool,
    now: i64,
}

impl Request<'_> {
    fn streaming(&self) -> bool {
        self.last
            .and_then(|last| last.get("fullStreaming"))
            .and_then(Value::as_bool)
            == Some(true)
    }

    /// A full inventory is due on first send, on request, or after a week.
    fn needs_full(&self) -> bool {
        let full_sent_at = self.last.and_then(|last| timestamp(last.get("fullSentAt")));
        match full_sent_at {
            Some(sent) if self.previous.is_some() && !self.force_full => {
                self.now - sent > FULL_REFRESH_AFTER_MICROS
            }
            _ => true,
        }
    }

    fn digest_only(&self) -> Plan {
        Plan {
            mode: "digest_only",
            items: Vec::new(),
            removed: Vec::new(),
            next_items: self.previous.clone().unwrap_or_default(),
            streaming: self.streaming(),
            full_complete: false,
        }
    }

    /// `plan_inventory`: a refresh that does not fit one request streams as
    /// successive deltas. The tracked snapshot keeps every item and removal
    /// not yet sent, so a later request continues the stream instead of
    /// restarting it or forgetting pending removals.
    fn plan(&self, limit: usize) -> Plan {
        let resuming = self.streaming();
        if !self.detail {
            return self.digest_only();
        }
        let refreshing = resuming || self.needs_full();
        if refreshing && !resuming && self.current.len() <= limit {
            return Plan {
                mode: "full",
                items: self.current.values().cloned().map(Value::Object).collect(),
                removed: Vec::new(),
                next_items: self
                    .current
                    .iter()
                    .map(|(key, item)| (key.clone(), tracked(item)))
                    .collect(),
                streaming: false,
                full_complete: true,
            };
        }
        let prior = self.previous.clone().unwrap_or_default();
        // Starting a refresh treats every current item as unknown to Guard Cloud.
        let baseline: Map<String, Value> = if resuming || !refreshing {
            prior
        } else {
            prior
                .into_iter()
                .filter(|(key, _)| !self.current.contains_key(key))
                .collect()
        };
        let changed: Vec<&String> = self
            .current
            .iter()
            .filter(|(key, item)| {
                baseline
                    .get(*key)
                    .and_then(|entry| entry.get("f"))
                    .and_then(Value::as_str)
                    != Some(item_fingerprint(item).as_str())
            })
            .map(|(key, _)| key)
            .collect();
        let mut gone: Vec<&String> = baseline
            .keys()
            .filter(|key| !self.current.contains_key(*key))
            .collect();
        gone.sort();
        let sent_changed = &changed[..changed.len().min(limit)];
        let sent_gone = &gone[..gone.len().min(limit)];
        let present: HashSet<String> = self
            .current
            .values()
            .map(|item| {
                identity(
                    field_of(item, "kind"),
                    field_of(item, "harness"),
                    field_of(item, "name"),
                    field_of(item, "hash"),
                )
            })
            .collect();
        let removed = sent_gone
            .iter()
            .map(|key| &baseline[key.as_str()])
            .filter(|entry| {
                !present.contains(&identity(
                    field(entry, "k"),
                    field(entry, "h"),
                    field(entry, "n"),
                    field(entry, "x"),
                ))
            })
            .map(|entry| {
                json!({
                    "kind": field(entry, "k"),
                    "name": field(entry, "n"),
                    "harness": field(entry, "h"),
                    "hash": field(entry, "x"),
                })
            })
            .collect();
        let mut next_items = baseline.clone();
        for key in sent_gone {
            next_items.remove(key.as_str());
        }
        for key in sent_changed {
            next_items.insert((*key).clone(), tracked(&self.current[key.as_str()]));
        }
        let unfinished = changed.len() > limit || gone.len() > limit;
        Plan {
            mode: "delta",
            items: sent_changed
                .iter()
                .map(|key| Value::Object(self.current[key.as_str()].clone()))
                .collect(),
            removed,
            next_items,
            streaming: refreshing && unfinished,
            full_complete: refreshing && !unfinished,
        }
    }
}

fn field_of(item: &Map<String, Value>, key: &str) -> Value {
    item.get(key).cloned().unwrap_or(Value::Null)
}

fn json_size(payload: &Value) -> usize {
    serde_json::to_string(payload).map_or(usize::MAX, |text| text.len())
}

/// `previous_items`: the tracked items of the last accepted send.
fn previous_items(last: Option<&Map<String, Value>>) -> Option<Map<String, Value>> {
    let items = last?.get("items")?.as_object()?;
    Some(
        items
            .iter()
            .filter(|(_, value)| value.is_object())
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}

fn hash_key(args: &Map<String, Value>) -> Result<&[u8], &'static str> {
    let key = args
        .get("hash_key")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    if key.len() < 32 {
        return Err(ERR_INVALID);
    }
    Ok(key.as_bytes())
}

fn rows(args: &Map<String, Value>) -> Result<&[Value], &'static str> {
    let rows = args
        .get("rows")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    if rows.len() > MAX_ROWS {
        return Err(ERR_INVALID);
    }
    Ok(rows)
}

fn flag(args: &Map<String, Value>, key: &str) -> Result<bool, &'static str> {
    args.get(key).and_then(Value::as_bool).ok_or(ERR_INVALID)
}

/// The static sections every candidate payload shares.
struct Sections<'a> {
    collected_at: String,
    client: &'a Value,
    machine: &'a Value,
    policy: &'a Value,
    tools: Vec<Value>,
}

impl Sections<'_> {
    fn assemble(&self, digest: &str, plan: &Plan, runtimes: Option<&Value>) -> Value {
        let mut payload = json!({
            "schemaVersion": SCHEMA_VERSION,
            "collectedAt": self.collected_at,
            "client": self.client,
            "machine": self.machine,
            "aiTools": self.tools,
            "inventory": {
                "digest": digest,
                "mode": plan.mode,
                "items": plan.items,
                "removed": plan.removed,
            },
            "policy": self.policy,
        });
        if let Some(runtimes) = runtimes {
            payload["runtimes"] = runtimes.clone();
        }
        payload
    }
}

/// Each tool row gains its artifact count and inventory digest.
fn tool_rows(
    args: &Map<String, Value>,
    items: &BTreeMap<String, Map<String, Value>>,
) -> Result<Vec<Value>, &'static str> {
    let tools = args
        .get("tools")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    tools
        .iter()
        .take(MAX_TOOLS)
        .map(|tool| {
            let mut tool = tool.as_object().ok_or(ERR_INVALID)?.clone();
            let harness = tool
                .get("harness")
                .and_then(Value::as_str)
                .ok_or(ERR_INVALID)?
                .to_owned();
            let owned: Vec<&Map<String, Value>> = items
                .values()
                .filter(|item| {
                    item.get("harness").and_then(Value::as_str) == Some(harness.as_str())
                })
                .collect();
            tool.insert(
                "artifactCount".to_owned(),
                Value::from(owned.len().min(MAX_ARTIFACT_COUNT)),
            );
            tool.insert(
                "inventoryDigest".to_owned(),
                Value::from(item_digest(owned.into_iter())),
            );
            Ok(Value::Object(tool))
        })
        .collect()
}

/// `build_fleet_posture_state` after collection: plan, assemble and fit.
fn build(args: &Map<String, Value>) -> KindResult {
    let current = inventory_items(rows(args)?, hash_key(args)?)?;
    let last = match args.get("last") {
        Some(Value::Object(last)) => Some(last),
        Some(Value::Null) | None => None,
        Some(_) => return Err(ERR_INVALID),
    };
    let now = args.get("now").and_then(parse_utc).ok_or(ERR_INVALID)?;
    let now_text = iso(now).ok_or(ERR_INVALID)?;
    let max_payload_bytes = args
        .get("max_payload_bytes")
        .and_then(Value::as_u64)
        .and_then(|bytes| usize::try_from(bytes).ok())
        .ok_or(ERR_INVALID)?;
    let request = Request {
        current: &current,
        previous: previous_items(last),
        last,
        force_full: flag(args, "force_full")?,
        detail: flag(args, "detail")?,
        now,
    };
    let sections = Sections {
        collected_at: now_text.clone(),
        client: args.get("client").ok_or(ERR_INVALID)?,
        machine: args.get("machine").ok_or(ERR_INVALID)?,
        policy: args.get("policy").ok_or(ERR_INVALID)?,
        tools: tool_rows(args, &current)?,
    };
    // Runtime identities are detail: a minimal report leaves them out.
    let mut runtimes = match args.get("runtimes") {
        Some(Value::Null) | None => None,
        Some(runtimes) if request.detail => Some(runtimes),
        Some(_) => None,
    };
    let digest = item_digest(current.values());
    let candidate = |limit: usize, runtimes: Option<&Value>| {
        let plan = request.plan(limit);
        let payload = sections.assemble(&digest, &plan, runtimes);
        (plan, payload)
    };
    let (mut plan, mut payload) = candidate(MAX_ITEMS_PER_SYNC, runtimes);
    let mut payload_bytes = json_size(&payload);
    if payload_bytes > max_payload_bytes && runtimes.is_some() {
        // Inventory rows matter more than runtime identities; drop those first.
        runtimes = None;
        (plan, payload) = candidate(MAX_ITEMS_PER_SYNC, runtimes);
        payload_bytes = json_size(&payload);
    }
    if payload_bytes > max_payload_bytes && plan.mode != "digest_only" {
        // Send as many items as fit, in successive deltas; digest_only only
        // when not even one item fits next to the machine and tool sections.
        let (mut low, mut high, mut best) = (1, MAX_ITEMS_PER_SYNC - 1, None);
        while low <= high {
            let middle = (low + high) / 2;
            let fitted = candidate(middle, runtimes);
            if json_size(&fitted.1) <= max_payload_bytes {
                best = Some(fitted);
                low = middle + 1;
            } else {
                high = middle - 1;
            }
        }
        (plan, payload) = best.unwrap_or_else(|| {
            let plan = request.digest_only();
            let payload = sections.assemble(&digest, &plan, None);
            (plan, payload)
        });
        payload_bytes = json_size(&payload);
    }
    if payload_bytes > max_payload_bytes {
        if let Some(tools) = payload["aiTools"].as_array_mut() {
            for tool in tools {
                tool["blindSpots"] = json!([]);
            }
        }
        payload_bytes = json_size(&payload);
    }
    let full_sent_at = if plan.full_complete {
        Value::from(now_text.clone())
    } else {
        last.and_then(|last| last.get("fullSentAt"))
            .cloned()
            .unwrap_or(Value::Null)
    };
    let mut summary = payload.clone();
    summary["inventory"]["items"] = json!([]);
    summary["inventory"]["removed"] = json!([]);
    let tool_states: Map<String, Value> = sections
        .tools
        .iter()
        .map(|tool| {
            (
                py_str(&tool["harness"]).unwrap_or_default(),
                field(tool, "protectionState"),
            )
        })
        .collect();
    Ok(json!({
        "payload": payload,
        "mode": plan.mode,
        "payload_bytes": payload_bytes,
        "advanced_inventory": plan.mode != "digest_only",
        "next_state": {
            "sentAt": now_text,
            "collectedAt": now_text,
            "mode": plan.mode,
            "inventoryDigest": digest,
            "inventoryItemsTracked": current.len(),
            "fullSentAt": full_sent_at,
            "fullStreaming": plan.streaming,
            "payloadBytes": payload_bytes,
            "items": plan.next_items,
            "tools": tool_states,
            "summary": summary,
        },
    }))
}

/// `reportable_inventory_rows` for the `extensions list` and `mcp list`
/// commands, so they show exactly what Guard Cloud can receive.
fn reportable_rows(args: &Map<String, Value>) -> KindResult {
    let selected: Vec<Value> = reportable(rows(args)?)?
        .into_iter()
        .map(|row| {
            json!({
                "index": row.index,
                "kind": row.kind,
                "harness": row.harness,
                "name": row.name,
                "first_seen_at": row.first_seen_at,
                "last_seen_at": row.last_seen_at,
                "config_path": row.config_path,
            })
        })
        .collect();
    Ok(json!({ "rows": selected }))
}

fn items(args: &Map<String, Value>) -> KindResult {
    let items = inventory_items(rows(args)?, hash_key(args)?)?;
    Ok(json!({ "items": items.into_values().collect::<Vec<_>>() }))
}

pub(crate) fn dispatch(kind: &str, args: &Value) -> KindResult {
    let args = args_object(args)?;
    match kind {
        "fleet_inventory_rows" => reportable_rows(args),
        "fleet_inventory_items" => items(args),
        "fleet_posture_build" => build(args),
        _ => Err(ERR_INVALID),
    }
}

#[cfg(test)]
#[path = "fleet_posture_inventory_tests.rs"]
mod tests;
