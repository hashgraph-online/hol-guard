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

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::guard_store_json::py_str;
use crate::guard_store_local_cli::parse_utc;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

#[path = "fleet_posture_aibom.rs"]
mod aibom;
#[path = "fleet_posture_plan.rs"]
mod plan;
#[path = "fleet_posture_sections.rs"]
mod sections;
#[path = "fleet_posture_selection.rs"]
mod selection;
#[path = "fleet_posture_tools.rs"]
mod tools;

use plan::{items_patch, previous_items, stored_items, Plan, Request};
use selection::{inventory_items, iso, item_digest, reportable};

const SCHEMA_VERSION: &str = "fleet-posture/v1";
const MAX_ITEMS_PER_SYNC: usize = 250;
const MAX_TOOLS: usize = 32;
const MAX_ARTIFACT_COUNT: usize = 100_000;
/// `FULL_REFRESH_AFTER`: a full inventory older than a week is resent.
const FULL_REFRESH_AFTER_MICROS: i64 = 7 * 24 * 60 * 60 * 1_000_000;
/// Rows one request may carry; the inventory table plus the AIBOM rows stay
/// far below this on any real machine.
const MAX_ROWS: usize = 50_000;

fn field(value: &Value, key: &str) -> Value {
    value.get(key).cloned().unwrap_or(Value::Null)
}

fn json_size(payload: &Value) -> usize {
    serde_json::to_string(payload).map_or(usize::MAX, |text| text.len())
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

/// The request's rows. The native request parser refuses any array wider
/// than 4096 entries, so a large inventory arrives as a list of row lists
/// that join back in order.
fn rows(args: &Map<String, Value>) -> Result<Vec<&Value>, &'static str> {
    let mut rows = Vec::new();
    for entry in args
        .get("rows")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
    {
        match entry {
            Value::Array(chunk) => rows.extend(chunk),
            row => rows.push(row),
        }
        if rows.len() > MAX_ROWS {
            return Err(ERR_INVALID);
        }
    }
    Ok(rows)
}

fn flag(args: &Map<String, Value>, key: &str) -> Result<bool, &'static str> {
    args.get(key).and_then(Value::as_bool).ok_or(ERR_INVALID)
}

/// The static sections every candidate payload shares.
struct Sections<'a> {
    collected_at: String,
    client: Value,
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

/// The reported tool rows, each with its artifact count and inventory digest.
fn tool_rows(
    args: &Map<String, Value>,
    items: &BTreeMap<String, Map<String, Value>>,
    request: &Request<'_>,
) -> Result<Vec<Value>, &'static str> {
    let tools = args
        .get("tools")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    Ok(
        tools::reported_tools(tools, request.last, request.now, request.detail)?
            .into_iter()
            .take(MAX_TOOLS)
            .map(|(harness, mut tool)| {
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
                Value::Object(tool)
            })
            .collect(),
    )
}

/// `build_fleet_posture_state` after collection: plan, assemble and fit.
fn build(args: &Map<String, Value>) -> KindResult {
    let current = inventory_items(&rows(args)?, hash_key(args)?)?;
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
    let stored = stored_items(last);
    let request = Request {
        current: &current,
        previous: previous_items(stored.as_ref()),
        last,
        force_full: flag(args, "force_full")?,
        detail: flag(args, "detail")?,
        now,
    };
    let sections = Sections {
        collected_at: now_text.clone(),
        client: tools::client_section(args.get("client").ok_or(ERR_INVALID)?)?,
        machine: args.get("machine").ok_or(ERR_INVALID)?,
        policy: args.get("policy").ok_or(ERR_INVALID)?,
        tools: tool_rows(args, &current, &request)?,
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
            "itemsPatch": items_patch(stored.as_ref(), &plan.next_items),
            "tools": tool_states,
            "summary": summary,
        },
    }))
}

/// `reportable_inventory_rows` for the `extensions list` and `mcp list`
/// commands, so they show exactly what Guard Cloud can receive.
fn reportable_rows(args: &Map<String, Value>) -> KindResult {
    let selected: Vec<Value> = reportable(&rows(args)?)?
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
    let items = inventory_items(&rows(args)?, hash_key(args)?)?;
    Ok(json!({ "items": items.into_values().collect::<Vec<_>>() }))
}

pub(crate) fn dispatch(kind: &str, args: &Value) -> KindResult {
    let args = args_object(args)?;
    match kind {
        "fleet_inventory_rows" => reportable_rows(args),
        "fleet_inventory_items" => items(args),
        "fleet_posture_build" => build(args),
        "fleet_aibom_rows" => aibom::dispatch(args),
        "fleet_policy_section" => sections::policy(args),
        "fleet_runtime_posture" => sections::runtimes(args),
        _ => Err(ERR_INVALID),
    }
}

#[cfg(test)]
#[path = "fleet_posture_inventory_tests.rs"]
mod tests;
