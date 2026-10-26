//! Plan signed custom-Extension continuity against exact local identities.
//!
//! Port of the former Python `custom_extension_continuity` planners (v1 exact
//! identity, v2 device-bound); parity vectors are recorded by
//! `scripts/record_custom_extension_continuity_vectors.py`. Pure: the client
//! sends a store snapshot and commits the returned plan in one transaction
//! guarded by the snapshot it sent.
//!
//! The planners say what should change; `commit` turns that into the commit the
//! client runs: which sync-state records are written, whether the plan needs a
//! protected extension authority and a negotiated capability, and the guard
//! every authority update carries. The client decides none of that.
//!
//! Stored payloads come back with sorted keys. Item order inside `items`
//! maps is returned separately so the client can keep the stored order.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

use super::guard_store_json::dumps_sorted;
use super::guard_store_observed_mcp::is_local_cli_id;
use super::policy_bundle_time::from_isoformat;

const SCHEMA_V1: &str = "guard.custom-extension-continuity.v1";
const SCHEMA_V2: &str = "guard.custom-extension-continuity.v2";
const MAX_ITEMS: usize = 100;
const MAX_COMMANDS: usize = 101;
const MAX_COMMAND_DEPTH: usize = 4;
const MAX_DEVICE_BINDINGS: usize = 1;
const TOP_LEVEL_FIELDS: &[&str] = &[
    "expiresAt",
    "items",
    "observedAt",
    "revision",
    "schemaVersion",
];
const V1_ITEM_FIELDS: &[&str] = &["cliId", "identityHash", "settings"];
const V2_ITEM_FIELDS: &[&str] = &["deviceIdentityHashes", "identityHash", "state"];
const SETTINGS_FIELDS: &[&str] = &["commands", "state"];
const PUBLIC_FIELDS: &[&str] = &["cloud_revision", "reason", "status", "surface"];
const ERR_REQUEST: &str = "native_custom_extension_continuity_invalid_request";

#[path = "custom_extension_continuity_commit.rs"]
mod commit;
#[path = "custom_extension_continuity_local.rs"]
mod local;
#[path = "custom_extension_continuity_support.rs"]
mod support;
#[path = "custom_extension_continuity_v2.rs"]
mod v2;

use commit::{commit_local_mutation, commit_plan};
use local::public_state;
use support::{
    has_exact_keys, is_command_id, is_sha256, local_override_status, observation_precondition,
    observed, ordered_keys, override_matches, plan_exact_settings, py_int, require_monotonic,
    scoped_identity, sha256_hex, string_list, timestamp, unset_update,
};
use v2::plan_v2;

enum Fail {
    Request,
    Refusal(String),
}

type Planned<T> = Result<T, Fail>;

fn refuse<T>(message: impl Into<String>) -> Planned<T> {
    Err(Fail::Refusal(message.into()))
}

/// Answer one continuity request. Refusals are part of the answer
/// (`{"error": message}`); only a malformed request is an error.
pub(crate) fn evaluate(request: &Value) -> Result<Value, &'static str> {
    let operation = request.get("operation").and_then(Value::as_str);
    settle(match operation {
        Some("plan") => commit_plan(request),
        Some("local_mutation") => commit_local_mutation(request),
        Some("public_state") => public_state(request),
        _ => Err(Fail::Request),
    })
}

/// A planner's outcome as the resident's answer.
fn settle(answer: Planned<Value>) -> Result<Value, &'static str> {
    match answer {
        Ok(value) => Ok(value),
        Err(Fail::Refusal(message)) => Ok(json!({ "error": message })),
        Err(Fail::Request) => Err(ERR_REQUEST),
    }
}

struct Snapshot<'a> {
    now: &'a str,
    authority: Authority<'a>,
    previous: &'a Value,
    previous_order: Vec<String>,
    removals: Map<String, Value>,
}

struct Authority<'a> {
    /// Locals keyed by `cli_id` in first-seen order, last row winning.
    locals: Vec<(&'a str, &'a Map<String, Value>)>,
    details: &'a Map<String, Value>,
    /// Locals whose details were read but not sent; the plan asks for them.
    missing: RefCell<BTreeSet<String>>,
}

impl<'a> Authority<'a> {
    fn local(&self, cli_id: &str) -> Option<&'a Map<String, Value>> {
        self.locals
            .iter()
            .find(|(id, _)| *id == cli_id)
            .map(|(_, local)| *local)
    }

    fn detail(&self, cli_id: &str, key: &str) -> Option<&'a Value> {
        let Some(detail) = self.details.get(cli_id) else {
            if self.local(cli_id).is_some() {
                self.missing.borrow_mut().insert(cli_id.to_owned());
            }
            return None;
        };
        detail.get(key)
    }

    fn grant(&self, cli_id: &str) -> Option<&'a Map<String, Value>> {
        self.detail(cli_id, "grant")?.as_object()
    }
}

struct Plan {
    updates: Vec<Value>,
    events: Vec<Value>,
    preconditions: Map<String, Value>,
    statuses: Vec<(String, Value)>,
}

impl Plan {
    fn new() -> Self {
        Self {
            updates: Vec::new(),
            events: Vec::new(),
            preconditions: Map::new(),
            statuses: Vec::new(),
        }
    }

    /// Python dict assignment: a repeated key keeps its first position.
    fn set_status(&mut self, key: &str, evidence: Value) {
        match self
            .statuses
            .iter_mut()
            .find(|(existing, _)| existing == key)
        {
            Some(slot) => slot.1 = evidence,
            None => self.statuses.push((key.to_owned(), evidence)),
        }
    }

    fn record(&mut self, key: &str, status: &str, evidence: Value) {
        self.events.push(json!([
            format!("custom_extension_continuity/{status}"),
            evidence.clone()
        ]));
        self.set_status(key, evidence);
    }

    fn answer(self, state: Map<String, Value>, stale: bool, removals: Value, v2: bool) -> Value {
        let order: Vec<&String> = self.statuses.iter().map(|(key, _)| key).collect();
        let mut state = state;
        state.insert(
            "items".to_owned(),
            Value::Object(self.statuses.iter().cloned().collect()),
        );
        json!({
            "error": null,
            "authority_updates": self.updates,
            "events": self.events,
            "observation_preconditions": self.preconditions,
            "state_item_order": order,
            "state": state,
            "write_last_good": !stale,
            "removals": removals,
            "v2": v2,
        })
    }
}

/// Plan against the sent details. The client starts with none; when the plan
/// reads details of a local that were not sent, the answer is
/// `{"need_details": [cli_id, ...]}` and the client asks again with them, so
/// only the locals the plan touches are loaded from the store.
fn plan(request: &Value) -> Planned<Value> {
    let snapshot = snapshot(request)?;
    let answer = plan_snapshot(request, &snapshot);
    if matches!(answer, Err(Fail::Request)) {
        return answer;
    }
    let missing = snapshot.authority.missing.take();
    if !missing.is_empty() {
        return Ok(json!({ "need_details": missing }));
    }
    answer
}

fn plan_snapshot(request: &Value, snapshot: &Snapshot<'_>) -> Planned<Value> {
    let continuity = request.get("continuity").ok_or(Fail::Request)?;
    let is_v2 = continuity
        .as_object()
        .is_some_and(|value| value.get("schemaVersion").and_then(Value::as_str) == Some(SCHEMA_V2));
    if !is_v2 {
        return plan_v1(continuity, snapshot);
    }
    let workspace = request
        .get("workspace_id")
        .and_then(Value::as_str)
        .filter(|workspace| !workspace.is_empty());
    let device = match request.get("device_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(device)) => Some(device.as_str()),
        Some(_) => return Err(Fail::Request),
    };
    match (workspace, device) {
        (Some(workspace), Some(device)) => plan_v2(continuity, snapshot, workspace, device),
        _ => refuse("v2 continuity requires workspace and device binding"),
    }
}

fn snapshot(request: &Value) -> Planned<Snapshot<'_>> {
    let locals = request
        .get("locals")
        .and_then(Value::as_array)
        .ok_or(Fail::Request)?;
    let mut deduped: Vec<(&str, &Map<String, Value>)> = Vec::new();
    for local in locals {
        let local = local.as_object().ok_or(Fail::Request)?;
        let cli_id = local
            .get("cli_id")
            .and_then(Value::as_str)
            .ok_or(Fail::Request)?;
        match deduped.iter_mut().find(|(id, _)| *id == cli_id) {
            Some(slot) => slot.1 = local,
            None => deduped.push((cli_id, local)),
        }
    }
    Ok(Snapshot {
        now: request
            .get("now")
            .and_then(Value::as_str)
            .ok_or(Fail::Request)?,
        authority: Authority {
            locals: deduped,
            details: request
                .get("details")
                .and_then(Value::as_object)
                .ok_or(Fail::Request)?,
            missing: RefCell::new(BTreeSet::new()),
        },
        previous: request.get("previous").unwrap_or(&Value::Null),
        previous_order: string_list(request.get("previous_item_order"))?,
        removals: request
            .get("removals")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default(),
    })
}

struct Frame<'a> {
    value: &'a Map<String, Value>,
    items: &'a [Value],
    revision: i128,
    expires: i64,
}

impl Frame<'_> {
    fn state(&self, schema: &str, stale: bool, digest: &str) -> Map<String, Value> {
        let mut state = Map::new();
        state.insert("schema_version".to_owned(), json!(schema));
        state.insert("cloud_revision".to_owned(), self.value["revision"].clone());
        state.insert("observed_at".to_owned(), self.value["observedAt"].clone());
        state.insert("expires_at".to_owned(), self.value["expiresAt"].clone());
        state.insert("stale".to_owned(), json!(stale));
        state.insert("observation_digest".to_owned(), json!(digest));
        state
    }

    fn evidence(&self) -> Map<String, Value> {
        let mut evidence = Map::new();
        evidence.insert("cloud_revision".to_owned(), self.value["revision"].clone());
        evidence
    }
}

fn frame<'a>(value: &'a Value, schema: &str) -> Planned<Frame<'a>> {
    let Some(object) = value
        .as_object()
        .filter(|object| has_exact_keys(object, TOP_LEVEL_FIELDS))
    else {
        return refuse("continuity observation contains unsupported fields");
    };
    if object.get("schemaVersion").and_then(Value::as_str) != Some(schema) {
        return refuse("unsupported continuity observation schema");
    }
    let Some(revision) = py_int(object.get("revision")).filter(|revision| *revision >= 1) else {
        return refuse("continuity revision must be positive");
    };
    let (Some(observed_at), Some(expires_at)) = (
        object.get("observedAt").and_then(Value::as_str),
        object.get("expiresAt").and_then(Value::as_str),
    ) else {
        return refuse("continuity timestamps are required");
    };
    let expires = timestamp(expires_at, "expiry")?;
    if expires <= timestamp(observed_at, "observation")? {
        return refuse("continuity expiry must follow observation");
    }
    match object.get("items").and_then(Value::as_array) {
        Some(items) if items.len() <= MAX_ITEMS => Ok(Frame {
            value: object,
            items,
            revision,
            expires,
        }),
        _ => refuse("continuity item limit exceeded"),
    }
}

struct V1Item<'a> {
    cli_id: &'a str,
    identity_hash: &'a str,
    state: &'a str,
    commands: &'a Map<String, Value>,
}

fn parse_v1_item<'a>(raw: &'a Value, seen: &mut BTreeSet<&'a str>) -> Planned<V1Item<'a>> {
    let Some(item) = raw
        .as_object()
        .filter(|item| has_exact_keys(item, V1_ITEM_FIELDS))
    else {
        return refuse("continuity item contains unsupported fields");
    };
    let Some(cli_id) = item
        .get("cliId")
        .and_then(Value::as_str)
        .filter(|cli_id| is_local_cli_id(cli_id) && !seen.contains(cli_id))
    else {
        return refuse("invalid or duplicate continuity identity");
    };
    let Some(identity_hash) = item
        .get("identityHash")
        .and_then(Value::as_str)
        .filter(|hash| is_sha256(hash))
    else {
        return refuse("invalid continuity identity hash");
    };
    seen.insert(cli_id);
    let Some(settings) = item
        .get("settings")
        .and_then(Value::as_object)
        .filter(|settings| has_exact_keys(settings, SETTINGS_FIELDS))
    else {
        return refuse("continuity settings contain unsupported fields");
    };
    let Some(state) = settings
        .get("state")
        .and_then(Value::as_str)
        .filter(|state| matches!(*state, "allowed" | "blocked"))
    else {
        return refuse("invalid continuity setting");
    };
    let Some(commands) = settings
        .get("commands")
        .and_then(Value::as_object)
        .filter(|commands| commands.len() <= MAX_COMMANDS)
    else {
        return refuse("invalid continuity command settings");
    };
    for (command_id, command_state) in commands {
        if !is_command_id(command_id) {
            return refuse("invalid continuity command identity");
        }
        if !matches!(command_state.as_str(), Some("inherit" | "allow" | "block")) {
            return refuse("invalid continuity command setting");
        }
    }
    Ok(V1Item {
        cli_id,
        identity_hash,
        state,
        commands,
    })
}

fn plan_v1(continuity: &Value, snapshot: &Snapshot<'_>) -> Planned<Value> {
    let frame = frame(continuity, SCHEMA_V1)?;
    let mut seen = BTreeSet::new();
    let items = frame
        .items
        .iter()
        .map(|raw| parse_v1_item(raw, &mut seen))
        .collect::<Planned<Vec<_>>>()?;
    let digest = sha256_hex(&dumps_sorted(continuity).ok_or(Fail::Request)?);
    require_monotonic(snapshot.previous, frame.revision, &digest)?;
    let stale = frame.expires <= timestamp(snapshot.now, "current time")?;
    let authority = &snapshot.authority;
    let mut plan = Plan::new();
    let mut remaining = snapshot.removals.clone();
    let mut removals_changed = false;
    for item in &items {
        let local = authority.local(item.cli_id);
        plan.preconditions
            .insert(item.cli_id.to_owned(), observation_precondition(local));
        let override_value = snapshot.removals.get(item.cli_id);
        let (status, reason) = if stale {
            ("stale", "cloud_observation_expired")
        } else if override_matches(override_value, item.identity_hash, frame.revision) {
            local_override_status(override_value)
        } else if let Some(local) = local.filter(|local| observed(local)) {
            if local.get("identity_hash").and_then(Value::as_str) != Some(item.identity_hash) {
                ("changed_identity", "identity_mismatch")
            } else {
                removals_changed |= remaining.remove(item.cli_id).is_some();
                if let Some(update) =
                    plan_exact_settings(authority, local, item.state, item.commands)?
                {
                    plan.updates.push(update);
                }
                ("applied", "same_identity")
            }
        } else {
            ("pending_observation", "local_identity_not_observed")
        };
        let mut evidence = Map::new();
        evidence.insert("cli_id".to_owned(), json!(item.cli_id));
        evidence.insert("identity_hash".to_owned(), json!(item.identity_hash));
        evidence.extend(frame.evidence());
        evidence.insert("status".to_owned(), json!(status));
        evidence.insert("reason".to_owned(), json!(reason));
        if let Some(surface) = local
            .and_then(|local| local.get("surface"))
            .filter(|surface| matches!(surface.as_str(), Some("cli" | "mcp" | "package-scripts")))
        {
            evidence.insert("surface".to_owned(), surface.clone());
        }
        plan.record(item.cli_id, status, Value::Object(evidence));
    }
    let state = frame.state(SCHEMA_V1, stale, &digest);
    let removals = if removals_changed {
        Value::Object(remaining)
    } else {
        Value::Null
    };
    Ok(plan.answer(state, stale, removals, false))
}

#[cfg(test)]
#[path = "custom_extension_continuity_tests.rs"]
mod tests;
