//! The effective connect state: the latest stored state reconciled with the
//! cloud profile and the last sync summary. The caller resolves the cloud
//! profile (credential health is Python-held evidence) and passes it in.

use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_connect::{latest_state, Proof, State, STATE_VERSION};
use crate::guard_store_db::{query_one, text, value_error, StoreResult};

type Summary = Map<String, Value>;

/// Python truthiness of a decoded JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_none_or(|n| n != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// `isinstance(value, int)`: a bool is an int in Python.
fn int_like(value: Option<&Value>) -> Option<&Value> {
    match value {
        Some(found @ Value::Bool(_)) => Some(found),
        Some(found @ Value::Number(number)) if number.as_i64().is_some() => Some(found),
        _ => None,
    }
}

fn magnitude(value: &Value) -> i64 {
    match value {
        Value::Bool(flag) => i64::from(*flag),
        other => other.as_i64().unwrap_or(0),
    }
}

/// `max(first, second)`: the first argument wins a tie, objects are returned as is.
fn py_max(first: Value, second: Value) -> Value {
    if magnitude(&second) > magnitude(&first) {
        second
    } else {
        first
    }
}

fn nonempty_text(summary: Option<&Summary>, key: &str) -> Option<Value> {
    match summary?.get(key) {
        Some(Value::String(found)) if !found.is_empty() => Some(Value::from(found.as_str())),
        _ => None,
    }
}

fn counted(summary: Option<&Summary>, keys: &[&str]) -> Value {
    let found = summary.and_then(|map| {
        keys.iter()
            .find_map(|key| map.get(*key))
            .and_then(|value| int_like(Some(value)))
    });
    match found {
        Some(value) => py_max(Value::from(0), value.clone()),
        None => Value::from(0),
    }
}

fn field(state: &State, name: &str) -> Value {
    state.fields.get(name).cloned().unwrap_or(Value::Null)
}

fn coerce(
    state: &State,
    status: &str,
    milestone: &str,
    reason: Option<&str>,
    summary: Option<&Summary>,
    now: &str,
) -> State {
    let mut proof = state.proof.clone();
    let receipts = counted(summary, &["receipts_stored"]);
    let inventory = counted(summary, &["inventory_tracked", "inventory"]);
    proof.set_default("pairing_completed_at", field(state, "completed_at"));
    match nonempty_text(summary, "synced_at") {
        Some(synced_at) => proof.set("first_synced_at", synced_at),
        None => proof.set_default("first_synced_at", Value::Null),
    }
    let existing = |name: &str, proof: &Proof| {
        int_like(proof.get(name))
            .cloned()
            .unwrap_or_else(|| Value::from(0))
    };
    let receipts = py_max(receipts, existing("receipts_stored", &proof));
    proof.set("receipts_stored", receipts);
    let inventory = py_max(inventory, existing("inventory_items", &proof));
    proof.set("inventory_items", inventory);
    for (name, source) in [
        ("runtime_session_id", "runtime_session_id"),
        ("runtime_session_synced_at", "runtime_session_synced_at"),
    ] {
        let value = nonempty_text(summary, source)
            .or_else(|| proof.get(name).cloned())
            .unwrap_or(Value::Null);
        proof.set(name, value);
    }
    let updated_at = Some(field(state, "updated_at"))
        .filter(truthy)
        .unwrap_or_else(|| Value::from(now));
    let completed_at = Some(field(state, "completed_at"))
        .filter(truthy)
        .or_else(|| proof.get("pairing_completed_at").cloned())
        .unwrap_or(Value::Null);
    let mut fields = Map::new();
    for name in [
        "request_id",
        "sync_url",
        "allowed_origin",
        "created_at",
        "expires_at",
    ] {
        fields.insert(name.to_owned(), field(state, name));
    }
    fields.insert("status".to_owned(), Value::from(status));
    fields.insert("milestone".to_owned(), Value::from(milestone));
    fields.insert("reason".to_owned(), reason.map_or(Value::Null, Value::from));
    fields.insert("updated_at".to_owned(), updated_at);
    fields.insert("completed_at".to_owned(), completed_at);
    fields.insert("proof".to_owned(), proof.to_value());
    fields.insert("version".to_owned(), Value::from(STATE_VERSION));
    fields.insert("poll_after_ms".to_owned(), Value::from(0));
    State { fields, proof }
}

fn requires_oauth(state: &State) -> bool {
    let named = matches!(state.fields.get("request_id"), Some(Value::String(id)) if !crate::guard_store_json::py_strip(id).is_empty());
    named && state.text("status") == "connected"
}

fn hydrate(
    latest: Option<State>,
    sync_url: &str,
    allowed_origin: Option<&str>,
    summary: Option<&Summary>,
    now: &str,
) -> State {
    let succeeded = summary.is_some_and(|map| !map.is_empty());
    let (default_milestone, default_reason) = if succeeded {
        ("first_sync_succeeded", "first_sync_succeeded")
    } else {
        ("first_sync_pending", "waiting_for_first_sync")
    };
    let Some(latest) = latest else {
        let mut fields = Map::new();
        for name in ["request_id", "created_at", "expires_at", "completed_at"] {
            fields.insert(name.to_owned(), Value::Null);
        }
        fields.insert("sync_url".to_owned(), Value::from(sync_url));
        fields.insert(
            "allowed_origin".to_owned(),
            allowed_origin.map_or(Value::Null, Value::from),
        );
        fields.insert("updated_at".to_owned(), Value::from(now));
        let seed = State {
            fields,
            proof: Proof::default(),
        };
        return coerce(
            &seed,
            "connected",
            default_milestone,
            Some(default_reason),
            summary,
            now,
        );
    };
    let mut hydrated = State {
        fields: latest.fields.clone(),
        proof: latest.proof.clone(),
    };
    let stored_url = latest.text("sync_url");
    let stored_origin = latest.text("allowed_origin");
    let url = if stored_url.is_empty() {
        sync_url
    } else {
        stored_url
    };
    let origin = if stored_origin.is_empty() {
        allowed_origin.unwrap_or("")
    } else {
        stored_origin
    };
    hydrated
        .fields
        .insert("sync_url".to_owned(), Value::from(url));
    hydrated
        .fields
        .insert("allowed_origin".to_owned(), Value::from(origin));
    let pick = |name: &'static str, default: &'static str| {
        let stored = latest.text(name);
        if stored.is_empty() { default } else { stored }.to_owned()
    };
    let status = pick("status", "connected");
    let milestone = pick("milestone", default_milestone);
    let reason = match latest.fields.get("reason") {
        Some(Value::String(found)) => found.clone(),
        _ => default_reason.to_owned(),
    };
    coerce(&hydrated, &status, &milestone, Some(&reason), summary, now)
}

fn normalize(
    latest: Option<State>,
    profile: Option<(&str, Option<&str>)>,
    summary: Option<&Summary>,
    now: &str,
) -> Option<State> {
    let Some((sync_url, allowed_origin)) = profile else {
        let state = latest?;
        if !requires_oauth(&state) {
            return Some(state);
        }
        let reason =
            "Guard Cloud authorization on this machine is incomplete. Run hol-guard connect again.";
        return Some(coerce(
            &state,
            "retry_required",
            "first_sync_failed",
            Some(reason),
            summary,
            now,
        ));
    };
    let normalized = hydrate(latest, sync_url, allowed_origin, summary, now);
    let (status, milestone) = (normalized.text("status"), normalized.text("milestone"));
    let has_summary = summary.is_some_and(|map| !map.is_empty());
    if has_summary
        && status != "retry_required"
        && !matches!(milestone, "first_sync_failed" | "sync_not_available")
    {
        return Some(coerce(
            &normalized,
            "connected",
            "first_sync_succeeded",
            Some("first_sync_succeeded"),
            summary,
            now,
        ));
    }
    if matches!(status, "expired" | "waiting")
        || matches!(milestone, "expired" | "waiting_for_browser")
    {
        return Some(coerce(
            &normalized,
            "connected",
            "first_sync_pending",
            Some("waiting_for_first_sync"),
            summary,
            now,
        ));
    }
    Some(normalized)
}

fn sync_summary(connection: &Connection) -> StoreResult<Option<Summary>> {
    let row = query_one(
        connection,
        "select payload_json from sync_state where state_key = 'sync_summary'",
        &[],
    )?;
    let Some(row) = row else {
        return Ok(None);
    };
    match serde_json::from_str::<Value>(text(&row, "payload_json")) {
        Ok(Value::Object(map)) => Ok(Some(map)),
        Ok(_) => Ok(None),
        Err(error) => value_error(&error.to_string()),
    }
}

pub(crate) fn effective_state(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let now = args.str("now")?;
    let latest = latest_state(connection, Some(now))?;
    let profile = match args.opt_object("cloud_profile")? {
        Some(map) => {
            let profile = Args(map);
            Some((profile.str("sync_url")?, profile.opt_str("allowed_origin")?))
        }
        None => None,
    };
    let summary = sync_summary(connection)?;
    let state = normalize(latest, profile, summary.as_ref(), now);
    Ok(state.map_or(Value::Null, State::into_value))
}
