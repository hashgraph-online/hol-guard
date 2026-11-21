//! Local grant mutations and the path-free public continuity state.

use serde_json::{json, Map, Value};

use super::*;

pub(super) fn local_mutation(request: &Value) -> Planned<Value> {
    let text = |key: &str| {
        request
            .get(key)
            .and_then(Value::as_str)
            .ok_or(Fail::Request)
    };
    let (cli_id, identity_hash, state) = (text("cli_id")?, text("identity_hash")?, text("state")?);
    let now = request.get("now").ok_or(Fail::Request)?;
    let active = request.get("active").and_then(Value::as_object);
    let mut removals = request
        .get("removals")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let revision = active
        .and_then(|active| active.get("cloud_revision"))
        .filter(|revision| py_int(Some(revision)).is_some())
        .cloned()
        .unwrap_or_else(|| json!(0));
    removals.insert(
        cli_id.to_owned(),
        json!({
            "identity_hash": identity_hash,
            "cloud_revision": revision,
            "state": state,
            "updated_at": now,
        }),
    );
    let (status, reason) = if state == "unset" {
        ("removed", "removed_locally")
    } else {
        ("locally_overridden", "local_authority_preserved")
    };
    let updated = active.and_then(|active| {
        let mut items = active.get("items")?.as_object()?.clone();
        let mut item = items.get(cli_id)?.as_object()?.clone();
        item.insert("status".to_owned(), json!(status));
        item.insert("reason".to_owned(), json!(reason));
        items.insert(cli_id.to_owned(), Value::Object(item));
        let mut active = active.clone();
        active.insert("items".to_owned(), Value::Object(items));
        Some(active)
    });
    let order = string_list(request.get("active_item_order"))?;
    let active_order = updated
        .as_ref()
        .and_then(|active| active.get("items")?.as_object())
        .map(|items| ordered_keys(items, &order))
        .unwrap_or_default();
    let local = request.get("local").and_then(Value::as_object);
    Ok(json!({
        "removals": removals,
        "active": updated,
        "active_item_order": active_order,
        "event": [
            format!("custom_extension_continuity/{status}"),
            {
                "cli_id": cli_id,
                "identity_hash": identity_hash,
                "status": status,
                "reason": reason,
            }
        ],
        "observation_precondition": observation_precondition(local),
    }))
}

pub(super) fn public_state(request: &Value) -> Planned<Value> {
    let now = request
        .get("now")
        .and_then(Value::as_str)
        .ok_or(Fail::Request)?;
    let stored = request.get("stored").and_then(Value::as_object);
    let items = stored
        .and_then(|stored| stored.get("items"))
        .and_then(Value::as_object);
    let expires_at = stored
        .and_then(|stored| stored.get("expires_at"))
        .and_then(Value::as_str);
    let (Some(items), Some(expires_at)) = (items, expires_at) else {
        return Ok(json!({ "states": {} }));
    };
    let stale = match (
        timestamp(expires_at, "expiry"),
        timestamp(now, "current time"),
    ) {
        (Ok(expires), Ok(now)) => expires <= now,
        _ => return Ok(json!({ "states": {} })),
    };
    let mut states = Map::new();
    for (cli_id, raw) in items {
        let Some(raw) = raw.as_object() else {
            continue;
        };
        let mut public: Map<String, Value> = raw
            .iter()
            .filter(|(key, _)| PUBLIC_FIELDS.contains(&key.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let keeps_status = matches!(
            public.get("status").and_then(Value::as_str),
            Some("removed" | "changed_identity")
        );
        if stale && !keeps_status {
            public.insert("status".to_owned(), json!("stale"));
            public.insert("reason".to_owned(), json!("cloud_observation_expired"));
        }
        states.insert(cli_id.clone(), Value::Object(public));
    }
    Ok(json!({ "states": states }))
}
