//! The commit a continuity answer asks the client to run.
//!
//! Planning says what should change. This module turns a plan into the commit
//! itself, so the client holds none of its policy:
//!
//! - `writes`: which sync-state records are written, by role (`state`,
//!   `last_good`, `removals`), each with the payload and the order its `items`
//!   keep. The client maps a role to the store key that holds it.
//! - `requirements`: whether the plan needs a protected extension authority and
//!   which capability the device must have negotiated. Only a v2 plan does.
//! - the guard: every authority update names an observation the store checks
//!   again inside the commit, and a plan that lacks one is refused here.

use serde_json::{json, Map, Value};

use super::*;

/// Capability the client must have negotiated before it may apply a v2 plan.
const V2_CAPABILITY: &str = "custom-extension-continuity.v2";
const ROLE_STATE: &str = "state";
const ROLE_LAST_GOOD: &str = "last_good";
const ROLE_REMOVALS: &str = "removals";

/// Plan a signed observation and answer the commit that applies it. A request
/// for more details, and a refusal, pass through exactly as planned.
pub(super) fn commit_plan(request: &Value) -> Planned<Value> {
    let Value::Object(mut answer) = plan(request)? else {
        return Err(Fail::Request);
    };
    if answer.contains_key("need_details") {
        return Ok(Value::Object(answer));
    }
    let updates = take(&mut answer, "authority_updates")?;
    let events = take(&mut answer, "events")?;
    let preconditions = take(&mut answer, "observation_preconditions")?;
    require_guards(&updates, &preconditions)?;
    let state = take(&mut answer, "state")?;
    let order = take(&mut answer, "state_item_order")?;
    let removals = take(&mut answer, "removals")?;
    let last_good = answer.get("write_last_good").and_then(Value::as_bool) == Some(true);
    let v2 = answer.get("v2").and_then(Value::as_bool) == Some(true);
    let mut roles = vec![ROLE_STATE];
    if last_good {
        roles.push(ROLE_LAST_GOOD);
    }
    let mut writes = vec![write(&roles, state, order)];
    if !removals.is_null() {
        writes.push(write(&[ROLE_REMOVALS], removals, Value::Null));
    }
    let capability = if v2 {
        json!(V2_CAPABILITY)
    } else {
        Value::Null
    };
    Ok(json!({
        "error": null,
        "authority_updates": updates,
        "events": events,
        "observation_preconditions": preconditions,
        "writes": writes,
        "requirements": { "protected_authority": v2, "capability": capability },
    }))
}

/// Record a local grant change and answer the commit that keeps it. The
/// removal tombstone is always written; the continuity state only when there
/// is a stored one to update.
pub(super) fn commit_local_mutation(request: &Value) -> Planned<Value> {
    let Value::Object(mut answer) = local::local_mutation(request)? else {
        return Err(Fail::Request);
    };
    let removals = take(&mut answer, "removals")?;
    let active = take(&mut answer, "active")?;
    let order = take(&mut answer, "active_item_order")?;
    let event = take(&mut answer, "event")?;
    let precondition = take(&mut answer, "observation_precondition")?;
    let mut writes = Vec::new();
    if !active.is_null() {
        writes.push(write(&[ROLE_STATE], active, order));
    }
    writes.push(write(&[ROLE_REMOVALS], removals, Value::Null));
    Ok(json!({
        "writes": writes,
        "event": event,
        "observation_precondition": precondition,
    }))
}

fn take(answer: &mut Map<String, Value>, key: &str) -> Planned<Value> {
    answer.remove(key).ok_or(Fail::Request)
}

/// One record to store under each of `roles`. `item_order` is the order of the
/// payload's `items` keys, or null for a payload that has none.
fn write(roles: &[&str], payload: Value, item_order: Value) -> Value {
    json!({ "stores": roles, "payload": payload, "item_order": item_order })
}

/// Every authority update carries the observation it was planned against, so
/// the store can refuse the commit if that observation changed meanwhile.
fn require_guards(updates: &Value, preconditions: &Value) -> Planned<()> {
    let (Some(updates), Some(preconditions)) = (updates.as_array(), preconditions.as_object())
    else {
        return Err(Fail::Request);
    };
    for update in updates {
        let guarded = update
            .get("cli_id")
            .and_then(Value::as_str)
            .and_then(|cli_id| preconditions.get(cli_id))
            .is_some_and(|precondition| !precondition.is_null());
        if !guarded {
            return refuse("continuity update has no observation guard");
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "custom_extension_continuity_commit_tests.rs"]
mod tests;
