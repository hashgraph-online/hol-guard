//! `_record_created_event` of `approvals.py`: the `approval.created` event,
//! and `guard.protection.ask_once_shown` for a prompted review, written with
//! a newly queued request in the queue write's transaction.

use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_approval_request::ApprovalRequest;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_guard_event::{add_guard_event, approval_created_event, from_json};
use crate::pyjson::PyVal;

const EVENT_UNAVAILABLE: &str = "native_approval_created_event_unavailable";
/// The policy actions whose prompt counts as an ask-once prompt.
const ASK_ONCE_ACTIONS: [&str; 2] = ["review", "require-reapproval"];

/// Write the creation events for `request`, queued at `now`.
pub(crate) fn record_created_events(
    connection: &Connection,
    request: &ApprovalRequest,
    prompt_shown: bool,
    now: &str,
) -> StoreResult<()> {
    let mut fields = Map::new();
    for (key, value) in [
        ("request_id", Value::from(request.request_id.as_str())),
        ("harness", Value::from(request.harness.as_str())),
        ("artifact_id", Value::from(request.artifact_id.as_str())),
        ("artifact_name", Value::from(request.artifact_name.as_str())),
        ("artifact_type", Value::from(request.artifact_type.as_str())),
        ("policy_action", request.policy_action.clone()),
        (
            "recommended_scope",
            Value::from(request.recommended_scope.as_str()),
        ),
        ("source_scope", Value::from(request.source_scope.as_str())),
        ("workspace", Value::from(request.workspace.clone())),
        ("publisher", Value::from(request.publisher.clone())),
    ] {
        fields.insert(key.to_owned(), value);
    }
    let (payload, _) =
        approval_created_event(&fields, now).ok_or(StoreError::Invalid(EVENT_UNAVAILABLE))?;
    add_guard_event(connection, "approval.created", &payload, now)?
        .ok_or(StoreError::Invalid(EVENT_UNAVAILABLE))?;
    let asks_once = request
        .policy_action
        .as_str()
        .is_some_and(|action| ASK_ONCE_ACTIONS.contains(&action));
    if !(prompt_shown && asks_once) {
        return Ok(());
    }
    let mut payload: Vec<(String, PyVal)> = Vec::with_capacity(4);
    for key in ["request_id", "harness", "artifact_id", "policy_action"] {
        let value = from_json(&fields[key]).ok_or(StoreError::Invalid(EVENT_UNAVAILABLE))?;
        payload.push((key.to_owned(), value));
    }
    add_guard_event(connection, "guard.protection.ask_once_shown", &payload, now)?
        .ok_or(StoreError::Invalid(EVENT_UNAVAILABLE))?;
    Ok(())
}
