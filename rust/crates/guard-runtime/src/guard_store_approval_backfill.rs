//! The write-time queue backfill the former Python writer ran: fill the
//! queue identity and counters of legacy approval rows before a queue write.
//!
//! The identity is derived in process, so the scan runs inside the write's
//! own immediate transaction. A row whose identity is rejected keeps its
//! legacy identity and only gains its counters, exactly as the Python batch
//! split left it. Every update fires the outbox update trigger, so a store
//! whose scan completed and committed is remembered for the life of the
//! resident, as Python remembered the home for the life of its process.

use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use guard_contracts::ApprovalQueueIdentityItemV1;
use rusqlite::Connection;
use serde_json::{json, Value};

use crate::approval_queue_identity_op::identify;
use crate::guard_store_db::{exec, query_all, Row, StoreResult};
use crate::guard_store_json::dumps_default;
use crate::pyjson;

/// `APPROVAL_QUEUE_BACKFILL_BATCH_SIZE`.
const BATCH: i64 = 500;
/// `_MAX_REQUEST_BYTES` of the resident identity request: a single row whose
/// request is larger was rejected.
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const REQUEST_SCHEMA: &str = "guard-approval-queue-identity-request.v1";

fn backfilled() -> &'static Mutex<HashSet<String>> {
    static STORES: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    STORES.get_or_init(|| Mutex::new(HashSet::new()))
}

fn store_key(connection: &Connection) -> Option<String> {
    connection
        .path()
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
}

/// Whether this store still needs its scan in this resident.
pub(crate) fn pending(connection: &Connection) -> bool {
    store_key(connection).is_none_or(|key| {
        !backfilled()
            .lock()
            .is_ok_and(|stores| stores.contains(&key))
    })
}

thread_local! {
    /// The store whose scan finished in the write now awaiting its commit.
    static STAGED: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Stage a store whose scan finished and whose write succeeded; `settle`
/// remembers it once the write's transaction commits.
pub(crate) fn mark_complete(connection: &Connection) {
    STAGED.with(|staged| *staged.borrow_mut() = store_key(connection));
}

/// Remember the staged store when its transaction committed, and forget it
/// when the transaction rolled back so the next write scans again.
pub(crate) fn settle(committed: bool) {
    let Some(key) = STAGED.with(|staged| staged.borrow_mut().take()) else {
        return;
    };
    if let (true, Ok(mut stores)) = (committed, backfilled().lock()) {
        stores.insert(key);
    }
}

/// `backfill_approval_queue_columns`: every legacy row, in created order.
pub(crate) fn backfill(connection: &Connection) -> StoreResult<()> {
    let mut after: Option<(String, String)> = None;
    loop {
        let rows = legacy_rows(connection, after.as_ref())?;
        let Some(last) = rows.last() else {
            return Ok(());
        };
        after = Some((
            py_text(last.get("created_at")),
            py_text(last.get("request_id")),
        ));
        for row in &rows {
            apply(connection, row)?;
        }
    }
}

fn legacy_rows(connection: &Connection, after: Option<&(String, String)>) -> StoreResult<Vec<Row>> {
    let mut predicate = "";
    let mut params = Vec::new();
    if let Some((created_at, request_id)) = after {
        predicate = "and (created_at > ? or (created_at = ? and request_id > ?))";
        params.extend([
            Value::from(created_at.as_str()),
            Value::from(created_at.as_str()),
            Value::from(request_id.as_str()),
        ]);
    }
    params.push(Value::from(BATCH));
    query_all(
        connection,
        &format!(
            "select request_id, harness, artifact_id, workspace, launch_target, \
             action_envelope_json, action_identity, queue_group_id, dedupe_count, \
             last_seen_at, created_at from approval_requests \
             where (action_identity is null or queue_group_id is null or last_seen_at is null \
             or dedupe_count is null or dedupe_count < 1) {predicate} \
             order by created_at asc, request_id asc limit ?"
        ),
        &params,
    )
}

/// `_apply_backfill_updates` for one row.
fn apply(connection: &Connection, row: &Row) -> StoreResult<()> {
    let field = |name: &str| row.get(name).cloned().unwrap_or(Value::Null);
    let missing = !truthy(row.get("action_identity")) || !truthy(row.get("queue_group_id"));
    let (action_identity, queue_group_id) = match missing.then(|| identity(row)).flatten() {
        Some((action, group)) => (Value::from(action), Value::from(group)),
        None => (field("action_identity"), field("queue_group_id")),
    };
    let dedupe_count = match row.get("dedupe_count").and_then(Value::as_i64) {
        Some(count) if count != 0 => count.max(1),
        _ => 1,
    };
    let last_seen_at = if truthy(row.get("last_seen_at")) {
        field("last_seen_at")
    } else {
        field("created_at")
    };
    exec(
        connection,
        "update approval_requests set action_identity = ?, queue_group_id = ?, \
         dedupe_count = ?, last_seen_at = ? where request_id = ?",
        &[
            action_identity,
            queue_group_id,
            Value::from(dedupe_count),
            last_seen_at,
            field("request_id"),
        ],
    )?;
    Ok(())
}

/// The resident's answer for one legacy row, or `None` when it rejected it.
fn identity(row: &Row) -> Option<(String, String)> {
    let envelope = match row.get("action_envelope_json") {
        Some(Value::String(text)) => match pyjson::parse(text) {
            // `json.dumps(allow_nan=False)` refused a non-finite value.
            Ok(parsed) if parsed.as_dict().is_some() => Some(parsed.to_json()?),
            _ => None,
        },
        _ => None,
    };
    let optional = |name: &str| row.get(name).and_then(Value::as_str).map(str::to_owned);
    let item = ApprovalQueueIdentityItemV1 {
        launch_target: optional("launch_target"),
        harness: py_text(row.get("harness")),
        workspace: optional("workspace"),
        artifact_id: py_text(row.get("artifact_id")),
        envelope,
        browser_intent: None,
        action_identity: optional("action_identity"),
        queue_group_id: optional("queue_group_id"),
    };
    let wire = json!({
        "operation": "approval_queue_identity",
        "request": {
            "schema": REQUEST_SCHEMA,
            "request_id": format!("approval-queue-identity-{}", "0".repeat(32)),
            "items": [serde_json::to_value(&item).ok()?],
        },
        "deadline_budget_ms": 10000,
    });
    if dumps_default(&wire)?.len() > MAX_REQUEST_BYTES {
        return None;
    }
    let identity = identify(&item)?;
    let action = identity["action_identity"]
        .as_str()
        .filter(|id| !id.is_empty())?;
    let group = identity["queue_group_id"]
        .as_str()
        .filter(|id| !id.is_empty())?;
    Some((action.to_owned(), group.to_owned()))
}

/// Python truthiness of a column value.
fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Number(number)) => number.as_f64() != Some(0.0),
        Some(_) => true,
    }
}

/// `str(value)` of a text column.
fn py_text(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "None".to_owned(),
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_is_remembered_only_after_commit() {
        let home = crate::guard_store_cmd_vectors_tests::temp_home("backfill-settle");
        let connection = Connection::open(home.join("guard.db")).unwrap();
        mark_complete(&connection);
        settle(false);
        assert!(pending(&connection), "a rolled-back scan must run again");
        settle(true);
        assert!(pending(&connection), "nothing staged after a rollback");
        mark_complete(&connection);
        settle(true);
        assert!(!pending(&connection), "a committed scan is remembered");
        let _ = std::fs::remove_dir_all(&home);
    }
}
