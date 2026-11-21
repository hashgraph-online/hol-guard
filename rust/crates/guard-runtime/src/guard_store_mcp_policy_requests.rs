//! Pending MCP policy requests (`MCPolicyRequestRepository`): staging, reads
//! that mark a request past its expiry expired first, and the decline, expiry
//! and failure transitions. The apply lives in `guard_store_policy_import`.
//!
//! A refused transition is an `{"error": code}` answer the caller maps to its
//! `PolicyToolError`.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_all, query_one, StoreError, StoreResult};
use crate::guard_store_json::aware_epoch_micros;

const COLUMNS: &str = "request_id, status, policy_document_id, policy_document_digest, \
     expected_current_digest, expected_policy_generation, mode, plan_json, created_at, \
     expires_at, resolved_at, result_json, failure_code";
/// Every column, for the repository's own reads; the dashboard reads omit
/// the idempotency hash and the candidate document.
const ALL_COLUMNS: &str = "request_id, idempotency_key_hash, status, policy_document_id, \
     policy_document_digest, expected_current_digest, expected_policy_generation, mode, \
     canonical_policy_yaml, plan_json, created_at, expires_at, resolved_at, result_json, \
     failure_code";
const STATUSES: [&str; 5] = ["pending", "applied", "declined", "expired", "failed"];

/// The stored request with its status as the repository reports it, or null.
pub(crate) fn get_request(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let request_id = args.str("request_id")?;
    let now = args.str("now")?;
    let columns = if args.flag("full")? {
        ALL_COLUMNS
    } else {
        COLUMNS
    };
    let sql = format!("select {columns} from mcp_policy_requests where request_id = ?");
    let Some(mut row) = query_one(connection, &sql, &[Value::from(request_id)])? else {
        return Ok(Value::Null);
    };
    let status = row.get("status").and_then(Value::as_str).unwrap_or("");
    if !STATUSES.contains(&status) {
        return Err(StoreError::Invalid(
            "native_guard_store_stored_value_invalid",
        ));
    }
    if !matches!(
        row.get("mode").and_then(Value::as_str),
        Some("merge" | "replace")
    ) {
        return Err(StoreError::Invalid(
            "native_guard_store_stored_value_invalid",
        ));
    }
    if status == "pending" {
        let expires_at = row.get("expires_at").and_then(Value::as_str).unwrap_or("");
        let invalid = || StoreError::Invalid("native_guard_store_stored_value_invalid");
        let expires = aware_epoch_micros(expires_at).ok_or_else(invalid)?;
        let current =
            aware_epoch_micros(now).ok_or(StoreError::Invalid("native_guard_store_invalid"))?;
        if current > expires {
            exec(
                connection,
                "update mcp_policy_requests set status = 'expired', resolved_at = ? \
                 where request_id = ? and status = 'pending'",
                &[Value::from(now), Value::from(request_id)],
            )?;
            row.insert("status".to_owned(), Value::from("expired"));
        }
    }
    Ok(Value::Object(row))
}

/// `list_pending_requests`: every pending request, newest first.
pub(crate) fn list_pending(connection: &Connection, _args: &Args) -> StoreResult<Value> {
    let rows = query_all(
        connection,
        &format!(
            "select {ALL_COLUMNS} from mcp_policy_requests where status = 'pending' \
             order by created_at desc"
        ),
        &[],
    )?;
    Ok(Value::Array(rows.into_iter().map(Value::Object).collect()))
}

/// `stage_request`: a new pending request, or the one an idempotency key
/// already staged when it carries the same candidate.
pub(crate) fn stage(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let key_hash = args.str("idempotency_key_hash")?;
    let digest = args.str("policy_document_digest")?;
    let mode = args.str("mode")?;
    let baseline = args.opt_str("expected_current_digest")?;
    let yaml = args.str("canonical_policy_yaml")?;
    if let Some(existing) = query_one(
        connection,
        "select request_id, status, policy_document_digest, mode, expected_current_digest, \
         canonical_policy_yaml, created_at, expires_at from mcp_policy_requests \
         where idempotency_key_hash = ?",
        &[json!(key_hash)],
    )? {
        let text = |name: &str| existing.get(name).and_then(Value::as_str);
        let same = text("policy_document_digest") == Some(digest)
            && text("mode") == Some(mode)
            && text("expected_current_digest").filter(|value| !value.is_empty())
                == baseline.filter(|value| !value.is_empty())
            && text("canonical_policy_yaml") == Some(yaml);
        if !same {
            return Ok(json!({"error": "idempotency_conflict"}));
        }
        return Ok(json!({
            "request_id": existing.get("request_id"),
            "status": existing.get("status"),
            "created_at": existing.get("created_at"),
            "expires_at": existing.get("expires_at"),
            "is_replay": true,
        }));
    }
    let request_id = args.str("request_id")?;
    let created_at = args.str("created_at")?;
    let expires_at = args.str("expires_at")?;
    let generation = match args.raw("expected_policy_generation") {
        Some(_) => Some(args.int("expected_policy_generation")?),
        None => None,
    };
    exec(
        connection,
        "insert into mcp_policy_requests (\
           request_id, idempotency_key_hash, status, policy_document_id, policy_document_digest, \
           expected_current_digest, expected_policy_generation, mode, canonical_policy_yaml, \
           plan_json, created_at, expires_at, resolved_at, result_json, failure_code\
         ) values (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, null, null, null)",
        &[
            json!(request_id),
            json!(key_hash),
            json!(args.str("policy_document_id")?),
            json!(digest),
            json!(baseline),
            json!(generation),
            json!(mode),
            json!(yaml),
            json!(args.str("plan_json")?),
            json!(created_at),
            json!(expires_at),
        ],
    )?;
    Ok(json!({
        "request_id": request_id,
        "status": "pending",
        "created_at": created_at,
        "expires_at": expires_at,
        "is_replay": false,
    }))
}

/// `_expire_request`: a pending request becomes expired.
pub(crate) fn expire(connection: &Connection, args: &Args) -> StoreResult<Value> {
    resolve(connection, args, "expired", None)
}

/// The failure mark the repository leaves when an apply broke unexpectedly.
pub(crate) fn fail(connection: &Connection, args: &Args) -> StoreResult<Value> {
    resolve(connection, args, "failed", Some("policy_write_failed"))
}

/// `decline_request`: a pending request becomes declined.
pub(crate) fn decline(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let resolved = resolve(connection, args, "declined", None)?;
    if resolved["resolved"] == json!(true) {
        return Ok(resolved);
    }
    let request_id = args.str("request_id")?;
    match query_one(
        connection,
        "select status from mcp_policy_requests where request_id = ?",
        &[json!(request_id)],
    )? {
        None => Ok(json!({"error": "policy_request_not_found"})),
        Some(row) => Ok(json!({
            "error": "approval_already_resolved",
            "status": row.get("status"),
        })),
    }
}

fn resolve(
    connection: &Connection,
    args: &Args,
    status: &str,
    failure_code: Option<&str>,
) -> StoreResult<Value> {
    let changed = exec(
        connection,
        "update mcp_policy_requests \
         set status = ?, resolved_at = ?, failure_code = coalesce(?, failure_code) \
         where request_id = ? and status = 'pending'",
        &[
            json!(status),
            json!(args.str("now")?),
            json!(failure_code),
            json!(args.str("request_id")?),
        ],
    )?;
    Ok(json!({"resolved": changed > 0}))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn store() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "create table mcp_policy_requests (request_id text primary key, \
                 idempotency_key_hash text not null, status text not null, \
                 policy_document_id text not null, policy_document_digest text not null, \
                 expected_current_digest text, expected_policy_generation integer, \
                 mode text not null, canonical_policy_yaml text not null, plan_json text not null, \
                 created_at text not null, expires_at text not null, resolved_at text, \
                 result_json text, failure_code text);
                 insert into mcp_policy_requests values ('r1', 'h', 'pending', 'd', 'g', null, null, \
                 'merge', 'y', '{}', '2026-01-01T00:00:00+00:00', '2026-01-02T00:00:00Z', null, null, null);",
            )
            .unwrap();
        connection
    }

    fn read(connection: &Connection, now: &str) -> Value {
        let args = json!({"request_id": "r1", "now": now});
        get_request(connection, &Args(args.as_object().unwrap())).unwrap()
    }

    #[test]
    fn a_pending_request_past_its_expiry_reads_expired() {
        let connection = store();
        assert_eq!(
            read(&connection, "2026-01-01T12:00:00+00:00")["status"],
            "pending"
        );
        assert_eq!(
            read(&connection, "2026-01-03T00:00:00+00:00")["status"],
            "expired"
        );
        let stored = read(&connection, "2026-01-04T00:00:00+00:00");
        assert_eq!(stored["status"], "expired");
        assert_eq!(stored["resolved_at"], "2026-01-03T00:00:00+00:00");
    }

    fn call(
        connection: &Connection,
        op: fn(&Connection, &Args) -> StoreResult<Value>,
        args: Value,
    ) -> Value {
        op(connection, &Args(args.as_object().unwrap())).unwrap()
    }

    fn staged(request_id: &str, yaml: &str) -> Value {
        json!({
            "request_id": request_id,
            "idempotency_key_hash": "k",
            "policy_document_id": "doc",
            "policy_document_digest": "sha256:a",
            "expected_current_digest": null,
            "expected_policy_generation": 2,
            "mode": "merge",
            "canonical_policy_yaml": yaml,
            "plan_json": "{}",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-01-01T00:10:00Z",
        })
    }

    #[test]
    fn staging_replays_the_same_key_and_refuses_another_candidate() {
        let connection = store();
        let first = call(&connection, stage, staged("r2", "y"));
        assert_eq!(first["is_replay"], json!(false));
        let replay = call(&connection, stage, staged("r3", "y"));
        assert_eq!(replay["request_id"], json!("r2"));
        assert_eq!(replay["is_replay"], json!(true));
        assert_eq!(
            call(&connection, stage, staged("r4", "other")),
            json!({"error": "idempotency_conflict"})
        );
        let pending = call(&connection, list_pending, json!({}));
        assert_eq!(pending.as_array().unwrap().len(), 2);
        assert_eq!(pending[0]["request_id"], json!("r2"));
        assert_eq!(pending[0]["canonical_policy_yaml"], json!("y"));
    }

    #[test]
    fn decline_resolves_once_and_reports_why_it_cannot_again() {
        let connection = store();
        let now = "2026-01-01T01:00:00Z";
        let declined = call(
            &connection,
            decline,
            json!({"request_id": "r1", "now": now}),
        );
        assert_eq!(declined, json!({"resolved": true}));
        assert_eq!(
            call(
                &connection,
                decline,
                json!({"request_id": "r1", "now": now})
            ),
            json!({"error": "approval_already_resolved", "status": "declined"})
        );
        assert_eq!(
            call(
                &connection,
                decline,
                json!({"request_id": "rx", "now": now})
            ),
            json!({"error": "policy_request_not_found"})
        );
    }

    #[test]
    fn a_failure_mark_records_its_code() {
        let connection = store();
        let now = "2026-01-01T01:00:00Z";
        call(&connection, fail, json!({"request_id": "r1", "now": now}));
        let stored = read(&connection, now);
        assert_eq!(stored["status"], "failed");
        let code: String = connection
            .query_row("select failure_code from mcp_policy_requests", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(code, "policy_write_failed");
        assert_eq!(
            call(&connection, expire, json!({"request_id": "r1", "now": now})),
            json!({"resolved": false})
        );
    }

    #[test]
    fn an_unknown_request_is_null() {
        let connection = store();
        let args = json!({"request_id": "missing", "now": "2026-01-01T00:00:00+00:00"});
        assert_eq!(
            get_request(&connection, &Args(args.as_object().unwrap())).unwrap(),
            Value::Null
        );
    }
}
