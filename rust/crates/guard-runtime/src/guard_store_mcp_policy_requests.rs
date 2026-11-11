//! Pending MCP policy requests, read as `MCPolicyRequestRepository.get_request`
//! reads them: a pending request past its expiry is marked expired first.

use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_one, StoreError, StoreResult};
use crate::guard_store_json::aware_epoch_micros;

const COLUMNS: &str = "request_id, status, policy_document_id, policy_document_digest, \
     expected_current_digest, expected_policy_generation, mode, plan_json, created_at, \
     expires_at, resolved_at, result_json, failure_code";
const STATUSES: [&str; 5] = ["pending", "applied", "declined", "expired", "failed"];

/// The stored request with its status as the repository reports it, or null.
pub(crate) fn get_request(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let request_id = args.str("request_id")?;
    let now = args.str("now")?;
    let sql = format!("select {COLUMNS} from mcp_policy_requests where request_id = ?");
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
