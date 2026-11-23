//! `recover_business_policy_source`: the store's half of an explicit
//! business-source recovery (`native_business_source_recovery.py`).
//!
//! The Python source owner verifies the prepared record, the anchors and the
//! fresh approval, and writes the private files. This op lands the store's
//! part in one transaction:
//!
//! - the installation witness the caller read must still be the stored one
//!   (`expected_witness`, absent or null for none), or nothing is written;
//! - with `business_witness`, the business install runs as
//!   `import_policy_rows` runs it: the imported rows go, the generation
//!   advances and the witness is staged;
//! - with `recovery_request`, the MCP policy request it names must still hold
//!   the recovered digest in `replace` mode and must not be declined. Its
//!   recovery marker is then recorded, so the request can no longer be
//!   applied over the recovered source.
//!
//! A refusal is an error, so the whole transaction rolls back.

use rusqlite::Connection;
use serde_json::{json, Value};

use super::{write_rows, BUSINESS_WITNESS_KEY, RECOVERY_PREFIX};
use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_one, value_error, StoreError, StoreResult};

const UPSERT_STATE: &str = "insert into sync_state (state_key, payload_json, updated_at) \
     values (?, ?, ?) on conflict(state_key) do update set \
     payload_json = excluded.payload_json, updated_at = excluded.updated_at";

pub(super) fn recover_business_policy_source(
    connection: &Connection,
    args: &Args,
) -> StoreResult<Value> {
    let now = args.str("now")?;
    if stored_witness(connection)?.as_deref() != args.opt_str("expected_witness")? {
        return value_error("native_business_source_current_digest_changed");
    }
    let mut answer = json!({"installed": false, "next_control_state": null});
    if args.opt_str("business_witness")?.is_some() {
        let (_, replaced, next_control_state) = write_rows(connection, args)?;
        answer = json!({
            "installed": true,
            "replaced": replaced,
            "next_control_state": next_control_state,
        });
    }
    if let Some(request) = args.opt_object("recovery_request")? {
        stage_request_recovery(connection, &Args(request), now)?;
    }
    Ok(answer)
}

pub(super) fn stage_witness(connection: &Connection, witness: &str, now: &str) -> StoreResult<()> {
    exec(
        connection,
        UPSERT_STATE,
        &[json!(BUSINESS_WITNESS_KEY), json!(witness), json!(now)],
    )?;
    Ok(())
}

fn stored_witness(connection: &Connection) -> StoreResult<Option<String>> {
    let Some(row) = query_one(
        connection,
        "select payload_json from sync_state where state_key = ?",
        &[json!(BUSINESS_WITNESS_KEY)],
    )?
    else {
        return Ok(None);
    };
    match row.get("payload_json") {
        Some(Value::String(text)) => Ok(Some(text.clone())),
        _ => Err(StoreError::Invalid(
            "native_guard_store_stored_value_invalid",
        )),
    }
}

/// `stage_request_recovery` (`mcp/policy_recovery_state.py`).
fn stage_request_recovery(connection: &Connection, request: &Args, now: &str) -> StoreResult<()> {
    let request_id = request.str("request_id")?;
    let digest = request.str("source_digest")?;
    let row = query_one(
        connection,
        "select policy_document_digest, mode, status from mcp_policy_requests \
         where request_id = ?",
        &[json!(request_id)],
    )?;
    let coherent = row.as_ref().is_some_and(|row| {
        let text = |name: &str| row.get(name).and_then(Value::as_str);
        text("policy_document_digest") == Some(digest)
            && text("mode") == Some("replace")
            && text("status") != Some("declined")
    });
    if !coherent {
        return value_error("candidate_digest_mismatch");
    }
    let digest_json = serde_json::to_string(digest)
        .map_err(|_| StoreError::Invalid("native_guard_store_args_invalid"))?;
    // The marker's text matches the Python writer's `json.dumps` output.
    let payload = format!("{{\"source_digest\": {digest_json}, \"request_recovered\": true}}");
    exec(
        connection,
        UPSERT_STATE,
        &[
            json!(format!("{RECOVERY_PREFIX}{request_id}")),
            json!(payload),
            json!(now),
        ],
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "guard_store_policy_recovery_tests.rs"]
mod tests;
