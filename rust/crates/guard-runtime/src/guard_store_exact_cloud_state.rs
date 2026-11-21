//! `exact_cloud_review_state`, `replace_exact_cloud_review_state` and
//! `has_exact_cloud_review_receipt`: the local consent rows behind signed
//! one-request Cloud reviews.
//!
//! Port of the raw `sync_state` reads in `runtime/exact_cloud_review.py` and
//! the compare-and-swap writer in `store_exact_cloud_review.py`. The signed
//! verdict itself is applied by `apply_signed_remote_exact_result`; these are
//! the rows the enable, disable and binding-drift paths read and replace.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_one, value_error, StoreError, StoreResult};
use crate::guard_store_exact_cloud_apply::{
    exact_state, record_event, revocation_state, CAPABILITY_KEY, REVOCATION_KEY,
};
use crate::guard_store_json::dumps_sorted;
use crate::guard_store_sync_state::write_encoded;

/// Whether `method` is one of the exact Cloud Review consent-row methods.
pub(crate) fn handles(method: &str) -> bool {
    matches!(
        method,
        "exact_cloud_review_state"
            | "replace_exact_cloud_review_state"
            | "has_exact_cloud_review_receipt"
    )
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        "exact_cloud_review_state" => Ok(json!({
            "capability": exact_state(connection, CAPABILITY_KEY)?,
            "revocation": revocation_state(connection)?,
        })),
        "replace_exact_cloud_review_state" => replace_method(connection, args),
        "has_exact_cloud_review_receipt" => receipt_method(connection, args),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

/// A required, non-empty text argument.
fn text<'a>(args: &Args<'a>, key: &str, code: &'static str) -> StoreResult<&'a str> {
    match args.raw(key).and_then(Value::as_str) {
        Some(value) if !value.is_empty() => Ok(value),
        _ => value_error(code),
    }
}

/// An object argument, or `None` when it is missing or null.
fn optional_object<'a>(
    args: &Args<'a>,
    key: &str,
    code: &'static str,
) -> StoreResult<Option<&'a Map<String, Value>>> {
    match args.raw(key) {
        None => Ok(None),
        Some(Value::Object(row)) => Ok(Some(row)),
        Some(_) => value_error(code),
    }
}

/// `_store_exact_state`: the row's object, or no row at all for `None`.
fn store_row(
    connection: &Connection,
    state_key: &str,
    payload: Option<&Map<String, Value>>,
    now: &str,
) -> StoreResult<()> {
    let Some(row) = payload else {
        exec(
            connection,
            "delete from sync_state where state_key = ?",
            &[Value::from(state_key)],
        )?;
        return Ok(());
    };
    let encoded = dumps_sorted(&Value::Object(row.clone()))
        .ok_or(StoreError::Invalid("native_exact_cloud_state_invalid"))?;
    write_encoded(connection, state_key, &encoded, now)
}

/// `replace_exact_cloud_review_state`: write the capability and revocation
/// rows and their event in one transaction. With
/// `require_expected_capability`, the stored capability must still equal
/// `expected_capability`, or nothing is written and the answer is `false`.
fn replace_method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let capability = optional_object(args, "capability", "invalid_capability")?;
    let revocation = optional_object(args, "revocation", "invalid_revocation")?;
    let now = text(args, "now", "invalid_now")?;
    let event_name = text(args, "event_name", "invalid_event_name")?;
    let Some(event_payload) = args.raw("event_payload").filter(|value| value.is_object()) else {
        return value_error("invalid_event_payload");
    };
    let require_expected = args.flag("require_expected_capability")?;
    if require_expected {
        let expected = args.raw("expected_capability").unwrap_or(&Value::Null);
        if exact_state(connection, CAPABILITY_KEY)? != *expected {
            return Ok(Value::Bool(false));
        }
    }
    store_row(connection, CAPABILITY_KEY, capability, now)?;
    store_row(connection, REVOCATION_KEY, revocation, now)?;
    record_event(connection, event_name, event_payload, now)?;
    Ok(Value::Bool(true))
}

/// `has_exact_cloud_review_receipt`: whether a verdict with this receipt id
/// was already claimed.
fn receipt_method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let receipt_id = text(args, "receipt_id", "invalid_receipt_id")?;
    let row = query_one(
        connection,
        "select 1 from guard_exact_cloud_review_receipts where receipt_id = ?",
        &[Value::from(receipt_id)],
    )?;
    Ok(Value::Bool(row.is_some()))
}

#[cfg(test)]
#[path = "guard_store_exact_cloud_state_tests.rs"]
mod tests;
