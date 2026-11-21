//! `record_policy_bundle_activation`: the `sync_state` rows and event the
//! cloud sync writes once a signed policy bundle is activated, and the receipt
//! redaction level the bundle sets.
//!
//! The bundle was verified and activated before this call; these rows are the
//! last-good copies a later sync falls back to. Everything runs in the one
//! store write, so a reader never sees the new last-good bundle with the old
//! redaction bookkeeping.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{value_error, StoreResult};
use crate::guard_store_json::dumps_default;
use crate::guard_store_receipt_redaction::{persist, reset, valid_level, Bookkeeping, Store};

const V2_CONTRACT: &str = "guard-policy-bundle.v2";
const CANONICAL_LAST_GOOD: &str = "policy_bundle_canonical_last_good";
const CANONICAL_PREVIOUS_GOOD: &str = "policy_bundle_canonical_previous_good";
const LEGACY_LAST_GOOD: &str = "policy_bundle_legacy_last_good";
const ROLLBACK_EVENT: &str = "policy_bundle/rollback";

/// Store the activated bundle as the last-good copy for its contract. A v2
/// bundle that replaces a different canonical bundle keeps that one as the
/// previous good copy. `rollback_reason` is given when Cloud's own bundle was
/// rejected and a stored bundle was restored instead.
pub(crate) fn record(
    store: &mut impl Bookkeeping,
    bundle: &Value,
    rollback_reason: Option<&str>,
    local_level: &str,
    now: &str,
) -> StoreResult<()> {
    if bundle.get("contractVersion").and_then(Value::as_str) == Some(V2_CONTRACT) {
        if let Some(previous) = store.read(CANONICAL_LAST_GOOD)? {
            if previous.is_object() && previous.get("bundleHash") != bundle.get("bundleHash") {
                store.write(CANONICAL_PREVIOUS_GOOD, &previous, now)?;
            }
        }
        store.write(CANONICAL_LAST_GOOD, bundle, now)?;
    } else {
        store.write(LEGACY_LAST_GOOD, bundle, now)?;
    }
    if let Some(reason) = rollback_reason {
        let payload = json!({"reason": reason, "restored": "policy_bundle_last_good"});
        let Some(encoded) = dumps_default(&payload) else {
            return value_error("invalid_payload");
        };
        store.add_event(ROLLBACK_EVENT, &encoded, now)?;
    }
    match bundle
        .get("receiptRedactionLevel")
        .and_then(Value::as_str)
        .filter(|level| valid_level(level))
    {
        Some(level) => persist(store, level, local_level, now),
        None => reset(store, local_level, now),
    }
}

/// The `record_policy_bundle_activation` store method.
pub(crate) fn method(connection: &Connection, source: &str, args: &Args<'_>) -> StoreResult<Value> {
    let bundle = args
        .raw("bundle")
        .filter(|bundle| bundle.is_object())
        .map_or_else(|| value_error("invalid_policy_bundle"), Ok)?;
    let local_level = args.str("local_level")?;
    if !valid_level(local_level) {
        return value_error("invalid_receipt_redaction_level");
    }
    let mut store = Store { connection, source };
    record(
        &mut store,
        bundle,
        args.opt_str("rollback_reason")?,
        local_level,
        args.str("now")?,
    )?;
    Ok(Value::Null)
}

#[cfg(test)]
#[path = "guard_store_policy_bundle_activated_tests.rs"]
mod tests;
