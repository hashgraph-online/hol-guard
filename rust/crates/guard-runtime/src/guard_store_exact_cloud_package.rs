//! The exact Cloud Review allow for a package install still waiting on the
//! request it queued.
//!
//! The package shim queues a request and waits for it in process. A Cloud
//! resolution mints an exact Cloud row bound to that request, not a saved
//! package approval, so the ordinary package lookup never reads it. These two
//! ops let only the waiting install, which names its own request, use it:
//!
//! - `peek_waited_exact_cloud_package_allow` returns the verified decision
//!   when it allows this artifact and hash, and `Null` otherwise. The row is
//!   already bound to the request's harness, workspace and publisher.
//! - `consume_waited_exact_cloud_package_allow` spends that decision once,
//!   re-checking it in the write transaction.
//!
//! The caller keeps the integrity key in the keyring and ships it; a missing
//! key reads as no authority.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_exact_cloud_apply::integrity_material;
use crate::guard_store_exact_cloud_peek::verified_decision;
use crate::resident_transport::constant_time_eq;

/// Only a package request's artifact may be answered here.
const PACKAGE_REQUEST_ARTIFACT: &str = ":package-request:";

fn canonical_now(args: &Args<'_>) -> StoreResult<String> {
    guard_contracts::canonical_utc_timestamp(args.str("now")?)
        .ok_or(StoreError::Invalid("exact_cloud_package_time_invalid"))
}

fn allows(decision: &Value, request_id: &str, artifact_id: &str, artifact_hash: &str) -> bool {
    let text = |field: &str| decision.get(field).and_then(Value::as_str);
    let stored_hash = text("artifact_hash").unwrap_or_default();
    text("action") == Some("allow")
        && text("request_id") == Some(request_id)
        && text("artifact_id") == Some(artifact_id)
        && artifact_id.contains(PACKAGE_REQUEST_ARTIFACT)
        && !stored_hash.is_empty()
        && constant_time_eq(stored_hash.as_bytes(), artifact_hash.as_bytes())
}

pub(crate) fn peek(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let request_id = args.str("request_id")?;
    let artifact_id = args.str("artifact_id")?;
    let artifact_hash = args.str("artifact_hash")?;
    let now = canonical_now(args)?;
    let Some((key, key_id)) = integrity_material(args)? else {
        return Ok(Value::Null);
    };
    let decision = verified_decision(connection, request_id, &now, &key, key_id)?;
    Ok(
        if allows(&decision, request_id, artifact_id, artifact_hash) {
            decision
        } else {
            Value::Null
        },
    )
}

pub(crate) fn consume(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let request_id = args.str("request_id")?;
    let decision = Value::Object(args.object("decision")?.clone());
    let now = canonical_now(args)?;
    let Some((key, key_id)) = integrity_material(args)? else {
        return Ok(json!(false));
    };
    let artifact_id = decision
        .get("artifact_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let artifact_hash = decision
        .get("artifact_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !allows(&decision, request_id, artifact_id, artifact_hash) {
        return Ok(json!(false));
    }
    Ok(json!(
        crate::continuation_grants::consume_exact_cloud_package(
            connection, request_id, &decision, &now, &key, key_id,
        )?
    ))
}

#[cfg(test)]
#[path = "guard_store_exact_cloud_package_tests.rs"]
mod tests;
