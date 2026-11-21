//! `GuardStore` — resident op owning request-path persistence over
//! `guard.db`. Each call opens the store (reusing a kept connection to the
//! same file), applies the same connection pragmas
//! as the Python store, runs one method in a single SQLite transaction,
//! finalizes trigger-written outbox payload hashes, commits, and reports the
//! outbox generation when rows changed.
//!
//! Process-local concerns (the storage-access lock, wake notification,
//! permission repair, fatal-store recovery, wall-clock timestamps) stay with
//! the caller, which passes every timestamp in the request.

use std::path::Path;
use std::time::{Duration, Instant};

use guard_contracts::{
    GuardStoreRequestV1, GuardStoreResultV1, GUARD_STORE_MAX_REQUEST_BYTES,
    GUARD_STORE_REQUEST_SCHEMA, GUARD_STORE_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use rusqlite::Connection;
use serde_json::{json, Value};

use super::context_digest_json::write_canonical_json_with_limit;
use crate::guard_store_approval_backfill;
use crate::guard_store_args::Args;
use crate::guard_store_connect as connect;
use crate::guard_store_db::{query_all, query_one, StoreError, StoreResult};
use crate::guard_store_native_review_queue as native_review_queue;
use crate::guard_store_op_dispatch::dispatch;
use crate::guard_store_op_kind::{method_kind, Kind};
use crate::guard_store_receipt_rollups as receipt_rollups;

pub(crate) const MAX_BUSY_TIMEOUT_MS: u64 = 600_000;
const CACHE_SIZE_KIB: i64 = 256 * 1024;
const MMAP_SIZE_BYTES: i64 = 1024 * 1024 * 1024;

/// The digest never covers policy-integrity key bytes: a reply, log or
/// diagnostic that carries the digest reveals nothing about the key. The
/// caller drops the same arguments before computing its own digest, exactly as
/// the policy-integrity rows request does.
const UNDIGESTED_ARGS: [&str; 1] = ["integrity_key_b64"];

fn request_digest(request: &GuardStoreRequestV1) -> Result<String, &'static str> {
    let mut material = serde_json::to_value(request).map_err(|_| "native_guard_store_invalid")?;
    if let Some(args) = material.get_mut("args").and_then(Value::as_object_mut) {
        for field in UNDIGESTED_ARGS {
            args.remove(field);
        }
    }
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&material, &mut bytes, GUARD_STORE_MAX_REQUEST_BYTES)
        .map_err(|_| "native_guard_store_request_too_large")?;
    Ok(format!("sha256:{}", digest_bytes(&bytes)))
}

#[cfg(test)]
pub(crate) fn evaluate_guard_store_request(
    request: &GuardStoreRequestV1,
) -> Result<Vec<u8>, String> {
    evaluate_guard_store_request_with_owner(request, None)
}

pub(crate) fn evaluate_guard_store_request_with_owner(
    request: &GuardStoreRequestV1,
    owner: Option<&crate::policy_store::PolicySnapshotStore>,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request).map_err(str::to_owned)?;
    let outcome = match owner {
        Some(owner) => evaluate_with_owner(request, Some(owner)),
        None => evaluate(request),
    };
    let (status, code, payload, generation) = match outcome {
        Ok((payload, generation)) => ("ok".to_owned(), "ok".to_owned(), Some(payload), generation),
        Err(error) => {
            let payload = Some(json!({ "message": error.message() }));
            ("error".to_owned(), error.code().to_owned(), payload, None)
        }
    };
    crate::encode_response(&GuardStoreResultV1 {
        schema: GUARD_STORE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
        outbox_generation: generation,
    })
}

pub(crate) fn evaluate(request: &GuardStoreRequestV1) -> StoreResult<(Value, Option<i64>)> {
    evaluate_with_owner(request, None)
}

/// Run one call and say whether its write committed, even when it fails.
///
/// The outbox generation is read after the commit, so a call can fail with its
/// write already durable; a caller that retries failed writes elsewhere must
/// not retry that one.
pub(crate) fn evaluate_committing(request: &GuardStoreRequestV1) -> (StoreResult<Value>, bool) {
    let mut committed = false;
    let outcome = evaluate_tracked(request, None, &mut committed);
    (outcome.map(|(payload, _)| payload), committed)
}

fn evaluate_with_owner(
    request: &GuardStoreRequestV1,
    owner: Option<&crate::policy_store::PolicySnapshotStore>,
) -> StoreResult<(Value, Option<i64>)> {
    evaluate_tracked(request, owner, &mut false)
}

fn evaluate_tracked(
    request: &GuardStoreRequestV1,
    owner: Option<&crate::policy_store::PolicySnapshotStore>,
    committed_write: &mut bool,
) -> StoreResult<(Value, Option<i64>)> {
    let invalid = |code| Err(StoreError::Invalid(code));
    if request.schema != GUARD_STORE_REQUEST_SCHEMA {
        return invalid("native_guard_store_schema_mismatch");
    }
    if request.request_id.is_empty()
        || request.source.is_empty()
        || !(1..=MAX_BUSY_TIMEOUT_MS).contains(&request.busy_timeout_ms)
    {
        return invalid("native_guard_store_invalid");
    }
    let path =
        crate::local_store_read::require_store_path(&request.store_path, &request.guard_home)
            .map_err(|_| StoreError::Invalid("native_guard_store_path_invalid"))?;
    // A paused review's request is built here and queued by the write it
    // names, so everything below sees that method.
    let started = Instant::now();
    let method = request.method.as_str();
    let delegated = [
        native_review_queue::METHOD,
        native_review_queue::BOUND_BASH_METHOD,
    ]
    .contains(&method)
    .then(|| {
        let budget_ms = request.busy_timeout_ms;
        native_review_queue::delegate(method, &request.args, owner, budget_ms, |ask| {
            crate::hook_direct::saved_decision::review_queue::connector::queued_lookup(
                &ask.request(request),
            )
        })
    })
    .transpose()?;
    // The caller's deadline covers the whole call, so the write waits for the
    // lock only as long as the hint left it. With nothing left a contended
    // write fails at once rather than commit after the caller gave up.
    let busy_timeout_ms = if delegated.is_some() {
        let spent = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        request.busy_timeout_ms.saturating_sub(spent).max(1)
    } else {
        request.busy_timeout_ms
    };
    let (method, request_args) = match &delegated {
        Some(delegated) => (delegated.method, &delegated.args),
        None => (request.method.as_str(), &request.args),
    };
    let kind = match method_kind(method) {
        Some(kind) => kind,
        None => return invalid("native_guard_store_method_unknown"),
    };
    // A waiting Codex hook's live wait is built before the store opens its
    // write: proving the bridge process live can spawn `ps`.
    let prepared =
        crate::codex_live_wait_build::prepare(method, request_args, Path::new(&request.guard_home));
    // A warm call reuses a kept connection: reopening parsed the whole schema
    // on every call (see `guard_store_write_cache`).
    let connection = crate::guard_store_write_cache::open_read_write_cached(&path)?;
    connection.busy_timeout(Duration::from_millis(busy_timeout_ms))?;
    apply_pragmas(&connection)?;
    // A total read only writes for the one-time rebuild a migration requests;
    // every other call stays lock-free.
    let args = Args(prepared.as_ref().unwrap_or(request_args));
    // A retry's block check alone writes nothing: it keeps the lock-free read
    // the separate block lookup had.
    let kind = if method == "settle_native_review_reuse" && !args.flag("spend")? {
        Kind::Read
    } else if (method == "count_receipts"
        && kind == Kind::Read
        && receipt_rollups::rebuild_pending(&connection)?)
        || (connect::is_state_read(method) && connect::read_persists_expiry(&connection, &args)?)
    {
        Kind::Write
    } else {
        kind
    };
    let writes = kind == Kind::Write;
    let initial_changes = connection.total_changes();
    match kind {
        Kind::Write => connection.execute_batch("BEGIN IMMEDIATE")?,
        Kind::Snapshot => connection.execute_batch("BEGIN")?,
        Kind::Read => {}
    }
    let outcome = dispatch(
        &connection,
        &request.source,
        &request.guard_home,
        method,
        &args,
        owner,
    );
    let mut payload = match outcome {
        Ok(payload) => payload,
        Err(error) => {
            if kind != Kind::Read {
                let _ = connection.execute_batch("ROLLBACK");
            }
            guard_store_approval_backfill::settle(false);
            return Err(error);
        }
    };
    // A connector-setup review's context is kept in the write that stored it.
    if let (Some(delegated), Kind::Write) = (&delegated, kind) {
        if let Some(code) = delegated.record_connector_context(&connection, &payload) {
            if let Some(reply) = payload.as_object_mut() {
                reply.insert("connector_context_error".to_owned(), Value::from(code));
            }
        }
    }
    if kind == Kind::Snapshot {
        connection.execute_batch("ROLLBACK")?;
    } else {
        let committed = finalize_and_commit(&connection, writes);
        guard_store_approval_backfill::settle(committed.is_ok());
        committed?;
        *committed_write = writes;
    }
    let generation = (connection.total_changes() > initial_changes)
        .then(|| outbox_generation(&connection))
        .transpose()?;
    // A paused review's hook response is rendered once its row is stored.
    let payload = match &delegated {
        Some(delegated) => delegated.with_response(payload, &request.guard_home),
        None => payload,
    };
    Ok((payload, generation))
}

fn apply_pragmas(connection: &Connection) -> StoreResult<()> {
    let journal: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if journal.eq_ignore_ascii_case("wal") {
        connection.execute_batch("pragma synchronous=NORMAL")?;
    }
    connection.execute_batch(&format!(
        "pragma cache_size=-{CACHE_SIZE_KIB}; pragma mmap_size={MMAP_SIZE_BYTES};"
    ))?;
    Ok(())
}

/// Finalize empty trigger-written payload digests, then commit.
fn finalize_and_commit(connection: &Connection, in_transaction: bool) -> StoreResult<()> {
    let pending = query_one(
        connection,
        "select 1 as present from guard_review_outbox_events where payload_hash = '' limit 1",
        &[],
    )?
    .is_some();
    if pending && !in_transaction {
        connection.execute_batch("BEGIN IMMEDIATE")?;
    }
    if pending {
        finalize_payload_hashes(connection)?;
    }
    if in_transaction || pending {
        connection.execute_batch("COMMIT")?;
    }
    Ok(())
}

fn finalize_payload_hashes(connection: &Connection) -> StoreResult<()> {
    let null = Value::Null;
    let rows = query_all(
        connection,
        "select stream_sequence, payload_json, oauth_source, oauth_subject_hash, \
         workspace_id, machine_id, machine_installation_id \
         from guard_review_outbox_events where payload_hash = ''",
        &[],
    )?;
    for row in &rows {
        let field = |name: &str| row.get(name).unwrap_or(&null);
        let digest = payload_digest(
            text(row, "payload_json"),
            [
                field("oauth_source"),
                field("oauth_subject_hash"),
                field("workspace_id"),
                field("machine_id"),
                field("machine_installation_id"),
            ],
        );
        exec(
            connection,
            "update guard_review_outbox_events set payload_hash = ? where stream_sequence = ?",
            &[Value::from(digest), field("stream_sequence").clone()],
        )?;
    }
    Ok(())
}

fn outbox_generation(connection: &Connection) -> StoreResult<i64> {
    let table = query_one(
        connection,
        "select 1 as present from sqlite_master \
         where type = 'table' and name = 'guard_review_outbox_wake_state'",
        &[],
    )?;
    if table.is_none() {
        return Ok(0);
    }
    Ok(query_one(
        connection,
        "select generation from guard_review_outbox_wake_state where singleton = 1",
        &[],
    )?
    .map_or(0, |row| crate::guard_store_db::int(&row, "generation")))
}

#[cfg(test)]
pub(crate) fn method_is_snapshot_for_test(method: &str) -> bool {
    method_kind(method) == Some(Kind::Snapshot)
}
