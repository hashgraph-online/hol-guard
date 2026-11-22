//! Runner authority evidence attached to the receipts one wrapper-mode
//! evaluation emitted. The rows are read, merged and rewritten inside the
//! store's write transaction, so no other writer can change them between the
//! read and the update.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_all, StoreError, StoreResult};
use crate::guard_store_json::dumps_default;
use crate::runner_authority_evaluation::receipt_evidence_merge;

const PAGE_ROWS: i64 = 500;
/// Artifact IDs bound into one query, well under SQLite's parameter limit.
const ID_CHUNK: usize = 500;
/// Stored evidence merged at once, so a page of large rows is not held whole.
const MERGE_BATCH_BYTES: usize = 512 * 1024;
const INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");

fn id_list(args: &Args<'_>, key: &str) -> StoreResult<Vec<Value>> {
    let ids = args.strings(key)?.ok_or(INVALID)?;
    Ok(ids.into_iter().map(Value::from).collect())
}

struct Amendment<'a> {
    artifact_ids: &'a [Value],
    evidence: &'a Map<String, Value>,
    approval_source: Value,
    source_actions: Vec<Value>,
    replace: bool,
}

/// Merges `evidence` into every receipt after `after_rowid` whose artifact is
/// one of `artifact_ids`, and returns how many receipts were rewritten.
pub(crate) fn amend(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let after_rowid = args.int("after_rowid")?;
    let artifact_ids = id_list(args, "artifact_ids")?;
    let amendment = Amendment {
        artifact_ids: &artifact_ids,
        source_actions: id_list(args, "source_actions")?,
        evidence: args.object("evidence")?,
        approval_source: Value::from(args.str("approval_source")?),
        replace: args.flag("replace_existing_source")?,
    };
    let mut changed = 0_i64;
    for ids in artifact_ids.chunks(ID_CHUNK) {
        changed += amend_artifacts(connection, &amendment, after_rowid, ids)?;
    }
    Ok(Value::from(changed))
}

/// Pages only the receipts of `ids`, so receipts of other artifacts are never
/// read while the write transaction is held.
fn amend_artifacts(
    connection: &Connection,
    amendment: &Amendment<'_>,
    after_rowid: i64,
    ids: &[Value],
) -> StoreResult<i64> {
    let placeholders = vec!["?"; ids.len()].join(", ");
    let sql = format!(
        "select rowid, artifact_id, policy_decision, scanner_evidence_json, approval_source \
         from runtime_receipts where rowid > ? and artifact_id in ({placeholders}) \
         order by rowid asc limit ?"
    );
    let mut cursor = after_rowid;
    let mut changed = 0_i64;
    loop {
        let mut params = Vec::with_capacity(ids.len() + 2);
        params.push(Value::from(cursor));
        params.extend(ids.iter().cloned());
        params.push(Value::from(PAGE_ROWS));
        let page = query_all(connection, &sql, &params)?;
        let Some(last) = page.last() else {
            break;
        };
        cursor = last.get("rowid").and_then(Value::as_i64).ok_or(INVALID)?;
        let mut batch = Vec::new();
        let mut batch_bytes = 0_usize;
        for row in page {
            let bytes = row
                .get("scanner_evidence_json")
                .and_then(Value::as_str)
                .map_or(0, str::len);
            if !batch.is_empty() && batch_bytes.saturating_add(bytes) > MERGE_BATCH_BYTES {
                changed += merge_and_write(connection, amendment, std::mem::take(&mut batch))?;
                batch_bytes = 0;
            }
            batch_bytes = batch_bytes.saturating_add(bytes);
            batch.push(Value::Object(row));
        }
        if !batch.is_empty() {
            changed += merge_and_write(connection, amendment, batch)?;
        }
    }
    Ok(changed)
}

fn merge_and_write(
    connection: &Connection,
    amendment: &Amendment<'_>,
    rows: Vec<Value>,
) -> StoreResult<i64> {
    let merged = receipt_evidence_merge(&json!({
        "rows": rows,
        "artifact_ids": amendment.artifact_ids,
        "evidence": amendment.evidence,
        "approval_source": amendment.approval_source,
        "source_actions": amendment.source_actions,
        "replace_existing_source": amendment.replace,
    }))
    .map_err(StoreError::Invalid)?;
    let updates = merged["updates"].as_array().ok_or(INVALID)?;
    let mut changed = 0_i64;
    for update in updates {
        let encoded = dumps_default(&update["scanner_evidence"]).ok_or(INVALID)?;
        changed += exec(
            connection,
            "update runtime_receipts set scanner_evidence_json = ?, approval_source = ? \
             where rowid = ?",
            &[
                Value::from(encoded),
                update["approval_source"].clone(),
                update["rowid"].clone(),
            ],
        )?;
    }
    Ok(changed)
}

#[cfg(all(test, unix))]
#[path = "guard_store_receipt_evidence_tests.rs"]
mod tests;
