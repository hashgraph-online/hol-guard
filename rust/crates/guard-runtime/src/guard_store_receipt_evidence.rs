//! Runner authority evidence attached to the receipts one wrapper-mode
//! evaluation emitted. The rows are read, merged and rewritten inside the
//! store's write transaction, so no other writer can change them between the
//! read and the update.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_all, StoreError, StoreResult};
use crate::guard_store_json::dumps_default;
use crate::runner_authority_evaluation::receipt_evidence_merge;

const PAGE_ROWS: i64 = 500;
const INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");

fn id_list(args: &Args<'_>, key: &str) -> StoreResult<Vec<Value>> {
    let ids = args.strings(key)?.ok_or(INVALID)?;
    Ok(ids.into_iter().map(Value::from).collect())
}

/// Merges `evidence` into every receipt after `after_rowid` whose artifact is
/// one of `artifact_ids`, and returns how many receipts were rewritten.
pub(crate) fn amend(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let after_rowid = args.int("after_rowid")?;
    let artifact_ids = id_list(args, "artifact_ids")?;
    let source_actions = id_list(args, "source_actions")?;
    let evidence = args.object("evidence")?;
    let approval_source = args.raw("approval_source").cloned().unwrap_or(Value::Null);
    let replace = args.flag("replace_existing_source")?;
    let mut cursor = after_rowid;
    let mut changed = 0_i64;
    loop {
        let page = query_all(
            connection,
            "select rowid, artifact_id, policy_decision, scanner_evidence_json, approval_source \
             from runtime_receipts where rowid > ? order by rowid asc limit ?",
            &[Value::from(cursor), Value::from(PAGE_ROWS)],
        )?;
        let Some(last) = page.last() else {
            break;
        };
        cursor = last.get("rowid").and_then(Value::as_i64).ok_or(INVALID)?;
        let rows: Vec<Value> = page
            .into_iter()
            .filter(|row| {
                row.get("artifact_id")
                    .is_some_and(|id| artifact_ids.contains(id))
            })
            .map(Value::Object)
            .collect();
        if rows.is_empty() {
            continue;
        }
        let merged = receipt_evidence_merge(&json!({
            "rows": rows,
            "artifact_ids": artifact_ids,
            "evidence": evidence,
            "approval_source": approval_source,
            "source_actions": source_actions,
            "replace_existing_source": replace,
        }))
        .map_err(StoreError::Invalid)?;
        let updates = merged["updates"].as_array().ok_or(INVALID)?;
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
    }
    Ok(Value::from(changed))
}

#[cfg(all(test, unix))]
#[path = "guard_store_receipt_evidence_tests.rs"]
mod tests;
