//! `resign_policy_rows` — the integrity migration and resign writes.
//!
//! `GuardStore.migrate_policy_integrity` and `resign_policy_integrity` decide
//! in Python which local rows to keep, which to drop and which to sign even
//! though they no longer verify. This op does the writes in one transaction:
//! it deletes `clear_decision_ids`, then advances the integrity generation
//! over the local rows that remain, signing every row in
//! `force_sign_decision_ids` and every row that still verifies at the
//! current generation. The control state stays with the caller, as for
//! `clear_policy_decisions`.
//!
//! The key is required. A resign without one would only delete rows, which
//! is what `clear_policy_decisions` already does.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, value_error, StoreResult};
use crate::guard_store_policy_upsert::{advance_generation, signing_material};

/// `_advance_policy_integrity_generation` with the deletes that precede it.
pub(crate) fn resign_policy_rows(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let Some(material) = signing_material(args)? else {
        return value_error("native_policy_integrity_key_required");
    };
    let clear = optional_ids(args, "clear_decision_ids")?;
    let forced = optional_ids(args, "force_sign_decision_ids")?;
    let cleared = if clear.is_empty() {
        0
    } else {
        // One JSON parameter, not one per id: a migration can drop more rows
        // than SQLite allows bound variables in a statement.
        exec(
            connection,
            "delete from policy_decisions \
             where decision_id in (select value from json_each(?))",
            &[Value::String(json!(clear).to_string())],
        )?
    };
    let next_control_state = advance_generation(
        connection,
        &material.key,
        material.key_id,
        args.str("now")?,
        material.current_generation,
        &forced,
    )?;
    Ok(json!({"cleared": cleared, "next_control_state": next_control_state}))
}

fn optional_ids(args: &Args, key: &str) -> StoreResult<Vec<i64>> {
    match args.raw(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(_) => args.ints(key),
    }
}

#[cfg(test)]
#[path = "guard_store_policy_resign_tests.rs"]
mod tests;
