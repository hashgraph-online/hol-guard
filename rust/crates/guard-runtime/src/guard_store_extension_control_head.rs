//! The committed extension-control head and its transitions, read for recovery.
//!
//! Port of the SQL reads the authority recovery, the persisted-authority
//! reader and the legacy secret migration check ran on their own SQLite
//! connection after the schema check:
//!
//! - `extension_control_snapshot_head` answers the snapshot row's revision,
//!   snapshot digest and catalog digest, or `{"snapshot": null}` when there
//!   is no row (or no snapshot table yet). A cell of the wrong type answers
//!   `null` in its place so the caller refuses the row.
//! - `extension_control_recovery_transition` answers the revision of the
//!   transition recovery must resume: one at the head revision that never
//!   committed, or the one after it.
//! - `extension_control_transition_committed` answers whether the head
//!   revision's transition committed.
//!
//! A store without the transition table has no transitions.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_one, StoreResult};
use crate::guard_store_local_cli_inventory::table_exists;

const HEAD: &str = "extension_control_snapshot_head";
const RECOVERY: &str = "extension_control_recovery_transition";
const COMMITTED: &str = "extension_control_transition_committed";
const SNAPSHOT_TABLE: &str = "extension_control_authority_snapshot";
const TRANSITION_TABLE: &str = "extension_control_authority_transition";
const COMMITTED_PHASE: &str = "committed";

pub(crate) fn handles(method: &str) -> bool {
    matches!(method, HEAD | RECOVERY | COMMITTED)
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        RECOVERY => recovery_transition(connection, args.int("revision")?),
        COMMITTED => committed(connection, args.int("revision")?),
        _ => head(connection),
    }
}

fn head(connection: &Connection) -> StoreResult<Value> {
    if !table_exists(connection, SNAPSHOT_TABLE)? {
        return Ok(json!({"snapshot": null}));
    }
    let row = query_one(
        connection,
        &format!(
            "select case when typeof(revision) = 'integer' then revision end as revision, \
                    case when typeof(snapshot_digest) = 'text' then snapshot_digest end \
                      as snapshot_digest, \
                    case when typeof(catalog_digest) = 'text' then catalog_digest end \
                      as catalog_digest \
             from {SNAPSHOT_TABLE} where singleton = 1"
        ),
        &[],
    )?;
    Ok(match row {
        None => json!({"snapshot": null}),
        Some(row) => {
            let cell = |name: &str| row.get(name).cloned().unwrap_or(Value::Null);
            json!({"snapshot": {
                "revision": cell("revision"),
                "snapshot_digest": cell("snapshot_digest"),
                "catalog_digest": cell("catalog_digest"),
            }})
        }
    })
}

fn recovery_transition(connection: &Connection, revision: i64) -> StoreResult<Value> {
    if !table_exists(connection, TRANSITION_TABLE)? {
        return Ok(json!({"revision": null}));
    }
    let row = query_one(
        connection,
        &format!(
            "select revision from {TRANSITION_TABLE} \
             where (revision = ?1 and phase != ?2) or revision = ?3 \
             order by revision limit 1"
        ),
        &[
            Value::from(revision),
            Value::from(COMMITTED_PHASE),
            Value::from(revision.saturating_add(1)),
        ],
    )?;
    let found = row
        .and_then(|row| row.get("revision").filter(|value| value.is_i64()).cloned())
        .unwrap_or(Value::Null);
    Ok(json!({"revision": found}))
}

fn committed(connection: &Connection, revision: i64) -> StoreResult<Value> {
    if !table_exists(connection, TRANSITION_TABLE)? {
        return Ok(json!({"committed": false}));
    }
    let row = query_one(
        connection,
        &format!("select 1 as found from {TRANSITION_TABLE} where revision = ?1 and phase = ?2"),
        &[Value::from(revision), Value::from(COMMITTED_PHASE)],
    )?;
    Ok(json!({"committed": row.is_some()}))
}

#[cfg(test)]
#[path = "guard_store_extension_control_head_tests.rs"]
mod tests;
