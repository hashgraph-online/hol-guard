//! Crash-safe validated SQLite schema for the workflow-capability authority:
//! the retired-index drop, the savepointed create-and-validate pass and the
//! strict owned-object equality check of the Python startup.

use std::collections::BTreeMap;

use rusqlite::Connection;

use crate::guard_store_wfcap_error::{WfError, WfResult};
use crate::guard_store_wfcap_schema_sql::{OBJECTS, STATEMENTS};

const MIGRATION_VERSION: i64 = 14;
const RECEIPT_EVENT_INDEX_MIGRATION_VERSION: i64 = 22;
const RETIRED_RECEIPT_EVENT_INDEX: &str = "idx_guard_workflow_receipt_event";
const SAVEPOINT: &str = "workflow_capability_schema_v14";

fn normalized_sql(statement: &str) -> String {
    statement
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" if not exists", "")
}

fn runtime<T>(message: impl Into<String>) -> WfResult<T> {
    Err(WfError::Runtime(message.into()))
}

fn validate_objects(connection: &Connection) -> WfResult<()> {
    let expected: Vec<((&str, &str), String)> = OBJECTS
        .iter()
        .zip(STATEMENTS.iter())
        .map(|(identity, statement)| (*identity, normalized_sql(statement)))
        .collect();
    let mut statement = connection.prepare(
        "select type, name, sql from sqlite_master \
         where name like 'guard_workflow_capabilit%' \
            or name like 'idx_guard_workflow_%' \
            or name like 'trg_guard_workflow_%'",
    )?;
    let mut actual: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let kind: String = row.get(0)?;
        let name: String = row.get(1)?;
        let sql: Option<String> = row.get(2)?;
        if let Some(sql) = sql {
            if !name.starts_with("sqlite_autoindex") {
                actual.insert((kind, name), normalized_sql(&sql));
            }
        }
    }
    let same_set = actual.len() == expected.len()
        && expected
            .iter()
            .all(|((kind, name), _)| actual.contains_key(&(kind.to_string(), name.to_string())));
    if !same_set {
        return runtime("invalid_workflow_capability_schema:owned_objects");
    }
    for ((kind, name), sql) in &expected {
        if actual.get(&(kind.to_string(), name.to_string())) != Some(sql) {
            return runtime(format!("invalid_workflow_capability_schema:{kind}:{name}"));
        }
    }
    Ok(())
}

fn migrate(connection: &Connection, applied_at: &str) -> WfResult<()> {
    for statement in STATEMENTS {
        connection.execute(statement, [])?;
    }
    validate_objects(connection)?;
    connection.execute(
        "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
        (MIGRATION_VERSION, applied_at),
    )?;
    let recorded: Option<String> = connection
        .query_row(
            "select applied_at from schema_migrations where version = ?",
            [MIGRATION_VERSION],
            |row| row.get(0),
        )
        .ok();
    if recorded.is_none_or(|text| text.is_empty()) {
        return runtime("workflow_capability_migration_not_recorded");
    }
    Ok(())
}

/// `ensure_workflow_capability_schema`.
pub(crate) fn ensure_schema(connection: &Connection, applied_at: &str) -> WfResult<()> {
    connection.execute(
        &format!("drop index if exists {RETIRED_RECEIPT_EVENT_INDEX}"),
        [],
    )?;
    connection.execute(
        "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
        (RECEIPT_EVENT_INDEX_MIGRATION_VERSION, applied_at),
    )?;
    connection.execute(&format!("savepoint {SAVEPOINT}"), [])?;
    let outcome = migrate(connection, applied_at);
    if let Err(error) = outcome {
        connection.execute(&format!("rollback to {SAVEPOINT}"), [])?;
        connection.execute(&format!("release {SAVEPOINT}"), [])?;
        return match error {
            WfError::Store(_) => runtime("invalid_workflow_capability_schema:migration"),
            other => Err(other),
        };
    }
    connection.execute(&format!("release {SAVEPOINT}"), [])?;
    Ok(())
}
