//! The local-CLI version 13 to 14 regroup: a mirror of
//! `regroup_pending_connector_reviews`.
//!
//! Pending reviews held only because Guard did not recognise the local CLI a
//! command launches move to that connector's group when they tie to one
//! observed CLI with no decision yet. The `connector_regroup` kind decides the
//! moves; this step reads its rows and applies them. Nothing is created,
//! resolved or deleted. The regroup is best effort: any store error rolls the
//! moves back and the schema bump continues.

use rusqlite::types::Value as SqlValue;
use rusqlite::Connection;
use serde_json::{json, Value};

use super::columns::table_columns;

/// `NON_RECOGNITION_RISK_SUMMARIES`.
pub(super) const NON_RECOGNITION_RISK_SUMMARIES: [&str; 3] = [
    "HOL Guard requires review because this command could not be confirmed read-only. \
     Splitting it into simpler commands can let the read-only parts run without review.",
    "HOL Guard requires review because this command could not be confirmed read-only.",
    "HOL Guard's workspace sandbox cannot run this program, so it was not started there.",
];
const MAX_COMMAND_CHARS: i64 = 4096;
const REVIEWS: &str = "select request_id, raw_command_text, queue_group_id, workspace \
     from approval_requests \
     where status = 'pending' and raw_command_text is not null \
     and length(raw_command_text) <= ?1 and workspace is not null and workspace != '' \
     and risk_summary in (?2, ?3, ?4) \
     order by created_at, request_id";
const OBSERVATIONS: &str = "select cli_id, identity_hash, name, source_path \
     from local_cli_observation \
     where kind = 'executable' and surface = 'cli' \
     and interpreter_name is null and example_label = name";
const DECIDED: &str =
    "select cli_id, identity_hash from local_cli_grant where state in ('allowed', 'blocked')";
const MOVE: &str = "update approval_requests set queue_group_id = ?1 where request_id = ?2";

/// Regroup the pending reviews that tie to one undecided CLI; returns how
/// many moved. A store error leaves every row as it was.
pub(super) fn regroup(connection: &Connection) -> usize {
    if connection
        .execute_batch("savepoint connector_regroup")
        .is_err()
    {
        return 0;
    }
    let Ok(moved) = apply(connection) else {
        let _ = connection.execute_batch(
            "rollback to savepoint connector_regroup; release savepoint connector_regroup",
        );
        return 0;
    };
    if connection
        .execute_batch("release savepoint connector_regroup")
        .is_err()
    {
        return 0;
    }
    moved
}

fn apply(connection: &Connection) -> rusqlite::Result<usize> {
    if !has_columns(
        connection,
        "approval_requests",
        &[
            "request_id",
            "status",
            "risk_summary",
            "raw_command_text",
            "queue_group_id",
        ],
    )? || !has_columns(
        connection,
        "local_cli_observation",
        &["cli_id", "identity_hash", "name", "kind", "surface"],
    )? {
        return Ok(0);
    }
    let [first, second, third] = NON_RECOGNITION_RISK_SUMMARIES;
    let reviews = rows(
        connection,
        REVIEWS,
        (MAX_COMMAND_CHARS, first, second, third),
        4,
    )?;
    if reviews.is_empty() {
        return Ok(0);
    }
    let observations = rows(connection, OBSERVATIONS, (), 4)?;
    let decided = if has_columns(
        connection,
        "local_cli_grant",
        &["cli_id", "identity_hash", "state"],
    )? {
        rows(connection, DECIDED, (), 2)?
    } else {
        Vec::new()
    };
    let request = json!({
        "reviews": reviews,
        "observations": observations,
        "decided": decided,
    });
    let Ok(answer) = crate::connector_regroup::dispatch(&request) else {
        return Ok(0);
    };
    let moves = planned(&answer);
    for (request_id, target) in &moves {
        connection.execute(MOVE, (target, request_id))?;
    }
    Ok(moves.len())
}

/// The `[request_id, queue_group_id]` moves, all or nothing: one malformed
/// move discards the plan.
fn planned(answer: &Value) -> Vec<(SqlValue, String)> {
    let Some(moves) = answer.get("moves").and_then(Value::as_array) else {
        return Vec::new();
    };
    let checked: Option<Vec<_>> = moves
        .iter()
        .map(|entry| {
            let [request_id, target] = entry.as_array()?.as_slice() else {
                return None;
            };
            let target = target.as_str().filter(|t| t.starts_with("connector:"))?;
            Some((sql_value(request_id)?, target.to_owned()))
        })
        .collect();
    checked.unwrap_or_default()
}

fn sql_value(value: &Value) -> Option<SqlValue> {
    if let Some(text) = value.as_str() {
        return Some(SqlValue::Text(text.to_owned()));
    }
    value.as_i64().map(SqlValue::Integer)
}

fn json_value(value: SqlValue) -> Value {
    match value {
        SqlValue::Integer(number) => Value::from(number),
        SqlValue::Real(number) => Value::from(number),
        SqlValue::Text(text) => Value::from(text),
        SqlValue::Null | SqlValue::Blob(_) => Value::Null,
    }
}

fn rows<P: rusqlite::Params>(
    connection: &Connection,
    sql: &str,
    params: P,
    width: usize,
) -> rusqlite::Result<Vec<Value>> {
    let mut statement = connection.prepare(sql)?;
    let mapped = statement.query_map(params, |row| {
        (0..width)
            .map(|index| row.get::<_, SqlValue>(index).map(json_value))
            .collect::<rusqlite::Result<Vec<_>>>()
            .map(Value::from)
    })?;
    mapped.collect()
}

fn has_columns(connection: &Connection, table: &str, required: &[&str]) -> rusqlite::Result<bool> {
    let names = table_columns(connection, table)?;
    Ok(required.iter().all(|name| names.contains(*name)))
}

#[cfg(test)]
#[path = "guard_store_schema_local_cli_regroup_tests.rs"]
mod tests;
