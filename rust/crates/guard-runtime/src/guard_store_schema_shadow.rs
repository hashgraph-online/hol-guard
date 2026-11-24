//! The command shadow step of the store opener: a mirror of
//! `ensure_command_shadow_schema`.
//!
//! The step owns two tables, their indexes and their triggers. A fresh store
//! gets the current objects. A store holding exactly one historical shape
//! (version 15, version 17 or the initial version 18 layout) is upgraded in
//! place with its rows kept. Any other shape, an object outside the step that
//! points at its tables, or an object that changed by hand is refused. All of
//! it happens inside one savepoint, so a refused store keeps nothing.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::types::Value;
use rusqlite::{params_from_iter, Connection, OptionalExtension};

use super::objects::canonical;
use super::shadow_sql::{
    CURRENT, CURRENT_VERSION, INITIAL_V18_EVALUATIONS, LEGACY, PREVIOUS_EVALUATIONS, VERSIONS,
};
use crate::guard_store_db::{StoreError, StoreResult};

type Schema = BTreeMap<String, String>;

const SAVEPOINT: &str = "command_shadow_schema_v18";
const EVALUATIONS: &str = "command_activity_shadow_evaluations";
const COHORTS: &str = "command_activity_shadow_cohorts";
const OWNED: [&str; 2] = [EVALUATIONS, COHORTS];
const INCOMPATIBLE: &str = "incompatible command shadow schema objects";
const RECORD: &str =
    "insert or ignore into schema_migrations (version, applied_at) values (?1, ?2)";
const EVALUATION_COLUMNS: [&str; 13] = [
    "activity_id",
    "occurred_at",
    "authoritative_action",
    "current_action",
    "current_disposition",
    "proposed_action",
    "proposed_disposition",
    "comparison",
    "proposal_version",
    "evaluator_schema_version",
    "control_generation",
    "sample_basis_points",
    "schema_version",
];
const COHORT_COLUMNS: [&str; 3] = ["activity_id", "ordinal", "cohort"];
const EXTERNAL_DEPENDENCIES: &str = "select name, sql from sqlite_master
    where sql is not null
      and (
        type = 'view'
        or (type = 'trigger' and lower(tbl_name) not in (?1, ?2))
        or (
          type = 'table'
          and (
            instr(lower(sql), 'create virtual table') > 0
            or name in (
              select name from pragma_table_list
              where schema = 'main' and type = 'virtual'
            )
          )
        )
      )
    order by type, name";

fn runtime(message: &str) -> StoreError {
    StoreError::Runtime(message.to_owned())
}

/// `ensure_command_shadow_schema`.
pub(super) fn ensure_shadow(connection: &Connection, now: &str) -> StoreResult<()> {
    super::tables::in_savepoint(connection, SAVEPOINT, || shadow(connection, now))
}

/// A historical profile: its first statement replaces the current one.
fn profile(first: &str) -> Vec<&str> {
    std::iter::once(first)
        .chain(CURRENT[1..].iter().copied())
        .collect()
}

fn shadow(connection: &Connection, now: &str) -> StoreResult<()> {
    let previous_statements = profile(PREVIOUS_EVALUATIONS);
    let initial_statements = profile(INITIAL_V18_EVALUATIONS);
    let current = expected(&CURRENT)?;
    let previous = expected(&previous_statements)?;
    let initial = expected(&initial_statements)?;
    let legacy = expected(&LEGACY)?;
    let names: BTreeSet<&str> = [&current, &previous, &initial, &legacy]
        .into_iter()
        .flat_map(|schema| schema.keys().map(String::as_str))
        .collect();
    let actual = read_schema(connection, &names)?;
    reject_external_foreign_keys(connection)?;
    reject_external_dependencies(connection, &[&current, &previous, &initial, &legacy])?;
    if actual == legacy {
        upgrade(connection, &LEGACY, "v15")?;
    } else if actual == previous {
        upgrade(connection, &previous_statements, "v17")?;
    } else if actual == initial {
        upgrade(connection, &initial_statements, "initial_v18")?;
    } else if actual.is_empty() {
        run_all(connection, &CURRENT)?;
    } else if actual != current {
        return Err(runtime(INCOMPATIBLE));
    }
    validate(connection, &current)?;
    for version in VERSIONS {
        connection.execute(RECORD, (version, now))?;
    }
    let applied: Option<Value> = connection
        .query_row(
            "select applied_at from schema_migrations where version = ?1",
            [CURRENT_VERSION],
            |row| row.get(0),
        )
        .optional()?;
    match applied {
        None => Err(runtime("command_shadow_migration_not_recorded")),
        Some(Value::Text(text)) if text.is_empty() => {
            Err(runtime("command_shadow_migration_not_recorded"))
        }
        Some(_) => Ok(()),
    }
}

fn run_all(connection: &Connection, statements: &[&str]) -> rusqlite::Result<()> {
    for statement in statements {
        connection.execute_batch(statement)?;
    }
    Ok(())
}

/// `_upgrade_schema`: drop the historical indexes and triggers, move the old
/// tables aside, create the current objects and copy every row across.
fn upgrade(connection: &Connection, source: &[&str], suffix: &str) -> StoreResult<()> {
    for (kind, name) in identities(source)? {
        if kind != "table" {
            connection.execute_batch(&format!("drop {kind} {name}"))?;
        }
    }
    connection.execute_batch(&format!(
        "alter table {COHORTS} rename to {COHORTS}_{suffix}; \
         alter table {EVALUATIONS} rename to {EVALUATIONS}_{suffix}"
    ))?;
    run_all(connection, &CURRENT)?;
    let columns = EVALUATION_COLUMNS.join(", ");
    connection.execute_batch(&format!(
        "insert into {EVALUATIONS} ({columns}) select {columns} from {EVALUATIONS}_{suffix}; \
         insert into {COHORTS} (activity_id, ordinal, cohort) \
         select activity_id, ordinal, cohort from {COHORTS}_{suffix} order by activity_id, ordinal; \
         drop table {COHORTS}_{suffix}; \
         drop table {EVALUATIONS}_{suffix}"
    ))?;
    Ok(())
}

/// `_validate_schema`: the current objects, then each table's columns and
/// primary key.
fn validate(connection: &Connection, current: &Schema) -> StoreResult<()> {
    let names = current.keys().map(String::as_str).collect();
    if read_schema(connection, &names)? != *current {
        return Err(runtime(INCOMPATIBLE));
    }
    for (table, columns, key) in [
        (EVALUATIONS, &EVALUATION_COLUMNS[..], &["activity_id"][..]),
        (
            COHORTS,
            &COHORT_COLUMNS[..],
            &["activity_id", "ordinal"][..],
        ),
    ] {
        let mut statement = connection.prepare(&format!("pragma table_info({table})"))?;
        let info = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(1)?, row.get::<_, i64>(5)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if !info
            .iter()
            .map(|(name, _)| name.as_str())
            .eq(columns.iter().copied())
        {
            return Err(runtime("incompatible command shadow schema columns"));
        }
        let mut primary: Vec<_> = info.iter().filter(|(_, pk)| *pk > 0).collect();
        primary.sort_by_key(|(_, pk)| *pk);
        if !primary
            .iter()
            .map(|(name, _)| name.as_str())
            .eq(key.iter().copied())
        {
            return Err(runtime("incompatible command shadow primary key"));
        }
    }
    Ok(())
}

/// `create (table|index|trigger) [if not exists] NAME`, canonical.
fn identity(text: &str) -> Option<(&str, &str)> {
    let rest = text.strip_prefix("create ")?;
    let (kind, rest) = ["table", "index", "trigger"]
        .into_iter()
        .find_map(|kind| Some((kind, rest.strip_prefix(kind)?.strip_prefix(' ')?)))?;
    let rest = rest.strip_prefix("if not exists ").unwrap_or(rest);
    let end = rest
        .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
        .unwrap_or(rest.len());
    (end > 0).then_some((kind, &rest[..end]))
}

fn unrecognized() -> StoreError {
    runtime("unrecognized command shadow schema statement")
}

/// `_schema_object_identities`.
fn identities(statements: &[&str]) -> StoreResult<Vec<(&'static str, String)>> {
    statements
        .iter()
        .map(|statement| {
            let text = canonical(statement);
            let (kind, name) = identity(&text).ok_or_else(unrecognized)?;
            Ok((kind_name(kind), name.to_owned()))
        })
        .collect()
}

fn kind_name(kind: &str) -> &'static str {
    match kind {
        "table" => "table",
        "index" => "index",
        _ => "trigger",
    }
}

/// `_expected_schema`: each object's canonical SQL without `if not exists`.
fn expected(statements: &[&str]) -> StoreResult<Schema> {
    statements
        .iter()
        .map(|statement| {
            let text = canonical(statement);
            let name = identity(&text).ok_or_else(unrecognized)?.1.to_owned();
            Ok((name, text.replacen(" if not exists", "", 1)))
        })
        .collect()
}

/// `_read_schema`: the named objects, plus any index or trigger on an owned
/// table.
fn read_schema(connection: &Connection, names: &BTreeSet<&str>) -> rusqlite::Result<Schema> {
    let marks = |from: usize, count: usize| {
        (from..from + count)
            .map(|index| format!("?{index}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let sql = format!(
        "select name, sql from sqlite_master where name in ({}) \
         or (type in ('index', 'trigger') and tbl_name in ({}) and sql is not null)",
        marks(1, names.len()),
        marks(names.len() + 1, OWNED.len()),
    );
    let mut statement = connection.prepare(&sql)?;
    let params = names.iter().copied().chain(OWNED);
    let rows = statement.query_map(params_from_iter(params), |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
    })?;
    rows.map(|row| {
        row.map(|(name, sql)| (name, canonical(&sql.unwrap_or_else(|| "None".to_owned()))))
    })
    .collect()
}

/// `_reject_external_foreign_keys`: no other table may reference an owned
/// one.
fn reject_external_foreign_keys(connection: &Connection) -> StoreResult<()> {
    let mut tables = connection.prepare(
        "select name from sqlite_master where type = 'table' and name not in (?1, ?2) order by name",
    )?;
    let names = tables
        .query_map(OWNED, |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut keys = connection.prepare("select \"table\" from pragma_foreign_key_list(?1)")?;
    for name in names {
        let targets = keys
            .query_map([&name], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if targets
            .iter()
            .any(|target| OWNED.contains(&target.to_lowercase().as_str()))
        {
            return Err(runtime("incompatible command shadow external foreign key"));
        }
    }
    Ok(())
}

/// `_reject_external_sql_dependencies`: a view, foreign trigger or virtual
/// table that names an owned table must be one this step declared.
fn reject_external_dependencies(connection: &Connection, allowed: &[&Schema]) -> StoreResult<()> {
    let mut statement = connection.prepare(EXTERNAL_DEPENDENCIES)?;
    let rows = statement
        .query_map(OWNED, |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (name, sql) in rows {
        let sql = canonical(&sql);
        if !names_owned_table(&sql) {
            continue;
        }
        if allowed.iter().any(|schema| schema.get(&name) == Some(&sql)) {
            continue;
        }
        return Err(runtime(
            "incompatible command shadow external schema dependency",
        ));
    }
    Ok(())
}

/// `_OWNED_IDENTIFIER_PATTERN`: an owned table name not inside a longer
/// identifier. `sql` is already lowercase.
fn names_owned_table(sql: &str) -> bool {
    let word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    OWNED.iter().any(|table| {
        sql.match_indices(table).any(|(start, _)| {
            let before = sql.as_bytes().get(start.wrapping_sub(1)).copied();
            let after = sql.as_bytes().get(start + table.len()).copied();
            !before.is_some_and(word) && !after.is_some_and(word)
        })
    })
}

#[cfg(test)]
#[path = "guard_store_schema_shadow_tests.rs"]
mod tests;
