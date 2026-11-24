//! The owned-object check the Python store runs after a schema family's
//! statements (`_validate_schema_object_sql`): every object a statement
//! creates must exist with exactly the declared SQL, compared after case and
//! whitespace are normalised. A store whose object was changed by hand, or
//! created by an incompatible release, is refused rather than used.

use rusqlite::{Connection, OptionalExtension};

use crate::guard_store_db::{StoreError, StoreResult};

pub(super) fn canonical(value: &str) -> String {
    value
        .trim()
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The object name a `create ... if not exists NAME` statement owns, and its
/// SQL as SQLite stores it.
fn declared(statement: &str, allow_unique: bool) -> Option<(String, String)> {
    let text = canonical(statement);
    let rest = text.strip_prefix("create ")?;
    let rest = match rest.strip_prefix("unique ") {
        Some(after) if allow_unique => after,
        Some(_) => return None,
        None => rest,
    };
    let after = ["table ", "index ", "trigger "]
        .into_iter()
        .find_map(|kind| rest.strip_prefix(kind))?
        .strip_prefix("if not exists ")?;
    let name: String = after
        .chars()
        .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
        .collect();
    if name.is_empty() {
        return None;
    }
    Some((name, text.replacen(" if not exists", "", 1)))
}

/// Check that every object `statements` create exists with its declared SQL.
pub(super) fn validate(
    connection: &Connection,
    statements: &[&str],
    family_label: &str,
    allow_unique: bool,
) -> StoreResult<()> {
    let mut expected = Vec::new();
    for statement in statements {
        let Some((name, sql)) = declared(statement, allow_unique) else {
            return Err(StoreError::Runtime(format!(
                "unrecognized command activity {family_label}schema statement"
            )));
        };
        if let Some((_, existing)) = expected.iter_mut().find(|(existing, _)| existing == &name) {
            *existing = sql;
        } else {
            expected.push((name, sql));
        }
    }
    let mut query = connection.prepare("select sql from sqlite_schema where name = ?1")?;
    for (name, sql) in &expected {
        let actual: Option<Option<String>> =
            query.query_row([name], |row| row.get(0)).optional()?;
        if actual.flatten().map(|text| canonical(&text)).as_ref() != Some(sql) {
            return Err(StoreError::Runtime(format!(
                "incompatible command activity {family_label}schema object: {name}"
            )));
        }
    }
    Ok(())
}
