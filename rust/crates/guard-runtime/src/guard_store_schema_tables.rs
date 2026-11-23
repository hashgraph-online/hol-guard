//! Shape checks the Python store runs after creating a schema family: the
//! exact column set, the primary key and the named indexes of a table, with
//! the same error messages. Also the savepoint every family runs inside.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::Connection;

use crate::guard_store_db::{StoreError, StoreResult};

fn refuse<T>(message: String) -> StoreResult<T> {
    Err(StoreError::Runtime(message))
}

/// Run `body` inside savepoint `name`: a failure rolls everything it did
/// back and returns the original error.
pub(super) fn in_savepoint<T>(
    connection: &Connection,
    name: &str,
    body: impl FnOnce() -> StoreResult<T>,
) -> StoreResult<T> {
    connection.execute_batch(&format!("savepoint {name}"))?;
    // A failed final release (SQLITE_BUSY from a reader's lock) leaves the
    // savepoint open, so it is rolled back like a failed body; the first
    // error is the one reported.
    let outcome = body().and_then(|value| {
        connection.execute_batch(&format!("release {name}"))?;
        Ok(value)
    });
    outcome.inspect_err(|_| {
        let _ = connection.execute_batch(&format!("rollback to {name}; release {name}"));
    })
}

/// Require `table` to have exactly `columns` and the primary key `key`, in
/// key order. Fails with `incompatible {table} schema` or
/// `incompatible {table} primary key`.
pub(super) fn check_table(
    connection: &Connection,
    table: &str,
    columns: &[&str],
    key: &[&str],
) -> StoreResult<()> {
    let mut statement = connection.prepare(&format!("pragma table_info({table})"))?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, i64>(5)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let actual: BTreeSet<&str> = rows.iter().map(|(name, _)| name.as_str()).collect();
    if actual != columns.iter().copied().collect::<BTreeSet<&str>>() {
        return refuse(format!("incompatible {table} schema"));
    }
    let mut keyed: Vec<&(String, i64)> =
        rows.iter().filter(|(_, position)| *position > 0).collect();
    keyed.sort_by_key(|(_, position)| *position);
    if keyed
        .iter()
        .map(|(name, _)| name.as_str())
        .ne(key.iter().copied())
    {
        return refuse(format!("incompatible {table} primary key"));
    }
    Ok(())
}

/// One expected index: its table, its columns in order, and whether it is
/// unique and partial.
pub(super) struct IndexShape {
    pub(super) name: &'static str,
    pub(super) table: &'static str,
    pub(super) columns: &'static [&'static str],
    pub(super) unique: bool,
    pub(super) partial: bool,
}

type Actual = (String, Vec<String>, bool, bool);

fn index_shapes(connection: &Connection, tables: &[&str]) -> StoreResult<BTreeMap<String, Actual>> {
    let mut shapes = BTreeMap::new();
    for table in tables {
        let mut list = connection.prepare(&format!("pragma index_list({table})"))?;
        let indexes = list
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (name, unique, partial) in indexes {
            let mut info = connection.prepare(&format!("pragma index_info({name})"))?;
            let columns = info
                .query_map([], |row| row.get::<_, Option<String>>(2))?
                .map(|column| column.map(Option::unwrap_or_default))
                .collect::<rusqlite::Result<Vec<_>>>()?;
            shapes.insert(
                name,
                ((*table).to_owned(), columns, unique != 0, partial != 0),
            );
        }
    }
    Ok(shapes)
}

/// Require every expected index on `tables` to have its declared shape.
/// Fails with `{message_prefix}{name}`.
pub(super) fn check_indexes(
    connection: &Connection,
    tables: &[&str],
    expected: &[IndexShape],
    message_prefix: &str,
) -> StoreResult<()> {
    let actual = index_shapes(connection, tables)?;
    for shape in expected {
        let matches = actual
            .get(shape.name)
            .is_some_and(|(table, columns, unique, partial)| {
                table == shape.table
                    && columns
                        .iter()
                        .map(String::as_str)
                        .eq(shape.columns.iter().copied())
                    && *unique == shape.unique
                    && *partial == shape.partial
            });
        if !matches {
            return refuse(format!("{message_prefix}{}", shape.name));
        }
    }
    Ok(())
}
