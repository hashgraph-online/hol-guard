//! SQLite access for the guard store op: row decoding that keeps the stored
//! SQLite type of every cell, and the error taxonomy the Python wrapper maps
//! back onto its exception types.

use rusqlite::types::ValueRef;
use rusqlite::{Connection, ErrorCode};
use serde_json::{Map, Number, Value};

pub(crate) type Row = Map<String, Value>;

/// Failure of one store method.
#[derive(Debug)]
pub(crate) enum StoreError {
    /// Python `ValueError` with its exact message.
    Value(String),
    /// Python `sqlite3.IntegrityError` raised by the method itself.
    Integrity(String),
    /// A request or stored value outside the contract; fail closed.
    Invalid(&'static str),
    Sqlite(rusqlite::Error),
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

pub(crate) type StoreResult<T> = Result<T, StoreError>;

pub(crate) fn value_error<T>(message: &str) -> StoreResult<T> {
    Err(StoreError::Value(message.to_owned()))
}

impl StoreError {
    /// Stable failure code in the `native_guard_store_*` namespace.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Value(_) => "native_guard_store_value_error",
            Self::Integrity(_) => "native_guard_store_integrity_error",
            Self::Invalid(_) => "native_guard_store_invalid",
            Self::Sqlite(error) => match error.sqlite_error_code() {
                Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => {
                    "native_guard_store_busy"
                }
                Some(ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase) => {
                    "native_guard_store_sqlite_corrupt"
                }
                Some(ErrorCode::SystemIoFailure) => "native_guard_store_sqlite_io",
                Some(ErrorCode::ConstraintViolation) => "native_guard_store_integrity_error",
                _ => "native_guard_store_sqlite_error",
            },
        }
    }

    pub(crate) fn message(&self) -> String {
        match self {
            Self::Value(message) | Self::Integrity(message) => message.clone(),
            Self::Invalid(reason) => (*reason).to_owned(),
            Self::Sqlite(error) => error.to_string(),
        }
    }
}

/// Bind one JSON value as the SQLite value Python's driver would bind.
fn bind(value: &Value) -> rusqlite::types::Value {
    use rusqlite::types::Value as Sql;
    match value {
        Value::Null => Sql::Null,
        Value::Bool(flag) => Sql::Integer(i64::from(*flag)),
        Value::Number(number) => number
            .as_i64()
            .map(Sql::Integer)
            .or_else(|| number.as_f64().map(Sql::Real))
            .unwrap_or(Sql::Null),
        Value::String(text) => Sql::Text(text.clone()),
        other => Sql::Text(other.to_string()),
    }
}

fn cell(value: ValueRef<'_>) -> StoreResult<Value> {
    Ok(match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(number) => Value::Number(number.into()),
        ValueRef::Real(number) => Number::from_f64(number)
            .map(Value::Number)
            .ok_or(StoreError::Invalid("native_guard_store_cell_invalid"))?,
        ValueRef::Text(bytes) => Value::String(
            String::from_utf8(bytes.to_vec())
                .map_err(|_| StoreError::Invalid("native_guard_store_cell_invalid"))?,
        ),
        ValueRef::Blob(_) => return Err(StoreError::Invalid("native_guard_store_cell_invalid")),
    })
}

/// `execute(sql, params).fetchall()`.
pub(crate) fn query_all(
    connection: &Connection,
    sql: &str,
    params: &[Value],
) -> StoreResult<Vec<Row>> {
    let mut statement = connection.prepare_cached(sql)?;
    let names: Vec<String> = statement
        .column_names()
        .iter()
        .map(|n| (*n).to_owned())
        .collect();
    let bound: Vec<rusqlite::types::Value> = params.iter().map(bind).collect();
    let mut rows = statement.query(rusqlite::params_from_iter(bound))?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let mut map = Row::new();
        for (index, name) in names.iter().enumerate() {
            map.insert(name.clone(), cell(row.get_ref(index)?)?);
        }
        out.push(map);
    }
    Ok(out)
}

/// `execute(sql, params).fetchone()`.
pub(crate) fn query_one(
    connection: &Connection,
    sql: &str,
    params: &[Value],
) -> StoreResult<Option<Row>> {
    Ok(query_all(connection, sql, params)?.into_iter().next())
}

/// `execute(sql, params)` returning `cursor.rowcount`.
pub(crate) fn exec(connection: &Connection, sql: &str, params: &[Value]) -> StoreResult<i64> {
    let mut statement = connection.prepare_cached(sql)?;
    let bound: Vec<rusqlite::types::Value> = params.iter().map(bind).collect();
    let changed = statement.execute(rusqlite::params_from_iter(bound))?;
    Ok(changed as i64)
}

pub(crate) fn text<'a>(row: &'a Row, name: &str) -> &'a str {
    row.get(name).and_then(Value::as_str).unwrap_or("")
}

pub(crate) fn int(row: &Row, name: &str) -> i64 {
    row.get(name).and_then(Value::as_i64).unwrap_or(0)
}

pub(crate) fn is_null(row: &Row, name: &str) -> bool {
    matches!(row.get(name), None | Some(Value::Null))
}

pub(crate) fn placeholders(count: usize) -> String {
    vec!["?"; count].join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_keep_cell_types() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "create table t (a integer, b text, c); insert into t values (1, 'x', null);",
            )
            .unwrap();
        let row = query_one(
            &connection,
            "select * from t where a = ?",
            &[Value::from(1)],
        )
        .unwrap()
        .unwrap();
        assert_eq!(row["a"], Value::from(1));
        assert_eq!(row["b"], Value::from("x"));
        assert_eq!(row["c"], Value::Null);
    }
}
