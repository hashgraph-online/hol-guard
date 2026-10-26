//! Shared helpers for the store-policy parity vector tests. The vectors were
//! recorded from the retired Python and seed a real SQLite store.

use std::io::Read;

use rusqlite::{types::ValueRef, Connection};
use serde_json::{json, Map, Value};

pub(crate) fn gunzip_json(bytes: &[u8]) -> Value {
    let mut text = String::new();
    flate2::read::GzDecoder::new(bytes)
        .read_to_string(&mut text)
        .expect("fixture must gunzip");
    serde_json::from_str(&text).expect("fixture must be JSON")
}

fn sql_param(value: &Value) -> rusqlite::types::Value {
    use rusqlite::types::Value as Sql;
    match value {
        Value::Null => Sql::Null,
        Value::Bool(flag) => Sql::Integer(i64::from(*flag)),
        Value::Number(number) => number
            .as_i64()
            .map(Sql::Integer)
            .unwrap_or_else(|| Sql::Real(number.as_f64().unwrap_or(0.0))),
        Value::String(text) => Sql::Text(text.clone()),
        other => Sql::Text(other.to_string()),
    }
}

fn insert_rows(connection: &Connection, table: &str, rows: &Value) {
    for row in rows.as_array().into_iter().flatten() {
        let object = row.as_object().expect("seed row must be an object");
        let columns: Vec<&str> = object.keys().map(String::as_str).collect();
        let marks = vec!["?"; columns.len()].join(", ");
        let sql = format!(
            "insert into {table} ({}) values ({marks})",
            columns.join(", ")
        );
        let params: Vec<rusqlite::types::Value> = object.values().map(sql_param).collect();
        connection
            .execute(&sql, rusqlite::params_from_iter(params))
            .unwrap_or_else(|error| panic!("seed insert into {table} failed: {error}"));
    }
}

/// Build an in-memory store from the recorded schema and a recorded dump.
pub(crate) fn seeded_store(schema_sql: &Value, seed: &Value) -> Connection {
    let connection = Connection::open_in_memory().expect("in-memory store");
    for statement in schema_sql.as_array().expect("schema array") {
        connection
            .execute_batch(statement.as_str().expect("schema statement"))
            .expect("schema statement must apply");
    }
    connection
        .execute(
            "insert into guard_approval_authority_revision (singleton, revision) values (1, 0)",
            [],
        )
        .expect("revision row");
    insert_rows(&connection, "policy_decisions", &seed["policy_decisions"]);
    insert_rows(
        &connection,
        "guard_local_once_approvals",
        &seed["guard_local_once_approvals"],
    );
    for event in seed["events"].as_array().into_iter().flatten() {
        connection
            .execute(
                "insert into guard_events (event_name, payload_json, occurred_at) values (?1, ?2, ?3)",
                rusqlite::params![
                    event["event_name"].as_str(),
                    event["payload"].to_string(),
                    event["occurred_at"].as_str()
                ],
            )
            .expect("seed event");
    }
    connection
        .execute(
            "update guard_approval_authority_revision set revision = ?1 where singleton = 1",
            [seed["revision"].as_i64().unwrap_or(0)],
        )
        .expect("seed revision");
    connection
}

fn dump_rows(connection: &Connection, sql: &str) -> Value {
    let mut statement = connection.prepare(sql).expect("dump statement");
    let names: Vec<String> = statement
        .column_names()
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    let rows = statement
        .query_map([], |row| {
            let mut object = Map::new();
            for (index, name) in names.iter().enumerate() {
                let value = match row.get_ref(index)? {
                    ValueRef::Null => Value::Null,
                    ValueRef::Integer(number) => json!(number),
                    ValueRef::Real(number) => json!(number),
                    ValueRef::Text(text) => json!(String::from_utf8_lossy(text)),
                    ValueRef::Blob(_) => Value::Null,
                };
                object.insert(name.clone(), value);
            }
            Ok(Value::Object(object))
        })
        .expect("dump query");
    Value::Array(rows.map(|row| row.expect("dump row")).collect())
}

/// The same projection the recorder took of the store after a claim.
pub(crate) fn dump_store(connection: &Connection) -> Value {
    let events = dump_rows(
        connection,
        "select event_name, payload_json, occurred_at from guard_events \
         where event_name like 'approval.%' order by event_id",
    );
    let events: Vec<Value> = events
        .as_array()
        .unwrap()
        .iter()
        .map(|event| {
            let payload: Value =
                serde_json::from_str(event["payload_json"].as_str().unwrap()).unwrap();
            json!({
                "event_name": event["event_name"],
                "payload": payload,
                "occurred_at": event["occurred_at"],
            })
        })
        .collect();
    let revision: i64 = connection
        .query_row(
            "select revision from guard_approval_authority_revision where singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    json!({
        "policy_decisions": dump_rows(connection, "select * from policy_decisions order by decision_id"),
        "guard_local_once_approvals": dump_rows(connection, "select * from guard_local_once_approvals order by approval_id"),
        "revision": revision,
        "events": events,
    })
}

pub(crate) fn decode_key(encoded: &Value) -> Option<Vec<u8>> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::decode_vec(encoded.as_str()?).ok()
}
