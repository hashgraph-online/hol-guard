//! Replays the observed MCP tool-action vectors recorded from the previous
//! Python compiler against the native store method.

use rusqlite::{types::Value as Sql, Connection};
use serde_json::Value;

use super::observed_mcp_tool_actions;

fn sql_value(value: &Value) -> Sql {
    match value {
        Value::Null => Sql::Null,
        Value::Bool(flag) => Sql::Integer(i64::from(*flag)),
        Value::Number(number) => number
            .as_i64()
            .map_or_else(|| Sql::Real(number.as_f64().unwrap()), Sql::Integer),
        Value::String(text) => Sql::Text(text.clone()),
        other => Sql::Text(other.to_string()),
    }
}

fn seed(connection: &Connection, schema: &[Value], rows: &serde_json::Map<String, Value>) {
    for statement in schema {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
    for (table, table_rows) in rows {
        for row in table_rows.as_array().unwrap() {
            let row = row.as_object().unwrap();
            let columns: Vec<&str> = row.keys().map(String::as_str).collect();
            let placeholders = vec!["?"; columns.len()].join(", ");
            let sql = format!(
                "insert into {table} ({}) values ({placeholders})",
                columns.join(", ")
            );
            let values: Vec<Sql> = row.values().map(sql_value).collect();
            connection
                .execute(&sql, rusqlite::params_from_iter(values))
                .unwrap();
        }
    }
}

#[test]
fn observed_mcp_tool_actions_match_recorded_python_vectors() {
    let recorded: Value = serde_json::from_str(include_str!(
        "../testdata/local_mcp/observed_mcp_tool_actions_vectors.json"
    ))
    .unwrap();
    let schema = recorded["schema"].as_array().unwrap();
    let vectors = recorded["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 30);
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let connection = Connection::open_in_memory().unwrap();
        let rows = vector["rows"].as_object().unwrap();
        seed(&connection, schema, rows);
        let actual = observed_mcp_tool_actions(&connection)
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(actual, vector["expected"], "{name}");
    }
}

#[test]
fn store_without_local_cli_tables_has_no_actions() {
    let connection = Connection::open_in_memory().unwrap();
    let actual = observed_mcp_tool_actions(&connection).unwrap();
    assert_eq!(actual, serde_json::json!({}));
}

#[test]
fn newer_or_missing_store_schema_is_not_read() {
    for marker in [
        "insert into local_cli_schema_migration values (1, 12, 'newer')",
        "select 1",
    ] {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(&format!(
                "create table local_cli_observation (cli_id text); \
                 create table local_cli_schema_migration \
                   (singleton integer, version integer, checksum text); {marker};"
            ))
            .unwrap();
        assert!(observed_mcp_tool_actions(&connection).is_err(), "{marker}");
    }
}

#[test]
fn malformed_rows_are_skipped_without_losing_valid_choices() {
    let recorded: Value = serde_json::from_str(include_str!(
        "../testdata/local_mcp/observed_mcp_tool_actions_vectors.json"
    ))
    .unwrap();
    let vector = recorded["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["name"] == "allowed_exact_states")
        .unwrap();
    let connection = Connection::open_in_memory().unwrap();
    seed(
        &connection,
        recorded["schema"].as_array().unwrap(),
        vector["rows"].as_object().unwrap(),
    );
    // An unrelated observation, its grant and a catalogued command each
    // carry a BLOB where the store writes text.
    connection
        .execute_batch(
            "create temp table o as select * from local_cli_observation limit 1; \
             update o set cli_id = 'local-cli.malformed', identity_hash = 'malformed', \
                 server_command = x'00ff'; \
             insert into local_cli_observation select * from o; \
             create temp table g as select * from local_cli_grant limit 1; \
             update g set cli_id = 'local-cli.malformed', identity_hash = x'00ff'; \
             insert into local_cli_grant select * from g; \
             create temp table c as select * from local_cli_command limit 1; \
             update c set command_id = 'tool-malformed', usage = x'00ff'; \
             insert into local_cli_command select * from c;",
        )
        .unwrap();
    let actual = observed_mcp_tool_actions(&connection).unwrap();
    assert_eq!(actual, vector["expected"]);
}
