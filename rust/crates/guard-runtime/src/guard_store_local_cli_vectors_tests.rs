//! Replays observed custom-extension vectors recorded from the original
//! Python store (see `testdata/guard_store/record_local_cli_vectors.py` and
//! `record_local_mcp_vectors.py`). Seeds, payloads,
//! errors and post-step table state all come from Python, never from Rust
//! output.

use std::path::Path;

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_cmd_vectors_tests::{apply_sql, dump, error_code, insert_rows, temp_home};
use crate::guard_store_op::evaluate_guard_store_request;

const LOCAL_CLI_VECTORS: &str = include_str!("../testdata/guard_store/local_cli_vectors.json");
const LOCAL_MCP_VECTORS: &str = include_str!("../testdata/guard_store/local_mcp_vectors.json");

fn build_database(path: &Path, vectors: &Value, scenario: &Value) {
    let connection = Connection::open(path).unwrap();
    connection.execute_batch("pragma journal_mode=wal").ok();
    connection
        .execute_batch("create table guard_review_outbox_events (stream_sequence integer primary key, payload_hash text not null default '')")
        .unwrap();
    for statement in vectors["schema_sql"].as_array().unwrap() {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
    for (table, rows) in scenario["seed"].as_object().unwrap() {
        insert_rows(&connection, table, rows);
    }
}

fn run_step(home: &Path, source: &str, now: &str, step: &Value) -> Value {
    let mut args: Map<String, Value> = step["wire_args"].as_object().unwrap().clone();
    if args.get("clock") == Some(&Value::from("<NOW>")) {
        args.insert("clock".to_owned(), Value::from(now));
    }
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "vector".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: step["method"].as_str().unwrap().to_owned(),
        source: source.to_owned(),
        busy_timeout_ms: 5000,
        args,
    };
    let bytes = evaluate_guard_store_request(&request).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn replay_vectors(text: &str, schema: &str) -> usize {
    let vectors: Value = serde_json::from_str(text).unwrap();
    assert_eq!(vectors["schema"], schema);
    let (source, now) = (
        vectors["source"].as_str().unwrap(),
        vectors["now"].as_str().unwrap(),
    );
    let order_by = vectors["order_by"].as_object().unwrap();
    let mut compared_steps = 0;
    for scenario in vectors["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let home = temp_home(name);
        build_database(&home.join("guard.db"), &vectors, scenario);
        let mut expected: Map<String, Value> = scenario["seed"].as_object().unwrap().clone();
        for (index, step) in scenario["steps"].as_array().unwrap().iter().enumerate() {
            let label = format!("{name}#{index} {} {}", step["method"], step["label"]);
            if step["method"] == "sql" {
                apply_sql(&home, step);
            } else {
                let reply = run_step(&home, source, now, step);
                match step["error"].as_object() {
                    None => {
                        assert_eq!(reply["status"], "ok", "{label}: {reply}");
                        assert_eq!(reply["payload"], step["native_payload"], "{label}");
                    }
                    Some(error) => {
                        assert_eq!(reply["status"], "error", "{label}: {reply}");
                        assert_eq!(
                            reply["code"],
                            error_code(error["type"].as_str().unwrap()),
                            "{label}"
                        );
                        if error["message_exact"] == true {
                            assert_eq!(reply["payload"]["message"], error["message"], "{label}");
                        }
                    }
                }
            }
            for (table, rows) in step["post_changed"].as_object().unwrap() {
                expected.insert(table.clone(), rows.clone());
            }
            let connection = Connection::open(home.join("guard.db")).unwrap();
            for (table, key) in order_by {
                assert_eq!(
                    dump(&connection, table, key.as_str().unwrap()),
                    expected[table],
                    "{label}: {table}"
                );
            }
            compared_steps += 1;
        }
        let _ = std::fs::remove_dir_all(&home);
    }
    compared_steps
}

#[test]
fn replays_every_recorded_local_cli_scenario() {
    let compared_steps = replay_vectors(LOCAL_CLI_VECTORS, "guard-store-local-cli-vectors.v1");
    assert!(compared_steps >= 45, "only {compared_steps} recorded steps");
}

#[test]
fn replays_every_recorded_local_mcp_scenario() {
    let compared_steps = replay_vectors(LOCAL_MCP_VECTORS, "guard-store-local-mcp-vectors.v1");
    assert!(compared_steps >= 40, "only {compared_steps} recorded steps");
}

/// A legacy Deny carry first asks Python to close the policy barrier and
/// writes nothing until it does.
#[test]
fn legacy_denial_waits_for_the_policy_barrier() {
    let vectors: Value = serde_json::from_str(LOCAL_MCP_VECTORS).unwrap();
    let (source, now) = (
        vectors["source"].as_str().unwrap(),
        vectors["now"].as_str().unwrap(),
    );
    let scenario = vectors["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scenario| scenario["name"] == "ensure_legacy_denial")
        .unwrap();
    let home = temp_home("local-mcp-barrier");
    build_database(&home.join("guard.db"), &vectors, scenario);
    let steps = scenario["steps"].as_array().unwrap();
    apply_sql(&home, &steps[0]);
    let mut open = steps[1].clone();
    open["wire_args"]["barrier_closed"] = Value::Bool(false);
    let before = Connection::open(home.join("guard.db"))
        .unwrap()
        .query_row("select count(*) from local_cli_observation", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap();
    let reply = run_step(&home, source, now, &open);
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(
        reply["payload"],
        serde_json::json!({ "need_barrier": true })
    );
    let after = Connection::open(home.join("guard.db"))
        .unwrap()
        .query_row("select count(*) from local_cli_observation", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap();
    assert_eq!(before, after);
    let reply = run_step(&home, source, now, &steps[1]);
    assert_eq!(reply["payload"], steps[1]["native_payload"]);
    let _ = std::fs::remove_dir_all(&home);
}
