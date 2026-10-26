//! Replays workflow-capability parity vectors recorded from the original
//! Python store (see `testdata/guard_store/record_workflow_capability_vectors.py`):
//! the requests, control blob writes, results, errors and post-step table
//! state all come from Python, never from Rust output. The test plays the
//! caller's part of the plan/commit protocol against an in-memory control blob.

use std::path::Path;

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_cmd_vectors_tests::{assert_rows, insert_rows, temp_home};
use crate::guard_store_db::{exec, query_all};
use crate::guard_store_op::evaluate_guard_store_request;

const VECTORS: &str = include_str!("../testdata/guard_store/workflow_capability_vectors.json");

const TABLES: [(&str, &str); 7] = [
    ("guard_workflow_capabilities", "capability_id"),
    ("guard_workflow_capability_authority_state", "capability_id"),
    ("guard_workflow_capability_revocations", "revocation_id"),
    ("guard_workflow_capability_receipts", "receipt_id"),
    (
        "guard_workflow_capability_authority_transitions",
        "sequence",
    ),
    ("guard_events", "event_id"),
    ("schema_migrations", "version"),
];

fn build_database(home: &Path, vectors: &Value, scenario: &Value) {
    let connection = Connection::open(home.join("guard.db")).unwrap();
    connection.execute_batch("pragma journal_mode=wal").ok();
    connection
        .execute_batch("create table guard_review_outbox_events (stream_sequence integer primary key, payload_hash text not null default '')")
        .unwrap();
    for statement in vectors["shared_schema_sql"].as_array().unwrap() {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
    for (table, rows) in scenario["seed"].as_object().unwrap() {
        if rows.as_array().is_some() {
            let exists: i64 = connection
                .query_row(
                    "select count(*) from sqlite_master where type = 'table' and name = ?",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            if exists == 1 {
                insert_rows(&connection, table, rows);
            } else {
                assert!(rows.as_array().unwrap().is_empty(), "{table}");
            }
        }
    }
}

fn call(home: &Path, source: &str, method: &str, args: Map<String, Value>) -> Value {
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "vector".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: method.to_owned(),
        source: source.to_owned(),
        busy_timeout_ms: 5000,
        args,
    };
    serde_json::from_slice(&evaluate_guard_store_request(&request).unwrap()).unwrap()
}

/// The caller's control blob: in-memory, with the recorded store fault.
struct Blob {
    value: Option<String>,
    writes: Vec<Value>,
    fail_at: Option<usize>,
}

impl Blob {
    fn persist(&mut self, encoded: &str) -> bool {
        let accepted = self.fail_at != Some(self.writes.len() + 1);
        self.writes.push(json!({"ok": accepted, "value": encoded}));
        if accepted {
            self.value = Some(encoded.to_owned());
        }
        accepted
    }

    fn persist_all(&mut self, writes: &Value) -> bool {
        for write in writes.as_array().unwrap() {
            if !self.persist(write.as_str().unwrap()) {
                return false;
            }
        }
        true
    }
}

struct Outcome {
    result: Value,
    error: Value,
}

fn unavailable() -> Value {
    json!({"kind": "capability", "code": "capability_control_unavailable"})
}

fn run_step(home: &Path, source: &str, step: &Value, blob: &mut Blob, label: &str) -> Outcome {
    let wire: Map<String, Value> = step["wire"].as_object().unwrap().clone();
    assert_eq!(
        wire["control_blob"],
        blob.value.as_deref().map_or(Value::Null, Value::from),
        "{label}: control blob carried into the step"
    );
    let planned = call(home, source, "workflow_capability_plan", wire.clone());
    assert_eq!(planned["status"], "ok", "{label}: {planned}");
    let plan = &planned["payload"];
    let failed = |error: Value| Outcome {
        result: Value::Null,
        error,
    };
    if plan["ok"] != true {
        if !blob.persist_all(&plan["writes"]) {
            return failed(unavailable());
        }
        return failed(plan["error"].clone());
    }
    if !blob.persist_all(&plan["writes"]) {
        return failed(unavailable());
    }
    let mut result = plan["result"].clone();
    if plan["commit"] == true {
        let mut args = wire;
        args.insert("plan_writes".into(), plan["writes"].clone());
        args.insert("plan_post_writes".into(), plan["post_writes"].clone());
        let committed = call(home, source, "workflow_capability_commit", args);
        assert_eq!(committed["status"], "ok", "{label}: {committed}");
        result = committed["payload"]["result"].clone();
        if !blob.persist_all(&committed["payload"]["post_writes"]) {
            return failed(unavailable());
        }
    }
    if step["op"] == "issue" {
        // Python returns the signed claim it was handed.
        result = serde_json::from_str(step["wire"]["signed_json"].as_str().unwrap()).unwrap();
    }
    Outcome {
        result,
        error: Value::Null,
    }
}

fn dump_existing(connection: &Connection) -> Map<String, Value> {
    let mut tables = Map::new();
    for (table, key) in TABLES {
        let exists = connection
            .query_row(
                "select count(*) from sqlite_master where type = 'table' and name = ?",
                [table],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        if exists == 1 {
            let rows = query_all(
                connection,
                &format!("select * from {table} order by {key}"),
                &[],
            )
            .unwrap();
            tables.insert(
                table.to_owned(),
                Value::Array(rows.into_iter().map(Value::Object).collect()),
            );
        }
    }
    tables
}

#[test]
fn replays_every_recorded_workflow_capability_scenario() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(
        vectors["schema"],
        "guard-store-workflow-capability-vectors.v1"
    );
    let source = vectors["source"].as_str().unwrap();
    let scenarios = vectors["scenarios"].as_array().unwrap();
    assert!(scenarios.len() >= 30);
    let mut compared = 0;
    for scenario in scenarios {
        let name = scenario["name"].as_str().unwrap();
        let home = temp_home(name);
        build_database(&home, &vectors, scenario);
        let mut expected: Map<String, Value> = scenario["seed"].as_object().unwrap().clone();
        let mut blob = Blob {
            value: None,
            writes: Vec::new(),
            fail_at: None,
        };
        for (index, step) in scenario["steps"].as_array().unwrap().iter().enumerate() {
            let label = format!("{name}#{index} {}", step["label"]);
            match step["op"].as_str().unwrap() {
                "sql" => {
                    let connection = Connection::open(home.join("guard.db")).unwrap();
                    // The recorder's sqlite connection enforces no foreign keys.
                    connection.execute_batch("pragma foreign_keys=off").unwrap();
                    for pair in step["statements"].as_array().unwrap() {
                        let params: Vec<Value> = pair[1].as_array().unwrap().clone();
                        exec(&connection, pair[0].as_str().unwrap(), &params).unwrap();
                    }
                }
                "blob" => blob.value = step["value"].as_str().map(str::to_owned),
                _ => {
                    blob.writes.clear();
                    blob.fail_at = step["fault"]
                        .as_str()
                        .and_then(|fault| fault.strip_prefix("fail_store_"))
                        .map(|count| count.parse().unwrap());
                    let outcome = run_step(&home, source, step, &mut blob, &label);
                    assert_eq!(outcome.error, step["error"], "{label}: error");
                    // Python re-encodes signed objects as canonical JSON text.
                    let recorded = step["result"].as_str().map_or_else(
                        || step["result"].clone(),
                        |text| {
                            serde_json::from_str(text).unwrap_or_else(|_| step["result"].clone())
                        },
                    );
                    assert_eq!(outcome.result, recorded, "{label}: result");
                    assert_eq!(
                        Value::Array(blob.writes.clone()),
                        step["blob_writes"],
                        "{label}: control writes"
                    );
                    assert_eq!(
                        blob.value.as_deref().map_or(Value::Null, Value::from),
                        step["blob_after"],
                        "{label}: control blob after"
                    );
                }
            }
            for (table, rows) in step["post_changed"].as_object().unwrap() {
                expected.insert(table.clone(), rows.clone());
            }
            let connection = Connection::open(home.join("guard.db")).unwrap();
            for (table, rows) in dump_existing(&connection) {
                assert_rows(&rows, &expected[&table], &format!("{label}: {table}"));
            }
            compared += 1;
        }
        let _ = std::fs::remove_dir_all(&home);
    }
    assert!(compared >= 200, "only {compared} recorded steps");
}
