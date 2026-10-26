//! Replays approval scope-sweep vectors recorded from the original Python
//! implementation (see
//! `testdata/guard_store/record_approval_resolution_sweep_vectors.py`).
//! Seeds, returned ids, resolved rows and errors all come from Python, never
//! from Rust output.

use std::collections::BTreeMap;

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_approval_read_scope::UNAVAILABLE;
use crate::guard_store_approval_reads::tests::{seed, store_call};
use crate::guard_store_cmd_vectors_tests::temp_home;

const VECTORS: &str =
    include_str!("../testdata/guard_store/approval_resolution_sweep_vectors.json");

pub(crate) fn states(path: &std::path::Path) -> BTreeMap<String, Vec<Value>> {
    let connection = Connection::open(path).unwrap();
    let mut statement = connection
        .prepare(
            "select request_id, status, resolution_action, resolution_scope, reason, resolved_at \
             from approval_requests",
        )
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            let cells = (0..6)
                .map(|index| {
                    row.get::<_, Option<String>>(index)
                        .map(|cell| cell.map_or(Value::Null, Value::String))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(cells)
        })
        .unwrap();
    rows.map(|row| {
        let mut row = row.unwrap();
        let id = row.remove(0);
        (id.as_str().unwrap().to_owned(), row)
    })
    .collect()
}

#[test]
fn replays_every_recorded_approval_scope_sweep() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(
        vectors["schema"],
        "guard-store-approval-resolution-sweep-vectors.v1"
    );
    let source = vectors["source"].as_str().unwrap();
    let mut replayed = 0;
    for scenario in vectors["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        for (index, call) in scenario["calls"].as_array().unwrap().iter().enumerate() {
            let label = format!("{name}#{index}");
            let home = temp_home(&format!("approval-sweep-{name}-{index}"));
            let path = home.join("guard.db");
            seed(&path, &vectors, scenario);
            let before = states(&path);
            let actual = store_call(
                &home,
                source,
                "resolve_matching_approval_requests",
                call["args"].clone(),
            );
            match &call["error"] {
                Value::Null => assert_eq!(actual, Ok(call["result"].clone()), "{label}"),
                error => {
                    assert_eq!(error["type"], "ApprovalScopeUnavailableError", "{label}");
                    assert_eq!(
                        actual.map_err(|(_, message)| message),
                        Err(UNAVAILABLE.to_owned()),
                        "{label}"
                    );
                }
            }
            let changed: Vec<Value> = states(&path)
                .into_iter()
                .filter(|(id, state)| before[id] != *state)
                .map(|(id, state)| json!([id, state[0], state[1], state[2], state[3], state[4]]))
                .collect();
            assert_eq!(Value::Array(changed), call["changed"], "{label}");
            let _ = std::fs::remove_dir_all(&home);
            replayed += 1;
        }
    }
    assert!(replayed >= 60, "replayed {replayed} calls");
}
