//! Replays approval metadata vectors recorded from the original Python
//! implementation (see
//! `testdata/guard_store/record_approval_metadata_vectors.py`). Seeds,
//! results and changed markers all come from Python, never from Rust output.

use std::collections::BTreeMap;

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_approval_reads::tests::{seed, store_call};
use crate::guard_store_cmd_vectors_tests::temp_home;

const VECTORS: &str = include_str!("../testdata/guard_store/approval_metadata_vectors.json");

fn notified(path: &std::path::Path) -> BTreeMap<String, Value> {
    let connection = Connection::open(path).unwrap();
    let mut statement = connection
        .prepare("select request_id, desktop_notified_at from approval_requests")
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            let marker: Option<String> = row.get(1)?;
            Ok((
                row.get::<_, String>(0)?,
                marker.map_or(Value::Null, Value::String),
            ))
        })
        .unwrap();
    rows.map(Result::unwrap).collect()
}

#[test]
fn replays_every_recorded_approval_metadata_call() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(
        vectors["schema"],
        "guard-store-approval-metadata-vectors.v1"
    );
    let mut replayed = 0;
    for scenario in vectors["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        for (index, call) in scenario["calls"].as_array().unwrap().iter().enumerate() {
            let label = format!("{name}#{index}");
            let home = temp_home(&format!("approval-metadata-{name}-{index}"));
            let path = home.join("guard.db");
            seed(&path, &vectors, scenario);
            if scenario["legacy_hint_column"] == true {
                Connection::open(&path)
                    .unwrap()
                    .execute_batch(
                        "alter table approval_requests drop column extension_allow_hint_json",
                    )
                    .unwrap();
            }
            let before = notified(&path);
            let actual = store_call(
                &home,
                call["source"].as_str().unwrap(),
                call["method"].as_str().unwrap(),
                call["args"].clone(),
            );
            assert_eq!(actual, Ok(call["result"].clone()), "{label}");
            let changed: Vec<Value> = notified(&path)
                .into_iter()
                .filter(|(id, marker)| before[id] != *marker)
                .map(|(id, marker)| json!([id, marker]))
                .collect();
            assert_eq!(Value::Array(changed), call["changed"], "{label}");
            let _ = std::fs::remove_dir_all(&home);
            replayed += 1;
        }
    }
    assert!(replayed >= 35, "replayed {replayed} calls");
}

/// Guard writes the hint with serde, so a non-finite number or a lone
/// surrogate never reaches the column; a hint holding one fails closed
/// instead of crossing the reply.
#[test]
fn a_hint_the_reply_cannot_carry_reads_as_scope_unavailable() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let scenario = &vectors["scenarios"][0];
    for (index, cell) in [r#"{"score": NaN}"#, r#"{"s": "\ud800"}"#]
        .iter()
        .enumerate()
    {
        let home = temp_home(&format!("approval-metadata-unreplyable-{index}"));
        let path = home.join("guard.db");
        seed(&path, &vectors, scenario);
        Connection::open(&path)
            .unwrap()
            .execute(
                "update approval_requests set extension_allow_hint_json = ?1 \
                 where request_id = 'h-object'",
                [cell],
            )
            .unwrap();
        let actual = store_call(
            &home,
            vectors["scenarios"][0]["calls"][0]["source"]
                .as_str()
                .unwrap(),
            "get_approval_extension_allow_hint",
            json!({"request_id": "h-object"}),
        );
        assert!(actual.is_err(), "{cell}: {actual:?}");
        let _ = std::fs::remove_dir_all(&home);
    }
}

#[test]
fn a_blob_hint_reads_as_no_hint() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let scenario = &vectors["scenarios"][0];
    let home = temp_home("approval-metadata-blob-hint");
    let path = home.join("guard.db");
    seed(&path, &vectors, scenario);
    Connection::open(&path)
        .unwrap()
        .execute(
            "update approval_requests set extension_allow_hint_json = ?1 \
             where request_id = 'h-object'",
            [br#"{"k": 1}"#.to_vec()],
        )
        .unwrap();
    let actual = store_call(
        &home,
        scenario["calls"][0]["source"].as_str().unwrap(),
        "get_approval_extension_allow_hint",
        json!({"request_id": "h-object"}),
    );
    assert_eq!(actual, Ok(Value::Null));
    let _ = std::fs::remove_dir_all(&home);
}

/// Adds a copy of the seeded `h-object` row under `request_id`.
fn add_copy(
    path: &std::path::Path,
    request_id: &str,
    group: &str,
    status: &str,
    marker: Option<&str>,
) {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(
            "drop table if exists temp.copy; \
             create temp table copy as select * from approval_requests where request_id = 'h-object';",
        )
        .unwrap();
    connection
        .execute(
            "update temp.copy set request_id = ?1, queue_group_id = ?2, status = ?3, \
             desktop_notified_at = ?4",
            rusqlite::params![request_id, group, status, marker],
        )
        .unwrap();
    connection
        .execute_batch("insert into approval_requests select * from temp.copy")
        .unwrap();
}

#[test]
fn a_connector_group_reads_the_marker_of_its_first_notified_command() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let scenario = &vectors["scenarios"][0];
    let home = temp_home("approval-metadata-connector-notice");
    let path = home.join("guard.db");
    seed(&path, &vectors, scenario);
    let first = "2026-03-01T12:00:00+00:00";
    add_copy(
        &path,
        "c-first",
        "connector:aa11:0000000000000001",
        "pending",
        Some(first),
    );
    add_copy(
        &path,
        "c-second",
        "connector:aa11:0000000000000002",
        "pending",
        None,
    );
    add_copy(
        &path,
        "c-other",
        "connector:bb22:0000000000000001",
        "pending",
        None,
    );
    add_copy(
        &path,
        "c-closed",
        "connector:cc33:0000000000000001",
        "approved",
        Some(first),
    );
    add_copy(
        &path,
        "c-after",
        "connector:cc33:0000000000000002",
        "pending",
        None,
    );
    add_copy(&path, "g-plain", "qg-seeded-two", "pending", None);
    let read = |request_id: &str| {
        store_call(
            &home,
            "guard",
            "approval_desktop_notified_at",
            json!({"request_id": request_id}),
        )
    };

    assert_eq!(read("c-second"), Ok(Value::from(first)));
    assert_eq!(read("c-first"), Ok(Value::from(first)));
    assert_eq!(read("c-other"), Ok(Value::Null));
    assert_eq!(read("c-after"), Ok(Value::Null));
    assert_eq!(read("g-plain"), Ok(Value::Null));
    let _ = std::fs::remove_dir_all(&home);
}
