//! The resident policy clear, against rows the Python signer recorded in
//! `testdata/policy_integrity_generation/vectors.json`.

use base64ct::{Base64UrlUnpadded, Encoding};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use super::clear_policy_decisions;
use crate::guard_store_args::Args;
use crate::guard_store_db::StoreError;
use crate::guard_store_policy_upsert::tests::{
    dump, generation, key, key_id, signed_rows, store, verifies_at,
};

fn args(fields: Value, signed: bool) -> Map<String, Value> {
    let mut args = fields.as_object().cloned().expect("object");
    args.insert("now".into(), json!("2026-10-16T09:00:00Z"));
    if signed {
        args.insert(
            "integrity_key_b64".into(),
            json!(Base64UrlUnpadded::encode_string(&key())),
        );
        args.insert("integrity_key_id".into(), json!(key_id()));
        args.insert("current_generation".into(), json!(3));
    }
    args
}

fn call(connection: &Connection, args: &Map<String, Value>) -> Value {
    clear_policy_decisions(connection, &Args(args)).expect("clear")
}

#[test]
fn clears_the_match_and_signs_the_rest_forward() {
    let connection = store(&signed_rows());

    let reply = call(
        &connection,
        &args(
            json!({"harness": "codex", "artifact_id": "codex:project:tool-1"}),
            true,
        ),
    );

    assert_eq!(reply["cleared"], json!(1));
    let stored = dump(&connection);
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0]["artifact_id"], json!("codex:project:tool-2"));
    assert_eq!(generation(&stored[0]), Some(4));
    assert!(verifies_at(&stored[0], 4));
    assert_eq!(
        reply["next_control_state"],
        json!({
            "cutover_complete": true,
            "generation": 4,
            "pending_generation": Value::Null,
            "version": 1,
        })
    );
}

#[test]
fn an_unsigned_only_clear_over_local_rows_deletes_nothing() {
    let connection = store(&signed_rows());

    let reply = call(
        &connection,
        &args(json!({"harness": "codex", "unsigned_only": true}), false),
    );

    assert_eq!(reply, json!({"needs_signing": true}));
    assert_eq!(dump(&connection).len(), 2);
}

#[test]
fn an_unsigned_only_clear_removes_remote_rows() {
    let mut rows = signed_rows();
    rows[1]["source"] = json!("cloud-sync");
    let connection = store(&rows);

    let reply = call(
        &connection,
        &args(
            json!({"harness": "codex", "source": "cloud-sync", "unsigned_only": true}),
            false,
        ),
    );

    assert_eq!(reply["cleared"], json!(1));
    assert_eq!(reply["next_control_state"], Value::Null);
    assert_eq!(dump(&connection).len(), 1);
}

#[test]
fn without_signing_material_nothing_is_signed() {
    let connection = store(&signed_rows());

    let reply = call(&connection, &args(json!({"harness": "codex"}), false));

    assert_eq!(reply["cleared"], json!(2));
    assert_eq!(reply["next_control_state"], Value::Null);
    assert!(dump(&connection).is_empty());
}

#[test]
fn an_artifact_clear_widens_to_the_remembered_row_siblings() {
    let mut rows = signed_rows();
    // A second row for the same remembered command under another hash.
    rows[1]["artifact_id"] = rows[0]["artifact_id"].clone();
    let connection = store(&rows);

    let reply = call(
        &connection,
        &args(
            json!({
                "harness": "codex",
                "artifact_id": "codex:project:tool-1",
                "artifact_hash": rows[0]["artifact_hash"],
            }),
            false,
        ),
    );

    assert_eq!(reply["cleared"], json!(2), "both displayed rows go");
}

#[test]
fn a_harness_scope_row_is_not_widened() {
    let mut rows = signed_rows();
    rows[0]["scope"] = json!("harness");
    rows[1]["artifact_id"] = rows[0]["artifact_id"].clone();
    let connection = store(&rows);

    let reply = call(
        &connection,
        &args(
            json!({
                "harness": "codex",
                "artifact_id": "codex:project:tool-1",
                "artifact_hash": rows[1]["artifact_hash"],
            }),
            false,
        ),
    );

    assert_eq!(reply["cleared"], json!(1), "only the exact match goes");
}

#[test]
fn an_unknown_scope_is_refused() {
    let connection = store(&signed_rows());

    let error = clear_policy_decisions(
        &connection,
        &Args(&args(json!({"scope": "everything"}), false)),
    )
    .expect_err("refused");

    assert!(
        matches!(error, StoreError::Value(message) if message == "Invalid policy scope: everything")
    );
    assert_eq!(dump(&connection).len(), 2);
}

#[test]
fn a_decision_id_clear_takes_only_those_rows_and_skips_widening() {
    let mut rows = signed_rows();
    rows[1]["artifact_id"] = rows[0]["artifact_id"].clone();
    let connection = store(&rows);
    let first = dump(&connection)[0]["decision_id"].clone();

    let reply = call(
        &connection,
        &args(
            json!({
                "harness": "codex",
                "artifact_id": "codex:project:tool-1",
                "decision_ids": [first],
            }),
            false,
        ),
    );

    assert_eq!(reply["cleared"], json!(1), "no sibling widening");
    assert_eq!(dump(&connection).len(), 1);
}

#[test]
fn an_empty_decision_id_list_clears_nothing() {
    let connection = store(&signed_rows());

    let reply = call(
        &connection,
        &args(json!({"decision_ids": [], "unsigned_only": true}), false),
    );

    assert_eq!(
        reply,
        json!({"cleared": 0, "next_control_state": Value::Null})
    );
    assert_eq!(dump(&connection).len(), 2);
}
