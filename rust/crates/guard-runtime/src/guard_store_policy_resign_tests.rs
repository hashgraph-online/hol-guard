//! The resident integrity resign, against rows the Python signer recorded in
//! `testdata/policy_integrity_generation/vectors.json`.

use base64ct::{Base64UrlUnpadded, Encoding};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use super::resign_policy_rows;
use crate::guard_store_args::Args;
use crate::guard_store_db::StoreError;
use crate::guard_store_policy_upsert::tests::{
    dump, generation, key, key_id, signed_rows, store, verifies_at,
};

fn args(fields: Value) -> Map<String, Value> {
    let mut args = fields.as_object().cloned().expect("object");
    args.insert("now".into(), json!("2026-10-16T09:00:00Z"));
    args.insert(
        "integrity_key_b64".into(),
        json!(Base64UrlUnpadded::encode_string(&key())),
    );
    args.insert("integrity_key_id".into(), json!(key_id()));
    args.insert("current_generation".into(), json!(3));
    args
}

fn ids(connection: &Connection) -> Vec<i64> {
    dump(connection)
        .iter()
        .map(|row| row["decision_id"].as_i64().expect("decision id"))
        .collect()
}

#[test]
fn clears_the_dropped_rows_and_signs_the_rest_forward() {
    let connection = store(&signed_rows());
    let dropped = ids(&connection)[0];

    let reply = resign_policy_rows(
        &connection,
        &Args(&args(json!({"clear_decision_ids": [dropped]}))),
    )
    .expect("resign");

    assert_eq!(reply["cleared"], json!(1));
    assert_eq!(reply["next_control_state"]["generation"], json!(4));
    let stored = dump(&connection);
    assert_eq!(stored.len(), 1);
    assert_eq!(generation(&stored[0]), Some(4));
    assert!(verifies_at(&stored[0], 4));
}

#[test]
fn a_forced_row_is_signed_even_when_it_no_longer_verifies() {
    let mut rows = signed_rows();
    rows[0]["payload_mac"] = json!("tampered");
    let connection = store(&rows);
    let forced = ids(&connection);

    let reply = resign_policy_rows(
        &connection,
        &Args(&args(json!({"force_sign_decision_ids": forced}))),
    )
    .expect("resign");

    assert_eq!(reply["cleared"], json!(0));
    for row in dump(&connection) {
        assert!(verifies_at(&row, 4), "every forced row signs forward");
    }
}

#[test]
fn an_unforced_row_that_does_not_verify_keeps_its_old_signature() {
    let mut rows = signed_rows();
    rows[0]["payload_mac"] = json!("tampered");
    let connection = store(&rows);

    let _ = resign_policy_rows(&connection, &Args(&args(json!({})))).expect("resign");

    let stored = dump(&connection);
    let unsigned = stored.iter().filter(|row| !verifies_at(row, 4)).count();
    assert_eq!(unsigned, 1);
}

#[test]
fn a_resign_without_the_key_is_refused() {
    let connection = store(&signed_rows());
    let mut fields = Map::new();
    fields.insert("now".into(), json!("2026-10-16T09:00:00Z"));

    let error = resign_policy_rows(&connection, &Args(&fields)).expect_err("refused");

    assert!(
        matches!(&error, StoreError::Value(message) if message == "native_policy_integrity_key_required")
    );
    assert_eq!(dump(&connection).len(), 2);
}
