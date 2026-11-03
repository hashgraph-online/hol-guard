//! The resident policy write, against rows the Python signer recorded in
//! `testdata/policy_integrity_generation/vectors.json`.

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use guard_policy_snapshot::policy_integrity::verify_local_policy_row;
use rusqlite::{params_from_iter, types::Value as SqlValue, Connection};
use serde_json::{json, Map, Value};

use super::upsert_policy;
use crate::guard_store_args::Args;
use crate::guard_store_op::evaluate_guard_store_request;
use crate::policy_integrity_generation::ROW_COLUMNS;

const VECTORS: &str = include_str!("../testdata/policy_integrity_generation/vectors.json");

/// The live schema, as `store_connection_schema.py` creates it: `decision_id`
/// has to be the row id for the insert to report the row it wrote.
const SCHEMA: &str = "create table policy_decisions (
  decision_id integer primary key autoincrement,
  harness text not null,
  scope text not null,
  artifact_id text,
  artifact_hash text,
  workspace text,
  publisher text,
  action text not null,
  reason text,
  owner text,
  source text not null default 'local',
  expires_at text,
  policy_document_schema_version text,
  policy_document_id text,
  policy_document_digest text,
  policy_rule_id text,
  policy_provenance_json text,
  updated_at text not null,
  integrity_version integer,
  integrity_generation integer,
  payload_hash text,
  payload_mac text,
  integrity_key_id text,
  signed_at text)";

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors json")
}

/// The key `record_vectors.py` signed with.
fn key() -> Vec<u8> {
    (0u8..32).collect()
}

fn key_id() -> String {
    vectors()["integrity_key_id"]
        .as_str()
        .expect("key id")
        .to_owned()
}

/// The two local rows of the `steady_current` vector, signed at generation 3.
fn signed_rows() -> Vec<Value> {
    vectors()["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["name"] == "steady_current")
        .expect("steady_current case")["rows"]
        .as_array()
        .expect("rows")
        .clone()
}

fn sql_value(value: &Value) -> SqlValue {
    match value {
        Value::Null => SqlValue::Null,
        Value::String(text) => SqlValue::Text(text.clone()),
        Value::Number(number) if number.is_i64() => SqlValue::Integer(number.as_i64().unwrap()),
        other => panic!("unexpected row value {other}"),
    }
}

fn store(rows: &[Value]) -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection.execute_batch(SCHEMA).unwrap();
    let placeholders = vec!["?"; ROW_COLUMNS.len()].join(", ");
    let insert = format!(
        "insert into policy_decisions ({}) values ({placeholders})",
        ROW_COLUMNS.join(", ")
    );
    for row in rows {
        let values = ROW_COLUMNS.iter().map(|column| sql_value(&row[*column]));
        connection
            .execute(&insert, params_from_iter(values))
            .unwrap();
    }
    connection
}

/// Every row in the table, by `decision_id`.
fn dump(connection: &Connection) -> Vec<Value> {
    let sql = format!(
        "select {} from policy_decisions order by decision_id",
        ROW_COLUMNS.join(", ")
    );
    let mut statement = connection.prepare(&sql).unwrap();
    let mut cursor = statement.query([]).unwrap();
    let mut rows = Vec::new();
    while let Some(row) = cursor.next().unwrap() {
        let mut object = Map::new();
        for (index, column) in ROW_COLUMNS.iter().enumerate() {
            let value = match row.get_ref(index).unwrap() {
                rusqlite::types::ValueRef::Null => Value::Null,
                rusqlite::types::ValueRef::Integer(number) => Value::from(number),
                rusqlite::types::ValueRef::Text(text) => {
                    Value::from(String::from_utf8(text.to_vec()).unwrap())
                }
                other => panic!("unexpected column value {other:?}"),
            };
            object.insert((*column).to_owned(), value);
        }
        rows.push(Value::Object(object));
    }
    rows
}

/// A write for `artifact_id`, with the signing material unless `signed` is off.
fn args(artifact_id: &str, signed: bool) -> Map<String, Value> {
    let mut args = Map::new();
    args.insert("harness".into(), json!("codex"));
    args.insert("scope".into(), json!("artifact"));
    args.insert("artifact_id".into(), json!(artifact_id));
    args.insert("artifact_hash".into(), Value::Null);
    args.insert("workspace".into(), Value::Null);
    args.insert("publisher".into(), Value::Null);
    args.insert("action".into(), json!("allow"));
    args.insert("reason".into(), json!("approved"));
    args.insert("owner".into(), json!("local-user"));
    args.insert("source".into(), json!("local"));
    args.insert("expires_at".into(), Value::Null);
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
    upsert_policy(connection, &Args(args)).expect("upsert")
}

fn generation(row: &Value) -> Option<i64> {
    row["integrity_generation"].as_i64()
}

fn verifies_at(row: &Value, trusted_generation: i64) -> bool {
    verify_local_policy_row(
        row,
        Some(&key()),
        Some(&key_id()),
        false,
        Some(trusted_generation),
    )
    .status
        == "valid"
}

#[test]
fn replaces_the_row_sharing_the_policy_key_and_signs_the_rest_forward() {
    let rows = signed_rows();
    let connection = store(&rows);
    let first_artifact = rows[0]["artifact_id"].as_str().unwrap().to_owned();
    // The stored row carries an artifact hash; the write that replaces it must
    // match on the same key, so reuse it rather than the null-hash default.
    let mut args = args(&first_artifact, true);
    args.insert("artifact_hash".into(), rows[0]["artifact_hash"].clone());

    let reply = call(&connection, &args);

    let stored = dump(&connection);
    assert_eq!(stored.len(), 2, "the matching row is replaced, not added");
    assert_eq!(
        reply["decision_id"].as_i64(),
        stored
            .last()
            .map(|row| row["decision_id"].as_i64().unwrap())
    );
    for row in &stored {
        assert_eq!(generation(row), Some(4), "{row}");
        assert!(verifies_at(row, 4), "{row}");
    }
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
fn a_tampered_row_is_left_behind_at_its_own_generation() {
    let rows = signed_rows();
    let connection = store(&rows);
    connection
        .execute(
            "update policy_decisions set reason = 'escalated' where decision_id = ?",
            [rows[1]["decision_id"].as_i64().unwrap()],
        )
        .unwrap();

    call(&connection, &args("codex:project:tool-3", true));

    let stored = dump(&connection);
    assert_eq!(stored.len(), 3);
    assert_eq!(generation(&stored[0]), Some(4), "the valid row moves");
    assert!(verifies_at(&stored[0], 4));
    assert_eq!(
        generation(&stored[1]),
        Some(3),
        "the tampered row is not re-signed into the trusted generation"
    );
    assert_eq!(stored[1]["payload_mac"], rows[1]["payload_mac"]);
    assert!(!verifies_at(&stored[1], 4));
    assert_eq!(generation(&stored[2]), Some(4), "the new row is signed");
    assert!(verifies_at(&stored[2], 4));
}

#[test]
fn remote_rows_are_never_signed_locally() {
    let mut rows = signed_rows();
    rows[1]["source"] = json!("cloud-sync");
    rows[1]["integrity_generation"] = Value::Null;
    rows[1]["payload_mac"] = Value::Null;
    let connection = store(&rows);

    call(&connection, &args("codex:project:tool-3", true));

    let stored = dump(&connection);
    assert_eq!(stored[1]["source"], json!("cloud-sync"));
    assert_eq!(generation(&stored[1]), None);
    assert_eq!(stored[1]["payload_mac"], Value::Null);
}

#[test]
fn a_remote_write_is_stored_unsigned() {
    let connection = store(&signed_rows());
    let mut args = args("codex:project:tool-3", true);
    args.insert("source".into(), json!("cloud-sync"));

    let reply = call(&connection, &args);

    let stored = dump(&connection);
    assert_eq!(reply["next_control_state"], Value::Null);
    assert_eq!(generation(&stored[2]), None, "the new row stays unsigned");
    assert_eq!(
        generation(&stored[0]),
        Some(3),
        "a remote write advances nothing"
    );
}

#[test]
fn without_signing_material_nothing_is_signed() {
    let connection = store(&signed_rows());

    let reply = call(&connection, &args("codex:project:tool-3", false));

    let stored = dump(&connection);
    assert_eq!(reply["next_control_state"], Value::Null);
    assert_eq!(stored.len(), 3);
    assert_eq!(generation(&stored[0]), Some(3));
    assert_eq!(generation(&stored[2]), None);
}

#[test]
fn partial_signing_material_is_refused() {
    let connection = store(&signed_rows());
    let mut args = args("codex:project:tool-3", true);
    args.remove("integrity_key_id");

    assert!(upsert_policy(&connection, &Args(&args)).is_err());
}

#[test]
fn an_unusable_key_is_refused() {
    let connection = store(&signed_rows());
    let mut args = args("codex:project:tool-3", true);
    args.insert("integrity_key_b64".into(), json!("not base64!!"));

    assert!(upsert_policy(&connection, &Args(&args)).is_err());
}

/// The key travels in `args`, and both ends drop it before they digest the
/// request: the resident here, the client in `native_guard_store.py`. If the
/// two lists ever disagree the client rejects every signed policy write for a
/// digest mismatch, so the property is pinned on this side too.
#[test]
fn the_request_digest_ignores_the_policy_integrity_key() {
    let home = std::env::temp_dir().join("guard-store-policy-upsert-digest");
    let request = |args: Map<String, Value>| GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "digest".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: "upsert_policy".to_owned(),
        source: "guard".to_owned(),
        busy_timeout_ms: 5000,
        args,
    };
    let digest = |args: Map<String, Value>| -> String {
        let reply: Value =
            serde_json::from_slice(&evaluate_guard_store_request(&request(args)).unwrap()).unwrap();
        reply["request_sha256"].as_str().unwrap().to_owned()
    };

    let bare = args("artifact", false);
    let mut keyed = bare.clone();
    keyed.insert("integrity_key_b64".to_owned(), json!("c2VjcmV0"));
    assert_eq!(digest(bare.clone()), digest(keyed.clone()));

    let mut other_key = bare.clone();
    other_key.insert("integrity_key_b64".to_owned(), json!("ZGlmZmVyZW50"));
    assert_eq!(digest(keyed), digest(other_key));

    let mut renamed = bare.clone();
    renamed.insert("integrity_key_id".to_owned(), json!("another-key-id"));
    assert_ne!(digest(bare), digest(renamed));
}
