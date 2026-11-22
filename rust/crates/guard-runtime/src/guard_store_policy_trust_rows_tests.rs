//! The policy bundle trust rows, read as one view, and the Review
//! verification keyring write.

use rusqlite::Connection;
use serde_json::{json, Value};

use super::*;

const NOW: &str = "2026-11-21T12:00:00Z";

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table sync_state (
               state_key text primary key, payload_json text not null,
               updated_at text not null);",
        )
        .unwrap();
    connection
}

fn call(connection: &Connection, method: &str, args: Value) -> StoreResult<Value> {
    let map = args.as_object().cloned().unwrap_or_default();
    dispatch(connection, method, &Args(&map))
}

fn put(connection: &Connection, key: &str, payload: &str) {
    connection
        .execute(
            "insert or replace into sync_state values (?1, ?2, ?3)",
            rusqlite::params![key, payload, NOW],
        )
        .unwrap();
}

fn rows(connection: &Connection) -> Value {
    call(connection, "policy_bundle_trust_rows", json!({})).unwrap()
}

#[test]
fn an_empty_store_reads_every_row_as_null() {
    let view = rows(&store());
    let fields = view.as_object().unwrap();
    assert_eq!(fields.len(), 12);
    assert_eq!(view["policy_bundle_deferred"], json!(false));
    assert!(fields
        .iter()
        .filter(|(name, _)| *name != "policy_bundle_deferred")
        .all(|(_, value)| value.is_null()));
}

#[test]
fn every_row_is_read_under_its_own_key() {
    let connection = store();
    let keys = [
        (BUNDLE_KEY, "policy_bundle"),
        (KEYRING_KEY, "policy_bundle_keyring"),
        (CHECKPOINT_KEY, "acceptance_checkpoint"),
        (PROVENANCE_KEY, "managed_keyring_provenance"),
        (SUPPLY_CHAIN_KEYRING_KEY, "supply_chain_keyring"),
        (REVIEW_KEYRING_KEY, "review_verification_keyring"),
        (ACK_KEY, "policy_bundle_ack"),
        (SYNC_SUMMARY_KEY, "sync_summary"),
        (LAST_ERROR_KEY, "policy_bundle_last_error"),
    ];
    for (key, _) in keys {
        put(&connection, key, &json!({ "row": key }).to_string());
    }
    let view = rows(&connection);
    for (key, field) in keys {
        assert_eq!(view[field], json!({ "row": key }), "{field}");
    }
}

#[test]
fn arrays_pass_through_and_scalars_read_as_null() {
    let connection = store();
    put(&connection, REVIEW_KEYRING_KEY, r#"[{"key_id":"k1"}]"#);
    put(&connection, KEYRING_KEY, "7");
    put(&connection, ACK_KEY, "not json");
    let view = rows(&connection);
    assert_eq!(
        view["review_verification_keyring"],
        json!([{ "key_id": "k1" }])
    );
    assert!(view["policy_bundle_keyring"].is_null());
    assert!(view["policy_bundle_ack"].is_null());
}

#[test]
fn only_the_workspace_id_leaves_the_credential_row() {
    let connection = store();
    put(
        &connection,
        OAUTH_CREDENTIALS_KEY,
        r#"{"workspace_id":"ws-1","access_material":"never-read"}"#,
    );
    let view = rows(&connection);
    assert_eq!(view["workspace_id"], json!("ws-1"));
    assert!(!view.to_string().contains("never-read"));
}

#[test]
fn a_blank_or_non_text_workspace_id_reads_as_null() {
    let connection = store();
    for payload in [
        r#"{"workspace_id":"  "}"#,
        r#"{"workspace_id":42}"#,
        r#"{}"#,
        r#"["ws-1"]"#,
    ] {
        put(&connection, OAUTH_CREDENTIALS_KEY, payload);
        assert!(rows(&connection)["workspace_id"].is_null(), "{payload}");
    }
}

#[test]
fn the_review_keyring_write_replaces_the_row() {
    let connection = store();
    let keys = json!([{ "key_id": "k1" }, { "key_id": "k2" }]);
    call(
        &connection,
        "record_review_verification_keyring",
        json!({ "keys": keys, "now": NOW }),
    )
    .unwrap();
    assert_eq!(rows(&connection)["review_verification_keyring"], keys);
    call(
        &connection,
        "record_review_verification_keyring",
        json!({ "keys": [], "now": NOW }),
    )
    .unwrap();
    assert_eq!(rows(&connection)["review_verification_keyring"], json!([]));
}

#[test]
fn a_malformed_keyring_write_stores_nothing() {
    let connection = store();
    for args in [
        json!({ "keys": [{ "key_id": "k1" }, "k2"], "now": NOW }),
        json!({ "keys": { "key_id": "k1" }, "now": NOW }),
        json!({ "now": NOW }),
        json!({ "keys": [], "now": " " }),
        json!({ "keys": [] }),
    ] {
        assert!(
            call(
                &connection,
                "record_review_verification_keyring",
                args.clone()
            )
            .is_err(),
            "{args}"
        );
    }
    assert!(rows(&connection)["review_verification_keyring"].is_null());
}

#[test]
fn an_unknown_method_is_refused() {
    assert!(call(&store(), "policy_bundle_trust_rows_extra", json!({})).is_err());
    assert!(handles("policy_bundle_trust_rows"));
    assert!(handles("record_review_verification_keyring"));
    assert!(!handles("cached_policy_bundle"));
}

#[test]
fn keys_only_leaves_the_bundle_out() {
    let connection = store();
    put(&connection, BUNDLE_KEY, r#"{"bundleVersion":"7"}"#);
    put(&connection, KEYRING_KEY, r#"{"keys":[]}"#);
    let view = call(
        &connection,
        "policy_bundle_trust_rows",
        json!({ "keys_only": true }),
    )
    .unwrap();
    assert!(view["policy_bundle"].is_null());
    assert_eq!(view["policy_bundle_deferred"], json!(false));
    assert_eq!(view["policy_bundle_keyring"], json!({ "keys": [] }));
    assert_eq!(
        rows(&connection)["policy_bundle"],
        json!({ "bundleVersion": "7" })
    );
}

#[test]
fn a_bundle_too_large_for_the_reply_is_deferred_with_its_stamp() {
    let connection = store();
    let large = json!({ "rules": "x".repeat(BUNDLE_INLINE_BYTES) }).to_string();
    put(&connection, BUNDLE_KEY, &large);
    put(&connection, KEYRING_KEY, r#"{"keys":[]}"#);
    let view = rows(&connection);
    assert!(view["policy_bundle"].is_null());
    assert_eq!(view["policy_bundle_deferred"], json!(true));
    assert_eq!(
        view["policy_bundle_stamp"],
        json!({ "updated_at": NOW, "bytes": large.len() })
    );
    assert_eq!(view["policy_bundle_keyring"], json!({ "keys": [] }));
    assert!(view.to_string().len() < BUNDLE_INLINE_BYTES);
}
