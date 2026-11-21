//! What the minted row must be: readable as valid authority by the code that
//! will allow an execution from it, signed under the purpose its authority
//! kind names, and refused outright wherever Python refused.
//!
//! `tests/test_guard_approval_reuse.py` and
//! `tests/test_guard_local_authority_integrity.py` drive the same store method
//! against the native binary end to end.

use super::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use guard_policy_snapshot::local_authority_integrity::verify_local_authority_payload;
use rusqlite::Connection;
use serde_json::Map;

use crate::local_once_store::{
    peek_local_once_approval_locked, verify_local_once_approval, LOCAL_ONCE_INTEGRITY_PURPOSE,
};

const KEY: &[u8] = b"local-once-mint-integrity-key!!!";
const KEY_ID: &str = "key-1";
const CREATED_AT: &str = "2026-01-01T00:00:00+00:00";
const EXPIRES_AT: &str = "2026-01-02T00:00:00+00:00";
const ARTIFACT_ID: &str = "pkg:npm/left-pad@1.3.0";
const ARTIFACT_HASH: &str = "sha256:abc";

fn connection() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table guard_local_once_approvals (approval_id text primary key,
               request_id text not null, harness text not null, artifact_id text not null,
               artifact_hash text not null, workspace text, publisher text, action text not null,
               created_at text not null, expires_at text not null, claimed_at text,
               integrity_version integer, payload_hash text, payload_mac text,
               integrity_key_id text, signed_at text, authority_kind text);",
        )
        .unwrap();
    connection
}

fn mint(
    connection: &Connection,
    authority_kind: &str,
    artifact_id: Option<&str>,
    expires_at: &str,
) -> StoreResult<Option<String>> {
    let request = LocalOnceMint {
        request_id: "req-1",
        harness: Value::from("codex"),
        artifact_id,
        artifact_hash: Some(ARTIFACT_HASH),
        workspace: Some("/tmp/project"),
        publisher: Value::from("left-pad"),
        action: Value::from("allow"),
        created_at: CREATED_AT,
        expires_at,
        authority_kind,
    };
    mint_local_once_approval(
        connection,
        &request,
        KEY,
        KEY_ID,
        "local_once_mint_time_invalid",
        "local_once_mint_random_failed",
    )
}

fn stored(connection: &Connection) -> Value {
    connection
        .query_row(
            "select approval_id, request_id, harness, artifact_id, artifact_hash, workspace, \
             publisher, action, created_at, expires_at, claimed_at, integrity_version, \
             payload_hash, payload_mac, integrity_key_id, signed_at, authority_kind \
             from guard_local_once_approvals",
            [],
            crate::local_once_store::row_to_value,
        )
        .unwrap()
}

fn row_count(connection: &Connection) -> i64 {
    connection
        .query_row(
            "select count(*) from guard_local_once_approvals",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

/// The reader that will allow an execution has to accept what the minter
/// wrote: the same signed field set, the same purpose, the same workspace key.
#[test]
fn a_minted_approval_is_read_back_as_valid_authority() {
    let connection = connection();
    let approval_id = mint(
        &connection,
        LOCAL_ONCE_LEGACY_AUTHORITY_KIND,
        Some(ARTIFACT_ID),
        EXPIRES_AT,
    )
    .unwrap()
    .unwrap();

    let row = stored(&connection);
    assert_eq!(
        verify_local_once_approval(&row, Some(KEY), Some(KEY_ID)).status,
        "valid"
    );
    assert_eq!(row["authority_kind"], Value::from("legacy"));
    assert_eq!(
        row["workspace"],
        Value::from(computed_workspace_policy_key(Some("/tmp/project")))
    );
    assert_eq!(row["claimed_at"], Value::Null);

    let decision = peek_local_once_approval_locked(
        &connection,
        "codex",
        Some(ARTIFACT_ID),
        Some(ARTIFACT_HASH),
        Some("/tmp/project"),
        Some("left-pad"),
        CREATED_AT,
        Some(KEY),
        Some(KEY_ID),
    )
    .unwrap()
    .unwrap();
    assert_eq!(decision["approval_id"], Value::from(approval_id));
    assert_eq!(decision["integrity_status"], Value::from("valid"));
}

/// A Cloud Review allow and a locally approved one are signed under different
/// purposes, so neither can be replayed as the other on the same install key.
#[test]
fn each_authority_kind_signs_under_its_own_purpose() {
    let connection = connection();
    mint(
        &connection,
        EXACT_CLOUD_AUTHORITY_KIND,
        Some(ARTIFACT_ID),
        EXPIRES_AT,
    )
    .unwrap();

    let row = stored(&connection);
    assert_eq!(
        verify_local_once_approval(&row, Some(KEY), Some(KEY_ID)).status,
        "valid"
    );

    let payload = json!({
        "approval_id": row["approval_id"],
        "request_id": row["request_id"],
        "harness": row["harness"],
        "artifact_id": row["artifact_id"],
        "artifact_hash": row["artifact_hash"],
        "workspace": row["workspace"],
        "publisher": row["publisher"],
        "action": row["action"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "claimed_at": Value::Null,
        "authority_kind": row["authority_kind"],
    });
    let integrity = json!({
        "integrity_version": row["integrity_version"],
        "payload_hash": row["payload_hash"],
        "payload_mac": row["payload_mac"],
        "integrity_key_id": row["integrity_key_id"],
        "signed_at": row["signed_at"],
    });
    assert_ne!(
        verify_local_authority_payload(
            &payload,
            &integrity,
            Some(KEY),
            Some(KEY_ID),
            LOCAL_ONCE_INTEGRITY_PURPOSE,
        )
        .status,
        "valid"
    );
}

/// A request naming no exact artifact has nothing to bind authority to; an
/// unsupported kind and an expiry at creation are the two `ValueError`s.
#[test]
fn unbound_unsupported_and_already_expired_mints_are_refused() {
    let connection = connection();
    assert!(mint(
        &connection,
        LOCAL_ONCE_LEGACY_AUTHORITY_KIND,
        None,
        EXPIRES_AT
    )
    .unwrap()
    .is_none());
    assert!(mint(
        &connection,
        LOCAL_ONCE_LEGACY_AUTHORITY_KIND,
        Some(""),
        EXPIRES_AT
    )
    .unwrap()
    .is_none());
    assert!(matches!(
        mint(&connection, "cloud", Some(ARTIFACT_ID), EXPIRES_AT),
        Err(StoreError::Value(_))
    ));
    assert!(matches!(
        mint(
            &connection,
            LOCAL_ONCE_LEGACY_AUTHORITY_KIND,
            Some(ARTIFACT_ID),
            CREATED_AT
        ),
        Err(StoreError::Value(_))
    ));
    assert_eq!(row_count(&connection), 0);
}

fn call(connection: &Connection, overrides: Value) -> StoreResult<Value> {
    let mut args: Map<String, Value> = serde_json::from_value(json!({
        "request_id": "req-1",
        "harness": "codex",
        "artifact_id": ARTIFACT_ID,
        "artifact_hash": ARTIFACT_HASH,
        "workspace": "/tmp/project",
        "publisher": "left-pad",
        "action": "allow",
        "created_at": CREATED_AT,
        "expires_at": EXPIRES_AT,
        "integrity_key_b64": Base64UrlUnpadded::encode_string(KEY),
        "integrity_key_id": KEY_ID,
    }))
    .unwrap();
    for (name, value) in serde_json::from_value::<Map<String, Value>>(overrides).unwrap() {
        args.insert(name, value);
    }
    record_local_once_approval(connection, &Args(&args))
}

/// The store method answers the approval id Python returned, and defaults to
/// the legacy authority kind when the caller names none.
#[test]
fn the_store_method_answers_the_minted_approval_id() {
    let connection = connection();
    let answer = call(&connection, json!({})).unwrap();
    let row = stored(&connection);
    assert_eq!(answer, row["approval_id"]);
    assert_eq!(row["authority_kind"], Value::from("legacy"));
    assert_eq!(
        verify_local_once_approval(&row, Some(KEY), Some(KEY_ID)).status,
        "valid"
    );
}

/// The caller named `exact-cloud`, so the row is minted under that kind rather
/// than the default.
#[test]
fn the_store_method_honours_a_named_authority_kind() {
    let connection = connection();
    call(&connection, json!({ "authority_kind": "exact-cloud" })).unwrap();
    assert_eq!(
        stored(&connection)["authority_kind"],
        Value::from("exact-cloud")
    );
}

/// Key material is the caller's to supply. Without usable material, and with a
/// timestamp the store cannot read, the call fails closed rather than writing a
/// row no reader can verify.
#[test]
fn the_store_method_fails_closed_without_usable_inputs() {
    let connection = connection();
    assert!(matches!(
        call(&connection, json!({ "integrity_key_b64": Value::Null })),
        Err(StoreError::Invalid("local_once_mint_key_missing"))
    ));
    assert!(matches!(
        call(&connection, json!({ "integrity_key_id": "" })),
        Err(StoreError::Invalid("local_once_mint_key_missing"))
    ));
    assert!(matches!(
        call(&connection, json!({ "created_at": "not-a-timestamp" })),
        Err(StoreError::Invalid("local_once_mint_time_invalid"))
    ));
    assert_eq!(row_count(&connection), 0);
}
