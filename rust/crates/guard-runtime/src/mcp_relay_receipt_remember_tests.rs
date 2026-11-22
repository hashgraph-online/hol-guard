use std::path::Path;

use base64ct::{Base64UrlUnpadded, Encoding};
use rusqlite::Connection;
use serde_json::{json, Value};

use crate::encrypted_secret_store::EncryptedFileSecretStore;
use crate::guard_store_cmd_vectors_tests::temp_home;
use crate::guard_store_policy_upsert::tests::SCHEMA;
use crate::guard_store_tool_call_evidence_tests::{build_database, count, vectors};
use crate::mcp_relay_receipt::remember::handed_back;
use crate::mcp_relay_receipt::tests::record;
use crate::mcp_relay_receipt::{is_plain, write};
use crate::policy_integrity_resolver::{
    build_scoped_secret_ref, load_policy_integrity_control_state, POLICY_INTEGRITY_CONTROL_REF,
    POLICY_INTEGRITY_KEY_REF,
};

/// The record an inline-approved forward leaves when the relay remembers it.
fn remembered() -> Value {
    let mut record = record("forward", "inline-approved", "allow");
    record["remember"] = json!(true);
    record
}

fn store_home(tag: &str, keyed: bool) -> std::path::PathBuf {
    let (receipts, inventory) = vectors();
    let home = temp_home(tag);
    build_database(&home.join("guard.db"), &receipts, &inventory);
    Connection::open(home.join("guard.db"))
        .unwrap()
        .execute_batch(SCHEMA)
        .unwrap();
    if keyed {
        let key: Vec<u8> = (0u8..32).collect();
        EncryptedFileSecretStore::new(&home)
            .set_secret(
                &build_scoped_secret_ref(POLICY_INTEGRITY_KEY_REF, &home),
                &Base64UrlUnpadded::encode_string(&key),
            )
            .unwrap();
    }
    home
}

fn saved_allows(home: &Path) -> Vec<(String, String, String, Option<String>)> {
    let connection = Connection::open(home.join("guard.db")).unwrap();
    let mut statement = connection
        .prepare(
            "select artifact_id, action, source, integrity_key_id from policy_decisions \
             where scope = 'artifact' order by decision_id",
        )
        .unwrap();
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn only_an_inline_approved_forward_may_remember() {
    assert!(is_plain(&remembered()));
    let mut refused = record("block", "inline-denied", "review");
    refused["remember"] = json!(true);
    assert!(!is_plain(&refused));
    let mut policy = record("forward", "policy", "allow");
    policy["remember"] = json!(true);
    assert!(!is_plain(&policy));
    let mut malformed = remembered();
    malformed["remember"] = json!("yes");
    assert!(!is_plain(&malformed));
}

#[test]
fn a_remembered_forward_saves_a_signed_allow_then_its_receipt() {
    let home = store_home("relay-remember-signed", true);
    let before = count(&home, "runtime_receipts");

    let unwritten = write(home.to_str().unwrap(), vec![remembered()]);

    assert!(unwritten.is_empty(), "{unwritten:?}");
    assert_eq!(count(&home, "runtime_receipts"), before + 1);
    let allows = saved_allows(&home);
    assert_eq!(allows.len(), 1, "{allows:?}");
    let (artifact_id, action, source, key_id) = &allows[0];
    assert_eq!(artifact_id, "codex:project:shell:run_command");
    assert_eq!(action, "allow");
    assert_eq!(source, "runtime-inline");
    assert!(key_id.is_some(), "the allow must be signed");
    let control =
        load_policy_integrity_control_state(&mut EncryptedFileSecretStore::new(&home), &home)
            .expect("finalized control state");
    assert_eq!(control["generation"], json!(1));
    assert!(control["pending_generation"].is_null(), "{control}");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn without_a_key_the_receipt_is_still_written() {
    let home = store_home("relay-remember-unkeyed", false);
    let before = count(&home, "runtime_receipts");

    let unwritten = write(home.to_str().unwrap(), vec![remembered()]);

    assert!(unwritten.is_empty(), "{unwritten:?}");
    assert_eq!(count(&home, "runtime_receipts"), before + 1);
    assert!(saved_allows(&home).is_empty());
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_home_without_a_store_hands_back_the_remembering_record() {
    let home = temp_home("relay-remember-no-store");
    let unwritten = write(home.to_str().unwrap(), vec![remembered()]);
    assert_eq!(unwritten, [remembered()]);
    let _ = std::fs::remove_dir_all(&home);
}

fn control_after(tag: &str, committed: bool) -> Value {
    let home = store_home(tag, true);
    let held = super::lock(home.to_str().unwrap()).expect("generation lock");
    super::save(
        home.to_str().unwrap(),
        &remembered(),
        "2026-01-01T00:00:00Z",
        &held,
        |_| (None, committed),
    );
    let control =
        load_policy_integrity_control_state(&mut EncryptedFileSecretStore::new(&home), &home)
            .expect("control state");
    let _ = std::fs::remove_dir_all(&home);
    control
}

#[test]
fn a_write_that_never_committed_puts_the_earlier_state_back() {
    let control = control_after("relay-remember-uncommitted", false);
    assert_eq!(control["generation"], json!(0));
    assert!(control["pending_generation"].is_null(), "{control}");
}

#[test]
fn a_committed_write_without_a_reply_leaves_the_generation_pending() {
    let control = control_after("relay-remember-committed-silent", true);
    assert_eq!(control["generation"], json!(0));
    assert_eq!(control["pending_generation"], json!(1), "{control}");
}

#[test]
fn a_control_state_that_does_not_load_is_never_reset() {
    let home = store_home("relay-remember-malformed-control", true);
    let control_ref = build_scoped_secret_ref(POLICY_INTEGRITY_CONTROL_REF, &home);
    let mut secrets = EncryptedFileSecretStore::new(&home);
    secrets.set_secret(&control_ref, "{not json").unwrap();
    let held = super::lock(home.to_str().unwrap()).expect("generation lock");
    let mut stored = false;
    super::save(
        home.to_str().unwrap(),
        &remembered(),
        "2026-01-01T00:00:00Z",
        &held,
        |_| {
            stored = true;
            (None, false)
        },
    );
    assert!(
        !stored,
        "no allow is written over an unreadable control state"
    );
    assert_eq!(
        EncryptedFileSecretStore::new(&home)
            .get_secret(&control_ref)
            .as_deref(),
        Some("{not json")
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_record_handed_back_after_its_allow_was_saved_is_retried_without_the_flag() {
    let queued = remembered();
    let mut forward = queued.clone();
    forward.as_object_mut().unwrap().remove("remember");
    assert_eq!(
        handed_back(&queued, std::slice::from_ref(&queued)),
        Some(queued.clone())
    );
    assert_eq!(
        handed_back(&queued, std::slice::from_ref(&forward)),
        Some(forward.clone())
    );
    assert_eq!(handed_back(&queued, &[]), None);
    assert_eq!(handed_back(&forward, std::slice::from_ref(&queued)), None);
}

fn published_after(tag: &str, mode: &str) -> Value {
    let home = store_home(tag, true);
    let state = json!({
        "backend": "vault",
        "cutover_complete": true,
        "degraded_reasons": [],
        "enforcement": "enforce",
        "generation": 0,
        "key_id": "key",
        "mode": mode,
    });
    let connection = Connection::open(home.join("guard.db")).unwrap();
    connection
        .execute_batch(
            "create table if not exists sync_state (state_key text primary key, \
             payload_json text not null, updated_at text not null)",
        )
        .unwrap();
    connection
        .execute(
            "insert into sync_state values ('policy_integrity', ?1, 'then')",
            [serde_json::to_string(&state).unwrap()],
        )
        .unwrap();

    let unwritten = write(home.to_str().unwrap(), vec![remembered()]);

    assert!(unwritten.is_empty(), "{unwritten:?}");
    let stored: String = connection
        .query_row(
            "select payload_json from sync_state where state_key = 'policy_integrity'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let _ = std::fs::remove_dir_all(&home);
    serde_json::from_str(&stored).unwrap()
}

#[test]
fn a_saved_allow_publishes_the_generation_its_rows_were_signed_at() {
    let published = published_after("relay-remember-publishes", "protected");
    assert_eq!(published["generation"], json!(1), "{published}");
    assert_eq!(published["mode"], json!("protected"));
    assert_eq!(published["key_id"], json!("key"));
}

#[test]
fn a_degraded_integrity_state_is_left_for_the_reconcile() {
    let published = published_after("relay-remember-degraded", "degraded");
    assert_eq!(published["generation"], json!(0), "{published}");
}
