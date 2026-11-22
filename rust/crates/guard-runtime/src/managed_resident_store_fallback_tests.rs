//! A store read another install's resident predates, answered by this runtime.

use std::path::PathBuf;

use rusqlite::Connection;
use serde_json::{json, Value};

use super::*;

struct Home(PathBuf);

impl Home {
    fn new(tag: &str) -> Self {
        let nonce = crate::unique_nanos::unique_nanos();
        let home = std::env::temp_dir().join(format!(
            "hol-guard-store-fallback-{tag}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&home).unwrap();
        let home = std::fs::canonicalize(home).unwrap();
        Connection::open(home.join("guard.db"))
            .unwrap()
            .execute_batch(
                "create table sync_state (
                   state_key text primary key, payload_json text not null,
                   updated_at text not null);",
            )
            .unwrap();
        Self(home)
    }

    fn envelope(&self, operation: &str, method: &str) -> Vec<u8> {
        let request = json!({
            "schema": "guard-store-request.v1",
            "request_id": "guard-store-fallback",
            "store_path": self.0.join("guard.db").to_string_lossy(),
            "guard_home": self.0.to_string_lossy(),
            "method": method,
            "source": "default",
            "busy_timeout_ms": 5000,
            "args": {},
        });
        serde_json::to_vec(&json!({
            "operation": operation,
            "request": request,
            "deadline_budget_ms": 5000,
        }))
        .unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What an older resident sends for a store method it does not know.
fn unknown_method_reply() -> Vec<u8> {
    store_reply(
        "native_guard_store_invalid",
        "native_guard_store_method_unknown",
    )
}

fn store_reply(code: &str, message: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "guard-store-result.v1",
        "request_id": "guard-store-fallback",
        "request_sha256": "sha256:0",
        "status": "error",
        "code": code,
        "payload": { "message": message },
        "outbox_generation": null,
    }))
    .unwrap()
}

#[test]
fn a_snapshot_read_the_resident_predates_is_answered_here() {
    let home = Home::new("snapshot");
    let payload = home.envelope("guard_store", "policy_bundle_trust_rows");
    let answer = answer_unknown_store_read(&payload, &unknown_method_reply())
        .expect("this runtime answers the read");
    let answer: Value = serde_json::from_slice(&answer).unwrap();
    assert_eq!(answer["schema"], "guard-store-result.v1");
    assert_eq!(answer["status"], "ok", "{answer}");
    assert_eq!(answer["request_id"], "guard-store-fallback");
    assert_eq!(answer["payload"]["policy_bundle_deferred"], json!(false));
}

#[test]
fn a_plain_read_the_resident_predates_is_answered_here() {
    let home = Home::new("read");
    let payload = home.envelope("guard_store", "get_sync_payload");
    let answer = answer_unknown_store_read(&payload, &unknown_method_reply());
    assert!(answer.is_some());
}

#[test]
fn any_other_resident_error_stands() {
    let home = Home::new("other-error");
    let payload = home.envelope("guard_store", "policy_bundle_trust_rows");
    for response in [
        store_reply("native_guard_store_busy", "database is locked"),
        store_reply(
            "native_guard_store_invalid",
            "native_guard_store_path_invalid",
        ),
        b"{\"error\":\"native_request_schema_unsupported\"}".to_vec(),
        b"not json".to_vec(),
    ] {
        assert!(answer_unknown_store_read(&payload, &response).is_none());
    }
}

#[test]
fn a_write_stays_with_the_resident() {
    let home = Home::new("write");
    let payload = home.envelope("guard_store", "upsert_policy");
    assert!(answer_unknown_store_read(&payload, &unknown_method_reply()).is_none());
}

#[test]
fn a_read_that_takes_the_write_lock_itself_stays_with_the_resident() {
    let home = Home::new("self-writing");
    for method in WRITES_ON_ITS_OWN {
        let payload = home.envelope("guard_store", method);
        assert!(
            answer_unknown_store_read(&payload, &unknown_method_reply()).is_none(),
            "{method}"
        );
    }
}

#[test]
fn every_self_writing_method_is_still_classified_as_a_read() {
    // A method that leaves the read kind no longer needs the list; one that is
    // renamed must be renamed here too, or the fallback would answer it.
    for method in WRITES_ON_ITS_OWN {
        assert!(
            matches!(method_kind(method), Some(Kind::Read)),
            "{method} is no longer a read-kind method"
        );
    }
}

#[test]
fn a_method_this_runtime_does_not_know_either_stands() {
    let home = Home::new("unknown-here");
    let payload = home.envelope("guard_store", "a_method_from_a_later_release");
    assert!(answer_unknown_store_read(&payload, &unknown_method_reply()).is_none());
}

#[test]
fn only_a_store_operation_is_answered() {
    let home = Home::new("operation");
    let payload = home.envelope("command_model", "policy_bundle_trust_rows");
    assert!(answer_unknown_store_read(&payload, &unknown_method_reply()).is_none());
}

#[test]
fn a_resident_of_this_runtime_keeps_its_reply() {
    let home = Home::new("same-runtime");
    let payload = home.envelope("guard_store", "policy_bundle_trust_rows");
    let unknown = unknown_method_reply();
    assert_eq!(reply(&payload, unknown.clone(), true), unknown);
    let answered: Value = serde_json::from_slice(&reply(&payload, unknown, false)).unwrap();
    assert_eq!(answered["status"], "ok", "{answered}");
}
