//! A store read another install's resident predates, answered by this runtime.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use rusqlite::Connection;
use serde_json::{json, Value};

use super::*;
use crate::guard_store_op_kind::{method_kind, Kind};

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

    fn request(&self, method: &str) -> Value {
        json!({
            "schema": "guard-store-request.v1",
            "request_id": "guard-store-fallback",
            "store_path": self.0.join("guard.db").to_string_lossy(),
            "guard_home": self.0.to_string_lossy(),
            "method": method,
            "source": "default",
            "busy_timeout_ms": 5000,
            "args": {},
        })
    }

    fn envelope(&self, operation: &str, method: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "operation": operation,
            "request": self.request(method),
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

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

/// This runtime's answer, or `None` when the resident's reply stands.
fn answered(payload: &[u8], response: &[u8], deadline: Instant) -> Option<Value> {
    let out = reply(payload, response.to_vec(), deadline);
    (out != response).then(|| serde_json::from_slice(&out).unwrap())
}

#[test]
fn a_snapshot_read_the_resident_predates_is_answered_here() {
    let home = Home::new("snapshot");
    let payload = home.envelope("guard_store", "policy_bundle_trust_rows");
    let answer =
        answered(&payload, &unknown_method_reply(), soon()).expect("this runtime answers the read");
    assert_eq!(answer["schema"], "guard-store-result.v1");
    assert_eq!(answer["status"], "ok", "{answer}");
    assert_eq!(answer["request_id"], "guard-store-fallback");
    assert_eq!(answer["payload"]["policy_bundle_deferred"], json!(false));
}

#[test]
fn the_answer_keeps_the_digest_of_the_request_as_sent() {
    // The local busy wait is cut to the time left, which must not change the
    // digest the caller binds the reply to.
    let home = Home::new("digest");
    let payload = home.envelope("guard_store", "policy_bundle_trust_rows");
    let sent: GuardStoreRequestV1 =
        serde_json::from_value(home.request("policy_bundle_trust_rows")).unwrap();
    let deadline = Instant::now() + Duration::from_millis(1500);
    let answer = answered(&payload, &unknown_method_reply(), deadline).unwrap();
    assert_eq!(
        answer["request_sha256"],
        json!(crate::guard_store_op::request_digest(&sent).unwrap())
    );
}

#[test]
fn a_spent_deadline_leaves_the_resident_reply() {
    let home = Home::new("deadline");
    let payload = home.envelope("guard_store", "policy_bundle_trust_rows");
    assert!(answered(&payload, &unknown_method_reply(), Instant::now()).is_none());
}

#[test]
fn a_plain_read_the_resident_predates_is_answered_here() {
    // An a24 CLI asked an a23 Desktop resident for `get_runtime_state`, and
    // `hol-guard status` failed until the Desktop app updated too.
    let home = Home::new("plain-read");
    let store = Connection::open(home.0.join("guard.db")).unwrap();
    store
        .execute_batch(
            "create table guard_runtime_state (
               state_key text primary key, session_id text, daemon_host text,
               daemon_port integer, started_at text, last_heartbeat_at text);
             insert into guard_runtime_state values
               ('runtime', 'session-1', '127.0.0.1', 4100, 't0', 't1');",
        )
        .unwrap();
    let payload = home.envelope("guard_store", "get_runtime_state");
    let answer =
        answered(&payload, &unknown_method_reply(), soon()).expect("this runtime answers the read");
    assert_eq!(answer["status"], "ok", "{answer}");
    assert_eq!(answer["payload"]["session_id"], "session-1");
    assert_eq!(answer["payload"]["daemon_port"], 4100);
    assert_eq!(answer["outbox_generation"], Value::Null);
}

#[test]
fn a_read_that_commits_on_its_own_stays_with_the_resident() {
    let home = Home::new("self-committing");
    for method in [
        "settle_claimed_native_allow",
        "complete_codex_live_decision",
        "run_storage_housekeeping",
    ] {
        assert!(method_kind(method) == Some(Kind::Read), "{method}");
        let payload = home.envelope("guard_store", method);
        assert!(
            answered(&payload, &unknown_method_reply(), soon()).is_none(),
            "{method}"
        );
    }
}

#[test]
fn every_excluded_read_is_a_known_read() {
    // A renamed method would otherwise drop out of the exclusion silently.
    for method in crate::guard_store_op_kind::SELF_COMMITTING_READS {
        assert!(method_kind(method) == Some(Kind::Read), "{method}");
        assert!(!crate::guard_store_op_kind::answerable_in_isolation(method));
    }
}

#[test]
fn a_write_stays_with_the_resident() {
    let home = Home::new("write");
    let payload = home.envelope("guard_store", "upsert_policy");
    assert!(answered(&payload, &unknown_method_reply(), soon()).is_none());
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
        assert!(answered(&payload, &response, soon()).is_none());
    }
}

#[test]
fn a_method_this_runtime_does_not_know_either_stands() {
    let home = Home::new("unknown-here");
    let payload = home.envelope("guard_store", "a_method_from_a_later_release");
    assert!(answered(&payload, &unknown_method_reply(), soon()).is_none());
}

#[test]
fn only_a_store_operation_is_answered() {
    let home = Home::new("operation");
    let payload = home.envelope("command_model", "policy_bundle_trust_rows");
    assert!(answered(&payload, &unknown_method_reply(), soon()).is_none());
}
