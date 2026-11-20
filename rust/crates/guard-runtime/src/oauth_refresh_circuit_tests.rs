use super::*;
use crate::package_authority_op::ResidentSupplyChainStore;

const GRANT: &str = "synthetic-refresh-grant";

fn store() -> (tempfile::TempDir, ResidentSupplyChainStore) {
    let home = tempfile::tempdir().unwrap();
    let store_path = home.path().join("guard.db");
    rusqlite::Connection::open(&store_path)
        .unwrap()
        .execute_batch(
            "create table sync_state (state_key text primary key, \
             payload_json text not null, updated_at text not null);",
        )
        .unwrap();
    let store = ResidentSupplyChainStore::new(&store_path, home.path());
    (home, store)
}

fn at(seconds: i64) -> Timestamp {
    Timestamp::from_unix_micros(1_800_000_000_000_000 + seconds * 1_000_000)
}

fn state(store: &dyn SupplyChainStore) -> Map<String, Value> {
    load(store)
}

#[test]
fn an_empty_circuit_is_open() {
    let (_home, store) = store();
    assert_eq!(check(&store, GRANT, at(0)), Check::Open);
}

#[test]
fn a_revoked_grant_parks_refresh_and_owes_its_notice_once() {
    let (_home, store) = store();
    let first = record_dead_grant(&store, GRANT, REVOKED, at(0));
    assert!(first.notice_due);
    assert_eq!(first.fingerprint.len(), 32);
    let saved = state(&store);
    assert_eq!(saved["consecutive_failures"], json!(1));
    assert_eq!(saved["backoff_seconds"], json!(30.0));
    assert_eq!(saved["failure_kind"], json!(REVOKED));
    assert_eq!(saved["notice_sent"], json!(false));
    assert!(saved.contains_key("last_error_at"));
    assert_eq!(
        check(&store, GRANT, at(10)),
        Check::Parked { rejected: false }
    );
    assert_eq!(check(&store, GRANT, at(31)), Check::Open);

    mark_notice_sent(&store, &first.fingerprint);
    let second = record_dead_grant(&store, GRANT, REVOKED, at(40));
    assert!(!second.notice_due);
    let saved = state(&store);
    assert_eq!(saved["consecutive_failures"], json!(2));
    assert_eq!(saved["backoff_seconds"], json!(60.0));
    assert_eq!(saved["notice_sent"], json!(true));
}

#[test]
fn a_rejected_grant_owes_its_notice_only_after_a_second_rejection() {
    let (_home, store) = store();
    assert!(!record_dead_grant(&store, GRANT, REJECTED, at(0)).notice_due);
    assert_eq!(
        check(&store, GRANT, at(1)),
        Check::Parked { rejected: true }
    );
    assert!(record_dead_grant(&store, GRANT, REJECTED, at(40)).notice_due);
}

#[test]
fn the_dead_grant_backoff_stops_at_the_maximum() {
    let (_home, store) = store();
    for step in 0..6 {
        record_dead_grant(&store, GRANT, REVOKED, at(step * 400));
    }
    assert_eq!(state(&store)["backoff_seconds"], json!(300.0));
}

#[test]
fn a_rate_limit_waits_out_retry_after_up_to_an_hour() {
    let (_home, store) = store();
    record_rate_limit(&store, GRANT, 7200, at(0));
    assert_eq!(state(&store)["backoff_seconds"], json!(3600));
    assert_eq!(
        check(&store, GRANT, at(100)),
        Check::RateLimited { wait_seconds: 3500 }
    );
    record_rate_limit(&store, GRANT, 0, at(0));
    assert_eq!(state(&store)["backoff_seconds"], json!(1));
}

#[test]
fn a_rate_limit_keeps_the_dead_grant_record() {
    let (_home, store) = store();
    let dead = record_dead_grant(&store, GRANT, REJECTED, at(0));
    mark_notice_sent(&store, &dead.fingerprint);
    record_rate_limit(&store, GRANT, 120, at(1));
    let saved = state(&store);
    assert_eq!(saved["consecutive_failures"], json!(1));
    assert_eq!(saved["needs_reauthorization"], json!(true));
    assert_eq!(saved["failure_kind"], json!(REJECTED));
    assert_eq!(saved["notice_sent"], json!(true));
    assert_eq!(
        check(&store, GRANT, at(60)),
        Check::Parked { rejected: true }
    );
}

#[test]
fn a_new_grant_clears_the_circuit() {
    let (_home, store) = store();
    record_dead_grant(&store, GRANT, REVOKED, at(0));
    assert_eq!(check(&store, "another-grant", at(1)), Check::Open);
    assert!(state(&store).contains_key("cleared_at"));
    assert_eq!(check(&store, GRANT, at(2)), Check::Open);
}

#[test]
fn clearing_writes_only_over_existing_state() {
    let (_home, store) = store();
    clear(&store, at(0));
    assert!(store.get_sync_payload(STATE_KEY).is_none());
    record_rate_limit(&store, GRANT, 60, at(0));
    clear(&store, at(1));
    let saved = state(&store);
    assert_eq!(saved.len(), 1);
    assert!(saved.contains_key("cleared_at"));
}

#[test]
fn the_salt_persists_so_fingerprints_stay_stable() {
    let (_home, store) = store();
    let first = record_dead_grant(&store, GRANT, REVOKED, at(0)).fingerprint;
    let second = record_dead_grant(&store, GRANT, REVOKED, at(1)).fingerprint;
    assert_eq!(first, second);
    assert_ne!(first, fingerprint(GRANT, &[0u8; 32]));
}

fn call(value: Value) -> Result<CircuitCall, serde_json::Error> {
    serde_json::from_value(value)
}

#[test]
fn dispatch_answers_each_operation() {
    let (_home, store) = store();
    let open = dispatch(
        &store,
        &call(json!({"op": "check", "refreshToken": GRANT})).unwrap(),
    );
    assert_eq!(open, Ok(json!({"state": "open"})));
    let dead = dispatch(
        &store,
        &call(json!({"op": "record_dead_grant", "refreshToken": GRANT, "failureKind": "revoked"}))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(dead["noticeDue"], json!(true));
    let parked = dispatch(
        &store,
        &call(json!({"op": "check", "refreshToken": GRANT})).unwrap(),
    );
    assert_eq!(
        parked,
        Ok(json!({"state": "parked", "failureKind": "revoked"}))
    );
    let sent = dispatch(
        &store,
        &call(json!({"op": "notice_sent", "fingerprint": dead["fingerprint"]})).unwrap(),
    );
    assert_eq!(sent, Ok(json!({"recorded": true})));
    assert_eq!(state(&store)["notice_sent"], json!(true));
    let limited = dispatch(
        &store,
        &call(json!({"op": "record_rate_limit", "refreshToken": GRANT, "retryAfterSeconds": 90}))
            .unwrap(),
    );
    assert_eq!(limited, Ok(json!({"recorded": true})));
    let cleared = dispatch(&store, &call(json!({"op": "clear"})).unwrap());
    assert_eq!(cleared, Ok(json!({"recorded": true})));
    let open = dispatch(
        &store,
        &call(json!({"op": "check", "refreshToken": GRANT})).unwrap(),
    );
    assert_eq!(open, Ok(json!({"state": "open"})));
}

#[test]
fn dispatch_refuses_incomplete_or_unknown_calls() {
    let (_home, store) = store();
    assert!(dispatch(&store, &call(json!({"op": "check"})).unwrap()).is_err());
    assert!(dispatch(
        &store,
        &call(json!({"op": "check", "refreshToken": ""})).unwrap()
    )
    .is_err());
    assert!(dispatch(
        &store,
        &call(json!({"op": "record_dead_grant", "refreshToken": GRANT, "failureKind": "expired"}))
            .unwrap()
    )
    .is_err());
    assert!(dispatch(
        &store,
        &call(json!({"op": "record_rate_limit", "refreshToken": GRANT})).unwrap()
    )
    .is_err());
    assert!(dispatch(&store, &call(json!({"op": "notice_sent"})).unwrap()).is_err());
    assert!(call(json!({"op": "check", "refreshToken": GRANT, "extra": 1})).is_err());
    assert!(call(json!({"op": "reset"})).is_err());
}
