use super::*;

const GRANT: &str = "synthetic-refresh-grant";

fn store() -> (tempfile::TempDir, Circuit) {
    let home = tempfile::tempdir().unwrap();
    rusqlite::Connection::open(home.path().join(STORE_FILE_NAME))
        .unwrap()
        .execute_batch(
            "create table sync_state (state_key text primary key, \
             payload_json text not null, updated_at text not null);",
        )
        .unwrap();
    let circuit = Circuit::new(home.path(), Backoff::new(30.0, 300.0));
    (home, circuit)
}

fn at(seconds: i64) -> Timestamp {
    Timestamp::from_unix_micros(1_800_000_000_000_000 + seconds * 1_000_000)
}

fn state(store: &Circuit) -> Map<String, Value> {
    state_of(read_payload(&store.connect().unwrap(), STATE_KEY).unwrap()).unwrap()
}

#[test]
fn an_empty_circuit_is_open() {
    let (_home, store) = store();
    assert_eq!(store.check(GRANT, at(0)).unwrap(), Check::Open);
}

#[test]
fn a_revoked_grant_parks_refresh_and_owes_its_notice_once() {
    let (_home, store) = store();
    let first = store.record_dead_grant(GRANT, REVOKED, at(0)).unwrap();
    assert!(first.notice_due);
    assert_eq!(first.fingerprint.len(), 32);
    let saved = state(&store);
    assert_eq!(saved["consecutive_failures"], json!(1));
    assert_eq!(saved["backoff_seconds"], json!(30.0));
    assert_eq!(saved["failure_kind"], json!(REVOKED));
    assert_eq!(saved["notice_sent"], json!(false));
    assert!(saved.contains_key("last_error_at"));
    assert_eq!(
        store.check(GRANT, at(10)).unwrap(),
        Check::Parked { rejected: false }
    );
    assert_eq!(store.check(GRANT, at(31)).unwrap(), Check::Open);

    store.mark_notice_sent(&first.fingerprint).unwrap();
    let second = store.record_dead_grant(GRANT, REVOKED, at(40)).unwrap();
    assert!(!second.notice_due);
    let saved = state(&store);
    assert_eq!(saved["consecutive_failures"], json!(2));
    assert_eq!(saved["backoff_seconds"], json!(60.0));
    assert_eq!(saved["notice_sent"], json!(true));
}

#[test]
fn a_rejected_grant_owes_its_notice_only_after_a_second_rejection() {
    let (_home, store) = store();
    assert!(
        !store
            .record_dead_grant(GRANT, REJECTED, at(0))
            .unwrap()
            .notice_due
    );
    assert_eq!(
        store.check(GRANT, at(1)).unwrap(),
        Check::Parked { rejected: true }
    );
    assert!(
        store
            .record_dead_grant(GRANT, REJECTED, at(40))
            .unwrap()
            .notice_due
    );
}

#[test]
fn the_dead_grant_backoff_stops_at_the_maximum() {
    let (_home, store) = store();
    for step in 0..6 {
        store
            .record_dead_grant(GRANT, REVOKED, at(step * 400))
            .unwrap();
    }
    assert_eq!(state(&store)["backoff_seconds"], json!(300.0));
}

#[test]
fn the_first_backoff_never_exceeds_the_maximum() {
    let (home, _circuit) = store();
    let circuit = Circuit::new(home.path(), Backoff::new(500.0, 300.0));
    circuit.record_dead_grant(GRANT, REVOKED, at(0)).unwrap();
    assert_eq!(state(&circuit)["backoff_seconds"], json!(300.0));
}

#[test]
fn an_unreadable_state_is_an_error_not_an_open_circuit() {
    let (_home, store) = store();
    store.record_dead_grant(GRANT, REVOKED, at(0)).unwrap();
    store
        .connect()
        .unwrap()
        .execute(
            "UPDATE sync_state SET payload_json = 'not json' WHERE state_key = ?1",
            [STATE_KEY],
        )
        .unwrap();
    assert!(store.check(GRANT, at(1)).is_err());
    assert!(store.record_rate_limit(GRANT, 60, at(1)).is_err());
}

#[test]
fn a_stored_state_that_is_not_an_object_is_an_error() {
    let (_home, store) = store();
    store
        .connect()
        .unwrap()
        .execute(
            "INSERT INTO sync_state (state_key, payload_json, updated_at) VALUES (?1, '[]', 'x')",
            [STATE_KEY],
        )
        .unwrap();
    assert!(store.check(GRANT, at(0)).is_err());
}

#[test]
fn an_unreadable_salt_is_an_error_not_a_new_salt() {
    let (_home, store) = store();
    store
        .connect()
        .unwrap()
        .execute(
            "INSERT INTO sync_state (state_key, payload_json, updated_at) \
             VALUES (?1, '{\"salt\": \"%%%\"}', 'x')",
            [SALT_KEY],
        )
        .unwrap();
    assert!(store.record_dead_grant(GRANT, REVOKED, at(0)).is_err());
    let kept = read_payload(&store.connect().unwrap(), SALT_KEY).unwrap();
    assert_eq!(kept, Some(json!({"salt": "%%%"})));
}

#[test]
fn a_store_without_the_table_reads_as_open() {
    let home = tempfile::tempdir().unwrap();
    let circuit = Circuit::new(home.path(), Backoff::new(30.0, 300.0));
    assert_eq!(circuit.check(GRANT, at(0)), Ok(Check::Open));
}

#[test]
fn a_rate_limit_waits_out_retry_after_up_to_an_hour() {
    let (_home, store) = store();
    store.record_rate_limit(GRANT, 7200, at(0)).unwrap();
    assert_eq!(state(&store)["backoff_seconds"], json!(3600));
    assert_eq!(
        store.check(GRANT, at(100)).unwrap(),
        Check::RateLimited { wait_seconds: 3500 }
    );
    store.record_rate_limit(GRANT, 0, at(0)).unwrap();
    assert_eq!(state(&store)["backoff_seconds"], json!(1));
}

#[test]
fn a_rate_limit_keeps_the_dead_grant_record() {
    let (_home, store) = store();
    let dead = store.record_dead_grant(GRANT, REJECTED, at(0)).unwrap();
    store.mark_notice_sent(&dead.fingerprint).unwrap();
    store.record_rate_limit(GRANT, 120, at(1)).unwrap();
    let saved = state(&store);
    assert_eq!(saved["consecutive_failures"], json!(1));
    assert_eq!(saved["needs_reauthorization"], json!(true));
    assert_eq!(saved["failure_kind"], json!(REJECTED));
    assert_eq!(saved["notice_sent"], json!(true));
    assert_eq!(
        store.check(GRANT, at(60)).unwrap(),
        Check::Parked { rejected: true }
    );
}

#[test]
fn a_new_grant_clears_the_circuit() {
    let (_home, store) = store();
    store.record_dead_grant(GRANT, REVOKED, at(0)).unwrap();
    assert_eq!(store.check("another-grant", at(1)).unwrap(), Check::Open);
    assert!(state(&store).contains_key("cleared_at"));
    assert_eq!(store.check(GRANT, at(2)).unwrap(), Check::Open);
}

#[test]
fn clearing_writes_only_over_existing_state() {
    let (_home, store) = store();
    store.clear(at(0)).unwrap();
    assert!(read_payload(&store.connect().unwrap(), STATE_KEY)
        .unwrap()
        .is_none());
    store.record_rate_limit(GRANT, 60, at(0)).unwrap();
    store.clear(at(1)).unwrap();
    let saved = state(&store);
    assert_eq!(saved.len(), 1);
    assert!(saved.contains_key("cleared_at"));
}

#[test]
fn the_salt_persists_so_fingerprints_stay_stable() {
    let (_home, store) = store();
    let first = store
        .record_dead_grant(GRANT, REVOKED, at(0))
        .unwrap()
        .fingerprint;
    let second = store
        .record_dead_grant(GRANT, REVOKED, at(1))
        .unwrap()
        .fingerprint;
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
