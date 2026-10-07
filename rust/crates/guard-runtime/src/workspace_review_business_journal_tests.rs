use super::super::super::tests::Fixture;
use super::*;

fn status(fixture: &Fixture, request_id: &str) -> serde_json::Value {
    let bytes = read(
        &fixture
            .root
            .join(DIRECTORY)
            .join(format!("{request_id}.json")),
        &fixture.root,
    )
    .unwrap()
    .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn retained_progress_cannot_recreate_an_attempt_and_records_no_provider_body() {
    let fixture = Fixture::new("business-journal-outcome");
    let journal = Journal::claimed(&fixture.store, "business-journal", &"a".repeat(64)).unwrap();
    assert_eq!(status(&fixture, "business-journal")["status"], "claimed");
    let journal = journal.start(&fixture.store).unwrap();
    assert_eq!(
        status(&fixture, "business-journal")["status"],
        "attempt_started"
    );
    journal
        .finish(&fixture.store, Some("b".repeat(64)))
        .unwrap();
    let value = status(&fixture, "business-journal");
    assert_eq!(value["status"], "api_accepted");
    assert_eq!(value["acknowledgement_binding"], "b".repeat(64));
    assert!(Journal::claimed(&fixture.store, "business-journal", &"a".repeat(64)).is_err());
    assert_eq!(value.as_object().unwrap().len(), 6);
}

#[test]
fn dropped_started_attempt_stays_uncertain_and_refuses_recreation() {
    let fixture = Fixture::new("business-journal-restart");
    let journal = Journal::claimed(&fixture.store, "business-crash", &"a".repeat(64)).unwrap();
    drop(journal.start(&fixture.store).unwrap());
    // Durable attempt_started means the outcome is unknown; there is no reload
    // API returning a Journal handle and no automatic resend transition.
    assert_eq!(
        status(&fixture, "business-crash")["status"],
        "attempt_started"
    );
    assert!(Journal::claimed(&fixture.store, "business-crash", &"a".repeat(64)).is_err());
    Journal::claimed(&fixture.store, "business-timeout", &"a".repeat(64))
        .unwrap()
        .start(&fixture.store)
        .unwrap()
        .finish(&fixture.store, None)
        .unwrap();
    assert_eq!(
        status(&fixture, "business-timeout")["status"],
        "unconfirmed"
    );
}

#[test]
fn changed_record_invalid_ack_and_wrong_store_refuse_transitions() {
    let fixture = Fixture::new("business-journal-changed");
    let journal = Journal::claimed(&fixture.store, "business-changed", &"a".repeat(64)).unwrap();
    super::super::super::tests::write(
        &fixture.root,
        &journal.path,
        &serde_json::json!({"changed":true}),
    );
    assert!(journal.start(&fixture.store).is_err());
    // Corrupt retained evidence intentionally refuses new claims in that
    // store. Exercise independent invalid-ack cases in an intact store.
    let fixture = Fixture::new("business-journal-invalid-ack");
    let journal = Journal::claimed(&fixture.store, "business-ack", &"a".repeat(64))
        .unwrap()
        .start(&fixture.store)
        .unwrap();
    assert!(journal
        .finish(&fixture.store, Some("raw-provider-id".into()))
        .is_err());
    assert_eq!(
        status(&fixture, "business-ack")["status"],
        "attempt_started"
    );
    let other = Fixture::new("business-journal-other");
    let journal = Journal::claimed(&fixture.store, "business-store", &"a".repeat(64)).unwrap();
    assert!(journal.start(&other.store).is_err());
    assert!(Journal::claimed(&fixture.store, "../escape", &"a".repeat(64)).is_err());
    assert!(Journal::claimed(&fixture.store, "business-invalid", "not-a-digest").is_err());
}

#[test]
fn concurrent_claim_journals_cannot_replace_one_another() {
    let fixture = Fixture::new("business-journal-concurrent");
    let barrier = std::sync::Barrier::new(2);
    let wins = std::thread::scope(|scope| {
        let run = || {
            barrier.wait();
            Journal::claimed(&fixture.store, "business-race", &"a".repeat(64)).is_ok()
        };
        let left = scope.spawn(run);
        let right = scope.spawn(run);
        usize::from(left.join().unwrap()) + usize::from(right.join().unwrap())
    });
    assert_eq!(wins, 1);
    assert_eq!(status(&fixture, "business-race")["status"], "claimed");
}

#[test]
fn capacity_and_failed_persistence_refuse_without_returning_a_handle() {
    let fixture = Fixture::new("business-journal-capacity");
    let directory = fixture.root.join(DIRECTORY);
    crate::resident_state::ensure_private_directory(&directory, true).unwrap();
    for index in 0..CAPACITY {
        Journal::claimed(
            &fixture.store,
            &format!("retained-{index}"),
            &"a".repeat(64),
        )
        .unwrap();
    }
    assert!(Journal::claimed(&fixture.store, "business-full", &"a".repeat(64)).is_err());
    assert!(!directory.join("business-full.json").exists());
    let other = Fixture::new("business-journal-persistence-refusal");
    let directory = other.root.join(DIRECTORY);
    crate::resident_state::ensure_private_directory(&directory, true).unwrap();
    // A directory where a private file is required must not be overwritten.
    crate::resident_state::ensure_private_directory(&directory.join("business-invalid.json"), true)
        .unwrap();
    assert!(Journal::claimed(&other.store, "business-invalid", &"a".repeat(64)).is_err());
    assert!(directory.join("business-invalid.json").is_dir());
}

#[test]
fn crash_temporary_does_not_consume_the_last_retained_slot() {
    let fixture = Fixture::new("business-journal-temp-capacity");
    for index in 0..CAPACITY - 1 {
        Journal::claimed(
            &fixture.store,
            &format!("retained-{index}"),
            &"a".repeat(64),
        )
        .unwrap();
    }
    let path = fixture
        .root
        .join(DIRECTORY)
        .join(".retained-0.json.123.987654.tmp");
    persist(&path, &fixture.root, b"{}").unwrap();
    Journal::claimed(&fixture.store, "business-last", &"a".repeat(64)).unwrap();
    assert!(path.exists());
    assert!(Journal::claimed(&fixture.store, "business-full", &"a".repeat(64)).is_err());
    assert!(!persistence_temporary(".unrecognized.tmp"));
    assert!(!persistence_temporary(".business-id.json.pid.123.tmp"));
}
