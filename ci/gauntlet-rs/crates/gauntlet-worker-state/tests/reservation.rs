use gauntlet_contracts::WorkerRequest;
use gauntlet_worker_state::{ReservationError, RunReservationJournal};
use serde_json::json;
use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;

const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DEPLOYMENT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const GENERATION: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const JOB: &str = "dddddddddddddddd";

fn request(deployment: &str) -> WorkerRequest {
    let bytes = serde_json::to_vec(&json!({
        "schema": "hol-gauntlet-worker-request.v1",
        "action": "run",
        "source_sha": SOURCE,
        "job_id": JOB,
        "deployment_digest": deployment,
    }))
    .unwrap();
    WorkerRequest::parse(&bytes).unwrap()
}

#[test]
fn reservation_survives_restart_and_refuses_replay_or_changed_pins() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let journal = RunReservationJournal::open(&root).unwrap();
    let marker = journal
        .reserve(&request(DEPLOYMENT), SOURCE, DEPLOYMENT, GENERATION)
        .unwrap();
    assert_eq!(marker.job_id, JOB);
    assert_eq!(marker.sha256.len(), 64);
    let raw = fs::read(root.join(format!("{JOB}.started.json"))).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(value["schema"], "hol-gauntlet-worker-started.v1");
    assert_eq!(value["deployment_digest"], DEPLOYMENT);
    drop(journal);

    let restarted = RunReservationJournal::open(&root).unwrap();
    assert_eq!(
        restarted
            .started(JOB, SOURCE, DEPLOYMENT, GENERATION)
            .unwrap(),
        Some(marker)
    );
    assert_eq!(
        restarted.reserve(&request(DEPLOYMENT), SOURCE, DEPLOYMENT, GENERATION),
        Err(ReservationError::AlreadyStarted)
    );
    assert_eq!(
        restarted.started(JOB, SOURCE, &"e".repeat(64), GENERATION),
        Err(ReservationError::InvalidMarker)
    );
}

#[test]
fn mismatched_outside_deployment_consumes_no_job_id() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let journal = RunReservationJournal::open(&root).unwrap();
    assert_eq!(
        journal.reserve(&request(DEPLOYMENT), SOURCE, &"e".repeat(64), GENERATION),
        Err(ReservationError::WrongRequest)
    );
    assert_eq!(
        journal
            .started(JOB, SOURCE, DEPLOYMENT, GENERATION)
            .unwrap(),
        None
    );
}

#[test]
fn concurrent_reservations_have_exactly_one_winner() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let root = root.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let journal = RunReservationJournal::open(&root).unwrap();
                barrier.wait();
                journal.reserve(&request(DEPLOYMENT), SOURCE, DEPLOYMENT, GENERATION)
            })
        })
        .collect();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(ReservationError::AlreadyStarted))
            .count(),
        1
    );
}

#[cfg(unix)]
#[test]
fn symlink_or_terminal_receipt_never_authorizes_another_run() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let outside = temporary.path().join("outside.json");
    fs::write(&outside, b"unchanged").unwrap();
    symlink(&outside, root.join(format!("{JOB}.started.json"))).unwrap();
    let journal = RunReservationJournal::open(&root).unwrap();
    assert_eq!(
        journal.reserve(&request(DEPLOYMENT), SOURCE, DEPLOYMENT, GENERATION),
        Err(ReservationError::AlreadyStarted)
    );
    assert_eq!(fs::read(&outside).unwrap(), b"unchanged");

    let second = tempfile::tempdir().unwrap();
    let second_root = second.path().canonicalize().unwrap();
    fs::write(
        second_root.join(format!("{JOB}.terminal.json")),
        b"retained",
    )
    .unwrap();
    let journal = RunReservationJournal::open(&second_root).unwrap();
    assert_eq!(
        journal.reserve(&request(DEPLOYMENT), SOURCE, DEPLOYMENT, GENERATION),
        Err(ReservationError::AlreadyStarted)
    );
}

#[test]
fn orphan_running_report_terminal_or_key_sidecar_blocks_a_new_reservation() {
    for suffix in ["running", "report", "terminal", "controller-key"] {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        fs::write(root.join(format!("{JOB}.{suffix}.json")), b"incomplete").unwrap();
        let journal = RunReservationJournal::open(&root).unwrap();
        assert_eq!(
            journal.reserve(&request(DEPLOYMENT), SOURCE, DEPLOYMENT, GENERATION),
            Err(ReservationError::AlreadyStarted),
            "{suffix} must consume the job ID"
        );
    }
}

#[test]
fn corrupted_marker_is_unknown_evidence_and_cannot_be_replaced() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let journal = RunReservationJournal::open(&root).unwrap();
    journal
        .reserve(&request(DEPLOYMENT), SOURCE, DEPLOYMENT, GENERATION)
        .unwrap();
    fs::write(root.join(format!("{JOB}.started.json")), b"partial").unwrap();
    assert_eq!(
        journal.started(JOB, SOURCE, DEPLOYMENT, GENERATION),
        Err(ReservationError::InvalidMarker)
    );
    assert_eq!(
        journal.reserve(&request(DEPLOYMENT), SOURCE, DEPLOYMENT, GENERATION),
        Err(ReservationError::AlreadyStarted)
    );
}

#[test]
fn live_worker_open_refuses_untrusted_or_exposed_ancestors() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    assert!(matches!(
        RunReservationJournal::open_root_owned(&root),
        Err(ReservationError::UnsafeRoot)
    ));
}
