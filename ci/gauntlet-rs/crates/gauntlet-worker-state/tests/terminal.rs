use gauntlet_contracts::WorkerRequest;
use gauntlet_worker_state::{
    ProcessIdentity, ReservationError, RunReservationJournal, TerminalOutcome,
};
use serde_json::json;
use std::fs;

const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DEPLOYMENT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const GENERATION: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const JOB: &str = "dddddddddddddddd";
const REPORT: &[u8] = br#"{"controls":{"passed":true},"schema":"test-report.v1"}"#;
const PROCESS: ProcessIdentity = ProcessIdentity {
    pid: 5432,
    start_ticks: 1234567,
};

fn request() -> WorkerRequest {
    let raw = serde_json::to_vec(&json!({
        "schema": "hol-gauntlet-worker-request.v1",
        "action": "run",
        "source_sha": SOURCE,
        "job_id": JOB,
        "deployment_digest": DEPLOYMENT,
    }))
    .unwrap();
    WorkerRequest::parse(&raw).unwrap()
}

#[test]
fn terminal_report_is_durable_bound_and_reconciled_after_restart() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let journal = RunReservationJournal::open(&root).unwrap();
    let started = journal
        .reserve(&request(), SOURCE, DEPLOYMENT, GENERATION)
        .unwrap();
    let terminal = journal
        .finish(
            &request(),
            SOURCE,
            DEPLOYMENT,
            GENERATION,
            &started.sha256,
            REPORT,
            PROCESS,
            0,
            TerminalOutcome::Passed,
        )
        .unwrap();
    assert_eq!(terminal.started_marker_sha256, started.sha256);
    assert_eq!(terminal.process, PROCESS);
    assert_eq!(terminal.sha256.len(), 64);
    assert_eq!(
        fs::read(root.join(format!("{JOB}.report.json"))).unwrap(),
        REPORT
    );
    drop(journal);

    let restarted = RunReservationJournal::open(&root).unwrap();
    assert_eq!(
        restarted.terminal(JOB, SOURCE, DEPLOYMENT, GENERATION),
        Ok(Some(terminal))
    );
    assert_eq!(
        restarted.reserve(&request(), SOURCE, DEPLOYMENT, GENERATION),
        Err(ReservationError::AlreadyStarted)
    );
    assert_eq!(
        restarted.terminal(JOB, SOURCE, &"e".repeat(64), GENERATION),
        Err(ReservationError::InvalidMarker)
    );
}

#[test]
fn terminal_rejects_wrong_marker_or_impossible_success_before_writing() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let journal = RunReservationJournal::open(&root).unwrap();
    let started = journal
        .reserve(&request(), SOURCE, DEPLOYMENT, GENERATION)
        .unwrap();
    let finish = |marker: &str, code, status| {
        journal.finish(
            &request(),
            SOURCE,
            DEPLOYMENT,
            GENERATION,
            marker,
            REPORT,
            PROCESS,
            code,
            status,
        )
    };
    assert_eq!(
        finish(&"f".repeat(64), 0, TerminalOutcome::Passed),
        Err(ReservationError::InvalidMarker)
    );
    assert_eq!(
        finish(&started.sha256, 1, TerminalOutcome::Passed),
        Err(ReservationError::InvalidMarker)
    );
    assert_eq!(
        journal.terminal(JOB, SOURCE, DEPLOYMENT, GENERATION),
        Ok(None)
    );
    assert!(!root.join(format!("{JOB}.report.json")).exists());
}

#[test]
fn report_only_or_corrupt_report_is_unknown_and_blocks_replacement() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let journal = RunReservationJournal::open(&root).unwrap();
    let started = journal
        .reserve(&request(), SOURCE, DEPLOYMENT, GENERATION)
        .unwrap();
    fs::write(root.join(format!("{JOB}.report.json")), REPORT).unwrap();
    assert_eq!(
        journal.terminal(JOB, SOURCE, DEPLOYMENT, GENERATION),
        Err(ReservationError::InvalidMarker)
    );
    assert_eq!(
        journal.finish(
            &request(),
            SOURCE,
            DEPLOYMENT,
            GENERATION,
            &started.sha256,
            REPORT,
            PROCESS,
            2,
            TerminalOutcome::Failed,
        ),
        Err(ReservationError::AlreadyStarted)
    );

    let second = tempfile::tempdir().unwrap();
    let second_root = second.path().canonicalize().unwrap();
    let second_journal = RunReservationJournal::open(&second_root).unwrap();
    let second_started = second_journal
        .reserve(&request(), SOURCE, DEPLOYMENT, GENERATION)
        .unwrap();
    second_journal
        .finish(
            &request(),
            SOURCE,
            DEPLOYMENT,
            GENERATION,
            &second_started.sha256,
            REPORT,
            PROCESS,
            2,
            TerminalOutcome::Failed,
        )
        .unwrap();
    fs::write(second_root.join(format!("{JOB}.report.json")), b"{}").unwrap();
    assert_eq!(
        second_journal.terminal(JOB, SOURCE, DEPLOYMENT, GENERATION),
        Err(ReservationError::InvalidMarker)
    );
}

#[cfg(unix)]
#[test]
fn symlinked_terminal_or_report_cannot_be_accepted() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let outside = temporary.path().join("outside.json");
    fs::write(&outside, b"unchanged").unwrap();
    let journal = RunReservationJournal::open(&root).unwrap();
    let started = journal
        .reserve(&request(), SOURCE, DEPLOYMENT, GENERATION)
        .unwrap();
    symlink(&outside, root.join(format!("{JOB}.report.json"))).unwrap();
    assert_eq!(
        journal.finish(
            &request(),
            SOURCE,
            DEPLOYMENT,
            GENERATION,
            &started.sha256,
            REPORT,
            PROCESS,
            0,
            TerminalOutcome::Passed,
        ),
        Err(ReservationError::AlreadyStarted)
    );
    assert_eq!(fs::read(outside).unwrap(), b"unchanged");
    assert!(journal
        .terminal(JOB, SOURCE, DEPLOYMENT, GENERATION)
        .is_err());
}
