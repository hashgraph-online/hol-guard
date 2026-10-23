use super::*;
use crate::controller_key::write_pin;
use gauntlet_contracts::WorkerRequest;
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
    WorkerRequest::parse(
        &serde_json::to_vec(&json!({
            "schema": "hol-gauntlet-worker-request.v1",
            "action": "run",
            "source_sha": SOURCE,
            "job_id": JOB,
            "deployment_digest": DEPLOYMENT,
        }))
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn keyed_terminal_requires_the_exact_sidecar_and_survives_restart() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let journal = RunReservationJournal::open(&root).unwrap();
    let public = "d".repeat(64);
    let started = journal
        .reserve_internal(&request(), SOURCE, DEPLOYMENT, GENERATION, Some(&public))
        .unwrap();
    let pin = write_pin(&journal, &started, &public, false).unwrap();
    let finish = |expected: Option<&str>| {
        journal.finish_internal(
            &request(),
            SOURCE,
            DEPLOYMENT,
            GENERATION,
            &started.sha256,
            REPORT,
            PROCESS,
            0,
            TerminalOutcome::Passed,
            expected,
        )
    };
    assert!(matches!(finish(None), Err(ReservationError::InvalidPins)));
    assert!(matches!(
        finish(Some(&"e".repeat(64))),
        Err(ReservationError::InvalidMarker)
    ));
    assert!(!root.join(format!("{JOB}.report.json")).exists());

    let terminal = finish(Some(&pin.raw_sha256)).unwrap();
    assert_eq!(
        terminal.controller_public_key_hex.as_deref(),
        Some(public.as_str())
    );
    assert_eq!(
        terminal.controller_key_pin_sha256.as_deref(),
        Some(pin.raw_sha256.as_str())
    );
    let raw = fs::read(root.join(format!("{JOB}.terminal.json"))).unwrap();
    let value: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(value["schema"], TERMINAL_SCHEMA_V2);
    assert_eq!(value["started_marker_sha256"], started.sha256);
    assert_eq!(value["controller_key_pin_sha256"], pin.raw_sha256);
    drop(journal);

    let restarted = RunReservationJournal::open(&root).unwrap();
    assert_eq!(
        restarted.terminal(JOB, SOURCE, DEPLOYMENT, GENERATION),
        Ok(Some(terminal))
    );
    let projected = restarted
        .project_read_only(&request(), SOURCE, Some(DEPLOYMENT), GENERATION)
        .unwrap();
    let wire: Value = serde_json::from_slice(&projected).unwrap();
    assert_eq!(wire["state"], "unknown");
    assert!(wire.get("status").is_none());
    let path = root.join(format!("{JOB}.controller-key.json"));
    let substituted = String::from_utf8(fs::read(&path).unwrap())
        .unwrap()
        .replace(&public, &"e".repeat(64));
    fs::write(&path, substituted).unwrap();
    assert_eq!(
        restarted.terminal(JOB, SOURCE, DEPLOYMENT, GENERATION),
        Err(ReservationError::InvalidMarker)
    );
}

#[test]
fn legacy_terminal_refuses_a_retroactive_key_sidecar() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let journal = RunReservationJournal::open(&root).unwrap();
    let started = journal
        .reserve(&request(), SOURCE, DEPLOYMENT, GENERATION)
        .unwrap();
    journal
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
    fs::write(root.join(format!("{JOB}.controller-key.json")), b"{}").unwrap();
    assert_eq!(
        journal.terminal(JOB, SOURCE, DEPLOYMENT, GENERATION),
        Err(ReservationError::InvalidMarker)
    );
}
