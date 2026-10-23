use gauntlet_contracts::{WorkerRequest, WorkerResponse, WorkerState};
use gauntlet_worker_state::{
    ProcessIdentity, ReservationError, RunReservationJournal, TerminalOutcome,
};
use serde_json::{json, Value};
use std::fs;

const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DEPLOYMENT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const GENERATION: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const JOB: &str = "dddddddddddddddd";

fn request(action: &str) -> WorkerRequest {
    let mut value = json!({
        "schema": "hol-gauntlet-worker-request.v1",
        "action": action,
        "source_sha": SOURCE,
        "job_id": JOB,
    });
    if action == "run" {
        value["deployment_digest"] = json!(DEPLOYMENT);
    }
    WorkerRequest::parse(&serde_json::to_vec(&value).unwrap()).unwrap()
}

fn projected(journal: &RunReservationJournal, action: &str) -> (Value, WorkerResponse) {
    let request = request(action);
    let raw = journal
        .project_read_only(&request, SOURCE, Some(DEPLOYMENT), GENERATION)
        .unwrap();
    let response = WorkerResponse::parse(&raw).unwrap();
    response
        .bind_request(&request, GENERATION, Some(DEPLOYMENT))
        .unwrap();
    (serde_json::from_slice(&raw).unwrap(), response)
}

#[test]
fn passive_projection_never_infers_a_running_job_or_launches_run() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let journal = RunReservationJournal::open(&root).unwrap();
    assert_eq!(
        projected(&journal, "inspect").1.state(),
        WorkerState::Unavailable
    );
    assert_eq!(
        projected(&journal, "run").1.state(),
        WorkerState::Unavailable
    );
    assert_eq!(
        projected(&journal, "progress").1.state(),
        WorkerState::NotStarted
    );
    assert_eq!(
        projected(&journal, "reconcile").1.state(),
        WorkerState::Unknown
    );

    journal
        .reserve(&request("run"), SOURCE, DEPLOYMENT, GENERATION)
        .unwrap();
    assert_eq!(projected(&journal, "run").1.state(), WorkerState::Unknown);
    assert_eq!(
        projected(&journal, "progress").1.state(),
        WorkerState::Unknown
    );
    assert_eq!(
        projected(&journal, "reconcile").1.state(),
        WorkerState::Unknown
    );
}

#[test]
fn verified_terminal_projects_exact_report_and_marker_hashes() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let journal = RunReservationJournal::open(&root).unwrap();
    let started = journal
        .reserve(&request("run"), SOURCE, DEPLOYMENT, GENERATION)
        .unwrap();
    let receipt = journal
        .finish(
            &request("run"),
            SOURCE,
            DEPLOYMENT,
            GENERATION,
            &started.sha256,
            br#"{"schema":"synthetic.v1"}"#,
            ProcessIdentity {
                pid: 5432,
                start_ticks: 9876,
            },
            0,
            TerminalOutcome::Passed,
        )
        .unwrap();
    for action in ["progress", "reconcile", "run"] {
        let (value, parsed) = projected(&journal, action);
        assert_eq!(parsed.state(), WorkerState::Terminal);
        assert_eq!(value["report_sha256"], receipt.report_sha256);
        assert_eq!(
            value["started_marker_sha256"],
            receipt.started_marker_sha256
        );
        assert_eq!(value["status"], "passed");
    }

    fs::write(root.join(format!("{JOB}.report.json")), b"{}").unwrap();
    assert_eq!(
        projected(&journal, "reconcile").1.state(),
        WorkerState::Unknown
    );
}

#[test]
fn independent_pins_are_required_before_any_state_projection() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let journal = RunReservationJournal::open(&root).unwrap();
    assert_eq!(
        journal.project_read_only(&request("run"), SOURCE, Some(&"e".repeat(64)), GENERATION),
        Err(ReservationError::WrongRequest)
    );
    assert_eq!(
        journal.project_read_only(
            &request("progress"),
            &"f".repeat(40),
            Some(DEPLOYMENT),
            GENERATION
        ),
        Err(ReservationError::InvalidPins)
    );
    let raw = journal
        .project_read_only(&request("progress"), SOURCE, None, GENERATION)
        .unwrap();
    assert_eq!(
        WorkerResponse::parse(&raw).unwrap().state(),
        WorkerState::Unavailable
    );
}
