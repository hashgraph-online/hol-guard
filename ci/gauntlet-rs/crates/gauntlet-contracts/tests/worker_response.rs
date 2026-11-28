//! Negative controls for the future VM worker's bounded response boundary.

use gauntlet_contracts::{WorkerRequest, WorkerResponse, WorkerState};
use serde_json::{json, Value};

const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const JOB: &str = "0123456789abcdef";
const GENERATION: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DEPLOYMENT: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const STARTED: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const REPORT: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

fn request(action: &str) -> WorkerRequest {
    let mut value = json!({
        "schema": "hol-gauntlet-worker-request.v1",
        "action": action,
        "source_sha": SHA,
        "job_id": JOB,
    });
    if action == "run" {
        value["deployment_digest"] = json!(DEPLOYMENT);
    }
    WorkerRequest::parse(&serde_json::to_vec(&value).unwrap()).unwrap()
}

fn response(action: &str, state: &str) -> Value {
    let mut value = json!({
        "schema": "hol-gauntlet-worker-response.v1",
        "action": action,
        "source_sha": SHA,
        "job_id": JOB,
        "worker_generation": GENERATION,
        "state": state,
    });
    if matches!(state, "staged" | "running" | "terminal") {
        value["deployment_digest"] = json!(DEPLOYMENT);
    }
    if matches!(state, "running" | "terminal") {
        value["started_marker_sha256"] = json!(STARTED);
    }
    if state == "running" {
        value["pid"] = json!(1234);
        value["process_start_ticks"] = json!(5678);
    }
    if state == "terminal" {
        value["report_sha256"] = json!(REPORT);
        value["exit_code"] = json!(0);
        value["status"] = json!("passed");
    }
    value
}

fn parse(value: &Value) -> Result<WorkerResponse, gauntlet_contracts::WorkerResponseError> {
    WorkerResponse::parse(&serde_json::to_vec(value).unwrap())
}

#[test]
fn fixed_states_bind_to_external_source_worker_and_deployment() {
    for (action, state, expected_state, needs_deployment) in [
        ("inspect", "staged", WorkerState::Staged, true),
        ("inspect", "unavailable", WorkerState::Unavailable, false),
        ("progress", "not-started", WorkerState::NotStarted, false),
        ("progress", "running", WorkerState::Running, true),
        ("reconcile", "unknown", WorkerState::Unknown, false),
        ("reconcile", "terminal", WorkerState::Terminal, true),
        ("run", "terminal", WorkerState::Terminal, true),
    ] {
        let parsed = parse(&response(action, state)).unwrap();
        assert_eq!(parsed.state(), expected_state);
        assert_eq!(
            parsed.report_sha256(),
            (state == "terminal").then_some(REPORT)
        );
        assert_eq!(
            parsed.started_marker_sha256(),
            matches!(state, "running" | "terminal").then_some(STARTED)
        );
        assert_eq!(
            parsed.process_identity(),
            (state == "running").then_some((1234, 5678))
        );
        assert_eq!(
            parsed.terminal_outcome(),
            (state == "terminal").then_some((0, "passed"))
        );
        let pin = needs_deployment.then_some(DEPLOYMENT);
        assert_eq!(parsed.deployment_digest(), pin);
        parsed
            .bind_request(
                &request(action),
                GENERATION,
                pin.or((action == "run").then_some(DEPLOYMENT)),
            )
            .unwrap();
        assert!(parsed
            .bind_request(&request(action), &"f".repeat(64), pin)
            .is_err());
        if needs_deployment || action == "run" {
            assert!(parsed
                .bind_request(&request(action), GENERATION, Some(&"f".repeat(64)))
                .is_err());
        }
    }
}

#[test]
fn missing_receipt_is_unknown_and_never_a_terminal_success() {
    let parsed = parse(&response("reconcile", "unknown")).unwrap();
    assert_eq!(parsed.state(), WorkerState::Unknown);
    assert_eq!(parsed.report_sha256(), None);
    assert_eq!(parsed.deployment_digest(), None);
}

#[test]
fn forged_fields_process_identity_and_status_are_refused() {
    let mut value = response("run", "terminal");
    value["command"] = json!("/bin/sh");
    assert!(parse(&value).is_err());
    let mut value = response("reconcile", "terminal");
    value["exit_code"] = json!(1);
    assert!(parse(&value).is_err());
    let mut value = response("progress", "running");
    value["process_start_ticks"] = json!(0);
    assert!(parse(&value).is_err());
    let mut value = response("progress", "running");
    value["pid"] = json!(true);
    assert!(parse(&value).is_err());
    let mut value = response("progress", "running");
    value["started_marker_sha256"] = json!("bad");
    assert!(parse(&value).is_err());
    let value = response("inspect", "terminal");
    assert!(parse(&value).is_err());
    let value = response("reconcile", "not-started");
    assert!(parse(&value).is_err());
    let duplicate = format!("{{\"schema\":\"hol-gauntlet-worker-response.v1\",\"action\":\"reconcile\",\"state\":\"unknown\",\"state\":\"terminal\",\"source_sha\":\"{SHA}\",\"job_id\":\"{JOB}\",\"worker_generation\":\"{GENERATION}\"}}");
    assert!(WorkerResponse::parse(duplicate.as_bytes()).is_err());
    assert!(WorkerResponse::parse(&vec![b' '; 2049]).is_err());
}

#[test]
fn same_shape_from_another_job_or_action_cannot_bind() {
    let parsed = parse(&response("reconcile", "terminal")).unwrap();
    assert!(parsed
        .bind_request(&request("progress"), GENERATION, Some(DEPLOYMENT))
        .is_err());
    let mut value = response("reconcile", "terminal");
    value["job_id"] = json!("fedcba9876543210");
    assert!(parse(&value)
        .unwrap()
        .bind_request(&request("reconcile"), GENERATION, Some(DEPLOYMENT))
        .is_err());
    assert!(parsed
        .bind_request(&request("reconcile"), GENERATION, None)
        .is_err());
}
