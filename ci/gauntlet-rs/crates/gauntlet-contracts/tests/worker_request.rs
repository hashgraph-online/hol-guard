//! Fixed request action and independent deployment-binding boundary.

use gauntlet_contracts::{WorkerAction, WorkerRequest};
use serde_json::{json, Value};

const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const JOB: &str = "0123456789abcdef";
const PIN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn request(action: &str) -> Value {
    let mut row = json!({
        "schema": "hol-gauntlet-worker-request.v1",
        "action": action,
        "source_sha": SHA,
        "job_id": JOB,
    });
    if action == "run" {
        row["deployment_digest"] = json!(PIN);
    }
    row
}

#[test]
fn only_four_fixed_actions_and_externally_bound_run_are_accepted() {
    for (name, action) in [
        ("inspect", WorkerAction::Inspect),
        ("progress", WorkerAction::Progress),
        ("reconcile", WorkerAction::Reconcile),
        ("run", WorkerAction::Run),
    ] {
        let raw = serde_json::to_vec(&request(name)).unwrap();
        let parsed = WorkerRequest::parse(&raw).unwrap();
        assert_eq!(parsed.action(), action);
        assert_eq!(parsed.source_sha(), SHA);
        assert_eq!(parsed.job_id(), JOB);
        assert_eq!(parsed.to_json(), request(name));
        assert_eq!(
            parsed.matches_deployment(SHA, PIN),
            action == WorkerAction::Run
        );
        assert!(!parsed.matches_deployment(SHA, &"c".repeat(64)));
    }
}

#[test]
fn command_path_profile_replay_fields_and_ambiguous_json_are_rejected() {
    for field in ["command", "path", "profile", "argv", "workdir", "retry"] {
        let mut row = request("run");
        row[field] = json!("/bin/sh");
        assert!(
            WorkerRequest::parse(&serde_json::to_vec(&row).unwrap()).is_err(),
            "{field}"
        );
    }
    let mut row = request("inspect");
    row["deployment_digest"] = json!(PIN);
    assert!(WorkerRequest::parse(&serde_json::to_vec(&row).unwrap()).is_err());
    let mut row = request("run");
    row["deployment_digest"] = Value::Null;
    assert!(WorkerRequest::parse(&serde_json::to_vec(&row).unwrap()).is_err());
    let mut row = request("run");
    row["job_id"] = json!("NOT-A-JOB");
    assert!(WorkerRequest::parse(&serde_json::to_vec(&row).unwrap()).is_err());
    let mut row = request("run");
    row["source_sha"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert!(WorkerRequest::parse(&serde_json::to_vec(&row).unwrap()).is_err());
    let duplicate = format!("{{\"schema\":\"hol-gauntlet-worker-request.v1\",\"action\":\"run\",\"action\":\"inspect\",\"source_sha\":\"{SHA}\",\"job_id\":\"{JOB}\",\"deployment_digest\":\"{PIN}\"}}");
    assert!(WorkerRequest::parse(duplicate.as_bytes()).is_err());
    assert!(WorkerRequest::parse(&vec![b' '; 1025]).is_err());
}
