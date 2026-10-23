use gauntlet_contracts::{canonicalize, WorkerState};
use gauntlet_host_state::{VmRustShadowError, VmRustShadowPlan};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;

const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const JOB: &str = "0123456789abcdef";
const DEPLOYMENT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const GENERATION: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const BINARY: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

fn operations() -> Value {
    serde_json::from_str(include_str!("../operations-defaults-v1.json")).unwrap()
}

fn plan() -> VmRustShadowPlan {
    VmRustShadowPlan::new(&operations(), SOURCE, JOB, DEPLOYMENT, GENERATION, BINARY).unwrap()
}

fn response() -> Vec<u8> {
    let value = json!({
        "schema":"hol-gauntlet-worker-response.v1",
        "action":"progress",
        "source_sha":SOURCE,
        "job_id":JOB,
        "worker_generation":GENERATION,
        "state":"not-started",
    });
    let mut bytes = canonicalize(value.to_string().as_bytes()).unwrap();
    bytes.push(b'\n');
    bytes
}

#[test]
fn fixed_plan_is_only_a_read_only_progress_probe() {
    let plan = plan();
    assert_eq!(plan.argv[0], operations()["limactl"]);
    assert_eq!(
        plan.argv[1..6],
        [
            "shell",
            "hol-beta-bootstrap-20261016-004",
            "--",
            "sudo",
            "-n"
        ]
    );
    assert_eq!(
        plan.argv[6],
        format!("/opt/hol-gauntlet/rust-worker-shadow-{BINARY}")
    );
    assert_eq!(plan.argv[7..], [SOURCE, DEPLOYMENT, GENERATION]);
    assert_eq!(plan.request["action"], "progress");
    assert!(plan.request.get("deployment_digest").is_none());
    assert_eq!(plan.to_json()["binary_pin_verified"], false);
    assert_eq!(plan.to_json()["execution_eligible"], false);
    assert_eq!(
        plan.parse_response(&response()).unwrap().state(),
        WorkerState::NotStarted
    );
}

#[test]
fn shadow_refuses_other_identity_noncanonical_or_extra_output() {
    let plan = plan();
    let mut wrong: Value = serde_json::from_slice(&response()).unwrap();
    wrong["worker_generation"] = json!("1".repeat(64));
    let mut wrong_bytes = canonicalize(wrong.to_string().as_bytes()).unwrap();
    wrong_bytes.push(b'\n');
    assert_eq!(
        plan.parse_response(&wrong_bytes),
        Err(VmRustShadowError::InvalidResponse)
    );
    let mut extra = response();
    extra.extend_from_slice(b"{}\n");
    assert_eq!(
        plan.parse_response(&extra),
        Err(VmRustShadowError::InvalidResponse)
    );
    assert_eq!(
        plan.parse_response(b"{\"state\":\"not-started\"}\n"),
        Err(VmRustShadowError::InvalidResponse)
    );
    assert_eq!(
        plan.parse_response(&vec![b'x'; 2050]),
        Err(VmRustShadowError::TooLarge)
    );
    assert_eq!(
        VmRustShadowPlan::new(
            &operations(),
            SOURCE,
            JOB,
            DEPLOYMENT,
            GENERATION,
            "../evil"
        ),
        Err(VmRustShadowError::InvalidPins)
    );
}

#[test]
fn fake_lima_receives_fixed_request_and_failure_stays_unavailable() {
    let temporary = tempfile::tempdir().unwrap();
    let fake = temporary.path().join("fake-limactl");
    let received = temporary.path().join("received.json");
    let output = String::from_utf8(response()).unwrap();
    fs::write(
        &fake,
        format!(
            "#!/bin/sh\nIFS= read -r request\nprintf '%s' \"$request\" > '{}'\nprintf '%s' '{}'\n",
            received.display(),
            output.trim_end()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
    let mut config = operations();
    config["limactl"] = json!(fake.to_str().unwrap());
    let plan = VmRustShadowPlan::new(&config, SOURCE, JOB, DEPLOYMENT, GENERATION, BINARY).unwrap();
    assert_eq!(
        plan.execute_read_only(),
        Err(VmRustShadowError::InvalidResponse)
    );
    // A response without the required final newline must refuse, even when
    // its JSON contents look correct.
    let sent: Value = serde_json::from_slice(&fs::read(&received).unwrap()).unwrap();
    assert_eq!(sent, plan.request);
    fs::write(
        &fake,
        format!(
            "#!/bin/sh\nIFS= read -r request\nprintf '%s\\n' '{}'\n",
            output.trim_end()
        ),
    )
    .unwrap();
    assert_eq!(
        plan.execute_read_only().unwrap().state(),
        WorkerState::NotStarted
    );
    fs::write(&fake, b"#!/bin/sh\nexit 7\n").unwrap();
    assert_eq!(
        plan.execute_read_only(),
        Err(VmRustShadowError::Unavailable)
    );
}
