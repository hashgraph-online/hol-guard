use gauntlet_contracts::WorkerRequest;
use gauntlet_worker_state::{
    fixed_launch_plan, fixed_rust_job_launch_plan, ReservationError, RunLaunchPins,
};
use serde_json::{json, Value};

fn run(source: &str, job: &str, deployment: &str) -> WorkerRequest {
    WorkerRequest::parse(
        &serde_json::to_vec(&json!({
            "schema":"hol-gauntlet-worker-request.v1",
            "action":"run",
            "source_sha":source,
            "job_id":job,
            "deployment_digest":deployment,
        }))
        .unwrap(),
    )
    .unwrap()
}

fn pins(row: &Value) -> RunLaunchPins {
    RunLaunchPins {
        source_sha: row["source_sha"].as_str().unwrap().to_owned(),
        deployment_digest: row["deployment_digest"].as_str().unwrap().to_owned(),
        config_digest: row["config_digest"].as_str().unwrap().to_owned(),
        controller_path: row["controller_path"].as_str().unwrap().to_owned(),
        python_path: row["python_path"].as_str().unwrap().to_owned(),
        interpreter_sha256: "e".repeat(64),
    }
}

#[test]
fn launch_vector_matches_two_pinned_python_worker_cases() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_worker_launch_v1.json")).unwrap();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    let source = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "ci/gauntlet/control_plane/vm_worker.py")
        .unwrap();
    assert_eq!(fixture["source_sha256"], source["sha256"]);
    assert_eq!(fixture["schema"], "gauntlet-worker-launch-fixtures.v1");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    for row in cases {
        let external = pins(row);
        let request = run(
            row["source_sha"].as_str().unwrap(),
            row["job_id"].as_str().unwrap(),
            row["deployment_digest"].as_str().unwrap(),
        );
        let actual = fixed_launch_plan(&request, &external, &"e".repeat(64))
            .unwrap()
            .to_json();
        for name in ["argv", "cwd", "env", "state_root", "output_dir", "log_path"] {
            assert_eq!(actual[name], row[name], "{name} in {row}");
        }
        assert_eq!(actual["execution_eligible"], false);
    }
}

#[test]
fn plan_refuses_wrong_deployment_interpreter_and_path_selectors() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_worker_launch_v1.json")).unwrap();
    let row = &fixture["cases"][0];
    let request = run(
        row["source_sha"].as_str().unwrap(),
        row["job_id"].as_str().unwrap(),
        row["deployment_digest"].as_str().unwrap(),
    );
    let external = pins(row);
    assert_eq!(
        fixed_launch_plan(&request, &external, &"0".repeat(64)),
        Err(ReservationError::InvalidPins)
    );
    let wrong_deployment = run(
        row["source_sha"].as_str().unwrap(),
        row["job_id"].as_str().unwrap(),
        &"0".repeat(64),
    );
    assert_eq!(
        fixed_launch_plan(&wrong_deployment, &external, &"e".repeat(64)),
        Err(ReservationError::WrongRequest)
    );
    let mut unsafe_controller = external.clone();
    unsafe_controller.controller_path = "/tmp/attacker".to_owned();
    assert_eq!(
        fixed_launch_plan(&request, &unsafe_controller, &"e".repeat(64)),
        Err(ReservationError::InvalidPins)
    );
    let mut unsafe_python = external;
    unsafe_python.python_path = "/tmp/attacker/python".to_owned();
    assert_eq!(
        fixed_launch_plan(&request, &unsafe_python, &"e".repeat(64)),
        Err(ReservationError::InvalidPins)
    );
    assert!(WorkerRequest::parse(
        &serde_json::to_vec(&json!({
            "schema":"hol-gauntlet-worker-request.v1",
            "action":"run",
            "source_sha":row["source_sha"],
            "job_id":row["job_id"],
            "deployment_digest":row["deployment_digest"],
            "command":"/bin/sh",
        }))
        .unwrap()
    )
    .is_err());
}

#[test]
fn rust_job_slice_is_derived_from_the_parsed_request_only() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_worker_launch_v1.json")).unwrap();
    let row = &fixture["cases"][0];
    let source = row["source_sha"].as_str().unwrap();
    let deployment = row["deployment_digest"].as_str().unwrap();
    let job_id = row["job_id"].as_str().unwrap();
    let request = run(source, job_id, deployment);
    let plan = fixed_rust_job_launch_plan(&request, &pins(row), &"e".repeat(64)).unwrap();
    assert_eq!(plan.fixed().to_json()["argv"], row["argv"]);
    assert_eq!(plan.job_slice(), format!("holgauntletrust{job_id}.slice"));
    assert_eq!(plan.job_cgroup(), format!("/holgauntletrust{job_id}.slice"));
    assert_eq!(
        plan.controller_cgroup(),
        format!("/system.slice/hol-gauntlet-rust-job-{job_id}")
    );
    let env = plan.environment();
    assert_eq!(env.len(), 4);
    assert_eq!(
        env["HOL_GAUNTLET_RUST_JOB_SLICE"],
        format!("holgauntletrust{job_id}.slice")
    );
    assert_eq!(env["PATH"], "/usr/bin:/bin");
    assert_eq!(env["LANG"], "C.UTF-8");
    assert_eq!(env["HOME"], "/root");

    let next = run(source, "fedcba9876543210", deployment);
    let other = fixed_rust_job_launch_plan(&next, &pins(row), &"e".repeat(64)).unwrap();
    assert_ne!(plan.job_slice(), other.job_slice());
    assert_ne!(plan.controller_cgroup(), other.controller_cgroup());
}
