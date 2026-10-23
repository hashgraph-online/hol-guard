use gauntlet_host_state::{VmProgressError, VmProgressPlan};
use serde_json::{json, Value};
use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;

const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const JOB: &str = "0123456789abcdef";
const DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn operations() -> Value {
    serde_json::from_str(include_str!("../operations-defaults-v1.json")).unwrap()
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("python_vm_progress_v1.json")).unwrap()
}

#[test]
fn fixed_progress_call_matches_pinned_python_with_and_without_deployment() {
    let fixture = fixture();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    let source = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "ci/gauntlet/control_plane/agent.py")
        .unwrap();
    assert_eq!(fixture["source_sha256"], source["sha256"]);
    assert_eq!(fixture["schema"], "gauntlet-vm-progress-fixtures.v1");
    for (name, digest) in [
        ("without_deployment", None),
        ("with_deployment", Some(DIGEST)),
    ] {
        let plan = VmProgressPlan::new(&operations(), SHA, JOB, digest).unwrap();
        let expected = &fixture[name];
        assert_eq!(plan.to_json()["argv"], expected["argv"]);
        assert_eq!(plan.to_json()["request"], expected["request"]);
        assert_eq!(
            plan.to_json()["timeout_seconds"],
            expected["timeout_seconds"]
        );
        assert_eq!(expected["capture_output"], true);
        assert_eq!(expected["text"], true);
        assert_eq!(plan.to_json()["admission_eligible"], false);
        assert_eq!(
            plan.parse_response(&serde_json::to_vec(&expected["response"]).unwrap())
                .unwrap(),
            expected["response"]
        );
    }
}

#[test]
fn progress_refuses_wrong_identity_duplicate_json_and_malformed_status() {
    let plan = VmProgressPlan::new(&operations(), SHA, JOB, None).unwrap();
    let mut wrong = fixture()["without_deployment"]["response"].clone();
    wrong["job_id"] = json!("0000000000000000");
    assert_eq!(
        plan.parse_response(&serde_json::to_vec(&wrong).unwrap()),
        Err(VmProgressError::InvalidResponse)
    );
    wrong["job_id"] = json!(JOB);
    wrong["process_alive"] = json!(0);
    assert_eq!(
        plan.parse_response(&serde_json::to_vec(&wrong).unwrap()),
        Err(VmProgressError::InvalidResponse)
    );
    assert_eq!(
        plan.parse_response(br#"{"source_sha":"a","source_sha":"b"}"#),
        Err(VmProgressError::InvalidResponse)
    );
    assert_eq!(
        plan.parse_response(&vec![b' '; 1024 * 1024 + 1]),
        Err(VmProgressError::TooLarge)
    );
}

#[test]
fn fake_lima_receives_only_fixed_progress_json_and_failed_probe_stays_unavailable() {
    let temporary = tempfile::tempdir().unwrap();
    let executable = temporary.path().join("fake-limactl");
    let input_file = temporary.path().join("stdin.json");
    let expected = &fixture()["with_deployment"]["response"];
    let stdout = serde_json::to_string(expected).unwrap();
    fs::write(
        &executable,
        format!(
            "#!/bin/sh\nread request\nprintf '%s' \"$request\" > '{}'\nprintf '%s' '{}'\n",
            input_file.display(),
            stdout
        ),
    )
    .unwrap();
    fs::set_permissions(&executable, Permissions::from_mode(0o700)).unwrap();
    let mut config = operations();
    config["limactl"] = json!(executable.to_str().unwrap());
    let plan = VmProgressPlan::new(&config, SHA, JOB, Some(DIGEST)).unwrap();
    assert_eq!(plan.execute_read_only().unwrap(), *expected);
    let sent: Value = serde_json::from_slice(&fs::read(input_file).unwrap()).unwrap();
    assert_eq!(sent, plan.request);
    assert_eq!(sent["action"], "progress");
    fs::write(&executable, b"#!/bin/sh\nexit 7\n").unwrap();
    assert_eq!(plan.execute_read_only(), Err(VmProgressError::Unavailable));
}

#[test]
fn unsafe_progress_selector_or_configuration_refuses() {
    assert_eq!(
        VmProgressPlan::new(&operations(), "bad", JOB, None),
        Err(VmProgressError::InvalidIdentity)
    );
    assert_eq!(
        VmProgressPlan::new(&operations(), SHA, "../other", None),
        Err(VmProgressError::InvalidIdentity)
    );
    assert_eq!(
        VmProgressPlan::new(&operations(), SHA, JOB, Some("bad")),
        Err(VmProgressError::InvalidIdentity)
    );
    let mut invalid = operations();
    invalid["vm"] = json!("../other");
    assert_eq!(
        VmProgressPlan::new(&invalid, SHA, JOB, None),
        Err(VmProgressError::InvalidConfig)
    );
}
