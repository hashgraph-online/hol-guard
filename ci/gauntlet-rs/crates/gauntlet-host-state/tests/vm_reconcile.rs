use gauntlet_host_state::{VmReconcileError, VmReconcilePlan};
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
    serde_json::from_str(include_str!("python_vm_reconcile_v1.json")).unwrap()
}

fn plan() -> VmReconcilePlan {
    VmReconcilePlan::new(&operations(), SHA, JOB, Some(DIGEST)).unwrap()
}

#[test]
fn fixed_reconcile_call_matches_pinned_python_and_has_no_replay_selector() {
    let frozen = fixture();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    for filename in ["agent.py", "vm_worker.py"] {
        let expected = manifest["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["path"] == format!("ci/gauntlet/control_plane/{filename}"))
            .unwrap();
        assert_eq!(frozen["source_sha256"][filename], expected["sha256"]);
    }
    assert_eq!(frozen["schema"], "gauntlet-vm-reconcile-fixtures.v1");
    for (key, digest) in [
        ("without_deployment", None),
        ("with_deployment", Some(DIGEST)),
    ] {
        let plan = VmReconcilePlan::new(&operations(), SHA, JOB, digest).unwrap();
        let expected = &frozen[key];
        assert_eq!(plan.to_json()["argv"], expected["argv"]);
        assert_eq!(plan.to_json()["request"], expected["request"]);
        assert_eq!(
            plan.to_json()["timeout_seconds"],
            expected["timeout_seconds"]
        );
        assert_eq!(plan.to_json()["admission_eligible"], false);
        assert_eq!(
            plan.parse_response(&serde_json::to_vec(&expected["response"]).unwrap())
                .unwrap(),
            expected["response"]
        );
    }
    let no_pin = VmReconcilePlan::new(&operations(), SHA, JOB, None).unwrap();
    assert_eq!(
        no_pin.parse_response(&serde_json::to_vec(&frozen["with_deployment"]["response"]).unwrap()),
        Err(VmReconcileError::InvalidResponse)
    );
}

#[test]
fn python_finish_projection_matches_frozen_terminal_cases() {
    for case in fixture()["finish_cases"].as_array().unwrap() {
        let response = &case["response"];
        if case["finish"].get("error").is_some() {
            assert_eq!(
                plan().classify_terminal(response),
                Err(VmReconcileError::InvalidResponse),
                "{}",
                case["name"]
            );
        } else {
            let projection = plan().classify_terminal(response).unwrap();
            for field in ["state", "post_state", "description"] {
                assert_eq!(projection[field], case["finish"][field], "{}", case["name"]);
            }
            assert_eq!(projection["admission_eligible"], false);
        }
    }
}

#[test]
fn malformed_or_unpinned_receipts_refuse_before_classification() {
    let plan = plan();
    let mut terminal = fixture()["with_deployment"]["response"].clone();
    terminal["model_tokens"] = json!(1);
    assert_eq!(
        plan.parse_response(&serde_json::to_vec(&terminal).unwrap()),
        Err(VmReconcileError::InvalidResponse)
    );
    terminal["model_tokens"] = json!(0);
    terminal["report_path"] = json!("/tmp/untrusted");
    assert_eq!(
        plan.parse_response(&serde_json::to_vec(&terminal).unwrap()),
        Err(VmReconcileError::InvalidResponse)
    );
    assert_eq!(
        plan.parse_response(br#"{"status":"unknown","status":"passed"}"#),
        Err(VmReconcileError::InvalidResponse)
    );
    assert_eq!(
        plan.parse_response(&vec![b' '; 1024 * 1024 + 1]),
        Err(VmReconcileError::TooLarge)
    );
    assert_eq!(
        VmReconcilePlan::new(&operations(), SHA, "../unsafe", Some(DIGEST)),
        Err(VmReconcileError::InvalidIdentity)
    );
}

#[test]
fn fake_lima_receives_only_read_only_reconcile_and_failure_stays_unavailable() {
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
    let plan = VmReconcilePlan::new(&config, SHA, JOB, Some(DIGEST)).unwrap();
    assert_eq!(plan.execute_read_only().unwrap(), *expected);
    let sent: Value = serde_json::from_slice(&fs::read(input_file).unwrap()).unwrap();
    assert_eq!(sent, plan.request);
    assert_eq!(sent["action"], "reconcile");
    fs::write(&executable, b"#!/bin/sh\nexit 7\n").unwrap();
    assert_eq!(plan.execute_read_only(), Err(VmReconcileError::Unavailable));
}
