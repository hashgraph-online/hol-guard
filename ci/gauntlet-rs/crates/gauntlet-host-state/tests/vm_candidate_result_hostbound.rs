//! Synthetic terminal frames cannot substitute for the durable host journal.

use gauntlet_contracts::canonicalize;
use gauntlet_host_state::{
    HostCandidateBuildPinJournal, HostCandidateBuildPins, VmHostBoundCandidateResultError,
    VmHostBoundCandidateResultPlan,
};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;

const JOB: &str = "c04e7f93a2b15d68";

fn pins() -> HostCandidateBuildPins {
    HostCandidateBuildPins {
        job_id: JOB.to_owned(),
        source_sha: "1".repeat(40),
        source_archive_sha256: "2".repeat(64),
        version: "3.49.0".to_owned(),
        tag: format!("local-{}", "1".repeat(40)),
        controller_root: "/opt/hol-gauntlet/controller-18d31910a8cefbd6".to_owned(),
        controller_tree_sha256: "3".repeat(64),
        uv_base_image_id: "4".repeat(64),
        rust_base_image_id: "5".repeat(64),
        builder_image_id: format!("sha256:{}", "6".repeat(64)),
        policy_sha256: "7".repeat(64),
        podman_sha256: "8".repeat(64),
        slirp4netns_sha256: "9".repeat(64),
        apparmor_parser_sha256: "a".repeat(64),
        seccomp_sha256: "b".repeat(64),
        runner_binary_sha256: "c".repeat(64),
        result_reader_binary_sha256: "d".repeat(64),
    }
}

fn operations() -> Value {
    serde_json::from_str(include_str!("../operations-defaults-v1.json")).unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    let mut raw = canonicalize(value.to_string().as_bytes()).unwrap();
    raw.push(b'\n');
    raw
}

#[test]
fn missing_host_record_refuses_before_any_vm_probe() {
    let dir = tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = HostCandidateBuildPinJournal::open(&root).unwrap();
    assert_eq!(
        VmHostBoundCandidateResultPlan::new(
            &operations(),
            &journal,
            JOB,
            &"e".repeat(64),
            &"f".repeat(64),
        ),
        Err(VmHostBoundCandidateResultError::HostPinUnavailable)
    );
}

#[test]
fn exact_terminal_frame_binds_host_record_and_refuses_alteration() {
    let dir = tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = HostCandidateBuildPinJournal::open(&root).unwrap();
    let record = journal.record(&pins()).unwrap();
    let plan = VmHostBoundCandidateResultPlan::new(
        &operations(),
        &journal,
        JOB,
        &"e".repeat(64),
        &"f".repeat(64),
    )
    .unwrap();
    assert_eq!(plan.argv().len(), 25);
    assert_eq!(
        plan.argv()[6],
        format!(
            "/opt/hol-gauntlet/rust-candidate-result-hostbound-shadow-{}",
            pins().result_reader_binary_sha256
        )
    );
    assert_eq!(plan.argv()[23], record.raw_sha256);
    assert_eq!(plan.argv()[24], record.host_nonce_hex);
    let mut frame = json!({
        "schema":"hol-gauntlet-candidate-result-read-shadow.v3",
        "tag":pins().tag,
        "job_id":JOB,
        "source_sha":pins().source_sha,
        "result_sha256":"e".repeat(64),
        "archive_sha256":"f".repeat(64),
        "wheel_sha256":"0".repeat(64),
        "version":"3.49.0",
        "client_pid":1234,
        "client_start_ticks":5678,
        "retained_files_match":true,
        "cleanup_absent":true,
        "host_anchor_present":true,
        "artifact_admitted":false,
        "execution_eligible":false,
        "host_pin_sha256":record.raw_sha256,
        "host_anchor_sha256":"1".repeat(64),
        "runner_binary_sha256":pins().runner_binary_sha256,
        "result_reader_binary_sha256":pins().result_reader_binary_sha256,
        "image_id":pins().builder_image_id,
        "policy_sha256":pins().policy_sha256,
    });
    let result = plan.parse_response(&bytes(&frame)).unwrap();
    assert_eq!(result["host_pin_journal_match"], true);
    assert_eq!(result["artifact_admitted"], false);
    frame["host_pin_sha256"] = json!("0".repeat(64));
    assert_eq!(
        plan.parse_response(&bytes(&frame)),
        Err(VmHostBoundCandidateResultError::InvalidResponse)
    );
    frame["host_pin_sha256"] = json!(record.raw_sha256);
    frame["surprise"] = json!(1);
    assert_eq!(
        plan.parse_response(&bytes(&frame)),
        Err(VmHostBoundCandidateResultError::InvalidResponse)
    );
    assert_eq!(
        plan.parse_response(b"{}\n"),
        Err(VmHostBoundCandidateResultError::InvalidResponse)
    );
}
