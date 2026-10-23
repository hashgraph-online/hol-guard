//! The host can only obtain a fixed candidate argv after a durable one-use
//! intent. No test here launches Lima or claims guest execution.

use gauntlet_contracts::canonicalize;
use gauntlet_host_state::{
    HostCandidateBuildPinError, HostCandidateBuildPinJournal, HostCandidateBuildPins,
    VmCandidateBuildError, VmCandidateBuildPlan,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;

const JOB: &str = "c04e7f93a2b15d68";

fn pins() -> HostCandidateBuildPins {
    HostCandidateBuildPins {
        job_id: JOB.to_owned(),
        source_sha: "76c31929833b5571d25a56d9783e24a0997d5422".to_owned(),
        source_archive_sha256: "bedd98ab7da8ca728484799e1ef6b13c854f7fcbb31a17ebdcc469c4c772af43"
            .to_owned(),
        version: "3.49.0".to_owned(),
        tag: "local-76c31929833b5571d25a56d9783e24a0997d5422".to_owned(),
        controller_root: "/opt/hol-gauntlet/controller-18d31910a8cefbd6".to_owned(),
        controller_tree_sha256: "33c98333891743e6976bee9a123365fe7fe95dcf1bf9b65ee39a59fb41043c68"
            .to_owned(),
        uv_base_image_id: "08ab0fa4ca8748587f792f899a6beadc2a3177d5943e3a6a6571c683c0a1f312"
            .to_owned(),
        rust_base_image_id: "3e50f04c5161f9c0c00f1b3b09eb1073977a44dca86f9637ae3cbbcc4fcf7b95"
            .to_owned(),
        builder_image_id: "sha256:39a6e74e48b2619189e191b5f5038ce0e27fba1cb57177d713e2077e64c7bb29"
            .to_owned(),
        policy_sha256: "3aa6b76487e84ccede7093a1d79e8eb3d5688de8260cdfd12ebd6d12743667a8"
            .to_owned(),
        podman_sha256: "f93ee492920150e229b9b41729bfe675073a4df0569ee5d570a8106b5a64506a"
            .to_owned(),
        slirp4netns_sha256: "4211dca7736aeb6fdd055350c8138d095d3dc5170f2ebf2a68fed5cdd4372f1c"
            .to_owned(),
        apparmor_parser_sha256: "68556e4676aaf0849a33ef38ee5a6617d8686a84edf3d5b191ee73e291ecb0c8"
            .to_owned(),
        seccomp_sha256: "cc374cf23846ce1f62f4dc807a8e2b8673c783c6f56cb475467621035d281e6c"
            .to_owned(),
        runner_binary_sha256: "1920692134fab02440a8f32b66965aedcacb6c18a19f549fb318f13a036cdfdb"
            .to_owned(),
        result_reader_binary_sha256:
            "f977ae6a0da162392cd0c03360083d78a98b66cd6e6e12144f8f7756f1363c98".to_owned(),
    }
}

fn operations() -> Value {
    serde_json::from_str(include_str!("../operations-defaults-v1.json")).unwrap()
}

fn terminal_bytes(invocation: &gauntlet_host_state::VmCandidateBuildInvocation) -> Vec<u8> {
    let pins = &invocation.record().pins;
    let mut body = json!({
        "schema":"hol-gauntlet-candidate-build-result.v3",
        "job_id":pins.job_id,
        "source_sha":pins.source_sha,
        "source_archive_sha256":pins.source_archive_sha256,
        "source_bytes":45439546,
        "local_version":if pins.tag.starts_with("local-") {json!(pins.version)} else {Value::Null},
        "tag":pins.tag,
        "image_id":pins.builder_image_id,
        "policy_sha256":pins.policy_sha256,
        "runtime_pins":{
            "podman_sha256":pins.podman_sha256,
            "slirp4netns_sha256":pins.slirp4netns_sha256,
            "apparmor_parser_sha256":pins.apparmor_parser_sha256,
            "seccomp_sha256":pins.seccomp_sha256,
        },
        "client_pid":1234,
        "client_start_ticks":5678,
        "status":"exited-zero",
        "exit_code":0,
        "stdout_sha256":"1".repeat(64),
        "stderr_sha256":"2".repeat(64),
        "unadmitted_export_bytes":20274622,
        "unadmitted_export_sha256":"3".repeat(64),
        "container_absent":true,
        "candidate_cgroup_drained":true,
        "build_profile_removed":true,
        "artifact_admitted":false,
        "execution_eligible":false,
        "host_pin_sha256":invocation.record().raw_sha256,
        "host_nonce_hex":invocation.record().host_nonce_hex,
        "host_anchor_sha256":"4".repeat(64),
        "runner_binary_sha256":pins.runner_binary_sha256,
        "result_reader_binary_sha256":pins.result_reader_binary_sha256,
    });
    let body_bytes = canonicalize(body.to_string().as_bytes()).unwrap();
    body["result_sha256"] = json!(format!("{:x}", Sha256::digest(&body_bytes)));
    let mut raw = canonicalize(body.to_string().as_bytes()).unwrap();
    raw.push(b'\n');
    raw
}

#[test]
fn release_tag_is_carried_to_probe_and_guest_and_terminal_requires_it() {
    let dir = tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = HostCandidateBuildPinJournal::open(&root).unwrap();
    let mut release = pins();
    release.version = "3.48.0".to_owned();
    release.tag = "v3.48.0".to_owned();
    let plan = VmCandidateBuildPlan::new(&operations(), release).unwrap();
    let probe = plan.preflight_plan(&"e".repeat(64)).unwrap();
    assert_eq!(probe.argv()[16], "v3.48.0");
    let invocation = plan.record_before_launch(&journal).unwrap();
    assert_eq!(invocation.argv()[16], "v3.48.0");
    let frame = terminal_bytes(&invocation);
    assert_eq!(
        invocation.parse_terminal_claim(&frame).unwrap()["exit_code"],
        0
    );
    let mut wrong: Value = serde_json::from_slice(&frame).unwrap();
    wrong["tag"] = json!("v3.49.0");
    let mut raw = canonicalize(wrong.to_string().as_bytes()).unwrap();
    raw.push(b'\n');
    assert!(invocation.parse_terminal_claim(&raw).is_err());
}

#[test]
fn fixed_invocation_exists_only_after_durable_host_pin() {
    let dir = tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = HostCandidateBuildPinJournal::open(&root).unwrap();
    let plan = VmCandidateBuildPlan::new(&operations(), pins()).unwrap();
    let preflight = plan.preflight_plan(&"e".repeat(64)).unwrap();
    assert_eq!(preflight.argv().len(), 22);
    assert_eq!(
        preflight.argv()[6],
        format!(
            "/opt/hol-gauntlet/rust-candidate-build-ready-shadow-{}",
            "e".repeat(64)
        )
    );
    assert_eq!(preflight.argv()[9], JOB);
    let response = json!({
        "schema":"hol-gauntlet-candidate-build-ready-shadow.v2",
        "job_id":JOB,
        "source_sha":pins().source_sha,
        "source_archive_sha256":pins().source_archive_sha256,
        "tag":pins().tag,
        "image_id":pins().builder_image_id,
        "policy_sha256":pins().policy_sha256,
        "free_disk_bytes":13_000_000_000_u64,
        "ready_at_probe":true,
        "host_pin_recorded":false,
        "candidate_started":false,
        "artifact_admitted":false,
        "execution_eligible":false,
    });
    let mut response_bytes = canonicalize(response.to_string().as_bytes()).unwrap();
    response_bytes.push(b'\n');
    assert_eq!(
        preflight.parse_response(&response_bytes).unwrap()["ready_at_probe"],
        true
    );
    let mut wrong = response.clone();
    wrong["policy_sha256"] = json!("0".repeat(64));
    let mut wrong_bytes = canonicalize(wrong.to_string().as_bytes()).unwrap();
    wrong_bytes.push(b'\n');
    assert!(preflight.parse_response(&wrong_bytes).is_err());
    wrong = response;
    wrong["free_disk_bytes"] = json!(1);
    wrong_bytes = canonicalize(wrong.to_string().as_bytes()).unwrap();
    wrong_bytes.push(b'\n');
    assert!(preflight.parse_response(&wrong_bytes).is_err());
    assert_eq!(journal.read(JOB), Err(HostCandidateBuildPinError::Missing));
    let invocation = plan.record_before_launch(&journal).unwrap();
    assert_eq!(journal.read(JOB).unwrap(), *invocation.record());
    let argv = invocation.argv();
    assert_eq!(argv.len(), 25);
    assert_eq!(argv[0], "/opt/homebrew/bin/limactl");
    assert_eq!(
        &argv[1..6],
        [
            "shell",
            "hol-beta-bootstrap-20261016-004",
            "--",
            "sudo",
            "-n"
        ]
    );
    assert_eq!(
        argv[6],
        format!(
            "/opt/hol-gauntlet/rust-candidate-run-hostbound-shadow-{}",
            pins().runner_binary_sha256
        )
    );
    assert_eq!(argv[7], pins().controller_root);
    assert_eq!(argv[9], JOB);
    assert_eq!(argv[21], pins().policy_sha256);
    assert_eq!(argv[22], pins().result_reader_binary_sha256);
    assert_eq!(argv[23], invocation.record().raw_sha256);
    assert_eq!(argv[24], invocation.record().host_nonce_hex);
    assert_eq!(invocation.to_json()["vm_started"], false);
    assert_eq!(invocation.to_json()["execution_eligible"], false);
    let terminal = terminal_bytes(&invocation);
    let claim = invocation.parse_terminal_claim(&terminal).unwrap();
    assert_eq!(claim["retained_result_reconciled"], false);
    assert_eq!(claim["artifact_admitted"], false);
    let mut altered: Value = serde_json::from_slice(&terminal).unwrap();
    altered["host_nonce_hex"] = json!("0".repeat(64));
    let mut altered_bytes = canonicalize(altered.to_string().as_bytes()).unwrap();
    altered_bytes.push(b'\n');
    assert!(invocation.parse_terminal_claim(&altered_bytes).is_err());
    altered["host_nonce_hex"] = json!(invocation.record().host_nonce_hex);
    altered["result_sha256"] = json!("0".repeat(64));
    altered_bytes = canonicalize(altered.to_string().as_bytes()).unwrap();
    altered_bytes.push(b'\n');
    assert!(invocation.parse_terminal_claim(&altered_bytes).is_err());
    assert!(matches!(
        plan.record_before_launch(&journal),
        Err(VmCandidateBuildError::HostPin(
            HostCandidateBuildPinError::AlreadyRecorded
        ))
    ));
}

#[test]
fn invalid_config_and_mutable_paths_refuse_before_a_pin() {
    let dir = tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = HostCandidateBuildPinJournal::open(&root).unwrap();
    let mut config = operations();
    config["release_build_backend"] = "github-actions".into();
    assert_eq!(
        VmCandidateBuildPlan::new(&config, pins()),
        Err(VmCandidateBuildError::InvalidConfig)
    );
    config = operations();
    config["build_memory_gib"] = 8.into();
    assert_eq!(
        VmCandidateBuildPlan::new(&config, pins()),
        Err(VmCandidateBuildError::InvalidConfig)
    );
    let mut changed = pins();
    changed.controller_root = "/opt/hol-gauntlet/controller".to_owned();
    assert_eq!(
        VmCandidateBuildPlan::new(&operations(), changed),
        Err(VmCandidateBuildError::InvalidPins)
    );
    changed = pins();
    changed.uv_base_image_id = "ghcr.io/astral-sh/uv:0.9.26".to_owned();
    assert_eq!(
        VmCandidateBuildPlan::new(&operations(), changed),
        Err(VmCandidateBuildError::InvalidPins)
    );
    assert!(VmCandidateBuildPlan::new(&operations(), pins())
        .unwrap()
        .preflight_plan("mutable-tag")
        .is_err());
    assert_eq!(journal.read(JOB), Err(HostCandidateBuildPinError::Missing));
}
