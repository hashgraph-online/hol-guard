use super::*;
use crate::io::open_absolute_directory;
use serde_json::Value;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;

const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const JOB: &str = "0123456789abcdef";
const DEPLOYMENT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CONFIG: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn private(path: &std::path::Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn fixture() -> (tempfile::TempDir, PathBuf, OwnedFd) {
    let temporary = tempfile::tempdir().unwrap();
    let outputs = temporary.path().canonicalize().unwrap().join("outputs");
    fs::create_dir(&outputs).unwrap();
    private(&outputs, 0o700);
    let job = outputs.join(JOB);
    fs::create_dir(&job).unwrap();
    private(&job, 0o700);
    let report = job.join("report");
    fs::create_dir(&report).unwrap();
    private(&report, 0o700);
    let frozen: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/python_worker_terminal_synthetic.json"
    ))
    .unwrap();
    let receipt = outputs.join(format!("{JOB}.json"));
    fs::write(&receipt, frozen["receipt"].to_string()).unwrap();
    private(&receipt, 0o600);
    let result = report.join("result.json");
    fs::write(&result, frozen["report_raw"].as_str().unwrap()).unwrap();
    private(&result, 0o600);
    let descriptor = open_absolute_directory(&outputs).unwrap();
    (temporary, outputs, descriptor)
}

#[test]
fn private_receipt_and_report_match_outside_pins_without_eligibility() {
    let (_temporary, _outputs, descriptor) = fixture();
    let result = read_for_owner(
        &descriptor,
        JOB,
        SOURCE,
        DEPLOYMENT,
        CONFIG,
        geteuid().as_raw(),
    )
    .unwrap();
    assert_eq!(result.status, "passed");
    assert!(result.report_consistent);
    assert!(!result.execution_eligible);
    assert!(read_for_owner(
        &descriptor,
        JOB,
        SOURCE,
        &"0".repeat(64),
        CONFIG,
        geteuid().as_raw(),
    )
    .is_err());
    assert!(read_for_owner(
        &descriptor,
        "../other",
        SOURCE,
        DEPLOYMENT,
        CONFIG,
        geteuid().as_raw(),
    )
    .is_err());
}

#[test]
fn unsafe_or_missing_retained_files_cannot_become_a_pass() {
    let (_temporary, outputs, descriptor) = fixture();
    let report = outputs.join(JOB).join("report/result.json");
    private(&report, 0o644);
    assert!(read_for_owner(
        &descriptor,
        JOB,
        SOURCE,
        DEPLOYMENT,
        CONFIG,
        geteuid().as_raw(),
    )
    .is_err());
    private(&report, 0o600);
    fs::remove_file(&report).unwrap();
    assert!(read_for_owner(
        &descriptor,
        JOB,
        SOURCE,
        DEPLOYMENT,
        CONFIG,
        geteuid().as_raw(),
    )
    .is_err());
    fs::write(&report, b"{}").unwrap();
    private(&report, 0o600);
    assert!(read_for_owner(
        &descriptor,
        JOB,
        SOURCE,
        DEPLOYMENT,
        CONFIG,
        geteuid().as_raw(),
    )
    .is_err());
}

#[test]
fn symlinked_or_hardlinked_receipt_is_refused() {
    let (_temporary, outputs, descriptor) = fixture();
    let receipt = outputs.join(format!("{JOB}.json"));
    let alternate = outputs.join("alternate.json");
    fs::hard_link(&receipt, &alternate).unwrap();
    assert!(read_for_owner(
        &descriptor,
        JOB,
        SOURCE,
        DEPLOYMENT,
        CONFIG,
        geteuid().as_raw(),
    )
    .is_err());
    fs::remove_file(&alternate).unwrap();
    fs::rename(&receipt, &alternate).unwrap();
    symlink(&alternate, &receipt).unwrap();
    assert!(read_for_owner(
        &descriptor,
        JOB,
        SOURCE,
        DEPLOYMENT,
        CONFIG,
        geteuid().as_raw(),
    )
    .is_err());
}

#[test]
fn live_entrypoint_never_reads_root_outputs_as_an_unprivileged_user() {
    if geteuid().as_raw() != 0 {
        assert!(read_python_worker_terminal_root_owned(JOB, SOURCE, DEPLOYMENT, CONFIG).is_err());
    }
}
