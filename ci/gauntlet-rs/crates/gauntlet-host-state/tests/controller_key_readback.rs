use gauntlet_contracts::canonicalize;
use gauntlet_host_state::{HostControllerKeyPins, HostKeyPinError, HostKeyPinRecord};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn pin() -> HostKeyPinRecord {
    HostKeyPinRecord {
        pins: HostControllerKeyPins {
            job_id: "a".repeat(16),
            source_sha: "b".repeat(40),
            deployment_digest: "c".repeat(64),
            worker_generation: "d".repeat(64),
            started_marker_sha256: "e".repeat(64),
            controller_key_pin_sha256: "f".repeat(64),
            controller_public_key_hex: "0".repeat(64),
        },
        raw_sha256: "1".repeat(64),
    }
}

fn canonical(value: &Value) -> Vec<u8> {
    canonicalize(value.to_string().as_bytes()).unwrap()
}

fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

fn response(pin: &HostKeyPinRecord) -> (Value, String, String, String) {
    let deterministic = "2".repeat(64);
    let report = json!({
        "schema":"hol-gauntlet-rust-deterministic-run-diagnostic.v1",
        "job_id":pin.pins.job_id,
        "source_sha":pin.pins.source_sha,
        "deployment_digest":pin.pins.deployment_digest,
        "worker_generation":pin.pins.worker_generation,
        "started_marker_sha256":pin.pins.started_marker_sha256,
        "controller_key_pin_sha256":pin.pins.controller_key_pin_sha256,
        "controller_public_key_hex":pin.pins.controller_public_key_hex,
        "config_digest":"3".repeat(64),
        "process":{"pid":5432,"start_ticks":1234567},
        "exit_code":0,
        "deterministic_report_sha256":deterministic,
        "producer_status_claim":"passed",
        "producer_cell_count":6,
        "six_control_openings":{},
        "independent_control_verdict":false,
        "execution_eligible":false,
    });
    let diagnostic = digest(&canonical(&report));
    let terminal = json!({
        "schema":"hol-gauntlet-worker-terminal.v2",
        "source_sha":pin.pins.source_sha,
        "job_id":pin.pins.job_id,
        "deployment_digest":pin.pins.deployment_digest,
        "worker_generation":pin.pins.worker_generation,
        "started_marker_sha256":pin.pins.started_marker_sha256,
        "controller_key_pin_sha256":pin.pins.controller_key_pin_sha256,
        "controller_public_key_hex":pin.pins.controller_public_key_hex,
        "report_sha256":diagnostic,
        "pid":5432,
        "process_start_ticks":1234567,
        "exit_code":0,
        "status":"invalid-evidence",
    });
    let terminal_sha = digest(&canonical(&terminal));
    let value = json!({
        "schema":"hol-gauntlet-rust-deterministic-readback.v1",
        "job_id":pin.pins.job_id,
        "source_sha":pin.pins.source_sha,
        "terminal":terminal,
        "diagnostic_report":report,
        "terminal_sha256":terminal_sha,
        "diagnostic_report_sha256":diagnostic,
        "deterministic_report_sha256":deterministic,
        "execution_eligible":false,
    });
    (value, terminal_sha, diagnostic, deterministic)
}

fn wire(value: &Value) -> Vec<u8> {
    let mut raw = canonical(value);
    raw.push(b'\n');
    raw
}

#[test]
fn exact_keyed_terminal_and_report_reopen_under_host_pin() {
    let pin = pin();
    let (value, terminal, diagnostic, deterministic) = response(&pin);
    let observed = pin
        .observe_deterministic_readback(&wire(&value), &terminal, &diagnostic, &deterministic)
        .unwrap();
    assert_eq!(observed.terminal_sha256, terminal);
    assert_eq!(observed.producer_status_claim, "passed");
    assert_eq!(observed.to_json()["execution_eligible"], false);
    assert_eq!(
        observed.to_json()["keyed_terminal_status"],
        "invalid-evidence"
    );
}

#[test]
fn changed_key_status_report_and_replay_claim_refuse() {
    let pin = pin();
    let (value, terminal, diagnostic, deterministic) = response(&pin);
    let mut changed_key = value.clone();
    changed_key["terminal"]["controller_key_pin_sha256"] = json!("9".repeat(64));
    let mut promoted = value.clone();
    promoted["terminal"]["status"] = json!("passed");
    let mut changed_report = value.clone();
    changed_report["diagnostic_report"]["producer_status_claim"] = json!("failed");
    let mut changed_source = value.clone();
    changed_source["diagnostic_report"]["source_sha"] = json!("a".repeat(40));
    for changed in [changed_key, promoted, changed_report, changed_source] {
        assert_eq!(
            pin.observe_deterministic_readback(
                &wire(&changed),
                &terminal,
                &diagnostic,
                &deterministic
            ),
            Err(HostKeyPinError::InvalidTerminal)
        );
    }
    let mut extra = wire(&value);
    extra.push(b'\n');
    assert_eq!(
        pin.observe_deterministic_readback(&extra, &terminal, &diagnostic, &deterministic),
        Err(HostKeyPinError::InvalidTerminal)
    );
    assert_eq!(
        pin.observe_deterministic_readback(
            &wire(&value),
            &"0".repeat(64),
            &diagnostic,
            &deterministic
        ),
        Err(HostKeyPinError::InvalidTerminal)
    );
}

#[test]
fn fixed_lima_readback_uses_only_the_pinned_job_and_reader() {
    let pin = pin();
    let (value, terminal, diagnostic, deterministic) = response(&pin);
    let reader = "7".repeat(64);
    let temporary = tempfile::tempdir().unwrap();
    let fake_lima = temporary.path().join("limactl-readback-fixture");
    let reply = String::from_utf8(canonical(&value)).unwrap();
    let script = format!(
        "#!/bin/sh\n[ \"$1\" = shell ] || exit 2\n[ \"$2\" = test-vm ] || exit 2\n[ \"$3\" = -- ] || exit 2\n[ \"$4\" = sudo ] || exit 2\n[ \"$5\" = -n ] || exit 2\n[ \"$6\" = /opt/hol-gauntlet/rust-deterministic-readback-{reader} ] || exit 2\n[ \"$7\" = {source} ] || exit 2\n[ \"$8\" = {job} ] || exit 2\n[ \"$9\" = {deployment} ] || exit 2\n[ \"${{10}}\" = {generation} ] || exit 2\n[ \"${{11}}\" = {reader} ] || exit 2\ncat <<'READBACK'\n{reply}\nREADBACK\n",
        source = pin.pins.source_sha,
        job = pin.pins.job_id,
        deployment = pin.pins.deployment_digest,
        generation = pin.pins.worker_generation,
    );
    fs::write(&fake_lima, script).unwrap();
    fs::set_permissions(&fake_lima, fs::Permissions::from_mode(0o700)).unwrap();
    let observed = pin
        .observe_fixed_vm_deterministic_readback(
            fake_lima.to_str().unwrap(),
            "test-vm",
            &reader,
            &terminal,
            &diagnostic,
            &deterministic,
        )
        .unwrap();
    assert_eq!(observed.terminal_sha256, terminal);
    assert_eq!(observed.producer_status_claim, "passed");
    assert_eq!(
        pin.observe_fixed_vm_deterministic_readback(
            fake_lima.to_str().unwrap(),
            "test-vm",
            &"Z".repeat(64),
            &terminal,
            &diagnostic,
            &deterministic,
        ),
        Err(HostKeyPinError::InvalidPins)
    );
}
