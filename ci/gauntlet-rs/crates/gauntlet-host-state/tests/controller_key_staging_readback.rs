use gauntlet_contracts::canonicalize;
use gauntlet_host_state::{
    HostControllerKeyPins, HostKeyPinError, HostKeyPinRecord, HostSdkTapJournalPin,
};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn pins() -> (HostKeyPinRecord, HostSdkTapJournalPin) {
    let key = HostKeyPinRecord {
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
    };
    let tap = HostSdkTapJournalPin {
        run_id: key.pins.job_id.clone(),
        host_key_record_sha256: key.raw_sha256.clone(),
        terminal_sha256: "2".repeat(64),
        report_sha256: "3".repeat(64),
        journal_sha256: "4".repeat(64),
        journal_bytes: 1024,
        sessions: 2,
        events: 24,
        observed_bytes: 2048,
        raw_sha256: "5".repeat(64),
    };
    (key, tap)
}

fn response(key: &HostKeyPinRecord, tap: &HostSdkTapJournalPin) -> Value {
    json!({
        "schema":"hol-gauntlet-staging-tap-restart-readback.v1",
        "run_id":key.pins.job_id,
        "source_sha":key.pins.source_sha,
        "config_digest":key.pins.deployment_digest,
        "worker_generation_sha256":key.pins.worker_generation,
        "started_marker_sha256":key.pins.started_marker_sha256,
        "controller_key_pin_sha256":key.pins.controller_key_pin_sha256,
        "controller_public_key_hex":key.pins.controller_public_key_hex,
        "terminal_sha256":tap.terminal_sha256,
        "report_sha256":tap.report_sha256,
        "tap_journal_sha256":tap.journal_sha256,
        "role":"success",
        "state":"verified-ineligible-terminal",
        "one_use_tap_tombstone_empty":true,
        "controller_tap_and_product_cgroups_absent":true,
        "conformance_package_created":false,
        "execution_eligible":false,
    })
}

fn wire(value: &Value) -> Vec<u8> {
    let mut raw = canonicalize(value.to_string().as_bytes()).unwrap();
    raw.push(b'\n');
    raw
}

#[test]
fn host_matches_complete_restart_readback_to_both_durable_pins() {
    let (key, tap) = pins();
    let observed = key
        .observe_staging_restart_readback(&wire(&response(&key, &tap)), &tap)
        .unwrap();
    assert_eq!(observed.host_tap_pin_sha256, tap.raw_sha256);
    assert_eq!(observed.role, "success");
    assert_eq!(observed.to_json()["execution_eligible"], false);
}

#[test]
fn changed_key_tap_cleanup_and_replayed_frame_refuse() {
    let (key, tap) = pins();
    let base = response(&key, &tap);
    let mut cases = Vec::new();
    for (field, changed) in [
        ("controller_key_pin_sha256", json!("9".repeat(64))),
        ("tap_journal_sha256", json!("9".repeat(64))),
        ("controller_tap_and_product_cgroups_absent", json!(false)),
        ("state", json!("running")),
        ("execution_eligible", json!(true)),
    ] {
        let mut candidate = base.clone();
        candidate[field] = changed;
        cases.push(wire(&candidate));
    }
    let mut repeated = wire(&base);
    repeated.push(b'\n');
    cases.push(repeated);
    for candidate in cases {
        assert_eq!(
            key.observe_staging_restart_readback(&candidate, &tap),
            Err(HostKeyPinError::InvalidTapJournal)
        );
    }
    let mut changed_tap = tap.clone();
    changed_tap.host_key_record_sha256 = "9".repeat(64);
    assert_eq!(
        key.observe_staging_restart_readback(&wire(&base), &changed_tap),
        Err(HostKeyPinError::InvalidTapJournal)
    );
}

#[test]
fn fixed_lima_call_uses_only_the_pinned_run_and_reader() {
    let (key, tap) = pins();
    let reader = "6".repeat(64);
    let temporary = tempfile::tempdir().unwrap();
    let fake_lima = temporary.path().join("limactl-staging-readback-fixture");
    let reply =
        String::from_utf8(canonicalize(response(&key, &tap).to_string().as_bytes()).unwrap())
            .unwrap();
    let script = format!(
        "#!/bin/sh\n[ \"$1\" = shell ] || exit 2\n[ \"$2\" = test-vm ] || exit 2\n[ \"$3\" = -- ] || exit 2\n[ \"$4\" = sudo ] || exit 2\n[ \"$5\" = -n ] || exit 2\n[ \"$6\" = /opt/hol-gauntlet/rust-staging-tap-restart-readback-{reader} ] || exit 2\n[ \"$7\" = {job} ] || exit 2\n[ \"$8\" = {source} ] || exit 2\n[ \"$9\" = {config} ] || exit 2\n[ \"${{10}}\" = {generation} ] || exit 2\n[ \"${{11}}\" = {started} ] || exit 2\n[ \"${{12}}\" = {key_pin} ] || exit 2\n[ \"${{13}}\" = {terminal} ] || exit 2\n[ \"${{14}}\" = {report} ] || exit 2\n[ \"${{15}}\" = {journal} ] || exit 2\n[ \"${{16}}\" = {reader} ] || exit 2\ncat <<'READBACK'\n{reply}\nREADBACK\n",
        job = key.pins.job_id,
        source = key.pins.source_sha,
        config = key.pins.deployment_digest,
        generation = key.pins.worker_generation,
        started = key.pins.started_marker_sha256,
        key_pin = key.pins.controller_key_pin_sha256,
        terminal = tap.terminal_sha256,
        report = tap.report_sha256,
        journal = tap.journal_sha256,
    );
    fs::write(&fake_lima, script).unwrap();
    fs::set_permissions(&fake_lima, fs::Permissions::from_mode(0o700)).unwrap();
    let observed = key
        .observe_fixed_vm_staging_restart_readback(
            fake_lima.to_str().unwrap(),
            "test-vm",
            &reader,
            &tap,
        )
        .unwrap();
    assert_eq!(observed.terminal_sha256, tap.terminal_sha256);
    assert_eq!(
        key.observe_fixed_vm_staging_restart_readback(
            fake_lima.to_str().unwrap(),
            "test-vm",
            &"Z".repeat(64),
            &tap,
        ),
        Err(HostKeyPinError::InvalidPins)
    );
}
