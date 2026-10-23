use gauntlet_contracts::{canonicalize, PrelaunchPrepared};
use gauntlet_host_state::{
    HostControllerKeyPinJournal, HostControllerKeyPins, HostKeyPinError, HostPrelaunchIdentity,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

const JOB: &str = "dddddddddddddddd";

fn pins() -> HostControllerKeyPins {
    HostControllerKeyPins {
        job_id: JOB.to_owned(),
        source_sha: "a".repeat(40),
        deployment_digest: "b".repeat(64),
        worker_generation: "c".repeat(64),
        started_marker_sha256: "d".repeat(64),
        controller_key_pin_sha256: "e".repeat(64),
        controller_public_key_hex: "f".repeat(64),
    }
}

fn prepared(pins: &HostControllerKeyPins) -> PrelaunchPrepared {
    PrelaunchPrepared {
        job_id: pins.job_id.clone(),
        source_sha: pins.source_sha.clone(),
        deployment_digest: pins.deployment_digest.clone(),
        worker_generation: pins.worker_generation.clone(),
        started_marker_sha256: pins.started_marker_sha256.clone(),
        controller_key_pin_sha256: pins.controller_key_pin_sha256.clone(),
        controller_public_key_hex: pins.controller_public_key_hex.clone(),
    }
}

fn planned_identity(pins: &HostControllerKeyPins) -> HostPrelaunchIdentity {
    HostPrelaunchIdentity {
        job_id: pins.job_id.clone(),
        source_sha: pins.source_sha.clone(),
        deployment_digest: pins.deployment_digest.clone(),
        worker_generation: pins.worker_generation.clone(),
    }
}

fn keyed_terminal(pins: &HostControllerKeyPins, report: &[u8]) -> Value {
    json!({
        "schema":"hol-gauntlet-worker-terminal.v2",
        "source_sha":pins.source_sha,
        "job_id":pins.job_id,
        "deployment_digest":pins.deployment_digest,
        "worker_generation":pins.worker_generation,
        "started_marker_sha256":pins.started_marker_sha256,
        "controller_key_pin_sha256":pins.controller_key_pin_sha256,
        "controller_public_key_hex":pins.controller_public_key_hex,
        "report_sha256":format!("{:x}", Sha256::digest(report)),
        "pid":5432,
        "process_start_ticks":1234567,
        "exit_code":0,
        "status":"passed",
    })
}

fn terminal_bytes(value: &Value) -> Vec<u8> {
    canonicalize(value.to_string().as_bytes()).unwrap()
}

#[test]
fn host_anchor_is_exclusive_durable_and_readable_after_restart() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = HostControllerKeyPinJournal::open(&root).unwrap();
    assert_eq!(journal.read(JOB), Err(HostKeyPinError::Missing));
    let recorded = journal.record(&pins()).unwrap();
    assert_eq!(recorded.pins, pins());
    assert_eq!(recorded.raw_sha256.len(), 64);
    assert_eq!(recorded.to_json()["execution_eligible"], false);
    let path = root.join(format!("{JOB}.controller-key-pin.json"));
    let metadata = fs::metadata(&path).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(
        journal.record(&pins()),
        Err(HostKeyPinError::AlreadyRecorded)
    );
    drop(journal);
    let restarted = HostControllerKeyPinJournal::open(&root).unwrap();
    assert_eq!(restarted.read(JOB), Ok(recorded));
}

#[test]
fn invalid_or_partial_pin_never_becomes_a_new_job() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = HostControllerKeyPinJournal::open(&root).unwrap();
    let mut invalid = pins();
    invalid.controller_public_key_hex = "G".repeat(64);
    assert_eq!(journal.record(&invalid), Err(HostKeyPinError::InvalidPins));
    assert_eq!(journal.read(JOB), Err(HostKeyPinError::Missing));
    let path = root.join(format!("{JOB}.controller-key-pin.json"));
    fs::write(&path, b"partial").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(journal.read(JOB), Err(HostKeyPinError::UnsafeRecord));
    assert_eq!(
        journal.record(&pins()),
        Err(HostKeyPinError::AlreadyRecorded)
    );
}

#[test]
fn symlink_and_replaced_host_directory_refuse_pin_custody() {
    let temporary = tempfile::tempdir().unwrap();
    let parent = temporary.path().canonicalize().unwrap();
    let root = parent.join("pins");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let outside = parent.join("outside-controller-key-pin.json");
    fs::write(&outside, b"unchanged").unwrap();
    let link = root.join(format!("{JOB}.controller-key-pin.json"));
    symlink(&outside, &link).unwrap();
    let journal = HostControllerKeyPinJournal::open(&root).unwrap();
    assert_eq!(journal.read(JOB), Err(HostKeyPinError::UnsafeRecord));
    assert_eq!(
        journal.record(&pins()),
        Err(HostKeyPinError::AlreadyRecorded)
    );
    assert_eq!(fs::read(&outside).unwrap(), b"unchanged");

    let moved = parent.join("moved-pin-root");
    fs::rename(&root, &moved).unwrap();
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(journal.read(JOB), Err(HostKeyPinError::Changed));
    assert_eq!(journal.record(&pins()), Err(HostKeyPinError::Changed));
}

#[test]
fn retained_host_pin_binds_a_keyed_terminal_and_exact_report_bytes() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = HostControllerKeyPinJournal::open(&root).unwrap();
    journal.record(&pins()).unwrap();
    drop(journal);
    let retained = HostControllerKeyPinJournal::open(&root)
        .unwrap()
        .read(JOB)
        .unwrap();
    let report = br#"{"controls":{"passed":true},"schema":"test-report.v1"}"#;
    let base = keyed_terminal(&pins(), report);
    let observed = retained
        .observe_keyed_terminal(&terminal_bytes(&base), report)
        .unwrap();
    assert_eq!(observed.producer_status, "passed");
    assert_eq!(observed.host_pin_record_sha256, retained.raw_sha256);
    assert_eq!(observed.to_json()["execution_eligible"], false);

    for field in [
        "started_marker_sha256",
        "controller_key_pin_sha256",
        "controller_public_key_hex",
    ] {
        let mut changed = base.clone();
        changed[field] = json!("0".repeat(64));
        assert_eq!(
            retained.observe_keyed_terminal(&terminal_bytes(&changed), report),
            Err(HostKeyPinError::InvalidTerminal),
            "changed {field} must refuse"
        );
    }
    assert_eq!(
        retained.observe_keyed_terminal(&terminal_bytes(&base), b"{}"),
        Err(HostKeyPinError::InvalidTerminal)
    );
    let mut impossible = base.clone();
    impossible["exit_code"] = json!(1);
    assert_eq!(
        retained.observe_keyed_terminal(&terminal_bytes(&impossible), report),
        Err(HostKeyPinError::InvalidTerminal)
    );
    let mut legacy = base;
    legacy["schema"] = json!("hol-gauntlet-worker-terminal.v1");
    assert_eq!(
        retained.observe_keyed_terminal(&terminal_bytes(&legacy), report),
        Err(HostKeyPinError::InvalidTerminal)
    );
}

#[test]
fn acknowledgement_is_issued_only_after_the_exact_host_record_is_durable() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = HostControllerKeyPinJournal::open(&root).unwrap();
    let prepared = prepared(&pins());
    let raw = prepared.to_bytes().unwrap();
    let planned = planned_identity(&pins());
    let mut wrong = planned.clone();
    wrong.job_id = "0".repeat(16);
    let mut wrong_source = planned.clone();
    wrong_source.source_sha = "0".repeat(40);
    let mut wrong_deployment = planned.clone();
    wrong_deployment.deployment_digest = "0".repeat(64);
    let mut wrong_generation = planned.clone();
    wrong_generation.worker_generation = "0".repeat(64);
    for wrong in [wrong, wrong_source, wrong_deployment, wrong_generation] {
        assert_eq!(
            journal.accept_prepared(&raw, &wrong),
            Err(HostKeyPinError::WrongPreparedIdentity)
        );
    }
    assert_eq!(journal.read(JOB), Err(HostKeyPinError::Missing));
    let (record, acknowledgement) = journal.accept_prepared(&raw, &planned).unwrap();
    assert_eq!(record.pins, pins());
    assert_eq!(journal.read(JOB), Ok(record));
    assert_eq!(prepared.verify_acknowledgement(&acknowledgement), Ok(()));
    assert_eq!(
        journal.accept_prepared(&raw, &planned),
        Err(HostKeyPinError::AlreadyRecorded)
    );
    assert_eq!(
        journal.accept_prepared(b"{}", &planned),
        Err(HostKeyPinError::InvalidPins)
    );
}

#[test]
fn bounded_local_pipe_completes_the_host_pin_exchange() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = HostControllerKeyPinJournal::open(&root).unwrap();
    let pins = pins();
    let prepared = prepared(&pins);
    let planned = planned_identity(&pins);
    let (host, mut worker) = UnixStream::pair().unwrap();
    worker
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let child = thread::spawn(move || {
        worker.write_all(&prepared.to_bytes().unwrap()).unwrap();
        worker.write_all(b"\n").unwrap();
        let mut ack = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            worker.read_exact(&mut byte).unwrap();
            if byte[0] == b'\n' {
                break;
            }
            ack.push(byte[0]);
            assert!(ack.len() <= 1024);
        }
        prepared.verify_acknowledgement(&ack).unwrap();
    });
    let record = journal
        .accept_prepared_pipe(&host, &host, &planned, Duration::from_secs(2))
        .unwrap();
    child.join().unwrap();
    assert_eq!(record.pins, pins);
    assert_eq!(journal.read(JOB), Ok(record));
}

#[test]
fn bounded_pipe_refuses_missing_or_oversized_prepared_frames() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = HostControllerKeyPinJournal::open(&root).unwrap();
    let planned = planned_identity(&pins());
    let (host, _worker) = UnixStream::pair().unwrap();
    assert_eq!(
        journal.accept_prepared_pipe(&host, &host, &planned, Duration::from_millis(50)),
        Err(HostKeyPinError::TransportTimedOut)
    );
    let (host, mut worker) = UnixStream::pair().unwrap();
    worker.write_all(&vec![b'x'; 1025]).unwrap();
    assert_eq!(
        journal.accept_prepared_pipe(&host, &host, &planned, Duration::from_secs(1)),
        Err(HostKeyPinError::FrameTooLarge)
    );
    assert_eq!(journal.read(JOB), Err(HostKeyPinError::Missing));
}

#[test]
fn lost_ack_reader_leaves_the_durable_host_pin_unresolved() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = HostControllerKeyPinJournal::open(&root).unwrap();
    let planned = planned_identity(&pins());
    let (host, mut worker) = UnixStream::pair().unwrap();
    worker
        .write_all(&prepared(&pins()).to_bytes().unwrap())
        .unwrap();
    worker.write_all(b"\n").unwrap();
    worker.shutdown(Shutdown::Read).unwrap();
    let result = journal.accept_prepared_pipe(&host, &host, &planned, Duration::from_secs(1));
    assert!(matches!(
        result,
        Err(HostKeyPinError::TransportFailed | HostKeyPinError::TransportTimedOut)
    ));
    assert_eq!(journal.read(JOB).unwrap().pins, pins());
}
