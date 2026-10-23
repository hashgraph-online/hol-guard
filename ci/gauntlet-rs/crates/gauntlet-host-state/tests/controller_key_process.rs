use gauntlet_contracts::{canonicalize, PrelaunchPrepared, WorkerRequest};
use gauntlet_host_state::{HostControllerKeyPinJournal, HostKeyPinError, HostPrelaunchIdentity};
use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::Duration;

fn prepared() -> PrelaunchPrepared {
    PrelaunchPrepared {
        job_id: "a".repeat(16),
        source_sha: "b".repeat(40),
        deployment_digest: "c".repeat(64),
        worker_generation: "d".repeat(64),
        started_marker_sha256: "e".repeat(64),
        controller_key_pin_sha256: "f".repeat(64),
        controller_public_key_hex: "0".repeat(64),
    }
}

fn planned(prepared: &PrelaunchPrepared) -> HostPrelaunchIdentity {
    HostPrelaunchIdentity {
        job_id: prepared.job_id.clone(),
        source_sha: prepared.source_sha.clone(),
        deployment_digest: prepared.deployment_digest.clone(),
        worker_generation: prepared.worker_generation.clone(),
    }
}

fn journal() -> (tempfile::TempDir, HostControllerKeyPinJournal) {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = HostControllerKeyPinJournal::open(&root).unwrap();
    (temporary, journal)
}

fn child(script: &str, argument: &str) -> std::process::Child {
    Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .arg("prelaunch-test-peer")
        .arg(argument)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn request(prepared: &PrelaunchPrepared, job_id: &str) -> WorkerRequest {
    let value = json!({
        "schema":"hol-gauntlet-worker-request.v1",
        "action":"run",
        "source_sha":prepared.source_sha,
        "job_id":job_id,
        "deployment_digest":prepared.deployment_digest,
    });
    WorkerRequest::parse(&canonicalize(value.to_string().as_bytes()).unwrap()).unwrap()
}

#[test]
fn child_ack_follows_durable_host_record_and_replay_refuses() {
    let (temporary, journal) = journal();
    let prepared = prepared();
    let expected = planned(&prepared);
    let raw = String::from_utf8(prepared.to_bytes().unwrap()).unwrap();
    let script = "printf '%s\\n' \"$1\"; IFS= read -r ack; test -n \"$ack\"";
    let peer = child(script, &raw);
    let mut accepted = journal
        .accept_prepared_child(peer, &expected, Duration::from_secs(2))
        .unwrap();
    assert_eq!(accepted.record().pins.job_id, prepared.job_id);
    assert!(accepted.process_id().is_some());
    assert_eq!(journal.read(&prepared.job_id).unwrap(), *accepted.record());
    assert!(accepted
        .wait_bounded(Duration::from_secs(2))
        .unwrap()
        .success());
    let replay = journal
        .accept_prepared_child(child(script, &raw), &expected, Duration::from_secs(2))
        .err()
        .unwrap();
    assert_eq!(replay.reason, HostKeyPinError::AlreadyRecorded);
    assert!(replay.pin_recorded_or_uncertain);
    drop(temporary);
}

#[test]
fn child_timeout_and_wrong_identity_do_not_create_a_pin() {
    let (_temporary, journal) = journal();
    let prepared = prepared();
    let expected = planned(&prepared);
    let timeout = journal
        .accept_prepared_child(
            child("sleep 5", "unused"),
            &expected,
            Duration::from_millis(50),
        )
        .err()
        .unwrap();
    assert_eq!(timeout.reason, HostKeyPinError::TransportTimedOut);
    assert!(!timeout.pin_recorded_or_uncertain);
    assert_eq!(
        journal.read(&prepared.job_id),
        Err(HostKeyPinError::Missing)
    );

    let mut wrong = prepared.clone();
    wrong.source_sha = "1".repeat(40);
    let raw = String::from_utf8(wrong.to_bytes().unwrap()).unwrap();
    let refused = journal
        .accept_prepared_child(
            child("printf '%s\\n' \"$1\"", &raw),
            &expected,
            Duration::from_secs(2),
        )
        .err()
        .unwrap();
    assert_eq!(refused.reason, HostKeyPinError::WrongPreparedIdentity);
    assert!(!refused.pin_recorded_or_uncertain);
    assert_eq!(
        journal.read(&prepared.job_id),
        Err(HostKeyPinError::Missing)
    );
}

#[test]
fn host_process_timeout_after_ack_retains_the_one_use_pin() {
    let (_temporary, journal) = journal();
    let prepared = prepared();
    let expected = planned(&prepared);
    let raw = String::from_utf8(prepared.to_bytes().unwrap()).unwrap();
    let mut accepted = journal
        .accept_prepared_child(
            child(
                "printf '%s\\n' \"$1\"; IFS= read -r ack; test -n \"$ack\"; sleep 5",
                &raw,
            ),
            &expected,
            Duration::from_secs(2),
        )
        .unwrap();
    assert_eq!(
        accepted.wait_bounded(Duration::from_millis(50)),
        Err(HostKeyPinError::TransportTimedOut)
    );
    assert_eq!(journal.read(&prepared.job_id).unwrap(), *accepted.record());
    assert!(accepted.process_id().is_none());
}

#[test]
fn fixed_run_request_precedes_prepared_and_wrong_job_refuses() {
    let (_temporary, first_journal) = journal();
    let prepared = prepared();
    let expected = planned(&prepared);
    let raw = String::from_utf8(prepared.to_bytes().unwrap()).unwrap();
    let script = "IFS= read -r request; test -n \"$request\" || exit 2; printf '%s\\n' \"$1\"; IFS= read -r ack; test -n \"$ack\"";
    let mut accepted = first_journal
        .send_run_request_and_accept_prepared_child(
            child(script, &raw),
            &request(&prepared, &prepared.job_id),
            &expected,
            Duration::from_secs(2),
        )
        .unwrap();
    assert!(accepted
        .wait_bounded(Duration::from_secs(2))
        .unwrap()
        .success());
    assert_eq!(
        first_journal.read(&prepared.job_id).unwrap(),
        *accepted.record()
    );

    let (_temporary, second_journal) = journal();
    let refused = second_journal
        .send_run_request_and_accept_prepared_child(
            child(script, &raw),
            &request(&prepared, &"1".repeat(16)),
            &expected,
            Duration::from_secs(2),
        )
        .err()
        .unwrap();
    assert_eq!(refused.reason, HostKeyPinError::WrongRequest);
    assert!(!refused.pin_recorded_or_uncertain);
    assert_eq!(
        second_journal.read(&prepared.job_id),
        Err(HostKeyPinError::Missing)
    );
}

#[test]
fn final_guest_result_is_bounded_after_durable_host_ack() {
    let (_temporary, journal) = journal();
    let prepared = prepared();
    let expected = planned(&prepared);
    let raw = String::from_utf8(prepared.to_bytes().unwrap()).unwrap();
    let script = "IFS= read -r request; test -n \"$request\" || exit 2; printf '%s\\n' \"$1\"; IFS= read -r ack; test -n \"$ack\" || exit 2; printf '%s\\n' '{\"ok\":true}'";
    let mut accepted = journal
        .send_run_request_and_accept_prepared_child(
            child(script, &raw),
            &request(&prepared, &prepared.job_id),
            &expected,
            Duration::from_secs(2),
        )
        .unwrap();
    assert_eq!(
        accepted.wait_bounded_result(Duration::from_secs(2), 64),
        Ok(b"{\"ok\":true}\n".to_vec())
    );
    assert_eq!(journal.read(&prepared.job_id).unwrap(), *accepted.record());
}

#[test]
fn oversized_guest_result_cannot_replace_the_host_pin() {
    let (_temporary, journal) = journal();
    let prepared = prepared();
    let expected = planned(&prepared);
    let raw = String::from_utf8(prepared.to_bytes().unwrap()).unwrap();
    let script =
        "printf '%s\\n' \"$1\"; IFS= read -r ack; test -n \"$ack\" || exit 2; printf '%0200d\\n' 0";
    let mut accepted = journal
        .accept_prepared_child(child(script, &raw), &expected, Duration::from_secs(2))
        .unwrap();
    assert_eq!(
        accepted.wait_bounded_result(Duration::from_secs(2), 64),
        Err(HostKeyPinError::FrameTooLarge)
    );
    assert_eq!(journal.read(&prepared.job_id).unwrap(), *accepted.record());
}
