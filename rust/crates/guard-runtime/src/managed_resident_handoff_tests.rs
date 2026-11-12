use super::{
    refuses_handoff, refuses_shutdown, rejects_runtime_request,
    retire_foreign_resident_rejecting_request, retire_orphaned_foreign_resident,
    shutdown_acknowledged, shutdown_intent, wait_for_resident_stop_containment, ShutdownIntent,
    HANDOFF_SHUTDOWN_REQUEST, SHUTDOWN_REFUSED_IN_USE, STOP_SHUTDOWN_REQUEST,
};
use crate::resident_protocol::ResidentOperationV1;
use crate::resident_state::{
    discover_states, process_start_marker, publish_state, runtime_digest, ResidentState,
};
use std::fs;
use std::time::{Duration, Instant};

fn test_root(label: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-handoff-{label}-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    fs::create_dir(&root).unwrap();
    root
}

fn state(runtime_sha256: &str) -> ResidentState {
    ResidentState {
        schema: "hol-guard-resident-state.v3".to_owned(),
        generation: 1,
        process_id: u32::MAX,
        process_start_marker: "resident".to_owned(),
        owner_process_id: u32::MAX,
        owner_process_start_marker: "dead".to_owned(),
        runtime_sha256: runtime_sha256.to_owned(),
        transport: "loopback".to_owned(),
        endpoint: "127.0.0.1:9".to_owned(),
        unix_endpoint_identity: None,
        token_hex: String::new(),
        created_ms: 1,
        state_mac: String::new(),
    }
}

/// Publish a live lease of `digest` for this process. The lease directory
/// must already exist, for example from `lease::acquire`.
fn write_lease(root: &std::path::Path, digest: &str) {
    let pid = std::process::id();
    let marker = process_start_marker(pid).unwrap();
    let lease = root
        .join("resident-client-leases.v1")
        .join(format!("client-{}.lease", &digest[..8]));
    fs::write(&lease, format!("{pid}\n{marker}\n{digest}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease, fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(windows)]
    crate::resident_state::protect_windows_private_path(&lease, false, root).unwrap();
}

#[test]
fn only_a_foreign_resident_without_its_own_clients_is_shut_down() {
    let root = test_root("orphaned");
    let digest = runtime_digest().unwrap();
    let foreign_digest = "f".repeat(64);
    // Newer clients' leases do not make an older resident in use.
    let current_lease = super::lease::acquire(&root).unwrap();
    let probe = || super::lease::unless_live(&root, &foreign_digest, || ()).is_some();
    assert!(probe());
    // A resident of this runtime is never handed over.
    let deadline = Instant::now() + Duration::from_millis(200);
    assert!(!retire_orphaned_foreign_resident(
        &root,
        &root,
        &state(&digest),
        &digest,
        deadline
    ));

    write_lease(&root, &foreign_digest);
    assert!(!probe());
    assert!(!retire_orphaned_foreign_resident(
        &root,
        &root,
        &state(&foreign_digest),
        &digest,
        deadline
    ));
    drop(current_lease);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn only_a_stop_acknowledgement_counts_as_shut_down() {
    assert!(shutdown_acknowledged(br#"{"status":"stopping"}"#));
    assert!(shutdown_acknowledged(br#"{"status":"stopped"}"#));
    assert!(!shutdown_acknowledged(
        br#"{"status":"stopping","error":"native_request_expired"}"#
    ));
    assert!(!shutdown_acknowledged(
        br#"{"error":"native_resident_overloaded"}"#
    ));
    assert!(!shutdown_acknowledged(b"not json"));
}

#[test]
fn stop_containment_leaves_a_replacement_resident_alone() {
    let root = test_root("replacement");
    let digest = runtime_digest().unwrap();
    // A client of the stopped runtime started a replacement meanwhile.
    publish_state(
        &root,
        2,
        std::process::id(),
        &digest,
        "loopback",
        "127.0.0.1:1".to_owned(),
        &[7u8; crate::AUTH_TOKEN_BYTES],
    )
    .unwrap();
    let stopped = state(&digest);
    let deadline = Instant::now() + Duration::from_millis(200);
    assert!(wait_for_resident_stop_containment(&root, &stopped, deadline, &[]).is_ok());
    assert_eq!(discover_states(&root, &digest).unwrap().len(), 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn only_identity_and_unsupported_schema_rejections_count_as_rejecting_request() {
    assert!(rejects_runtime_request(
        br#"{"error":"snapshot_runtime_identity_mismatch","retryable":false}"#
    ));
    assert!(rejects_runtime_request(
        br#"{"error":"native_request_schema_unsupported","retryable":false}"#
    ));
    // Safe-error mapping folds unlisted errors into this code; it is not a
    // version signal.
    assert!(!rejects_runtime_request(
        br#"{"error":"native_request_invalid_json","retryable":false}"#
    ));
    assert!(!rejects_runtime_request(
        br#"{"error":"snapshot_rule_digest_mismatch","retryable":false}"#
    ));
    assert!(!rejects_runtime_request(br#"{"status":"accepted"}"#));
    assert!(!rejects_runtime_request(b"not json"));
}

#[test]
fn a_request_rejection_retires_only_an_acknowledging_foreign_resident() {
    let root = test_root("policy-rejection");
    let digest = runtime_digest().unwrap();
    let rejection = br#"{"error":"snapshot_runtime_identity_mismatch","retryable":false}"#;
    let deadline = Instant::now() + Duration::from_millis(200);
    // A resident of this runtime is never replaced by its own client.
    assert!(!retire_foreign_resident_rejecting_request(
        &root,
        &state(&digest),
        &digest,
        rejection,
        deadline
    ));
    let unsupported = br#"{"error":"native_request_schema_unsupported","retryable":false}"#;
    assert!(!retire_foreign_resident_rejecting_request(
        &root,
        &state(&digest),
        &digest,
        unsupported,
        deadline
    ));
    // A foreign resident that answers some other error, including the code
    // every unlisted failure is rewritten to, keeps its clients' grants.
    for other in [
        &br#"{"error":"native_request_invalid_json","retryable":false}"#[..],
        &br#"{"error":"native_resident_overloaded","retryable":true}"#[..],
    ] {
        assert!(!retire_foreign_resident_rejecting_request(
            &root,
            &state(&"f".repeat(64)),
            &digest,
            other,
            deadline
        ));
    }
    // Any other answer from a foreign resident is returned to the caller.
    assert!(!retire_foreign_resident_rejecting_request(
        &root,
        &state(&"f".repeat(64)),
        &digest,
        br#"{"status":"accepted"}"#,
        deadline
    ));
    // A foreign resident that does not acknowledge the shutdown stays.
    assert!(!retire_foreign_resident_rejecting_request(
        &root,
        &state(&"f".repeat(64)),
        &digest,
        rejection,
        deadline
    ));
    fs::remove_dir_all(root).unwrap();
}

fn shutdown_body(payload: &[u8]) -> serde_json::Value {
    let value = crate::strict_json_value(payload).unwrap();
    match crate::strict_json::from_value::<ResidentOperationV1>(value).unwrap() {
        ResidentOperationV1::Shutdown(body) => body,
        other => panic!("not a shutdown: {other:?}"),
    }
}

#[test]
fn regression_handoff_shutdown_is_refused_while_own_clients_use_the_published_runtime() {
    // Two installs shared one home: the publisher bound every snapshot to
    // runtime A, while an older install's hook (runtime B) reached A's
    // resident, was rejected and asked it to shut down although A's clients
    // held live leases. B's resident then exited on A's snapshot, A's clients
    // restarted A, and the two stopped each other every few seconds until
    // B's restart budget opened. Shipped clients still send that handoff, so
    // A's resident refuses it.
    let root = test_root("refuse-handoff");
    let digest = runtime_digest().unwrap();
    let own_lease = super::lease::acquire(&root).unwrap();
    // Older clients send a bare request; current ones name the handoff.
    for request in [
        serde_json::json!({}),
        serde_json::json!({"intent": "handoff"}),
    ] {
        assert!(refuses_handoff(&request, &root, &digest, || Some(
            digest.clone()
        )));
    }
    assert_eq!(SHUTDOWN_REFUSED_IN_USE, "native_resident_in_use");
    // A refusal is not an acknowledgement, so the handoff client returns
    // the rejection instead of retrying.
    assert!(!shutdown_acknowledged(
        br#"{"error":"native_resident_in_use","retryable":false}"#
    ));
    drop(own_lease);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn handoff_shutdown_is_honoured_when_the_home_publishes_for_another_runtime() {
    // The legitimate handoff: the publisher moved to another runtime.
    let root = test_root("handoff-other-publisher");
    let digest = runtime_digest().unwrap();
    let own_lease = super::lease::acquire(&root).unwrap();
    assert!(!refuses_handoff(
        &serde_json::json!({}),
        &root,
        &digest,
        || Some("e".repeat(64))
    ));
    drop(own_lease);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn handoff_shutdown_is_honoured_when_the_published_snapshot_cannot_be_read() {
    // `published_runtime_identity` answers `None` for a missing, unreadable,
    // malformed or unauthenticated publisher snapshot; any doubt stops.
    let root = test_root("handoff-unreadable");
    let digest = runtime_digest().unwrap();
    let own_lease = super::lease::acquire(&root).unwrap();
    assert!(!refuses_handoff(
        &serde_json::json!({}),
        &root,
        &digest,
        || None
    ));
    // Without a policy store nothing is known about the publisher.
    assert!(!refuses_shutdown(&serde_json::json!({}), None));
    drop(own_lease);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn handoff_shutdown_is_honoured_when_no_own_client_is_live() {
    let root = test_root("handoff-unused");
    let digest = runtime_digest().unwrap();
    let published = || Some(digest.clone());
    // No lease at all.
    assert!(!refuses_handoff(
        &serde_json::json!({}),
        &root,
        &digest,
        published
    ));
    // Only another runtime's client is live.
    let other_digest = "e".repeat(64);
    let own_lease = super::lease::acquire(&root).unwrap();
    drop(own_lease);
    write_lease(&root, &other_digest);
    assert!(!refuses_handoff(
        &serde_json::json!({}),
        &root,
        &digest,
        published
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn an_explicit_stop_is_always_honoured() {
    let root = test_root("explicit-stop");
    let digest = runtime_digest().unwrap();
    let own_lease = super::lease::acquire(&root).unwrap();
    assert!(!refuses_handoff(
        &shutdown_body(STOP_SHUTDOWN_REQUEST),
        &root,
        &digest,
        || Some(digest.clone())
    ));
    drop(own_lease);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_bare_legacy_shutdown_parses_as_a_handoff() {
    assert_eq!(
        shutdown_intent(&shutdown_body(br#"{"operation":"shutdown","request":{}}"#)),
        ShutdownIntent::Handoff
    );
    assert_eq!(
        shutdown_intent(&shutdown_body(HANDOFF_SHUTDOWN_REQUEST)),
        ShutdownIntent::Handoff
    );
    assert_eq!(
        shutdown_intent(&shutdown_body(STOP_SHUTDOWN_REQUEST)),
        ShutdownIntent::Stop
    );
    // Anything but an explicit stop may be refused, never the reverse.
    assert_eq!(
        shutdown_intent(&serde_json::json!({"intent": "later"})),
        ShutdownIntent::Handoff
    );
    assert_eq!(
        shutdown_intent(&serde_json::Value::Null),
        ShutdownIntent::Handoff
    );
}

#[cfg(unix)]
#[test]
fn regression_a_fifo_named_like_a_lease_does_not_block_the_refusal_probe() {
    // `DirEntry::file_type` does not follow links, and only a regular file is
    // opened, so a FIFO planted in the lease directory answers "not live"
    // instead of blocking the resident's shutdown answer on its open.
    let root = test_root("handoff-fifo");
    let digest = runtime_digest().unwrap();
    drop(super::lease::acquire(&root).unwrap());
    let fifo = root
        .join("resident-client-leases.v1")
        .join(format!("client-{}.lease", &digest[..8]));
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success());
    let (sender, receiver) = std::sync::mpsc::channel();
    let probe_root = root.clone();
    let probe_digest = digest.clone();
    std::thread::spawn(move || {
        let _ = sender.send(super::lease::definitely_live(&probe_root, &probe_digest));
    });
    let answer = receiver.recv_timeout(Duration::from_secs(10));
    if answer.is_err() {
        // Release a probe stuck on the FIFO's open before failing.
        let _ = fs::OpenOptions::new().write(true).open(&fifo);
    }
    assert_eq!(answer, Ok(false));
    fs::remove_dir_all(root).unwrap();
}
