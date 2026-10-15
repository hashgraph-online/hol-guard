use super::{
    rejects_runtime_request, retire_foreign_resident_rejecting_request,
    retire_orphaned_foreign_resident, shutdown_acknowledged, wait_for_resident_stop_containment,
};
use crate::resident_state::{
    discover_states, process_start_marker, publish_state, runtime_digest, ResidentState,
};
use std::fs;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn test_root(label: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-handoff-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
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

#[test]
fn only_a_foreign_resident_without_its_own_clients_is_shut_down() {
    let root = test_root("orphaned");
    let digest = runtime_digest().unwrap();
    let foreign_digest = "f".repeat(64);
    let pid = std::process::id();
    let marker = process_start_marker(pid).unwrap();
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

    let foreign_lease = root
        .join("resident-client-leases.v1")
        .join("client-foreign.lease");
    fs::write(
        &foreign_lease,
        format!("{pid}\n{marker}\n{foreign_digest}\n"),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&foreign_lease, fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(windows)]
    crate::resident_state::protect_windows_private_path(&foreign_lease, false, &root).unwrap();
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
