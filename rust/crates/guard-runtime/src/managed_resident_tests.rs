use super::*;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[test]
fn generation_parser_rejects_zero_and_non_numeric() {
    assert!(parse_generation("0").is_err());
    assert!(parse_generation("not-a-number").is_err());
    assert_eq!(parse_generation("7").unwrap(), 7);
}

#[test]
fn client_deadline_is_bounded() {
    assert_eq!(
        client_timeout(br#"{"deadline_budget_ms":999999}"#),
        Duration::from_secs(9)
    );
    assert_eq!(client_timeout(br#"{}"#), Duration::from_millis(750));
}

#[test]
fn client_stream_eof_is_clean_and_partial_headers_fail_closed() {
    use std::io::Cursor;

    assert_eq!(
        read_client_stream_frame(&mut Cursor::new(Vec::<u8>::new())).unwrap(),
        None
    );
    let error = read_client_stream_frame(&mut Cursor::new(vec![0, 0])).unwrap_err();
    assert_eq!(error, "native_client_stream_frame_truncated");
}

#[test]
fn client_stream_frames_are_bounded_and_big_endian() {
    use std::io::Cursor;

    let mut encoded = Vec::new();
    write_client_stream_frame(&mut encoded, b"{}").unwrap();
    assert_eq!(&encoded[..4], &[0, 0, 0, 2]);
    assert_eq!(
        read_client_stream_frame(&mut Cursor::new(encoded)).unwrap(),
        Some(b"{}".to_vec())
    );
    let oversized = vec![0xff; crate::MAX_NATIVE_RESPONSE_BYTES + 1];
    assert_eq!(
        write_client_stream_frame(&mut Vec::new(), &oversized).unwrap_err(),
        "native_client_stream_response_too_large"
    );
}

#[test]
fn client_leases_keep_shared_resident_alive_until_last_client_closes() {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-client-lease-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let digest = runtime_digest().unwrap();
    let first = lease::acquire(&root).unwrap();
    let second = lease::acquire(&root).unwrap();
    assert!(lease::any_live(&root, &digest));
    let foreign = root
        .join("resident-client-leases.v1")
        .join("client-foreign.lease");
    fs::write(
        &foreign,
        format!(
            "{}\n{}\n{}\n",
            std::process::id(),
            process_start_marker(std::process::id()).unwrap(),
            "f".repeat(64)
        ),
    )
    .unwrap();
    #[cfg(windows)]
    crate::resident_state::protect_windows_private_path(&foreign, false).unwrap();
    assert!(lease::any_live_for_home(&root));
    drop(first);
    assert!(lease::any_live(&root, &digest));
    drop(second);
    assert!(!lease::any_live(&root, &digest));
    fs::remove_file(foreign).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn stale_lease_cleanup_requires_a_dead_process_identity() {
    use std::fs;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-stale-lease-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let directory = root.join("resident-client-leases.v1");
    fs::create_dir(&directory).unwrap();
    let current_process_lease = directory.join("client-current.lease");
    fs::write(
        &current_process_lease,
        format!(
            "{}\n{}\n{}\n",
            std::process::id(),
            process_start_marker(std::process::id()).unwrap(),
            "f".repeat(64)
        ),
    )
    .unwrap();
    let dead_process_lease = directory.join("client-dead.lease");
    fs::write(
        &dead_process_lease,
        "4294967295\nstale\n".to_owned() + &"e".repeat(64) + "\n",
    )
    .unwrap();
    #[cfg(windows)]
    {
        crate::resident_state::protect_windows_private_path(&directory, true).unwrap();
        crate::resident_state::protect_windows_private_path(&current_process_lease, false).unwrap();
        crate::resident_state::protect_windows_private_path(&dead_process_lease, false).unwrap();
    }
    std::thread::sleep(lease::LEASE_EXPIRY + Duration::from_millis(100));
    assert!(!lease::any_live_for_home(&root));
    assert!(current_process_lease.exists());
    assert!(!dead_process_lease.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn lease_directory_overflow_fails_closed_without_unbounded_collection() {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-lease-overflow-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(root.join("resident-client-leases.v1")).unwrap();
    #[cfg(unix)]
    {
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            root.join("resident-client-leases.v1"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    #[cfg(windows)]
    {
        crate::resident_state::protect_windows_private_path(&root, true).unwrap();
        crate::resident_state::protect_windows_private_path(
            &root.join("resident-client-leases.v1"),
            true,
        )
        .unwrap();
    }
    for index in 0..=64 {
        let path = root
            .join("resident-client-leases.v1")
            .join(format!("client-{index:03}.lease"));
        fs::write(&path, format!("4294967295\nstale\n{}\n", "e".repeat(64))).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        #[cfg(windows)]
        crate::resident_state::protect_windows_private_path(&path, false).unwrap();
    }
    assert!(lease::any_live_for_home(&root));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn owner_liveness_expires_after_launcher_and_all_clients_disappear() {
    use std::fs;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-owner-liveness-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let lease = lease::acquire(&root).unwrap();
    let alive = managed_owner_liveness(&root, 1, "never-matches".to_owned());
    std::thread::sleep(Duration::from_millis(150));
    assert!(alive.load(Ordering::Acquire));
    drop(lease);
    for _ in 0..40 {
        if !alive.load(Ordering::Acquire) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!alive.load(Ordering::Acquire));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn stale_process_identity_errors_are_platform_scoped() {
    let stale_unavailable =
        is_stale_process_identity_error("native_resident_process_identity_unavailable");
    let stale_mismatch =
        is_stale_process_identity_error("native_resident_process_identity_mismatch");
    assert!(stale_unavailable);
    assert!(stale_mismatch);
    assert!(!is_stale_process_identity_error(
        "native_resident_state_mac_invalid"
    ));
    assert!(!is_stale_process_identity_error(
        "native_client_auth_rejected"
    ));
}

#[test]
fn stale_transport_retry_allowlist_preserves_auth_and_integrity_failures() {
    let retryable_codes = [
        "native_client_connect_failed",
        "native_resident_process_identity_unavailable",
        "native_resident_process_identity_mismatch",
    ];
    for code in retryable_codes {
        assert!(is_retryable_live_request_error(
            &crate::resident_client::ResidentClientError {
                code: code.to_owned(),
                retryable_teardown: false,
            }
        ));
    }

    let terminal_codes = [
        "native_client_frame_read_failed",
        "native_client_frame_write_failed",
        "native_client_auth_rejected",
        "native_client_peer_identity_mismatch",
        "native_client_response_binding_failed",
        "native_client_response_digest_mismatch",
    ];
    for code in terminal_codes {
        assert!(!is_retryable_live_request_error(
            &crate::resident_client::ResidentClientError {
                code: code.to_owned(),
                retryable_teardown: false,
            }
        ));
    }
    for code in [
        "native_client_frame_read_failed",
        "native_client_frame_write_failed",
    ] {
        assert!(is_retryable_live_request_error(
            &crate::resident_client::ResidentClientError {
                code: code.to_owned(),
                retryable_teardown: true,
            }
        ));
    }
    assert!(is_retryable_live_request_error(
        &crate::resident_client::ResidentClientError {
            code: "native_client_auth_nonce_failed".to_owned(),
            retryable_teardown: true,
        }
    ));
    assert!(!is_retryable_live_request_error(
        &crate::resident_client::ResidentClientError {
            code: "native_client_auth_nonce_failed".to_owned(),
            retryable_teardown: false,
        }
    ));
}

#[cfg(unix)]
#[test]
fn managed_owner_lock_is_exclusive_for_resident_lifetime() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-owner-lock-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

    let first = acquire_managed_owner_lock(&root).unwrap();
    assert!(matches!(
        acquire_managed_owner_lock(&root),
        Err(error) if error == "native_resident_owner_busy"
    ));
    let marker = root.join(MANAGED_OWNER_LOCK_FILE_NAME);
    let displaced = root.join("managed-resident-owner.v1.lock.displaced");
    fs::rename(&marker, &displaced).unwrap();
    fs::write(&marker, []).unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        acquire_managed_owner_lock(&root),
        Err(error) if error == "native_resident_owner_busy"
    ));
    drop(first);
    let second = acquire_managed_owner_lock(&root).unwrap();
    drop(second);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn managed_owner_lock_rejects_second_process() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::time::{SystemTime, UNIX_EPOCH};

    if let Some(root) = std::env::var_os("HOL_GUARD_OWNER_LOCK_CHILD") {
        let root = PathBuf::from(root);
        let _lock = acquire_managed_owner_lock(&root).unwrap();
        fs::write(root.join("child-ready"), []).unwrap();
        std::thread::sleep(Duration::from_secs(5));
        return;
    }

    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-owner-lock-process-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let marker = root.join("child-ready");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("managed_owner_lock_rejects_second_process")
        .arg("--nocapture")
        .env(
            "HOL_GUARD_OWNER_LOCK_CHILD",
            root.to_string_lossy().as_ref(),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let mut child_ready = false;
    for _ in 0..200 {
        if marker.exists() {
            child_ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let result = if child_ready {
        acquire_managed_owner_lock(&root)
    } else {
        Err("child_not_ready".to_owned())
    };
    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_dir_all(&root);

    assert!(child_ready, "child process did not acquire the owner lock");
    assert!(matches!(
        result,
        Err(error) if error == "native_resident_owner_busy"
    ));
}
