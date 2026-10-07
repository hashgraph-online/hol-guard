use super::*;

#[test]
fn restart_mapping_retains_hard_failure_without_swallowing_unrelated_errors() {
    let mut cause = None;
    assert_eq!(
        retain_live_failure(
            Err("native_resident_live_request_failed:native_client_auth_rejected".into()),
            &mut cause
        ),
        Ok(None)
    );
    assert_eq!(
        cause.as_deref(),
        Some("native_resident_live_request_failed:native_client_auth_rejected")
    );
    for code in [
        "native_resident_state_mac_invalid",
        "native_client_deadline_exceeded",
        "native_resident_live_request_failed_extra",
        "native_resident_live_request_failed",
    ] {
        let error = code.to_owned();
        assert_eq!(
            retain_live_failure(Err(error.clone()), &mut cause),
            Err(error)
        );
    }
    assert_eq!(
        retain_live_failure(Ok(Some(b"response".to_vec())), &mut cause),
        Ok(Some(b"response".to_vec()))
    );
}

#[cfg(unix)]
#[test]
fn authenticated_initial_probe_reaches_restart_and_preserves_auth_failure() {
    // Run the real initial-probe path in a child so the diagnostic stream is
    // asserted as well as the registered Result error code.
    if std::env::var_os("HOL_GUARD_RETRY_DIAGNOSTIC_TEST_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("authenticated_initial_probe_reaches_restart_and_preserves_auth_failure")
            .arg("--nocapture")
            .env("HOL_GUARD_RETRY_DIAGNOSTIC_TEST_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains(
            "native_resident_recovery_previous_failure=native_resident_live_request_failed:native_client_auth_rejected"
        ));
        return;
    }
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};
    let root = std::env::temp_dir().join(format!(
        "hol-guard-live-failure-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let digest = runtime_digest().unwrap();
    let scope = state_scope(&root, &digest).unwrap();
    crate::resident_state::publish_state(
        &scope,
        1,
        std::process::id(),
        &digest,
        "loopback",
        endpoint,
        &[7; crate::AUTH_TOKEN_BYTES],
    )
    .unwrap();
    let worker = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut requests = 0;
        while requests < 2 && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    // The client revalidates process identity after connect
                    // and before sending its nonce. Let the fixture honor the
                    // client's four-second budget rather than closing early.
                    stream
                        .set_read_timeout(Some(Duration::from_secs(4)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(4)))
                        .unwrap();
                    let mut nonce = [0; crate::AUTH_NONCE_BYTES];
                    stream.read_exact(&mut nonce).unwrap();
                    stream.write_all(&[0; crate::AUTH_PROOF_BYTES]).unwrap();
                    requests += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("test listener failed: {error}"),
            }
        }
        requests
    });
    let client_lease = lease::acquire(&root).unwrap();
    let result = client_request_with_deadline(
        &root,
        b"{}",
        Instant::now() + Duration::from_secs(4),
        &client_lease,
    );
    let probes = worker.join().unwrap();
    drop(client_lease);
    fs::remove_dir_all(&root).unwrap();
    let error = result.unwrap_err();
    // Reaching the spawn admission gate proves both the initial probe and the
    // lock-protected probe recovered; no replacement process is actually started.
    assert_eq!(probes, 2);
    assert_eq!(error, "native_policy_verifier_key_missing");
}
