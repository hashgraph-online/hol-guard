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
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!(
        "hol-guard-live-failure-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
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
                    // Accepted sockets inherit nonblocking mode on some Unix hosts.
                    stream.set_nonblocking(false).unwrap();
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

#[test]
fn a_state_whose_pid_was_reused_does_not_count_as_live() {
    let process_id = std::process::id();
    let marker = crate::resident_state::process_start_marker(process_id).unwrap();
    let mut state = crate::resident_state::ResidentState {
        schema: String::new(),
        generation: 1,
        process_id,
        process_start_marker: marker,
        owner_process_id: process_id,
        owner_process_start_marker: String::new(),
        runtime_sha256: String::new(),
        transport: String::new(),
        endpoint: String::new(),
        unix_endpoint_identity: None,
        token_hex: String::new(),
        created_ms: 1,
        state_mac: String::new(),
    };
    assert!(state_may_be_live(&state));
    state.process_start_marker = "stale-process-marker".to_owned();
    assert!(!state_may_be_live(&state));
}

/// A private `<home>/native-runtime` state base with this runtime's empty scope,
/// so discovery sees no live resident.
fn owner_release_fixture(label: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    use std::fs;
    let home = std::env::temp_dir().join(format!(
        "hol-guard-owner-release-{label}-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    let base = home.join("native-runtime");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&base).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    }
    state_scope(&base, &runtime_digest().unwrap()).unwrap();
    (home, base)
}

#[test]
fn owner_release_waits_for_an_exiting_owner() {
    use std::sync::mpsc;
    let (home, base) = owner_release_fixture("exiting");
    let digest = runtime_digest().unwrap();
    let (held, wait_held) = mpsc::channel();
    let holder_base = base.clone();
    // The holder has no generation file, like a resident that retired its
    // state and is still on its way out.
    let holder = thread::spawn(move || {
        let lock = crate::managed_resident::acquire_managed_owner_lock(&holder_base).unwrap();
        held.send(()).unwrap();
        thread::sleep(Duration::from_millis(200));
        drop(lock);
    });
    wait_held.recv().unwrap();
    let started = Instant::now();
    let result = await_owner_release(&base, &digest, started + Duration::from_secs(10));
    let waited = started.elapsed();
    holder.join().unwrap();
    let successor = crate::managed_resident::acquire_managed_owner_lock(&base).map(drop);
    std::fs::remove_dir_all(&home).unwrap();
    assert_eq!(result, Ok(()));
    assert!(
        waited >= Duration::from_millis(100),
        "returned while the owner was held"
    );
    assert!(
        successor.is_ok(),
        "a successor could not take the released lock"
    );
}

#[test]
fn owner_release_names_an_owner_kept_past_the_deadline() {
    let (home, base) = owner_release_fixture("foreign");
    let digest = runtime_digest().unwrap();
    let lock = crate::managed_resident::acquire_managed_owner_lock(&base).unwrap();
    let result = await_owner_release(&base, &digest, Instant::now() + Duration::from_millis(100));
    drop(lock);
    std::fs::remove_dir_all(&home).unwrap();
    assert_eq!(result, Err("native_resident_owner_busy".to_owned()));
}

#[test]
fn owner_release_names_a_live_foreign_owner_at_once() {
    let (home, base) = owner_release_fixture("foreign-live");
    let lock = crate::managed_resident::acquire_managed_owner_lock(&base).unwrap();
    let started = Instant::now();
    let mut probes = 0;
    let result = await_owner_release_with(&base, started + Duration::from_secs(10), || {
        probes += 1;
        OwnerHolder::OtherRuntime
    });
    let waited = started.elapsed();
    drop(lock);
    std::fs::remove_dir_all(&home).unwrap();
    assert_eq!(result, Err("native_resident_owner_busy".to_owned()));
    assert_eq!(probes, 1, "a live foreign owner was polled");
    assert!(
        waited < Duration::from_secs(1),
        "waited {waited:?} on a live foreign owner"
    );
}

#[test]
fn owner_release_caps_the_wait_for_an_exiting_owner() {
    let (home, base) = owner_release_fixture("cap");
    let digest = runtime_digest().unwrap();
    let lock = crate::managed_resident::acquire_managed_owner_lock(&base).unwrap();
    let started = Instant::now();
    let result = await_owner_release(&base, &digest, started + Duration::from_secs(30));
    let waited = started.elapsed();
    drop(lock);
    std::fs::remove_dir_all(&home).unwrap();
    assert_eq!(result, Err("native_resident_owner_busy".to_owned()));
    assert!(waited >= OWNER_RELEASE_WAIT, "returned after {waited:?}");
    assert!(
        waited < OWNER_RELEASE_WAIT + Duration::from_secs(3),
        "the startup deadline replaced the release cap: {waited:?}"
    );
}

#[test]
fn owner_release_classifies_the_lock_holder_by_live_state() {
    let process_id = std::process::id();
    let marker = crate::resident_state::process_start_marker(process_id).unwrap();
    let state =
        |runtime_sha256: &str, process_start_marker: &str| crate::resident_state::ResidentState {
            schema: String::new(),
            generation: 1,
            process_id,
            process_start_marker: process_start_marker.to_owned(),
            owner_process_id: process_id,
            owner_process_start_marker: String::new(),
            runtime_sha256: runtime_sha256.to_owned(),
            transport: String::new(),
            endpoint: String::new(),
            unix_endpoint_identity: None,
            token_hex: String::new(),
            created_ms: 1,
            state_mac: String::new(),
        };
    let own = state("own-digest", &marker);
    let foreign = state("foreign-digest", &marker);
    let stale_foreign = state("foreign-digest", "stale-process-marker");
    assert_eq!(
        classify_owner_holder([], "own-digest"),
        OwnerHolder::Exiting
    );
    assert_eq!(
        classify_owner_holder([&stale_foreign], "own-digest"),
        OwnerHolder::Exiting
    );
    assert_eq!(
        classify_owner_holder([&foreign], "own-digest"),
        OwnerHolder::OtherRuntime
    );
    assert_eq!(
        classify_owner_holder([&foreign, &own], "own-digest"),
        OwnerHolder::ThisRuntime
    );
}

/// A private state base for a live-failure fixture, like the one the
/// authenticated probe test builds. Unix mode bits keep the published token
/// out of other users' reach; the Windows spawn path is covered separately.
#[cfg(unix)]
fn private_live_root(label: &str) -> std::path::PathBuf {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!(
        "hol-guard-live-{label}-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    root
}

#[cfg(unix)]
#[test]
fn a_published_endpoint_nobody_serves_is_replaced_rather_than_reported() {
    // Bind and release, so the address belongs to this host and nothing
    // answers on it: the shape a resident leaves behind when it dies without
    // retiring its state.
    let endpoint = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().to_string()
    };
    let root = private_live_root("dead-port");
    let digest = runtime_digest().unwrap();
    let scope = state_scope(&root, &digest).unwrap();
    crate::resident_state::publish_state(
        &scope,
        1,
        std::process::id(),
        &digest,
        "loopback",
        endpoint,
        &[11; crate::AUTH_TOKEN_BYTES],
    )
    .unwrap();
    let client_lease = lease::acquire(&root).unwrap();
    let result = client_request_with_deadline(
        &root,
        b"{}",
        Instant::now() + Duration::from_secs(4),
        &client_lease,
    );
    drop(client_lease);
    std::fs::remove_dir_all(&root).unwrap();
    // A refused connect says the resident is already gone, so the client
    // starts its own instead of returning the dead endpoint's failure.
    assert_eq!(result.unwrap_err(), "native_policy_verifier_key_missing");
}

#[cfg(unix)]
#[test]
fn a_resident_that_never_answers_the_handshake_does_not_spend_the_request_budget() {
    use std::io::Read;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let root = private_live_root("silent-handshake");
    let digest = runtime_digest().unwrap();
    let scope = state_scope(&root, &digest).unwrap();
    crate::resident_state::publish_state(
        &scope,
        1,
        std::process::id(),
        &digest,
        "loopback",
        endpoint,
        &[13; crate::AUTH_TOKEN_BYTES],
    )
    .unwrap();
    let (stop, wait_stop) = std::sync::mpsc::channel::<()>();
    let worker = thread::spawn(move || {
        // Take the client's nonce and answer nothing. Every accepted
        // connection is held open until the request has returned, so only the
        // client's own handshake window can end the exchange: a socket closed
        // under it would end the read as an ordinary disconnect instead.
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut accepted = Vec::new();
        while accepted.len() < 2 && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    // Accepted sockets inherit nonblocking mode on some Unix hosts.
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(4)))
                        .unwrap();
                    let mut nonce = [0; crate::AUTH_NONCE_BYTES];
                    stream
                        .read_exact(&mut nonce)
                        .expect("a probe reached the peer without a nonce");
                    accepted.push(stream);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("test listener failed: {error}"),
            }
        }
        let probes = accepted.len();
        let _ = wait_stop.recv_timeout(Duration::from_secs(10));
        drop(accepted);
        probes
    });
    let client_lease = lease::acquire(&root).unwrap();
    let started = Instant::now();
    let result = client_request_with_deadline(
        &root,
        b"{}",
        started + Duration::from_secs(4),
        &client_lease,
    );
    let waited = started.elapsed();
    let _ = stop.send(());
    let probes = worker.join().unwrap();
    drop(client_lease);
    std::fs::remove_dir_all(&root).unwrap();
    // Both the initial probe and the lock-protected probe reached the silent
    // peer and gave up on their own window.
    assert_eq!(probes, 2);
    // Reaching the spawn admission gate proves the handshake ended on the
    // client's auth window rather than the request budget, which would have
    // reported `native_client_deadline_exceeded` instead.
    assert_eq!(result.unwrap_err(), "native_policy_verifier_key_missing");
    assert!(waited < Duration::from_secs(4), "waited {waited:?}");
}

/// A child for [`a_killed_resident_leaves_no_identity_to_match`] to kill.
///
/// It is started by name through the test binary, so the case below needs no
/// program on `PATH`. The wait is only an upper bound on how long it survives
/// a parent that never gets to kill it.
#[cfg(unix)]
#[test]
#[ignore = "started as a child by a_killed_resident_leaves_no_identity_to_match"]
fn waits_for_the_parent_that_started_it() {
    std::thread::sleep(Duration::from_secs(30));
}

#[cfg(unix)]
#[test]
fn a_killed_resident_leaves_no_identity_to_match() {
    // The child is this test binary running the ignored case above. A program
    // from `PATH` would make a runner without it fail at `spawn`, before any
    // of the identity assertions below ran.
    let mut child =
        std::process::Command::new(std::env::current_exe().expect("the test binary names itself"))
            .args(["waits_for_the_parent_that_started_it", "--ignored"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("the test binary could not be started");
    let process_id = child.id();
    let marker = crate::resident_state::process_start_marker(process_id)
        .expect("a live process has a start marker");
    assert_eq!(
        crate::resident_state::validate_process_start_marker(process_id, &marker),
        Ok(())
    );
    child.kill().unwrap();
    child.wait().unwrap();
    // A reaped pid is free at once. Either it names nothing, or it names a
    // process that did not start when the resident did; both refuse, and
    // neither may be mistaken for the resident that was killed.
    let error = crate::resident_state::validate_process_start_marker(process_id, &marker)
        .expect_err("a killed resident still matched its recorded identity");
    assert!(
        error == "native_resident_process_identity_mismatch"
            || error == "native_resident_process_identity_unavailable",
        "{error}"
    );
}

#[cfg(unix)]
#[test]
fn a_scope_that_cannot_be_written_publishes_no_state() {
    use std::fs;
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;

    let (home, base) = owner_release_fixture("read-only-scope");
    let digest = runtime_digest().unwrap();
    let scope = state_scope(&base, &digest).unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    fs::set_permissions(&scope, fs::Permissions::from_mode(0o500)).unwrap();
    // A superuser ignores the directory mode, so the mode proves nothing there.
    let probe = scope.join("writable-probe");
    let writable = fs::File::create(&probe).is_ok();
    if writable {
        fs::remove_file(&probe).unwrap();
    }
    let result = crate::resident_state::publish_state(
        &scope,
        1,
        std::process::id(),
        &digest,
        "loopback",
        endpoint,
        &[13; crate::AUTH_TOKEN_BYTES],
    );
    fs::set_permissions(&scope, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir_all(&home).unwrap();
    if writable {
        return;
    }
    assert_eq!(
        result.map(|_| ()),
        Err("native_resident_state_write_failed".to_owned())
    );
}
