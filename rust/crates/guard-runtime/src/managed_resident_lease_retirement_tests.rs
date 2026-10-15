use super::*;

#[test]
fn expired_live_process_leases_drain_and_a_fresh_lease_remains() {
    let root = test_directory("expired-live-owner");
    let directory = lease_directory(&root).expect("lease directory should be available");
    let process_id = std::process::id();
    let start_marker = crate::resident_state::process_start_marker(process_id)
        .expect("current process should have a start marker");
    let digest = "ab".repeat(32);
    let body = format!("{process_id}\n{start_marker}\n{digest}\n");
    let stale_at = SystemTime::now()
        .checked_sub(LEASE_EXPIRY + Duration::from_secs(60))
        .expect("test clock should support stale timestamp");
    let fresh = directory.join(format!("client-{process_id}-fresh.lease"));
    for index in 0..LEASE_MAX_DIRECTORY_ENTRIES {
        let path = directory.join(format!("client-{process_id}-stale-{index:04}.lease"));
        let mut file = fixture_file_handle(&path);
        file.write_all(body.as_bytes())
            .expect("fixture should be written");
        file.set_modified(stale_at)
            .expect("fixture should become stale");
    }
    fixture_file(&fresh, body.as_bytes());

    let observed_at = fs::metadata(&fresh).unwrap().modified().unwrap();
    let mut retained = false;
    for _ in 0..4 {
        assert!(fresh.is_file(), "the prior sweep removed a fresh lease");
        retained = any_live_with_clock(&root, None, || observed_at);
    }

    assert!(retained);
    assert!(fresh.is_file());
    let remaining = fs::read_dir(&directory)
        .expect("lease directory should remain readable")
        .filter_map(Result::ok)
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("client-") && name.ends_with(".lease")
        })
        .count();
    assert_eq!(remaining, 1);
    // Advancing the same clock still expires and removes the unrenewed lease.
    let expired_at = observed_at + LEASE_EXPIRY + Duration::from_secs(1);
    assert!(!any_live_with_clock(&root, None, || expired_at));
    assert!(!fresh.exists());
    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[test]
fn update_retirement_preserves_an_expired_live_same_runtime_lease() {
    let root = test_directory("retire-expired-live");
    let directory = lease_directory(&root).expect("lease directory should be available");
    let process_id = std::process::id();
    let start_marker = crate::resident_state::process_start_marker(process_id)
        .expect("current process should have a start marker");
    let digest =
        crate::resident_state::runtime_digest().expect("runtime digest should be available");
    let path = directory.join(format!("client-{process_id}-expired.lease"));
    let mut file = fixture_file_handle(&path);
    file.write_all(format!("{process_id}\n{start_marker}\n{digest}\n").as_bytes())
        .expect("fixture should be written");
    file.set_modified(
        SystemTime::now()
            .checked_sub(LEASE_EXPIRY + Duration::from_secs(1))
            .expect("test clock should support stale timestamp"),
    )
    .expect("fixture should become stale");
    drop(file);

    let result = retire_clients_for_update(&root, &digest, Instant::now() + Duration::from_secs(2));
    assert_eq!(
        result,
        Err("native_resident_client_retirement_failed".to_owned())
    );
    assert!(
        path.exists(),
        "an expired live lease must remain fail-closed"
    );
    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[cfg(any(unix, windows))]
#[test]
fn update_retirement_removes_an_expired_dead_same_runtime_lease() {
    let root = test_directory("retire-expired-dead");
    let directory = lease_directory(&root).expect("lease directory should be available");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--help")
        .spawn()
        .expect("short-lived child should start");
    let process_id = child.id();
    let status = child.wait().expect("short-lived child should be reaped");
    assert!(
        status.success(),
        "short-lived child should exit successfully"
    );
    let digest =
        crate::resident_state::runtime_digest().expect("runtime digest should be available");
    let path = directory.join(format!("client-{process_id}-expired.lease"));
    let mut file = fixture_file_handle(&path);
    file.write_all(format!("{process_id}\nstale\n{digest}\n").as_bytes())
        .expect("fixture should be written");
    file.set_modified(
        SystemTime::now()
            .checked_sub(LEASE_EXPIRY + Duration::from_secs(1))
            .expect("test clock should support stale timestamp"),
    )
    .expect("test fixture should become stale");
    drop(file);

    let result = retire_clients_for_update(&root, &digest, Instant::now() + Duration::from_secs(2));
    assert_eq!(result, Ok(()));
    assert!(
        !path.exists(),
        "a definitively dead lease should be drained"
    );
    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[cfg(windows)]
#[test]
fn update_retirement_removes_a_recent_lease_of_an_exited_held_process() {
    let root = test_directory("retire-exited-held");
    let directory = lease_directory(&root).expect("lease directory should be available");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("short-lived child should start");
    let process_id = child.id();
    assert!(child.wait().expect("child should exit").success());
    // `child` still holds its process handle, so the exited process keeps its
    // start marker but no longer reports an image path.
    let start_marker = crate::resident_state::process_start_marker(process_id)
        .expect("a held exited process should keep its start marker");
    let digest =
        crate::resident_state::runtime_digest().expect("runtime digest should be available");
    let path = directory.join(format!("client-{process_id}-recent.lease"));
    fixture_file(
        &path,
        format!("{process_id}\n{start_marker}\n{digest}\n").as_bytes(),
    );

    let result = retire_clients_for_update(&root, &digest, Instant::now() + Duration::from_secs(2));
    drop(child);
    assert_eq!(result, Ok(()));
    assert!(!path.exists(), "an exited owner's lease should be drained");
    fs::remove_dir_all(root).expect("test directory should be removable");
}
