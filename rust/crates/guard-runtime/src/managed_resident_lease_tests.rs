use super::*;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn test_directory(label: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "hol-guard-managed-lease-lock-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos()
    ));
    fs::create_dir(&directory).expect("test directory should be unique");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("test directory should be private");
    }
    directory
}

#[test]
fn dropping_owned_malformed_lease_removes_the_owned_artifact() {
    let root = test_directory("malformed-owned");
    let lease = acquire(&root).expect("lease acquisition should succeed");
    let path = lease.path.clone();
    fs::write(&path, b"partial lease").expect("lease should be corruptible for the fixture");

    drop(lease);

    assert!(!path.exists());
    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[cfg(unix)]
#[test]
fn dropping_owned_lease_preserves_a_replacement_at_the_original_path() {
    let root = test_directory("replacement");
    let lease = acquire(&root).expect("lease acquisition should succeed");
    let path = lease.path.clone();
    fs::remove_file(&path).expect("fixture should remove the original lease path");
    fs::write(&path, b"replacement").expect("fixture should create a replacement path");

    drop(lease);

    assert_eq!(
        fs::read(&path).expect("replacement should remain present"),
        b"replacement"
    );
    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[test]
fn stale_malformed_lease_is_removed_by_liveness_cleanup() {
    let root = test_directory("malformed-stale");
    let directory = lease_directory(&root).expect("lease directory should be available");
    let path = directory.join("client-malformed.lease");
    let mut file = crate::resident_state::private_file(&path, true)
        .expect("malformed fixture should be created");
    file.write_all(b"partial lease")
        .expect("fixture should be written");
    file.set_modified(
        SystemTime::now()
            .checked_sub(LEASE_EXPIRY + Duration::from_secs(1))
            .expect("test clock should support stale timestamp"),
    )
    .expect("fixture should become stale");

    drop(file);

    assert!(!any_live_for_home(&root));
    assert!(!path.exists());
    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[test]
fn uninspectable_lease_path_retains_the_resident() {
    let root = test_directory("uninspectable");
    let directory = lease_directory(&root).expect("lease directory should be available");
    fs::create_dir(directory.join("client-uninspectable.lease"))
        .expect("uninspectable lease fixture should be created");

    assert!(any_live_for_home(&root));

    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[test]
fn initial_lease_lock_retries_until_the_current_holder_releases() {
    let directory = test_directory("eventual");
    let held = acquire_directory_lock(&directory)
        .expect("initial lock open should succeed")
        .expect("test should hold the lease lock");
    let (busy_sender, busy_receiver) = std::sync::mpsc::channel();
    LOCK_BUSY_NOTIFICATION.with(|notification| *notification.borrow_mut() = Some(busy_sender));
    let releaser = thread::spawn(move || {
        busy_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("retry path should observe the held lock");
        drop(held);
    });

    let acquired = acquire_directory_lock_with_retry(&directory, Duration::from_millis(100));
    releaser.join().expect("lock releaser should exit cleanly");
    let acquired = acquired.expect("bounded retry should acquire after release");
    drop(acquired);
    fs::remove_dir_all(directory).expect("test directory should be removable");
}

#[test]
fn initial_lease_lock_returns_busy_at_the_retry_deadline() {
    let directory = test_directory("bounded");
    let held = acquire_directory_lock(&directory)
        .expect("initial lock open should succeed")
        .expect("test should hold the lease lock");
    let releaser = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        drop(held);
    });

    let result = acquire_directory_lock_with_retry(&directory, Duration::from_millis(20));
    assert!(matches!(
        result,
        Err(error) if error == "native_resident_lease_busy"
    ));
    releaser.join().expect("lock releaser should exit cleanly");
    fs::remove_dir_all(directory).expect("test directory should be removable");
}

#[test]
fn busy_lease_directory_is_retained_as_live() {
    let root = test_directory("busy-liveness");
    let directory = lease_directory(&root).expect("lease directory should be available");
    let held = acquire_directory_lock(&directory)
        .expect("initial lock open should succeed")
        .expect("test should hold the lease lock");

    assert!(any_live_for_home(&root));

    drop(held);
    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[test]
fn lease_directory_entry_overflow_is_retained_as_live() {
    let root = test_directory("entry-overflow");
    let directory = lease_directory(&root).expect("lease directory should be available");
    fs::write(directory.join("client-valid.lease"), []).expect("lease fixture should write");
    for index in 0..LEASE_MAX_DIRECTORY_ENTRIES {
        fs::write(directory.join(format!("unrelated-{index:03}")), [])
            .expect("unrelated fixture should write");
    }

    assert!(any_live_for_home(&root));

    fs::remove_dir_all(root).expect("test directory should be removable");
}
