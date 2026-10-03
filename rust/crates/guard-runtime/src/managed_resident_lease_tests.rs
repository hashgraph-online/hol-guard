use super::*;
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use std::sync::mpsc::Sender;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

thread_local! {
    static LOCK_BUSY_NOTIFICATION: RefCell<Option<Sender<()>>> = const { RefCell::new(None) };
    static LOCK_RETRY_DEADLINE_NOTIFICATION: RefCell<Option<Sender<(Instant, Instant)>>> =
        const { RefCell::new(None) };
}

pub(super) fn notify_lock_busy_for_test() {
    LOCK_BUSY_NOTIFICATION.with(|notification| {
        if let Some(sender) = notification.borrow_mut().take() {
            let _ = sender.send(());
        }
    });
}

pub(super) fn notify_lock_retry_deadline_for_test(deadline: Instant) {
    LOCK_RETRY_DEADLINE_NOTIFICATION.with(|notification| {
        if let Some(sender) = notification.borrow_mut().take() {
            let _ = sender.send((deadline, Instant::now()));
        }
    });
}

fn fixture_file(path: &Path, bytes: &[u8]) {
    #[cfg(windows)]
    {
        use std::io::Write;
        let private_root = path.parent().unwrap_or(path);
        let mut file = crate::resident_state::private_file(path, false, private_root).unwrap();
        file.write_all(bytes).unwrap();
    }
    #[cfg(not(windows))]
    fs::write(path, bytes).unwrap();
}

fn fixture_directory(path: &Path) {
    #[cfg(windows)]
    {
        crate::resident_state::ensure_private_directory(path, true).unwrap();
    }
    #[cfg(not(windows))]
    fs::create_dir(path).unwrap();
}

fn fixture_file_handle(path: &Path) -> fs::File {
    #[cfg(windows)]
    {
        let private_root = path.parent().unwrap_or(path);
        crate::resident_state::private_file(path, true, private_root).unwrap()
    }
    #[cfg(not(windows))]
    fs::File::create(path).unwrap()
}

fn test_directory(label: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "hol-guard-managed-lease-lock-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos()
    ));
    fixture_directory(&directory);
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
    fixture_file(&path, b"partial lease");

    drop(lease);

    assert!(!path.exists());
    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[test]
fn expired_one_shot_removes_its_owned_lease_without_lock_contention() {
    let root = test_directory("expired-owned");
    let lease = acquire(&root)
        .expect("lease acquisition should succeed")
        .with_deadline(Instant::now());
    let path = lease.path.clone();
    drop(lease);
    assert!(!path.exists());
    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[test]
fn expired_one_shot_does_not_retry_a_busy_cleanup_lock() {
    let root = test_directory("expired-busy");
    let lease = acquire(&root)
        .expect("lease acquisition should succeed")
        .with_deadline(Instant::now());
    let path = lease.path.clone();
    let directory = lease_directory(&root).expect("lease directory should be available");
    let private_root = private_root_for_state_base(&root).expect("private root should exist");
    let lock = acquire_directory_lock(&directory, &private_root)
        .expect("lock should be valid")
        .expect("lock should be free");
    let (busy_sender, busy_receiver) = std::sync::mpsc::channel();
    let (deadline_sender, deadline_receiver) = std::sync::mpsc::channel();
    LOCK_BUSY_NOTIFICATION.with(|notification| *notification.borrow_mut() = Some(busy_sender));
    LOCK_RETRY_DEADLINE_NOTIFICATION
        .with(|notification| *notification.borrow_mut() = Some(deadline_sender));
    drop(lease);
    let cleanup_attempt = busy_receiver.try_recv();
    cleanup_attempt.expect("cleanup must attempt the lock");
    assert!(
        deadline_receiver.try_recv().is_err(),
        "cleanup must not enter the retry loop"
    );
    LOCK_RETRY_DEADLINE_NOTIFICATION.with(|notification| *notification.borrow_mut() = None);
    assert!(path.exists(), "a busy owned lease remains fail-closed");
    drop(lock);
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
    let mut file = fixture_file_handle(&path);
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
    fixture_directory(&directory.join("client-uninspectable.lease"));

    assert!(any_live_for_home(&root));

    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[test]
fn initial_lease_lock_retries_until_the_current_holder_releases() {
    let directory = test_directory("eventual");
    let held = acquire_directory_lock(&directory, &directory)
        .expect("initial lock open should succeed")
        .expect("test should hold the lease lock");
    let (busy_sender, busy_receiver) = std::sync::mpsc::channel();
    LOCK_BUSY_NOTIFICATION.with(|notification| *notification.borrow_mut() = Some(busy_sender));
    let releaser = thread::spawn(move || {
        busy_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("retry path should observe the held lock");
        drop(held);
    });

    let acquired =
        acquire_directory_lock_with_retry(&directory, &directory, Duration::from_secs(2));
    releaser.join().expect("lock releaser should exit cleanly");
    let acquired = acquired.expect("bounded retry should acquire after release");
    drop(acquired);
    fs::remove_dir_all(directory).expect("test directory should be removable");
}

#[test]
fn initial_lease_lock_returns_busy_at_the_retry_deadline() {
    let directory = test_directory("bounded");
    let held = acquire_directory_lock(&directory, &directory)
        .expect("initial lock open should succeed")
        .expect("test should hold the lease lock");
    let (deadline_sender, deadline_receiver) = std::sync::mpsc::channel();
    LOCK_RETRY_DEADLINE_NOTIFICATION
        .with(|notification| *notification.borrow_mut() = Some(deadline_sender));
    let releaser = thread::spawn(move || {
        deadline_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("retry path should reach its deadline");
        drop(held);
    });

    let result =
        acquire_directory_lock_with_retry(&directory, &directory, Duration::from_millis(20));
    assert!(matches!(
        result,
        Err(error) if error == "native_resident_lease_busy"
    ));
    releaser.join().expect("lock releaser should exit cleanly");
    fs::remove_dir_all(directory).expect("test directory should be removable");
}

#[test]
fn absolute_lease_deadline_can_wait_beyond_stream_retry_budget() {
    let root = test_directory("absolute-eventual");
    let directory = lease_directory(&root).expect("lease directory should be available");
    let held = acquire_directory_lock(&directory, &root)
        .expect("initial lock open should succeed")
        .expect("test should hold the lease lock");
    crate::resident_state::runtime_digest()
        .expect("runtime digest should be available before timing the lock wait");
    let (busy_sender, busy_receiver) = std::sync::mpsc::channel();
    let (started_sender, started_receiver) = std::sync::mpsc::channel();
    let worker_root = root.clone();
    let worker = thread::spawn(move || {
        LOCK_BUSY_NOTIFICATION.with(|notification| *notification.borrow_mut() = Some(busy_sender));
        started_sender
            .send(())
            .expect("absolute retry worker should start");
        let started = Instant::now();
        let acquired = acquire_until(&worker_root, started + Duration::from_secs(3));
        let elapsed = started.elapsed();
        let succeeded = acquired.is_ok();
        drop(acquired);
        (succeeded, elapsed)
    });
    started_receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("absolute retry worker should be scheduled");
    busy_receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("absolute retry path should observe the held lock");
    thread::sleep(Duration::from_millis(250));
    drop(held);
    let (succeeded, elapsed) = worker.join().expect("absolute retry worker should exit");
    assert!(succeeded);
    assert!(elapsed >= Duration::from_millis(200));
    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[test]
fn absolute_lease_deadline_returns_busy_without_stream_budget_extension() {
    use std::cell::Cell;

    let root = test_directory("absolute-contention");
    let directory = lease_directory(&root).expect("lease directory should be available");
    let held = acquire_directory_lock(&directory, &root)
        .expect("initial lock open should succeed")
        .expect("test should hold the lease lock");
    let started = Instant::now();
    let clock = Cell::new(started);
    let deadline = started + Duration::from_millis(30);
    let (busy_sender, busy_receiver) = std::sync::mpsc::channel();
    let (deadline_sender, deadline_receiver) = std::sync::mpsc::channel();
    LOCK_BUSY_NOTIFICATION.with(|notification| *notification.borrow_mut() = Some(busy_sender));
    LOCK_RETRY_DEADLINE_NOTIFICATION
        .with(|notification| *notification.borrow_mut() = Some(deadline_sender));
    let mut sleeps = Vec::new();
    // Exercise real lock contention with a controlled clock. Runner scheduling
    // and ACL setup cannot consume the budget before the first lock attempt.
    let result = acquire_directory_lock_with_clock(
        &directory,
        &root,
        deadline,
        || clock.get(),
        |duration| {
            assert!(duration <= deadline.saturating_duration_since(clock.get()));
            sleeps.push(duration);
            clock.set(clock.get() + duration);
        },
    );
    assert!(matches!(result, Err(error) if error == "native_resident_lease_busy"));
    busy_receiver
        .try_recv()
        .expect("the real lock must have been contested");
    let (used_deadline, _) = deadline_receiver
        .try_recv()
        .expect("deadline must be observed");
    assert_eq!(used_deadline, deadline);
    assert_eq!(clock.get(), deadline);
    assert_eq!(
        sleeps.iter().copied().sum::<Duration>(),
        Duration::from_millis(30)
    );
    assert_eq!(sleeps.last(), Some(&Duration::from_millis(15)));
    drop(held);
    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[test]
fn absolute_lease_deadline_survives_private_file_setup() {
    let root = test_directory("absolute-bounded");
    let directory = lease_directory(&root).expect("lease directory should be available");
    let held = acquire_directory_lock(&directory, &root)
        .expect("initial lock open should succeed")
        .expect("test should hold the lease lock");
    crate::resident_state::runtime_digest()
        .expect("runtime digest should be available before the lock wait");
    let (deadline_sender, deadline_receiver) = std::sync::mpsc::channel();
    let (started_sender, started_receiver) = std::sync::mpsc::channel();
    let worker_root = root.clone();
    let worker = thread::spawn(move || {
        LOCK_RETRY_DEADLINE_NOTIFICATION
            .with(|notification| *notification.borrow_mut() = Some(deadline_sender));
        let deadline = Instant::now() + Duration::from_millis(30);
        started_sender
            .send(deadline)
            .expect("absolute bounded worker should start");
        acquire_until(&worker_root, deadline)
            .err()
            .unwrap_or_else(|| "acquired".to_owned())
    });
    let requested_deadline = started_receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("absolute bounded worker should be scheduled");
    let (used_deadline, observed_at) = deadline_receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("absolute retry path should reach its deadline");
    drop(held);
    let error = worker.join().expect("absolute bounded worker should exit");
    assert_eq!(error, "native_resident_lease_busy");
    // Validate the deadline actually used, not scheduling/ACL latency outside
    // the retry loop. The real lock remains held until the rejection path fires.
    assert_eq!(used_deadline, requested_deadline);
    assert!(observed_at >= requested_deadline);
    assert_eq!(
        fs::read_dir(&directory)
            .expect("lease directory should remain readable")
            .count(),
        1,
        "an expired request must not publish a client lease"
    );
    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[test]
fn expired_absolute_lock_deadline_rejects_before_opening_a_lock() {
    let root = test_directory("expired-before-open");
    let missing = root.join("must-not-be-opened");
    let deadline = Instant::now() - Duration::from_millis(1);
    let (sender, receiver) = std::sync::mpsc::channel();
    LOCK_RETRY_DEADLINE_NOTIFICATION.with(|notification| *notification.borrow_mut() = Some(sender));
    let result = acquire_directory_lock_until(&missing, &root, deadline);
    assert!(matches!(result, Err(error) if error == "native_resident_lease_busy"));
    let (used_deadline, observed_at) = receiver.try_recv().expect("deadline must be observed");
    assert_eq!(used_deadline, deadline);
    assert!(observed_at >= deadline);
    assert!(!missing.exists());
    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[test]
fn busy_lease_directory_is_retained_as_live() {
    let root = test_directory("busy-liveness");
    let directory = lease_directory(&root).expect("lease directory should be available");
    let held = acquire_directory_lock(&directory, &directory)
        .expect("initial lock open should succeed")
        .expect("test should hold the lease lock");

    assert!(any_live_for_home(&root));

    drop(held);
    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[test]
fn stale_lease_overflow_drains_instead_of_keeping_the_resident() {
    let root = test_directory("stale-overflow");
    let directory = lease_directory(&root).expect("lease directory should be available");
    let stale_at = SystemTime::now()
        .checked_sub(LEASE_EXPIRY + Duration::from_secs(1))
        .expect("test clock should support stale timestamp");
    let count = LEASE_MAX_DIRECTORY_ENTRIES + 10;
    for index in 0..count {
        let path = directory.join(format!("client-stale-{index:04}.lease"));
        let mut file = fixture_file_handle(&path);
        file.write_all(b"partial lease")
            .expect("fixture should be written");
        file.set_modified(stale_at)
            .expect("fixture should become stale");
    }

    let mut retained = true;
    for _ in 0..4 {
        retained = any_live_for_home(&root);
        if !retained {
            break;
        }
    }

    assert!(!retained);
    let remaining = fs::read_dir(&directory)
        .expect("lease directory should remain readable")
        .filter_map(Result::ok)
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("client-") && name.ends_with(".lease")
        })
        .count();
    assert_eq!(remaining, 0);
    fs::remove_dir_all(root).expect("test directory should be removable");
}

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
        .checked_sub(LEASE_EXPIRY + Duration::from_secs(1))
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

    let mut retained = false;
    for _ in 0..4 {
        retained = any_live_for_home(&root);
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
    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[test]
fn lease_directory_entry_overflow_is_retained_as_live() {
    let root = test_directory("entry-overflow");
    let directory = lease_directory(&root).expect("lease directory should be available");
    fixture_file(&directory.join("client-valid.lease"), &[]);
    for index in 0..LEASE_MAX_DIRECTORY_ENTRIES {
        fixture_file(&directory.join(format!("unrelated-{index:03}")), &[]);
    }

    assert!(any_live_for_home(&root));

    fs::remove_dir_all(root).expect("test directory should be removable");
}
