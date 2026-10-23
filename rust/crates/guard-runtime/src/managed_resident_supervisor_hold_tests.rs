use super::*;
use std::fs;
use std::sync::mpsc;
use std::thread;

/// A held scope is proved by a stop that gives up, so these tests use a bound
/// of their own rather than sleeping out `SUPERVISOR_QUIESCE_TIMEOUT`, which
/// is sized for a supervisor still waiting on its child's stderr.
const TEST_QUIESCE_TIMEOUT: Duration = Duration::from_millis(50);

/// A private scope with a private parent, which is what the hold's lock file
/// is opened against.
fn test_scope(label: &str) -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-supervisor-hold-{label}-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    crate::resident_state::ensure_private_directory(&root, true)
        .expect("test root should be created");
    let scope = root.join("resident-v3-test");
    crate::resident_state::ensure_private_directory(&scope, true)
        .expect("test scope should be created");
    (root, scope)
}

#[cfg(windows)]
#[test]
fn a_scope_no_supervisor_holds_is_already_quiesced() {
    let (root, scope) = test_scope("free");

    wait_for_supervisor_quiesce(&scope).expect("an unheld scope should be quiesced at once");

    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[cfg(windows)]
#[test]
fn a_stop_waits_for_the_supervisor_to_release_its_hold() {
    let (root, scope) = test_scope("waits");
    let hold = hold_scope(&scope).expect("a private scope should be holdable");
    let (released, release_seen) = mpsc::channel();
    let releaser = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        released.send(()).expect("the test should still be waiting");
        drop(hold);
    });

    wait_for_supervisor_quiesce(&scope).expect("a released hold should let the stop through");

    release_seen
        .try_recv()
        .expect("the stop must not return before the hold is released");
    releaser.join().expect("the releasing thread should finish");
    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[test]
fn a_stop_reports_a_supervisor_that_never_finishes() {
    let (root, scope) = test_scope("pending");
    let hold = hold_scope(&scope).expect("a private scope should be holdable");

    assert_eq!(
        wait_for_supervisor_quiesce_within(&scope, TEST_QUIESCE_TIMEOUT),
        Err("native_resident_supervisor_exit_pending".to_owned())
    );

    drop(hold);
    fs::remove_dir_all(root).expect("test directory should be removable");
}

/// Two supervisors can share a scope, and the stop waits for the last one.
#[cfg(windows)]
#[test]
fn the_hold_is_shared_between_supervisors() {
    let (root, scope) = test_scope("shared");
    let first = hold_scope(&scope).expect("the first supervisor should hold the scope");
    let second = hold_scope(&scope).expect("a second supervisor should hold the same scope");

    drop(first);
    assert_eq!(
        wait_for_supervisor_quiesce_within(&scope, TEST_QUIESCE_TIMEOUT),
        Err("native_resident_supervisor_exit_pending".to_owned())
    );
    drop(second);
    wait_for_supervisor_quiesce(&scope).expect("the last hold released should quiesce the scope");

    fs::remove_dir_all(root).expect("test directory should be removable");
}

/// A supervisor still waiting for its child's stderr holds the scope for up to
/// `MANAGED_STOP_TIMEOUT`, so the stop's own bound has to outlast that wait
/// and the budget lock that follows it, or an ordinary exit reads as a stop
/// failure.
#[cfg(windows)]
#[test]
fn the_stop_outwaits_the_supervisors_longest_ordinary_tail() {
    assert!(SUPERVISOR_QUIESCE_TIMEOUT > crate::managed_resident::MANAGED_STOP_TIMEOUT * 2);
}

/// A stop that found no resident waits for the supervisor's writes as far as
/// its own deadline, then leaves a supervisor that is still busy to finish on
/// its own instead of failing the stop.
#[test]
fn a_stop_without_a_resident_waits_for_the_hold_only_within_its_deadline() {
    let (root, scope) = test_scope("deadline");
    let hold = hold_scope(&scope).expect("a private scope should be holdable");
    let (released, release_seen) = mpsc::channel();
    let releaser = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        released.send(()).expect("the test should still be waiting");
        drop(hold);
    });

    wait_for_scope_quiesce(&scope, Instant::now() + Duration::from_secs(5));

    release_seen
        .try_recv()
        .expect("the stop must not return before the hold is released");
    releaser.join().expect("the releasing thread should finish");

    let busy = hold_scope(&scope).expect("the scope should be holdable again");
    let started = Instant::now();
    wait_for_scope_quiesce(&scope, started + TEST_QUIESCE_TIMEOUT);
    assert!(started.elapsed() >= TEST_QUIESCE_TIMEOUT);

    drop(busy);
    fs::remove_dir_all(root).expect("test directory should be removable");
}

/// A stop's exclusive probe lasts only an instant, so a supervisor that meets
/// one still takes its hold instead of running its child without it.
#[test]
fn a_supervisor_claims_its_hold_after_a_stops_probe() {
    let (root, scope) = test_scope("probe");
    let probe = open_hold_file(&scope).expect("the hold file should open");
    fs2::FileExt::try_lock_exclusive(&probe).expect("an idle scope should be probed");
    let releaser = thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        let _ = fs2::FileExt::unlock(&probe);
    });

    let hold = hold_scope(&scope);

    releaser.join().expect("the probing thread should finish");
    assert!(
        hold.is_some(),
        "a supervisor must not run unheld after a probe"
    );
    drop(hold);
    fs::remove_dir_all(root).expect("test directory should be removable");
}
