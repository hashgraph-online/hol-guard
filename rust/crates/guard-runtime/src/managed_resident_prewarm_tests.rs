use super::*;

use std::fs;
use std::path::PathBuf;

fn test_directory(label: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "hol-guard-managed-prewarm-{label}-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    fs::create_dir(&directory).expect("test directory should be creatable");
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .expect("test directory should be private");
    directory
}

#[test]
fn the_prewarm_asks_the_resident_for_its_health() {
    let value = crate::strict_json_value(PREWARM_PAYLOAD).expect("the payload should be a request");
    let operation =
        crate::strict_json::from_value::<crate::resident_protocol::ResidentOperationV1>(value)
            .expect("the resident should answer the operation the prewarm sends");
    assert!(
        matches!(
            operation,
            crate::resident_protocol::ResidentOperationV1::Health(_)
        ),
        "the prewarm asks for health, which decides nothing: {operation:?}"
    );
}

#[test]
fn a_client_already_holding_a_lease_keeps_the_prewarm_out() {
    let state_base = test_directory("held");
    let held = super::super::lease::acquire(&state_base).expect("the test should hold a lease");
    let started = Instant::now();
    run_with_hold(&state_base, Duration::from_secs(600)).expect("a held resident is a warm one");
    assert!(
        started.elapsed() < PREWARM_HOLD,
        "the prewarm returned before taking a lease or a hold of its own"
    );
    drop(held);
    let _ = fs::remove_dir_all(&state_base);
}

#[test]
fn the_hold_ends_when_its_window_closes() {
    let window = Duration::from_millis(120);
    let executable = std::env::current_exe().expect("the test binary should be on disk");
    let started = Instant::now();
    hold_lease(window, Some(&executable));
    assert!(
        started.elapsed() >= window,
        "the hold served its whole window"
    );
}

#[test]
fn the_hold_ends_when_this_runtime_is_uninstalled() {
    let state_base = test_directory("uninstalled");
    let missing = state_base.join("hol-guard-runtime");
    let started = Instant::now();
    hold_lease(Duration::from_secs(600), Some(&missing));
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "an uninstalled runtime ends the hold instead of keeping the replaced resident alive"
    );
    let _ = fs::remove_dir_all(&state_base);
}

#[test]
fn the_hold_ends_when_a_new_runtime_is_installed_over_this_one() {
    // An upgrade installs atomically: the path it replaces never disappears,
    // so a hold that watched only for absence would keep the replaced
    // resident leased while the new runtime tried to retire it.
    let state_base = test_directory("upgraded");
    let installed = state_base.join("hol-guard-runtime");
    fs::write(&installed, b"the runtime this prewarm started").expect("the runtime should install");
    let replacement = state_base.join("hol-guard-runtime.new");
    fs::write(&replacement, b"the runtime an upgrade installs").expect("the upgrade should stage");

    let watched = installed.clone();
    let upgrade = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        fs::rename(&replacement, &watched).expect("the upgrade should replace the runtime");
    });

    let started = Instant::now();
    hold_lease(Duration::from_secs(600), Some(&installed));
    let held = started.elapsed();
    upgrade.join().expect("the upgrade thread should finish");

    assert!(
        held < Duration::from_secs(30),
        "a runtime replaced at the same path ends the hold, after {held:?}"
    );
    let _ = fs::remove_dir_all(&state_base);
}

#[test]
fn a_nearly_spent_restart_budget_keeps_the_prewarm_out() {
    // A prewarm is an optimisation; the spawn a user is waiting on is not.
    // With one free restart left, the prewarm must leave it alone.
    let state_base = test_directory("budget");
    let digest = runtime_digest().expect("the test runtime should have a digest");
    let scope = state_scope(&state_base, &digest).expect("the scope should be creatable");

    assert!(
        super::super::restart_budget::speculative_spawn_allowed(&scope)
            .expect("an unused budget should be readable"),
        "a host that has restarted nothing may be prewarmed"
    );

    super::super::restart_budget::consume(&scope).expect("the first spawn should be charged");
    assert!(
        super::super::restart_budget::speculative_spawn_allowed(&scope)
            .expect("the budget should be readable"),
        "one charged restart still leaves room for a prewarm and a real request"
    );

    super::super::restart_budget::consume(&scope).expect("the second spawn should be charged");
    assert!(
        !super::super::restart_budget::speculative_spawn_allowed(&scope)
            .expect("the budget should be readable"),
        "the last free restart belongs to a request someone is waiting on"
    );

    let started = Instant::now();
    run_with_hold(&state_base, Duration::from_secs(600))
        .expect("a prewarm that stands down is not a failure");
    assert!(
        started.elapsed() < PREWARM_HOLD,
        "the prewarm returned without taking a lease or a hold"
    );
    let _ = fs::remove_dir_all(&state_base);
}

#[test]
fn an_unknown_executable_still_serves_the_window() {
    let window = Duration::from_millis(120);
    let started = Instant::now();
    hold_lease(window, None);
    assert!(
        started.elapsed() >= window,
        "an unknown executable bounds nothing but the upgrade watch"
    );
}
