#[cfg(windows)]
use super::super::private_file::backup_path;
use super::super::requested_stop::{record as record_requested_stop, take as take_requested_stop};
use super::*;
use std::fs;
#[cfg(windows)]
use std::io::{Read, Write};
use std::path::PathBuf;

/// Any process id will do here: the note is only ever read back for the same
/// one, and these tests stand in for both halves of that handshake.
const SERVING_CHILD: u32 = 4_242;

#[test]
fn repeated_updates_replace_budget_without_leaving_temporary_state() {
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-restart-budget-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    fs::create_dir(&scope).unwrap();

    consume(&scope).unwrap();
    consume(&scope).unwrap();

    let encoded = fs::read(scope.join("restart-budget.json")).unwrap();
    let budget: RestartBudget = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(budget.schema, BUDGET_SCHEMA);
    assert_eq!(budget.attempts, 2);
    assert_eq!(
        fs::read_dir(&scope)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count(),
        0
    );

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn authenticated_stop_clears_restart_attempts() {
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-restart-budget-clear-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    std::fs::create_dir(&scope).unwrap();

    consume(&scope).unwrap();
    consume(&scope).unwrap();
    consume(&scope).unwrap();
    assert_eq!(
        consume(&scope).unwrap_err(),
        "native_resident_restart_circuit_open"
    );
    clear(&scope).unwrap();
    consume(&scope).unwrap();

    std::fs::remove_dir_all(scope).unwrap();
}

fn temp_scope(label: &str) -> PathBuf {
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-restart-budget-{label}-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    std::fs::create_dir(&scope).unwrap();
    scope
}
fn read_budget(scope: &Path) -> RestartBudget {
    serde_json::from_slice(&std::fs::read(scope.join("restart-budget.json")).unwrap()).unwrap()
}

/// Put this scope's window far enough in the past that a release carrying a
/// synthetic `ran_for` still belongs to it. A real spawn always happens
/// after the window it is charged to opens and before its own exit; a test
/// that charges and releases in the same millisecond has to say so.
fn backdate_window(scope: &Path, ms_ago: u64) {
    let private_root = crate::resident_state::private_root_for_scope(scope).unwrap();
    let mut budget = read_budget(scope);
    budget.window_start_ms = now_ms().unwrap().saturating_sub(ms_ago);
    write_private(
        &scope.join("restart-budget.json"),
        &serde_json::to_vec(&budget).unwrap(),
        &private_root,
    )
    .unwrap();
}

#[test]
fn backoff_doubles_to_a_bounded_ceiling() {
    assert_eq!(backoff_ms(0), 2_000);
    assert_eq!(backoff_ms(1), 4_000);
    assert_eq!(backoff_ms(2), 8_000);
    assert_eq!(backoff_ms(4), 30_000);
    assert_eq!(backoff_ms(u32::MAX), 30_000);
}

#[test]
fn elapsed_backoff_allows_one_respawn_then_backs_off_longer() {
    let scope = temp_scope("backoff");
    for _ in 0..MAX_RESTARTS_PER_WINDOW {
        consume(&scope).unwrap();
    }
    assert_eq!(
        consume(&scope).unwrap_err(),
        "native_resident_restart_circuit_open"
    );
    let first = read_budget(&scope);
    assert_eq!(first.backoff_steps, 1);
    assert!(first.circuit_until_ms > now_ms().unwrap());
    // While the backoff runs the respawn stays refused.
    assert_eq!(
        consume(&scope).unwrap_err(),
        "native_resident_restart_circuit_open"
    );
    assert_eq!(read_budget(&scope).backoff_steps, 1);

    // Once the backoff has elapsed one respawn is allowed, and the next
    // refusal interval doubles instead of reusing a fixed circuit.
    let private_root = crate::resident_state::private_root_for_scope(&scope).unwrap();
    let elapsed = RestartBudget {
        circuit_until_ms: now_ms().unwrap() - 1,
        ..first
    };
    write_private(
        &scope.join("restart-budget.json"),
        &serde_json::to_vec(&elapsed).unwrap(),
        &private_root,
    )
    .unwrap();
    consume(&scope).unwrap();
    let second = read_budget(&scope);
    assert_eq!(second.backoff_steps, 2);
    assert_eq!(second.attempts, MAX_RESTARTS_PER_WINDOW + 1);
    let remaining = second.circuit_until_ms - now_ms().unwrap();
    assert!(remaining > 2_000 && remaining <= 4_000);
    assert_eq!(
        consume(&scope).unwrap_err(),
        "native_resident_restart_circuit_open"
    );

    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn budget_written_before_backoff_steps_existed_is_still_valid() {
    let scope = temp_scope("legacy-budget");
    let private_root = crate::resident_state::private_root_for_scope(&scope).unwrap();
    let legacy = format!(
        "{{\"schema\":\"{BUDGET_SCHEMA}\",\"window_start_ms\":{},\"attempts\":1,\"circuit_until_ms\":0}}",
        now_ms().unwrap()
    );
    write_private(
        &scope.join("restart-budget.json"),
        legacy.as_bytes(),
        &private_root,
    )
    .unwrap();

    consume(&scope).unwrap();

    let budget = read_budget(&scope);
    assert_eq!(budget.attempts, 2);
    assert_eq!(budget.backoff_steps, 0);
    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn clear_reopens_a_tripped_circuit() {
    let scope = temp_scope("clear-circuit");
    for _ in 0..MAX_RESTARTS_PER_WINDOW {
        consume(&scope).unwrap();
    }
    assert!(consume(&scope).is_err());
    clear(&scope).unwrap();
    let budget = read_budget(&scope);
    assert_eq!(
        (
            budget.attempts,
            budget.circuit_until_ms,
            budget.backoff_steps
        ),
        (0, 0, 0)
    );
    consume(&scope).unwrap();
    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_held_budget_lock_reads_as_busy_and_a_spawn_waits_it_out() {
    let scope = temp_scope("held-lock");
    let held = acquire_budget_lock(&scope).unwrap();
    // Windows reports this overlap as a lock violation rather than WouldBlock.
    assert_eq!(
        acquire_budget_lock(&scope).err().as_deref(),
        Some("native_resident_restart_budget_busy")
    );
    let waiting_scope = scope.clone();
    let (started, worker_started) = std::sync::mpsc::channel();
    let spawn = std::thread::spawn(move || {
        started.send(()).unwrap();
        consume(&waiting_scope)
    });
    worker_started.recv().unwrap();
    std::thread::sleep(Duration::from_millis(100));
    // Still waiting on the held lock, not refused with a busy error.
    assert!(!spawn.is_finished());
    drop(held);
    spawn.join().unwrap().unwrap();
    assert_eq!(read_budget(&scope).attempts, 1);
    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_spawn_out_of_time_on_a_held_budget_lock_charges_nothing() {
    let scope = temp_scope("held-lock-deadline");
    let held = acquire_budget_lock(&scope).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_millis(60);
    assert_eq!(
        consume_before(&scope, Some(deadline)).err().as_deref(),
        Some("native_client_deadline_exceeded")
    );
    drop(held);
    assert!(!scope.join("restart-budget.json").exists());
    std::fs::remove_dir_all(scope).unwrap();
}

#[cfg(windows)]
#[test]
fn restart_budget_lock_retains_directory_binding_until_drop() {
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-restart-budget-directory-binding-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    crate::resident_state::ensure_private_directory(&scope, true).unwrap();
    let renamed = scope.with_file_name(format!(
        "{}-renamed",
        scope.file_name().unwrap().to_string_lossy()
    ));
    let lock = acquire_budget_lock(&scope).unwrap();

    assert!(fs::rename(&scope, &renamed).is_err());

    drop(lock);
    fs::rename(&scope, &renamed).unwrap();
    fs::remove_dir_all(renamed).unwrap();
}

#[cfg(windows)]
#[test]
fn interrupted_windows_replace_restores_previous_budget() {
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-restart-budget-recovery-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    fs::create_dir(&scope).unwrap();
    consume(&scope).unwrap();
    let path = scope.join("restart-budget.json");
    let encoded = {
        let mut file =
            crate::resident_state::open_private_read(&path, 4096, "restart_budget", &scope)
                .unwrap()
                .unwrap();
        let mut encoded = Vec::new();
        file.read_to_end(&mut encoded).unwrap();
        encoded
    };
    let backup = backup_path(&path);
    let mut backup_file = crate::resident_state::private_file(&backup, true, &scope).unwrap();
    backup_file.write_all(&encoded).unwrap();
    backup_file.sync_all().unwrap();
    drop(backup_file);
    crate::resident_state::remove_windows_private_file(&path, &scope).unwrap();

    consume(&scope).unwrap();

    let budget: RestartBudget = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(budget.attempts, 2);
    fs::remove_dir_all(scope).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_budget_existence_requires_private_regular_file_handle() {
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-restart-budget-handle-check-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    crate::resident_state::ensure_private_directory(&scope, true).unwrap();
    let path = scope.join("restart-budget.json");

    assert!(!existing_private_file(&path, &scope).unwrap());
    let file = crate::resident_state::private_file(&path, true, &scope).unwrap();
    drop(file);
    assert!(existing_private_file(&path, &scope).unwrap());
    assert!(existing_private_file(&scope, &scope).is_err());

    fs::remove_dir_all(scope).unwrap();
}

const SERVED_RUN: Duration = Duration::from_secs(3);
const INSTANT_RUN: Duration = Duration::from_millis(5);

#[test]
fn only_a_served_run_that_exited_cleanly_counts_as_orderly() {
    assert!(orderly_exit(true, SERVED_RUN, false));
    assert!(orderly_exit(true, Duration::from_millis(1_000), false));
    assert!(!orderly_exit(true, Duration::from_millis(999), false));
    assert!(!orderly_exit(false, SERVED_RUN, false));
    assert!(!orderly_exit(false, INSTANT_RUN, false));
}

#[test]
fn a_run_that_was_asked_to_stop_is_orderly_however_briefly_it_lived() {
    assert!(orderly_exit(true, INSTANT_RUN, true));
    assert!(orderly_exit(true, Duration::from_millis(1), true));
    // Being asked to stop does not excuse ending badly.
    assert!(!orderly_exit(false, INSTANT_RUN, true));
}

#[test]
fn repeated_requested_stops_never_open_the_restart_circuit() {
    // The shape that took every prompt down: a second runtime sharing the
    // guard home stops this one's resident the instant it starts, over and
    // over inside one window. Each of those is a complete lifecycle.
    let scope = temp_scope("requested-stop-loop");
    for _ in 0..(MAX_RESTARTS_PER_WINDOW * 3) {
        consume(&scope).expect("a stop that was asked for is never a restart");
        record_requested_stop(&scope, SERVING_CHILD).unwrap();
        backdate_window(&scope, INSTANT_RUN.as_millis() as u64 + 1_000);
        let stop_requested = take_requested_stop(&scope, SERVING_CHILD);
        assert!(stop_requested);
        release_after_exit(
            &scope,
            orderly_exit(true, INSTANT_RUN, stop_requested),
            INSTANT_RUN,
        )
        .unwrap();
        assert_eq!(read_budget(&scope).attempts, 0);
    }
    consume(&scope).expect("the circuit stays closed after repeated requested stops");

    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn repeated_one_shot_client_cycles_never_open_the_restart_circuit() {
    // Ten `hol-guard hook` calls inside one window: each cold-spawns a
    // resident, is answered, and the resident shuts down once the call's
    // lease expires. None of that is a restart.
    let scope = temp_scope("one-shot-cycles");
    for _ in 0..10 {
        consume(&scope).expect("an answered one-shot cycle is never refused");
        backdate_window(&scope, SERVED_RUN.as_millis() as u64 + 1_000);
        release_after_exit(&scope, true, SERVED_RUN).unwrap();
        assert_eq!(read_budget(&scope).attempts, 0);
    }
    consume(&scope).expect("the circuit stays closed after ten served cycles");

    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_crashing_resident_still_opens_the_restart_circuit() {
    let scope = temp_scope("crash-loop");
    for _ in 0..MAX_RESTARTS_PER_WINDOW {
        consume(&scope).unwrap();
        release_after_exit(&scope, false, INSTANT_RUN).unwrap();
    }
    assert_eq!(read_budget(&scope).attempts, MAX_RESTARTS_PER_WINDOW);
    assert_eq!(
        consume(&scope).unwrap_err(),
        "native_resident_restart_circuit_open"
    );

    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_resident_that_exits_zero_immediately_keeps_its_restart_charge() {
    // A success reported before the resident can have served anything is a
    // loop, not a cycle: the budget must still pace it.
    let scope = temp_scope("instant-success");
    for _ in 0..MAX_RESTARTS_PER_WINDOW {
        consume(&scope).unwrap();
        release_after_exit(&scope, orderly_exit(true, INSTANT_RUN, false), INSTANT_RUN).unwrap();
    }
    assert_eq!(
        consume(&scope).unwrap_err(),
        "native_resident_restart_circuit_open"
    );

    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_served_run_after_crashes_closes_the_open_circuit() {
    let scope = temp_scope("recovered");
    for _ in 0..MAX_RESTARTS_PER_WINDOW {
        consume(&scope).unwrap();
    }
    assert_eq!(
        consume(&scope).unwrap_err(),
        "native_resident_restart_circuit_open"
    );
    assert!(read_budget(&scope).circuit_until_ms > now_ms().unwrap());

    backdate_window(&scope, SERVED_RUN.as_millis() as u64 + 1_000);
    release_after_exit(&scope, true, SERVED_RUN).unwrap();
    let recovered = read_budget(&scope);
    assert_eq!(recovered.attempts, MAX_RESTARTS_PER_WINDOW - 1);
    assert_eq!(recovered.circuit_until_ms, 0);
    assert_eq!(recovered.backoff_steps, 0);
    consume(&scope).expect("a resident that served again may be restarted");

    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_release_without_a_budget_writes_nothing() {
    let scope = temp_scope("no-budget");
    release_after_exit(&scope, true, SERVED_RUN).unwrap();
    assert!(!scope.join("restart-budget.json").exists());

    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn an_older_run_cannot_clear_a_newer_windows_crash_circuit() {
    // A resident spawned in an earlier window can exit cleanly long after a
    // crash loop has started in the current one. Its charge was paid to the
    // window that has since rolled over, so releasing it here would hand the
    // loop a free restart and wipe the backoff pacing it.
    let scope = temp_scope("stale-release");
    for _ in 0..MAX_RESTARTS_PER_WINDOW {
        consume(&scope).unwrap();
    }
    assert_eq!(
        consume(&scope).unwrap_err(),
        "native_resident_restart_circuit_open"
    );
    let crashing = read_budget(&scope);

    release_after_exit(&scope, true, Duration::from_millis(RESTART_WINDOW_MS * 2)).unwrap();

    let after = read_budget(&scope);
    assert_eq!(after.attempts, crashing.attempts);
    assert_eq!(after.circuit_until_ms, crashing.circuit_until_ms);
    assert_eq!(after.backoff_steps, crashing.backoff_steps);
    assert_eq!(
        consume(&scope).unwrap_err(),
        "native_resident_restart_circuit_open"
    );

    std::fs::remove_dir_all(scope).unwrap();
}
