//! A failing resident must not become one process per failure.
//!
//! Every spawn is charged against the restart budget before the process is
//! created, so the bound these tests prove is a bound on processes: a grant is
//! a resident, a refusal is not. The three shapes a crash loop actually takes
//! are a tight retry loop, a loop patient enough to wait out each backoff, and
//! a burst of clients that all miss the resident at once.

use super::*;
use std::path::PathBuf;
use std::sync::mpsc;

/// What a perfectly patient caller can take out of one window: the free
/// restarts, plus one resident for every backoff step that still elapses
/// inside the window. Past that the window rolls over and the count starts
/// again, so the bound a crash loop runs into is this rate, not a total.
fn grants_per_window() -> u64 {
    let mut elapsed = 0u64;
    let mut grants = u64::from(MAX_RESTARTS_PER_WINDOW);
    let mut step = 0u32;
    loop {
        elapsed = elapsed.saturating_add(backoff_ms(step));
        if elapsed >= RESTART_WINDOW_MS {
            return grants;
        }
        grants += 1;
        step += 1;
    }
}

fn budget_of(scope: &Path) -> RestartBudget {
    serde_json::from_slice(&std::fs::read(scope.join("restart-budget.json")).unwrap()).unwrap()
}

fn flood_scope(label: &str) -> PathBuf {
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-restart-flood-{label}-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    std::fs::create_dir(&scope).unwrap();
    scope
}

#[test]
fn sixty_four_failures_in_a_row_start_three_residents() {
    let scope = flood_scope("tight");

    let mut granted = 0usize;
    for _ in 0..64 {
        match consume(&scope) {
            Ok(()) => granted += 1,
            Err(error) => assert_eq!(error, "native_resident_restart_circuit_open"),
        }
    }

    assert_eq!(granted, MAX_RESTARTS_PER_WINDOW as usize);
    // Retrying faster buys nothing back. A refusal while the circuit is open
    // returns before it reaches the backoff, so the sixty refusals after the
    // first one leave the same single step behind that the first one set.
    assert_eq!(budget_of(&scope).backoff_steps, 1);

    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_loop_patient_enough_to_wait_out_every_backoff_is_held_to_a_rate() {
    let scope = flood_scope("patient");

    // A caller that waits exactly as long as each refusal tells it to, and
    // crashes again the moment it is served. Its clock is simulated so the
    // minutes pass here the way they pass for it, window rollovers included.
    let start = now_ms().unwrap();
    let mut clock = start;
    let mut granted = 0usize;
    for _ in 0..64 {
        match consume_simulated(&scope, clock) {
            Ok(()) => granted += 1,
            Err(error) => {
                assert_eq!(error, "native_resident_restart_circuit_open");
                // The refusal names the moment the next spawn becomes
                // possible, and nothing the caller does brings it closer.
                let next_spawn_ms = budget_of(&scope).circuit_until_ms;
                assert!(next_spawn_ms > clock, "a refusal must name a later moment");
                clock = next_spawn_ms;
            }
        }
    }

    let elapsed_ms = clock - start;
    // What holds a crash loop back is a rate, not a ceiling it hits once: the
    // window does keep rolling over while the caller waits, and each one hands
    // out the free restarts again. Sixty-four failures still cannot be served
    // as sixty-four processes, and the ones that are served arrive over
    // minutes instead of all at once.
    assert!(granted < 64, "granted {granted} residents for 64 failures");
    let windows = elapsed_ms / RESTART_WINDOW_MS + 1;
    assert!(
        granted as u64 <= windows * grants_per_window(),
        "{granted} residents inside {windows} window(s) of {elapsed_ms}ms"
    );
    assert!(
        elapsed_ms >= 4 * RESTART_WINDOW_MS,
        "64 failures demanded only {elapsed_ms}ms of waiting"
    );

    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn sixty_four_clients_that_all_miss_the_resident_at_once_do_not_each_start_one() {
    let scope = flood_scope("burst");

    let (results, collect) = mpsc::channel();
    let threads: Vec<_> = (0..64)
        .map(|_| {
            let scope = scope.clone();
            let results = results.clone();
            std::thread::spawn(move || results.send(consume(&scope)).unwrap())
        })
        .collect();
    drop(results);
    let outcomes: Vec<_> = collect.iter().collect();
    for thread in threads {
        thread.join().unwrap();
    }

    assert_eq!(outcomes.len(), 64);
    let granted = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
    // The budget is taken under an exclusive lock, so a burst is charged one
    // at a time however many clients arrive together.
    assert!(
        granted <= MAX_RESTARTS_PER_WINDOW as usize,
        "a burst of 64 started {granted} residents"
    );
    for outcome in &outcomes {
        if let Err(error) = outcome {
            // A client that could not take the lock in time is refused too.
            // Either way it did not start a resident.
            assert!(
                matches!(
                    error.as_str(),
                    "native_resident_restart_circuit_open" | "native_resident_restart_budget_busy"
                ),
                "unexpected refusal {error}"
            );
        }
    }

    std::fs::remove_dir_all(scope).unwrap();
}
