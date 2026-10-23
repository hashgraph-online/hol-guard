use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use super::private_file::recover_interrupted_replace;
use super::private_file::{existing_private_file, read_private_bytes, write_private};

const RESTART_WINDOW_MS: u64 = 60_000;
// A crash loop is slowed by bounded exponential backoff, not stopped for a
// fixed half minute: the first refusal lasts RESTART_BACKOFF_BASE_MS and each
// further restart doubles it up to RESTART_BACKOFF_MAX_MS.
const RESTART_BACKOFF_BASE_MS: u64 = 2_000;
const RESTART_BACKOFF_MAX_MS: u64 = 30_000;
const MAX_RESTARTS_PER_WINDOW: u32 = 3;
/// How long a supervised resident must live before its own exit counts as a
/// healthy start-serve-exit cycle rather than a restart. An ownerless
/// resident is held for `LEASE_EXPIRY` after its last client lease drops, so
/// every orderly cycle outlives this; a resident that reports success within
/// milliseconds, over and over, is still a loop and keeps its charge.
const HEALTHY_RUN_MIN_MS: u128 = 1_000;
/// Every budget update holds the lock for one small read and write, so a
/// spawn, a reset and a supervisor recording its exit each wait briefly for
/// one another instead of failing on an ordinary overlap.
const BUDGET_LOCK_RETRY_DELAY: Duration = Duration::from_millis(25);
const BUDGET_LOCK_RETRIES: u32 = 20;
const BUDGET_SCHEMA: &str = "hol-guard-resident-restart-budget.v1";
const BUDGET_LOCK_FILE: &str = "restart-budget.lock";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestartBudget {
    schema: String,
    window_start_ms: u64,
    attempts: u32,
    circuit_until_ms: u64,
    #[serde(default)]
    backoff_steps: u32,
}

fn backoff_ms(steps: u32) -> u64 {
    RESTART_BACKOFF_BASE_MS
        .saturating_mul(1u64 << steps.min(8))
        .min(RESTART_BACKOFF_MAX_MS)
}

struct RestartBudgetLock {
    file: File,
    #[cfg(windows)]
    _directory_binding: guard_runtime_windows_process::PrivateDirectoryBinding,
}

impl Drop for RestartBudgetLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

fn acquire_budget_lock(scope: &Path) -> Result<RestartBudgetLock, String> {
    let path = scope.join(BUDGET_LOCK_FILE);
    let private_root = crate::resident_state::private_root_for_scope(scope)?;
    #[cfg(windows)]
    let (file, directory_binding) = crate::resident_state::private_lock_file(&path, &private_root)
        .map_err(|_| "native_resident_restart_budget_lock_failed".to_owned())?;
    #[cfg(not(windows))]
    let file = crate::resident_state::private_lock_file(&path, &private_root)
        .map_err(|_| "native_resident_restart_budget_lock_failed".to_owned())?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
        // Windows reports a held lock as ERROR_LOCK_VIOLATION, not WouldBlock.
        // Treating that as a hard failure turned an ordinary race with the
        // supervisor's exit bookkeeping into a failed resident spawn.
        if crate::resident_state::is_lock_contention(&error) {
            "native_resident_restart_budget_busy".to_owned()
        } else {
            "native_resident_restart_budget_lock_failed".to_owned()
        }
    })?;
    Ok(RestartBudgetLock {
        file,
        #[cfg(windows)]
        _directory_binding: directory_binding,
    })
}

fn now_ms() -> Result<u64, String> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "native_resident_clock_invalid".to_owned())?
            .as_millis(),
    )
    .map_err(|_| "native_resident_clock_invalid".to_owned())
}

/// Read this scope's budget when it already exists, validating the private
/// file and its schema. Absent state is not an error: the first spawn in a
/// home starts from a fresh budget.
fn read_existing_budget(path: &Path, private_root: &Path) -> Result<Option<RestartBudget>, String> {
    let Some(bytes) = read_private_bytes(path, private_root, "restart_budget")? else {
        return Ok(None);
    };
    let value = crate::strict_json_value(&bytes)
        .map_err(|_| "native_resident_restart_budget_invalid".to_owned())?;
    let budget = serde_json::from_value::<RestartBudget>(value)
        .map_err(|_| "native_resident_restart_budget_invalid".to_owned())?;
    if budget.schema != BUDGET_SCHEMA {
        return Err("native_resident_restart_budget_invalid".to_owned());
    }
    Ok(Some(budget))
}

pub(super) fn consume_for_spawn(
    state_base: &Path,
    scope: &Path,
    deadline: Instant,
) -> Result<(), String> {
    let verifier_key = state_base.join(crate::policy_store::VERIFIER_KEY_FILE_NAME);
    match std::fs::symlink_metadata(&verifier_key) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() != crate::policy_store::VERIFIER_KEY_BYTES as u64 =>
        {
            return Err("native_policy_verifier_key_invalid".to_owned());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err("native_policy_verifier_key_missing".to_owned());
        }
        Err(_) => return Err("native_policy_verifier_key_stat_failed".to_owned()),
    }
    consume_before(scope, Some(deadline))
}

#[cfg(test)]
pub(super) fn consume(scope: &Path) -> Result<(), String> {
    consume_before(scope, None)
}

/// Charge one spawn. A request that runs out of time while it waits for the
/// lock charges nothing, so a resident is never started for an answer the
/// client can no longer wait for.
fn consume_before(scope: &Path, deadline: Option<Instant>) -> Result<(), String> {
    let private_root = crate::resident_state::private_root_for_scope(scope)?;
    let _lock = acquire_budget_lock_waiting(scope, deadline)?;
    let path = scope.join("restart-budget.json");
    #[cfg(windows)]
    recover_interrupted_replace(&path, &private_root)?;
    let now = now_ms()?;
    let mut budget = read_existing_budget(&path, &private_root)?.unwrap_or_else(|| RestartBudget {
        schema: BUDGET_SCHEMA.to_owned(),
        window_start_ms: now,
        attempts: 0,
        circuit_until_ms: 0,
        backoff_steps: 0,
    });
    if budget.circuit_until_ms > now {
        return Err("native_resident_restart_circuit_open".to_owned());
    }
    if now.saturating_sub(budget.window_start_ms) >= RESTART_WINDOW_MS {
        budget.window_start_ms = now;
        budget.attempts = 0;
        budget.circuit_until_ms = 0;
        budget.backoff_steps = 0;
    }
    if budget.attempts >= MAX_RESTARTS_PER_WINDOW {
        // Past the free restarts the resident is respawned at most once per
        // backoff interval instead of being refused for the whole window.
        let backoff_elapsed = budget.circuit_until_ms != 0;
        budget.circuit_until_ms = now.saturating_add(backoff_ms(budget.backoff_steps));
        budget.backoff_steps = budget.backoff_steps.saturating_add(1);
        if !backoff_elapsed {
            let encoded = serde_json::to_vec(&budget)
                .map_err(|_| "native_resident_restart_budget_encode_failed".to_owned())?;
            write_private(&path, &encoded, &private_root)?;
            return Err("native_resident_restart_circuit_open".to_owned());
        }
    }
    budget.attempts += 1;
    let encoded = serde_json::to_vec(&budget)
        .map_err(|_| "native_resident_restart_budget_encode_failed".to_owned())?;
    write_private(&path, &encoded, &private_root)
}

/// Whether a finished resident run was an orderly lifecycle rather than a
/// restart.
///
/// A run that was asked to stop is orderly however briefly it lived. Asking
/// it to live a second first is not a test of health. A `shutdown` operation
/// reaches a resident from exactly two places: a runtime of a different
/// digest retiring it to take the home-wide owner lock, and an explicit
/// `resident-stop`. Two builds installed against one guard home -- a desktop
/// bundle and a package install, say -- therefore stop each other's resident
/// within milliseconds, over and over. Scoring those stops as crashes opened
/// the circuit after three of them in a minute, and from there no resident
/// could start, no policy could be published, and every prompt was refused
/// with `native_policy_not_ready`.
///
/// Only a run that failed -- a non-zero exit, a signal, or a success reported
/// so fast the resident cannot have served anything and nobody asked it to
/// stop -- keeps the charge its spawn took.
pub(super) fn orderly_exit(success: bool, ran_for: Duration, stop_requested: bool) -> bool {
    success && (stop_requested || ran_for.as_millis() >= HEALTHY_RUN_MIN_MS)
}

fn acquire_budget_lock_waiting(
    scope: &Path,
    deadline: Option<Instant>,
) -> Result<RestartBudgetLock, String> {
    let mut waited = 0;
    loop {
        match acquire_budget_lock(scope) {
            Err(error)
                if error == "native_resident_restart_budget_busy"
                    && waited < BUDGET_LOCK_RETRIES =>
            {
                if deadline
                    .is_some_and(|deadline| Instant::now() + BUDGET_LOCK_RETRY_DELAY >= deadline)
                {
                    return Err("native_client_deadline_exceeded".to_owned());
                }
                waited += 1;
                std::thread::sleep(BUDGET_LOCK_RETRY_DELAY);
            }
            Ok(_) if deadline.is_some_and(|deadline| Instant::now() >= deadline) => {
                return Err("native_client_deadline_exceeded".to_owned());
            }
            result => return result,
        }
    }
}

/// Give back the restart charge a spawn took when the resident it started
/// went on to run and exit cleanly.
///
/// This runs in the supervisor once it has reaped its serving child, so it
/// can arrive after the next client has already consumed for its own spawn.
/// Releasing one attempt rather than resetting the counter keeps that
/// ordering harmless: charges from runs that really did crash stay on the
/// budget, and a crash loop still opens the circuit after
/// `MAX_RESTARTS_PER_WINDOW` of them.
pub(super) fn release_after_exit(
    scope: &Path,
    orderly: bool,
    ran_for: Duration,
) -> Result<(), String> {
    if !orderly {
        return Ok(());
    }
    let private_root = crate::resident_state::private_root_for_scope(scope)?;
    let _lock = acquire_budget_lock_waiting(scope, None)?;
    let path = scope.join("restart-budget.json");
    #[cfg(windows)]
    recover_interrupted_replace(&path, &private_root)?;
    let Some(mut budget) = read_existing_budget(&path, &private_root)? else {
        return Ok(());
    };
    if budget.attempts == 0 && budget.circuit_until_ms == 0 && budget.backoff_steps == 0 {
        return Ok(());
    }
    // The charge this run is giving back was taken from the window that was
    // open when it was spawned. If the budget has rolled into a newer window
    // since, every attempt and any circuit on it belong to later runs, and a
    // long-lived resident finishing now must not clear the crash loop that
    // started after it.
    let started_ms =
        now_ms()?.saturating_sub(u64::try_from(ran_for.as_millis()).unwrap_or(u64::MAX));
    if budget.window_start_ms > started_ms {
        return Ok(());
    }
    budget.attempts = budget.attempts.saturating_sub(1);
    // A resident that completed a full cycle is not the one the backoff was
    // pacing, so the next spawn starts from the free restarts again.
    budget.circuit_until_ms = 0;
    budget.backoff_steps = 0;
    let encoded = serde_json::to_vec(&budget)
        .map_err(|_| "native_resident_restart_budget_encode_failed".to_owned())?;
    write_private(&path, &encoded, &private_root)
}

pub(super) fn clear(scope: &Path) -> Result<(), String> {
    let private_root = crate::resident_state::private_root_for_scope(scope)?;
    let _lock = acquire_budget_lock_waiting(scope, None)?;
    let path = scope.join("restart-budget.json");
    if !existing_private_file(&path, &private_root)? {
        return Ok(());
    }
    let encoded = serde_json::to_vec(&RestartBudget {
        schema: BUDGET_SCHEMA.to_owned(),
        window_start_ms: now_ms()?,
        attempts: 0,
        circuit_until_ms: 0,
        backoff_steps: 0,
    })
    .map_err(|_| "native_resident_restart_budget_encode_failed".to_owned())?;
    write_private(&path, &encoded, &private_root)
}

#[cfg(test)]
#[path = "resident_restart_budget_tests.rs"]
mod tests;
