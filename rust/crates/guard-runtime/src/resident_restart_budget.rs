use serde::{Deserialize, Serialize};
use std::fs::File;
#[cfg(not(windows))]
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

fn write_private(path: &Path, bytes: &[u8], private_root: &Path) -> Result<(), String> {
    let temporary = temporary_path(path)?;
    if existing_private_file(&temporary, private_root)? {
        #[cfg(windows)]
        crate::resident_state::remove_windows_private_file(&temporary, private_root)
            .map_err(|_| "native_resident_restart_budget_recovery_failed".to_owned())?;
        #[cfg(not(windows))]
        fs::remove_file(&temporary)
            .map_err(|_| "native_resident_restart_budget_recovery_failed".to_owned())?;
    }
    #[cfg(not(windows))]
    let mut options = OpenOptions::new();
    #[cfg(not(windows))]
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    let mut file = crate::resident_state::private_file(&temporary, true, private_root)
        .map_err(|_| "native_resident_restart_budget_write_failed".to_owned())?;
    #[cfg(not(windows))]
    let mut file = options
        .open(&temporary)
        .map_err(|_| "native_resident_restart_budget_write_failed".to_owned())?;
    let write_result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "native_resident_restart_budget_write_failed".to_owned());
    drop(file);
    if write_result.is_err() {
        #[cfg(windows)]
        let _ = crate::resident_state::remove_windows_private_file(&temporary, private_root);
        #[cfg(not(windows))]
        let _ = fs::remove_file(&temporary);
        return write_result;
    }
    let replace_result = replace_temporary(&temporary, path, private_root);
    if replace_result.is_err() {
        #[cfg(windows)]
        let _ = crate::resident_state::remove_windows_private_file(&temporary, private_root);
        #[cfg(not(windows))]
        let _ = fs::remove_file(&temporary);
        return replace_result;
    }
    #[cfg(unix)]
    File::open(
        path.parent()
            .ok_or_else(|| "native_resident_restart_budget_write_failed".to_owned())?,
    )
    .and_then(|directory| directory.sync_all())
    .map_err(|_| "native_resident_restart_budget_write_failed".to_owned())?;
    Ok(())
}

fn existing_private_file(path: &Path, private_root: &Path) -> Result<bool, String> {
    #[cfg(not(windows))]
    let _ = private_root;

    #[cfg(windows)]
    {
        // Existence and type are established by one validated handle.  Do
        // not use pathname metadata here: a same-name replacement between a
        // stat and the subsequent open must never be treated as our budget
        // file, and foreign-owner/reparse objects must fail closed.
        crate::resident_state::open_private_read(path, 4096, "restart_budget", private_root)
            .map(|file| file.is_some())
            .map_err(|_| "native_resident_restart_budget_invalid".to_owned())
    }

    #[cfg(not(windows))]
    {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err("native_resident_restart_budget_stat_failed".to_owned()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 4096 {
            return Err("native_resident_restart_budget_invalid".to_owned());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let owner = path
                .parent()
                .and_then(|parent| fs::symlink_metadata(parent).ok())
                .map(|parent| parent.uid());
            if owner != Some(metadata.uid()) || metadata.permissions().mode() & 0o077 != 0 {
                return Err("native_resident_restart_budget_invalid".to_owned());
            }
        }
        Ok(true)
    }
}

#[cfg(not(windows))]
fn replace_temporary(temporary: &Path, path: &Path, _private_root: &Path) -> Result<(), String> {
    fs::rename(temporary, path).map_err(|_| {
        let _ = fs::remove_file(temporary);
        "native_resident_restart_budget_write_failed".to_owned()
    })
}

#[cfg(windows)]
fn replace_temporary(temporary: &Path, path: &Path, private_root: &Path) -> Result<(), String> {
    crate::resident_state::replace_windows_private_file(temporary, path, private_root)
        .map_err(|_| "native_resident_restart_budget_write_failed".to_owned())
}

#[cfg(windows)]
fn backup_path(path: &Path) -> PathBuf {
    path.with_extension("json.previous")
}

#[cfg(windows)]
fn recover_interrupted_replace(path: &Path, private_root: &Path) -> Result<(), String> {
    let backup = backup_path(path);
    let path_exists = existing_private_file(path, private_root)
        .map_err(|_| "native_resident_restart_budget_recovery_failed".to_owned())?;
    let backup_exists = existing_private_file(&backup, private_root)
        .map_err(|_| "native_resident_restart_budget_recovery_failed".to_owned())?;
    match (path_exists, backup_exists) {
        (false, true) => {
            crate::resident_state::replace_windows_private_file(&backup, path, private_root)
                .map_err(|_| "native_resident_restart_budget_recovery_failed".to_owned())
        }
        (true, true) => crate::resident_state::remove_windows_private_file(&backup, private_root)
            .map(|_| ())
            .map_err(|_| "native_resident_restart_budget_recovery_failed".to_owned()),
        _ => Ok(()),
    }
}

fn temporary_path(path: &Path) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "native_resident_restart_budget_write_failed".to_owned())?;
    Ok(path.with_file_name(format!(".{name}.{}.tmp", std::process::id())))
}

/// Read this scope's budget when it already exists, validating the private
/// file and its schema. Absent state is not an error: the first spawn in a
/// home starts from a fresh budget.
fn read_existing_budget(path: &Path, private_root: &Path) -> Result<Option<RestartBudget>, String> {
    if !existing_private_file(path, private_root)? {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    let file = {
        #[cfg(windows)]
        {
            crate::resident_state::open_private_read(path, 4096, "restart_budget", private_root)?
                .ok_or_else(|| "native_resident_restart_budget_read_failed".to_owned())?
        }
        #[cfg(not(windows))]
        {
            let mut options = OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            }
            options
                .open(path)
                .map_err(|_| "native_resident_restart_budget_read_failed".to_owned())?
        }
    };
    let metadata = file
        .metadata()
        .map_err(|_| "native_resident_restart_budget_stat_failed".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 4096 {
        return Err("native_resident_restart_budget_invalid".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let path_metadata = fs::symlink_metadata(path)
            .map_err(|_| "native_resident_restart_budget_stat_failed".to_owned())?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_file()
            || path_metadata.dev() != metadata.dev()
            || path_metadata.ino() != metadata.ino()
            || metadata.nlink() != 1
            || path
                .parent()
                .and_then(|parent| fs::symlink_metadata(parent).ok())
                .map(|parent| parent.uid())
                != Some(metadata.uid())
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("native_resident_restart_budget_invalid".to_owned());
        }
    }
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| "native_resident_restart_budget_read_failed".to_owned())?;
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

/// Whether a finished resident run was an orderly start-serve-exit cycle.
///
/// A one-shot `hol-guard hook` call owns the resident it spawns: the resident
/// starts, answers, and shuts itself down a second after the call's lease
/// drops. That is a complete lifecycle, not a restart, and charging it to the
/// crash-loop budget made four ordinary tool calls inside a minute open the
/// circuit. Only a run that failed -- a non-zero exit, a signal, or a
/// success reported so fast the resident cannot have served anything -- keeps
/// the charge its spawn took.
pub(super) fn healthy_exit(success: bool, ran_for: Duration) -> bool {
    success && ran_for.as_millis() >= HEALTHY_RUN_MIN_MS
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
    success: bool,
    ran_for: Duration,
) -> Result<(), String> {
    if !healthy_exit(success, ran_for) {
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
