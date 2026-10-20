//! Close out one supervised resident run.
//!
//! The client that asked for a resident is a one-shot process and is usually
//! gone before the resident it spawned has finished. The supervisor is the
//! only process that outlives that client and reaps the serving child, so it
//! is the one place that can say whether a run was an orderly
//! start-serve-exit cycle or a failure, and the only place that can keep the
//! child's stderr.

#[cfg(windows)]
use std::fs::File;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::time::Instant;
use std::time::{Duration, SystemTime};

use super::resident_failure_log;
use super::restart_budget;

/// The supervisor keeps writing in the runtime scope after its serving child
/// is gone: the stderr record first, then the restart budget. A stop that
/// only proves the child has exited can return while those writes are still
/// open, and on Windows the handles they hold make the scope directory
/// impossible to remove. The supervisor therefore holds this file shared for
/// its whole run, from before the spawn until after the record is written,
/// and a stop takes the exclusive lock so that "stopped" means no supervisor
/// is still inside the scope.
///
/// Only Windows needs this. A Unix scope can be removed while a supervisor
/// still has files open in it, and making every Unix stop wait out the
/// supervisor's stderr tail would push it past the bound callers give it.
#[cfg(windows)]
const SUPERVISOR_HOLD_FILE: &str = "supervisor-exit.v1.lock";
/// A supervisor that has already reaped its child has one bounded record
/// write and the budget lock left to do, so a stop polls for the hold rather
/// than sleeping out its whole bound.
#[cfg(windows)]
const SUPERVISOR_QUIESCE_RETRY_DELAY: Duration = Duration::from_millis(10);
/// How long a stop waits for the supervisors inside the scope to finish.
///
/// This must outlast everything a supervisor still does while holding the
/// scope, not just the writes themselves: it waits up to
/// `MANAGED_STOP_TIMEOUT` for the child's stderr, because a grandchild can
/// keep that pipe open after the resident is gone, and the failure record
/// and the restart budget then take their own bounded lock waits. Bounding the stop by
/// `MANAGED_STOP_TIMEOUT` alone would race that ordinary tail and report a
/// resident that has in fact stopped as still running.
#[cfg(windows)]
const SUPERVISOR_QUIESCE_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(windows)]
struct SupervisorHold {
    file: File,
}

#[cfg(windows)]
impl Drop for SupervisorHold {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

/// The runtime scope of one supervised run, together with the hold that says
/// the supervisor is still inside it. Passing it into
/// [`record_supervised_exit`] by value is what keeps the hold alive for
/// exactly as long as the supervisor writes.
pub(super) struct SupervisedScope {
    scope: PathBuf,
    /// When the scope was claimed, before the child was spawned. A failure
    /// record written after this belongs to a later run.
    started: SystemTime,
    #[cfg(windows)]
    _hold: Option<SupervisorHold>,
}

/// Resolve the scope of a run that is about to be spawned and claim it for
/// this supervisor.
pub(super) fn supervised_scope(state_base: &Path, digest: &str) -> Result<SupervisedScope, String> {
    let scope = crate::resident_state::state_scope(state_base, digest)?;
    let started = SystemTime::now();
    #[cfg(windows)]
    let supervised = {
        let hold = hold_scope(&scope);
        SupervisedScope {
            scope,
            started,
            _hold: hold,
        }
    };
    #[cfg(not(windows))]
    let supervised = SupervisedScope { scope, started };
    Ok(supervised)
}

/// Claiming the scope is best effort: a hold that cannot be taken leaves the
/// stop path exactly as it was before, and a resident must still start.
#[cfg(windows)]
fn hold_scope(scope: &Path) -> Option<SupervisorHold> {
    let file = open_hold_file(scope).ok()?;
    fs2::FileExt::try_lock_shared(&file).ok()?;
    Some(SupervisorHold { file })
}

#[cfg(windows)]
fn open_hold_file(scope: &Path) -> Result<File, String> {
    let private_root = crate::resident_state::private_root_for_scope(scope)?;
    let path = scope.join(SUPERVISOR_HOLD_FILE);
    let (file, directory_binding) = crate::resident_state::private_lock_file(&path, &private_root)?;
    // The supervisor must not hold a directory barrier for its child's
    // lifetime; other clients still bind this ancestry.
    drop(directory_binding);
    Ok(file)
}

/// Quiesce the scope while holding the home-wide startup lock a client takes
/// before it spawns, so no new supervisor can claim the scope while the probe
/// waits and keep it claimed for its resident's whole life.
///
/// The lock is handed back so the caller can clear the restart budget under
/// it. Without it a start may already have charged the budget for a new run,
/// and that charge must stand.
#[cfg(windows)]
pub(super) fn quiesce_under_startup_lock(
    state_base: &Path,
    digest: &str,
    scope: &Path,
) -> Result<Option<crate::resident_state::StartupLock>, String> {
    let startup = hold_startup_for_quiesce(state_base, digest);
    wait_for_supervisor_quiesce(scope)?;
    Ok(startup)
}

/// A Unix supervisor takes no hold, so there is nothing to wait for: the
/// scope stays removable while its last writes finish. The startup lock is
/// still taken for the budget, but only if it is free now, so a start in
/// progress cannot hold up the stop.
#[cfg(not(windows))]
pub(super) fn quiesce_under_startup_lock(
    state_base: &Path,
    digest: &str,
    _scope: &Path,
) -> Result<Option<crate::resident_state::StartupLock>, String> {
    if let Ok(Some(lock)) = crate::resident_state::acquire_startup_lock(state_base) {
        return Ok(Some(lock));
    }
    if matches!(
        crate::resident_state::clear_stale_startup_lock(state_base, digest),
        Ok(true)
    ) {
        return Ok(crate::resident_state::acquire_startup_lock(state_base)
            .ok()
            .flatten());
    }
    Ok(None)
}

/// Take the startup lock clients spawn under, waiting out a start that is
/// already under way. Best effort: a lock that cannot be had leaves the probe
/// as it was, bounded by its own timeout.
#[cfg(windows)]
fn hold_startup_for_quiesce(
    state_base: &Path,
    digest: &str,
) -> Option<crate::resident_state::StartupLock> {
    let deadline = Instant::now() + super::MANAGED_STOP_TIMEOUT;
    loop {
        if let Ok(Some(lock)) = crate::resident_state::acquire_startup_lock(state_base) {
            return Some(lock);
        }
        if matches!(
            crate::resident_state::clear_stale_startup_lock(state_base, digest),
            Ok(true)
        ) {
            continue;
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(super::CLIENT_RETRY_DELAY);
    }
}

/// Wait until no supervisor is writing in this scope any more. The caller has
/// already proved the serving children are gone; this proves the processes
/// that reap them have finished their records, so the scope can be read as
/// final and removed.
#[cfg(windows)]
pub(super) fn wait_for_supervisor_quiesce(scope: &Path) -> Result<(), String> {
    wait_for_supervisor_quiesce_within(scope, SUPERVISOR_QUIESCE_TIMEOUT)
}

#[cfg(windows)]
fn wait_for_supervisor_quiesce_within(scope: &Path, timeout: Duration) -> Result<(), String> {
    let Ok(file) = open_hold_file(scope) else {
        // A hold that cannot be opened cannot have been taken either.
        return Ok(());
    };
    let deadline = Instant::now() + timeout;
    loop {
        if fs2::FileExt::try_lock_exclusive(&file).is_ok() {
            let _ = fs2::FileExt::unlock(&file);
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("native_resident_supervisor_exit_pending".to_owned());
        }
        std::thread::sleep(SUPERVISOR_QUIESCE_RETRY_DELAY);
    }
}

/// Read the serving child's stderr on a thread of its own, handing the bytes
/// back over a channel rather than a join: a grandchild that inherited the
/// pipe can hold it open after the resident itself is gone, and the
/// supervisor must still finish. The pump never touches the record file, so
/// one left behind by an earlier run cannot overwrite a later run's record.
#[cfg(not(windows))]
pub(super) fn capture_resident_stderr(
    child: &mut std::process::Child,
) -> Option<std::sync::mpsc::Receiver<Vec<u8>>> {
    let stderr = child.stderr.take()?;
    let (sender, receiver) = std::sync::mpsc::channel();
    let _pump = std::thread::spawn(move || {
        let _ = sender.send(resident_failure_log::collect_resident_stderr(stderr));
    });
    Some(receiver)
}

/// Hand the restart budget the classification of this exit, and leave the
/// user a record of the runs that were not healthy. A broken record or a
/// busy budget must not change the supervised result, so both are best
/// effort here.
pub(super) fn record_supervised_exit(
    supervised: SupervisedScope,
    stderr: Option<Vec<u8>>,
    success: bool,
    exit_code: Option<i32>,
    ran_for: Duration,
) {
    let code = exit_code.map_or_else(|| "none".to_owned(), |code| code.to_string());
    let ran_for_ms = ran_for.as_millis();
    let note = if !success {
        Some(format!(
            "native_resident_managed_exit_failed exit_code={code} ran_for_ms={ran_for_ms}"
        ))
    } else if restart_budget::healthy_exit(success, ran_for) {
        None
    } else {
        // A resident that reports success before it can have served anything
        // keeps its restart charge; say so where it can be seen.
        Some(format!(
            "native_resident_managed_exit_premature exit_code={code} ran_for_ms={ran_for_ms}"
        ))
    };
    // Stderr the pump has not handed over yet is lost rather than waited for,
    // but the exit note is still written: a pipe held open by a descendant
    // must not cost the user the reason the run ended.
    let stderr = stderr.unwrap_or_default();
    let scope = supervised.scope.clone();
    resident_failure_log::write_run_unless_superseded(
        &scope,
        &stderr,
        note.as_deref(),
        supervised.started,
    );
    let _ = restart_budget::release_after_exit(&scope, success, ran_for);
    // The hold is released last: it is what tells a waiting stop that these
    // writes are over.
    #[cfg(windows)]
    drop(supervised);
}

/// Close out a run the Unix supervisor owns, collecting the stderr its pump
/// has read. The pipe can outlive the resident, so the record waits only as
/// long as a stop would.
#[cfg(not(windows))]
pub(super) fn record_supervised_run(
    supervised: SupervisedScope,
    stderr: Option<std::sync::mpsc::Receiver<Vec<u8>>>,
    status: std::process::ExitStatus,
    ran_for: Duration,
) {
    let stderr = stderr.and_then(|stderr| stderr.recv_timeout(super::MANAGED_STOP_TIMEOUT).ok());
    record_supervised_exit(supervised, stderr, status.success(), status.code(), ran_for);
}

#[cfg(all(test, windows))]
#[path = "managed_resident_supervisor_hold_tests.rs"]
mod supervisor_hold_tests;
