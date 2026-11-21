//! A saved opt-in outlives an idle or restarted runtime. Guard rests an empty
//! worker and wakes it on the next request; waking never creates new consent.
use super::*;

/// One automatic attempt per window, so a runtime that keeps failing settles.
pub(super) const RETRY: Duration = Duration::from_secs(30);
/// Callers sit behind an 8 second transport budget and still need their call.
const WAIT: Duration = Duration::from_secs(4);
/// A worker that stops this soon after starting is broken, not resting.
const SETTLED: Duration = Duration::from_secs(300);

/// Names a worker that stopped on its own. One that had run a while rests and
/// wakes on demand; one that stops right after starting is shown to the user,
/// so a crashing runtime is never restarted in a loop.
pub(super) fn closed(state: &State) -> &'static str {
    if state.started.is_some_and(|at| at.elapsed() < SETTLED) {
        "runtime_crashed"
    } else {
        "runtime_closed"
    }
}

/// On by the user's saved choice, with nothing running and nothing broken.
/// A failed verification leaves its own diagnostic and is not retried here.
pub(super) fn resting(state: &State) -> bool {
    !state.closed
        && !state.stopping
        && state.settings.requested.enabled
        && state.settings.effective.enabled
        && state.settings.verification_permitted
        && state.settings.diagnostic.is_none()
        && !state.settings.effective.runtime_id.is_empty()
        && state.runtime.is_none()
        && state.pending.is_none()
        && state.upgrade.is_none()
        && state.cutover.is_none()
        && matches!(
            state.error.as_deref(),
            None | Some("runtime_idle" | "runtime_closed")
        )
}

impl Service {
    /// Loads the saved choice when the resident starts, so the first command
    /// after a restart can wake a resting CIGAR without waiting for the
    /// dashboard or an agent to ask first. An unreadable file leaves it off.
    pub(crate) fn restore(&self, home: &std::path::Path) {
        let Ok(generation) = self.configuration_generation() else {
            return;
        };
        retire_old_engine(home);
        if let Ok(settings) = crate::guard_config_load::context_assistance_config(home) {
            let _ = self.configure_at(settings, generation);
        }
    }

    /// Starts verification for a resting opt-in without waiting for it.
    pub(crate) fn wake(
        &self,
        home: &std::path::Path,
        wanted: impl FnOnce(&AssistanceSettings) -> bool,
    ) -> bool {
        {
            let Ok(mut state) = lock(&self.state) else {
                return false;
            };
            if !resting(&state)
                || !wanted(&state.settings)
                || state.woke.is_some_and(|at| at.elapsed() < RETRY)
            {
                return false;
            }
            state.woke = Some(Instant::now());
        }
        let Err(error) = self.schedule(Check::Activate, home.to_path_buf()) else {
            return true;
        };
        if let Ok(mut state) = lock(&self.state) {
            if error == "native_context_assistance_busy" {
                // Nothing started, so the next request may try again.
                state.woke = None;
            } else if resting(&state) {
                // A start that cannot happen is shown instead of "resting".
                let code = error.trim_start_matches("native_context_assistance_");
                state.error = Some(code.to_string());
            }
        }
        false
    }

    /// Lets a command hook reach the wake after it releases policy locks.
    /// Never blocks: a contended service is simply asked on the next command.
    #[cfg(target_os = "macos")]
    pub(crate) fn execution_resting(&self) -> bool {
        self.state.try_lock().is_ok_and(|state| {
            resting(&state)
                && state.settings.effective.features.execution_context
                && state.settings.effective.sources.native_policy_facts
                && state.woke.is_none_or(|at| at.elapsed() >= RETRY)
        })
    }

    /// Wakes a resting runtime and waits a bounded time for its verification.
    pub(crate) fn wake_and_wait(
        &self,
        home: &std::path::Path,
        wanted: impl FnOnce(&AssistanceSettings) -> bool,
    ) {
        self.wake(home, wanted);
        let deadline = Instant::now() + WAIT;
        while Instant::now() < deadline {
            let waking = lock(&self.state).is_ok_and(|state| {
                state
                    .pending
                    .as_ref()
                    .is_some_and(|job| job.operation == Check::Activate)
            });
            if !waking {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

#[cfg(test)]
#[path = "context_assistance_service_wake_tests.rs"]
mod tests;

/// Folders only the retired Python engine wrote. The built-in engine keeps its
/// data under `work`, and `jobs`/`switch-jobs` hold the shared lifecycle lease.
const RETIRED_DIRS: [&str; 15] = [
    "installations",
    "interpreters",
    "artifacts",
    "bundles",
    "staging",
    "downloads",
    "python",
    "python-staging",
    "python-work",
    "python-jobs",
    "python-artifacts",
    "python-downloads",
    "catalog-jobs",
    "catalog-downloads",
    "verification",
];

/// A profile that chose the retired Python engine is cleared and moved to the
/// built-in engine once: switch jobs recorded for the old engine and its saved
/// CIGAR memory are deleted (the built-in engine cannot read that memory),
/// then the same on/off choice is kept with `builtin`. Picked projects stay.
/// Any failure leaves the old choice in place, which the registry reports as
/// `runtime_retired`; the next start tries again.
fn retire_old_engine(home: &std::path::Path) {
    use crate::policy_store::context_assistance_registry::{switching::DataRemoval, BUILTIN_ID};
    remove_retired_dirs(home);
    let Ok(Some(raw)) = crate::guard_config_update::read_home_config(home) else {
        return;
    };
    let Ok(config) = crate::guard_config_update::assistance_preferences(&raw) else {
        return;
    };
    if config.runtime_id.is_empty() || config.runtime_id == BUILTIN_ID {
        return;
    }
    let Ok(removal) = DataRemoval::acquire(home) else {
        return;
    };
    // The lifecycle lease is held, so no switch job can run meanwhile. Jobs
    // saved before this point refer to the retired engine and to records the
    // removal below deletes; keeping them would leave a job nobody can recover.
    if remove_dir_if_present(&home.join("context-assistance").join("switch-jobs")).is_err() {
        return;
    }
    if removal.remove_memory().is_err() {
        return;
    }
    let _ = crate::guard_config_update::select_builtin_context_assistance(home);
}

/// Old-engine folders are removed on every start, whatever is selected, so a
/// profile that downloaded the Python engine without selecting it, or a
/// deletion that failed once, is cleaned up the next time Guard starts.
fn remove_retired_dirs(home: &std::path::Path) {
    let root = home.join("context-assistance");
    for name in RETIRED_DIRS {
        let _ = remove_dir_if_present(&root.join(name));
    }
}

fn remove_dir_if_present(path: &std::path::Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}
