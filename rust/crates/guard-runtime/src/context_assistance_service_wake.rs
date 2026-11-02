//! A saved opt-in outlives an idle or restarted runtime. Guard rests an empty
//! worker and wakes it on the next request; waking never creates new consent.
use super::*;

/// One automatic attempt per window, so a runtime that keeps failing settles.
const RETRY: Duration = Duration::from_secs(30);
/// Callers sit behind an 8 second transport budget and still need their call.
const WAIT: Duration = Duration::from_secs(4);

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
        self.schedule(Check::Activate, home.to_path_buf()).is_ok()
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
