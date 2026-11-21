//! A direct hook that meets the business-source fence while a policy update
//! holds it polls inside its own budget, then defers to the daemon.
//!
//! The fence refuses admission before any evaluation, so retrying the same
//! envelope is safe. The poll never outlasts the request budget less a
//! margin, so the daemon still answers fail-closed inside the harness hook
//! timeout when the update outlasts it. A hook that waited and was then
//! admitted reports how long it waited, so the daemon can count it in the
//! fence window it records.

use super::HookDirectDefer;
use crate::policy_store::PolicySnapshotStore;
use guard_contracts::GuardHookEnvelopeV2;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

const POLICY_SOURCE_FENCE_ERROR: &str = "native_business_source_mutation_in_progress";
/// The longest a hook waits for a policy update to finish.
const REBUILD_WAIT: Duration = Duration::from_millis(8_000);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Left for evaluation, rendering and transport after the last poll.
const BUDGET_MARGIN: Duration = Duration::from_millis(250);

/// The edge answer and, when the hook polled through the fence first, how long
/// it waited.
pub(super) type Admitted = (Vec<u8>, Option<Duration>);

/// `evidence` with the hook's fence wait, which the daemon records as a
/// policy update's fence window, when it waited.
pub(super) fn with_wait(mut evidence: Value, waited: Option<Duration>) -> Value {
    if let Some(waited) = waited {
        evidence["fence_wait_ms"] = json!(u64::try_from(waited.as_millis()).unwrap_or(u64::MAX));
    }
    evidence
}

pub(super) fn evaluate(
    envelope: GuardHookEnvelopeV2,
    policy_store: &PolicySnapshotStore,
) -> Result<Admitted, HookDirectDefer> {
    let budget = Duration::from_millis(envelope.deadline_budget_ms.unwrap_or(0));
    poll_through_fence(
        fence_wait(budget),
        || crate::edge::evaluate_envelope_with_store(envelope.clone(), policy_store),
        std::thread::sleep,
    )
}

/// The bounded wait: the rebuild bound, never past the budget less margin.
pub(super) fn fence_wait(budget: Duration) -> Duration {
    REBUILD_WAIT.min(budget.saturating_sub(BUDGET_MARGIN))
}

pub(super) fn poll_through_fence(
    wait: Duration,
    mut attempt: impl FnMut() -> Result<Vec<u8>, String>,
    mut sleep: impl FnMut(Duration),
) -> Result<Admitted, HookDirectDefer> {
    let started = Instant::now();
    let mut waited = false;
    loop {
        match attempt() {
            Ok(edge) => return Ok((edge, waited.then(|| started.elapsed()))),
            // The daemon owns the stable policy-update answer once the wait
            // is spent; this path never answers a verdict it did not reach.
            Err(code)
                if code == POLICY_SOURCE_FENCE_ERROR
                    && started.elapsed() + POLL_INTERVAL <= wait =>
            {
                waited = true;
                sleep(POLL_INTERVAL);
            }
            Err(_) => return Err(HookDirectDefer::EdgeFailed),
        }
    }
}

#[cfg(test)]
#[path = "hook_direct_fence_tests.rs"]
mod tests;
