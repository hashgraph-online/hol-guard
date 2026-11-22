//! Waiting for a direct lane the daemon closed to republish.
//!
//! The daemon closes the direct lane while it republishes a moved fact (saved
//! decisions, review facts, the structured view itself) and routes its hooks
//! through the edge meanwhile. The republish lands at a newer generation, so a
//! `PostToolUse` routed in that window names a generation the lane will not
//! come back at. Withholding at once hid ordinary output that happened to
//! finish during the republish, such as a contained run's.

use super::*;

/// How often a routed `PostToolUse` looks for the lane to reopen.
const REOPEN_POLL: Duration = Duration::from_millis(10);

/// A structured-output view and the acknowledged binding it was read under.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StructuredLaneView {
    pub(crate) generation: u64,
    pub(crate) policy_digest: String,
    pub(crate) view: Option<Value>,
}

impl PolicySnapshotStore {
    /// The structured-output view for a hook the daemon routed here, waiting
    /// until `wait_until` for a lane the daemon closed to republish.
    ///
    /// The view comes from the requested generation and digest, or from a
    /// newer binding once its republish is acknowledged: that binding carries
    /// the daemon's current structured view, and the caller rechecks against
    /// the same binding before it releases content. Only a lane that last
    /// admitted a hook at the requested generation and digest is waited on;
    /// a lane that never opened there has nothing that will reopen it, so it
    /// answers at once. A lane that is not back by `wait_until` answers
    /// `None`, which withholds.
    pub(crate) fn structured_output_binding_awaiting(
        &self,
        generation: u64,
        policy_digest: &str,
        wait_until: Instant,
    ) -> Option<StructuredLaneView> {
        loop {
            let bound = self.bound_lane();
            let candidate = match &bound {
                Some((bound, digest)) if *bound == generation && digest == policy_digest => {
                    Some((generation, policy_digest))
                }
                Some((bound, digest)) if *bound > generation => Some((*bound, digest.as_str())),
                _ => None,
            };
            if let Some((generation, policy_digest)) = candidate {
                if let Some(view) =
                    self.structured_output_binding(generation, policy_digest, Some(wait_until))
                {
                    return Some(StructuredLaneView {
                        generation,
                        policy_digest: policy_digest.to_owned(),
                        view,
                    });
                }
            }
            let now = Instant::now();
            if bound.is_none()
                || !self.direct_lane_was_admitted_at(generation, policy_digest)
                || now >= wait_until
            {
                return None;
            }
            std::thread::sleep(REOPEN_POLL.min(wait_until - now));
        }
    }

    pub(super) fn note_direct_lane_admitted(&self, binding: &DirectLaneBinding) {
        let Ok(mut admitted) = self.direct_lane_admitted.lock() else {
            return;
        };
        let current = admitted.as_ref().is_some_and(|(generation, digest)| {
            *generation == binding.generation && *digest == binding.policy_digest
        });
        if !current {
            *admitted = Some((binding.generation, binding.policy_digest.clone()));
        }
    }

    pub(super) fn forget_direct_lane_admission(&self) {
        if let Ok(mut admitted) = self.direct_lane_admitted.lock() {
            *admitted = None;
        }
    }

    fn direct_lane_was_admitted_at(&self, generation: u64, policy_digest: &str) -> bool {
        self.direct_lane_admitted.lock().is_ok_and(|admitted| {
            admitted.as_ref().is_some_and(|(admitted, digest)| {
                *admitted == generation && digest == policy_digest
            })
        })
    }

    fn bound_lane(&self) -> Option<(u64, String)> {
        self.direct_lane.lock().ok().and_then(|binding| {
            binding
                .as_ref()
                .map(|binding| (binding.generation, binding.policy_digest.clone()))
        })
    }
}

#[cfg(all(test, unix))]
#[path = "policy_store_direct_lane_reopen_tests.rs"]
mod tests;
