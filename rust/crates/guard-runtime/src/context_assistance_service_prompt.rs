//! The agent-prompt lane: a quick yes/no on whether CIGAR may add project
//! context, and the live worker to ask. Never blocks a hook on a busy lock
//! and never creates consent; a resting opt-in is woken, not turned on.
use super::*;

/// The worker a prompt may use, and the generation it belongs to.
pub(crate) struct PromptLane {
    pub(crate) actor: Arc<RuntimeActor<Engine>>,
    generation: u64,
}

fn chosen(settings: &AssistanceSettings) -> bool {
    settings.requested.enabled
        && settings.effective.enabled
        && settings.verification_permitted
        && settings.diagnostic.is_none()
        && settings.effective.features.agent_context
        && settings.effective.sources.workspace_documents
}

impl Service {
    /// Whether someone turned on project context for their AI apps. Cheap
    /// and lock-free on contention, so a prompt pays nothing when it is off.
    pub(crate) fn prompt_context_chosen(&self) -> bool {
        self.state
            .try_lock()
            .is_ok_and(|state| !state.closed && chosen(&state.settings))
    }

    /// Starts a resting worker in `guard_home` without waiting for it, so it
    /// is up by the time a prompt asks. Does nothing unless project context
    /// is on, and never turns it on.
    pub(crate) fn warm_prompt_lane(&self, guard_home: &std::path::Path) {
        if self.prompt_context_chosen() {
            self.wake(guard_home, chosen);
        }
    }

    /// The live worker for a prompt, waking a resting one in `guard_home`
    /// and waiting for it until `deadline` at most.
    pub(crate) fn prompt_lane(
        &self,
        guard_home: &std::path::Path,
        deadline: Instant,
    ) -> Option<PromptLane> {
        self.wake(guard_home, chosen);
        loop {
            if let Ok(mut state) = self.state.try_lock() {
                if state.closed || !chosen(&state.settings) {
                    return None;
                }
                if let Some(actor) = state.runtime.as_ref().filter(|a| a.is_active()).cloned() {
                    state.last_used = Instant::now();
                    return Some(PromptLane {
                        actor,
                        generation: state.generation,
                    });
                }
                let waking = state
                    .pending
                    .as_ref()
                    .is_some_and(|job| job.operation == Check::Activate);
                if !waking {
                    return None;
                }
            }
            if Instant::now() + Duration::from_millis(50) >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// True while the lane's worker is still the current one and project
    /// context is still on, so an answer is never shown after a change.
    pub(crate) fn prompt_lane_current(&self, lane: &PromptLane) -> bool {
        lock(&self.state).is_ok_and(|state| {
            state.generation == lane.generation
                && chosen(&state.settings)
                && state
                    .runtime
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &lane.actor))
        })
    }
}
