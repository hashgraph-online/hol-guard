//! The agent-prompt lane: a quick yes/no on whether CIGAR may add project
//! context, and the live worker to ask. Never blocks a hook on a busy lock
//! and never creates consent; a resting opt-in is woken, not turned on.
use super::*;

/// The worker a prompt may use, and the generation it belongs to.
pub(crate) struct PromptLane {
    pub(crate) actor: Arc<RuntimeActor<Engine>>,
    generation: u64,
}

/// Why a prompt has no live worker to ask.
pub(crate) enum LaneMiss {
    /// Project context is off, Guard is closing, or CIGAR is not starting.
    Off,
    /// CIGAR is on and was still starting when the deadline came.
    Starting,
}

/// How long [`Service::prompt_context_chosen`] waits for a busy lock.
const CHOSEN_WAIT: Duration = Duration::from_millis(40);

fn chosen(settings: &AssistanceSettings) -> bool {
    settings.requested.enabled
        && settings.effective.enabled
        && settings.verification_permitted
        && settings.diagnostic.is_none()
        && settings.effective.features.agent_context
        && settings.effective.sources.workspace_documents
}

impl Service {
    /// Whether someone turned on project context for their AI apps. Cheap:
    /// a busy lock is waited for a few milliseconds at most, so a prompt that
    /// lands while another hook holds it still gets its context.
    pub(crate) fn prompt_context_chosen(&self) -> bool {
        let until = Instant::now() + CHOSEN_WAIT;
        loop {
            match self.state.try_lock() {
                Ok(state) => return !state.closed && chosen(&state.settings),
                Err(std::sync::TryLockError::WouldBlock) if Instant::now() < until => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => return false,
            }
        }
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
    ) -> Result<PromptLane, LaneMiss> {
        self.wake(guard_home, chosen);
        self.lane_watch().wait(deadline)
    }

    /// A handle that waits for the worker without borrowing the service, so
    /// a prompt that found CIGAR starting can leave a warm-up behind.
    pub(crate) fn lane_watch(&self) -> LaneWatch {
        LaneWatch {
            state: Arc::clone(&self.state),
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

/// Waits for a worker someone already woke; never wakes one itself.
pub(crate) struct LaneWatch {
    state: Arc<Mutex<State>>,
}

impl LaneWatch {
    /// The live worker, waiting for a starting one until `deadline` at most.
    pub(crate) fn wait(&self, deadline: Instant) -> Result<PromptLane, LaneMiss> {
        loop {
            if let Ok(mut state) = self.state.try_lock() {
                if state.closed || !chosen(&state.settings) {
                    return Err(LaneMiss::Off);
                }
                if let Some(actor) = state.runtime.as_ref().filter(|a| a.is_active()).cloned() {
                    state.last_used = Instant::now();
                    return Ok(PromptLane {
                        actor,
                        generation: state.generation,
                    });
                }
                let waking = state
                    .pending
                    .as_ref()
                    .is_some_and(|job| job.operation == Check::Activate);
                if !waking {
                    return Err(LaneMiss::Off);
                }
            }
            if Instant::now() + Duration::from_millis(50) >= deadline {
                return Err(LaneMiss::Starting);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

#[cfg(test)]
impl Service {
    /// Project context on, with a start that stays pending until
    /// `end_start_for_tests`.
    pub(crate) fn hold_start_for_tests(&self) {
        let mut config = guard_context_assistance::ContextAssistanceConfig {
            enabled: true,
            runtime_id: "selected".into(),
            ..Default::default()
        };
        config.features.agent_context = true;
        config.sources.workspace_documents = true;
        self.configure(AssistanceSettings {
            requested: config.clone(),
            effective: config,
            verification_permitted: true,
            ..Default::default()
        })
        .unwrap();
        let mut state = lock(&self.state).unwrap();
        state.pending = Some(Pending {
            id: state.generation,
            operation: Check::Activate,
            cancel: Arc::default(),
        });
    }

    pub(crate) fn end_start_for_tests(&self) {
        lock(&self.state).unwrap().pending = None;
    }
}
