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
/// How long a prompt waits for settings saved since the last one to load.
const FOLLOW_WAIT: Duration = Duration::from_millis(250);
/// Largest settings file a prompt reads to see whether it changed.
const FOLLOW_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// The saved settings file's bytes, or `None` when it is missing, not a
/// regular file or larger than [`FOLLOW_MAX_BYTES`].
fn read_saved_settings(path: &std::path::Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > FOLLOW_MAX_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(FOLLOW_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= FOLLOW_MAX_BYTES).then_some(bytes)
}

pub(super) fn chosen(settings: &AssistanceSettings) -> bool {
    settings.requested.enabled
        && settings.effective.enabled
        && settings.verification_permitted
        && settings.diagnostic.is_none()
        && settings.effective.features.agent_context
        && settings.effective.sources.workspace_documents
}

impl Service {
    /// Picks up settings saved since the prompt lane last looked, so turning
    /// project context on or off reaches the next prompt without anything
    /// asking for CIGAR's status first. The file is only hashed here; the
    /// settings are reloaded when its bytes changed, on their own thread, and
    /// a prompt waits for that briefly at most.
    pub(crate) fn follow_saved_settings(&self, guard_home: &std::path::Path) {
        use std::hash::{DefaultHasher, Hash, Hasher};
        let path = guard_home.join(crate::package_authority_config::HOME_CONFIG_FILENAME);
        let Some(bytes) = read_saved_settings(&path) else {
            return;
        };
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        let stamp = hasher.finish();
        match self.followed.lock() {
            Ok(mut followed) if *followed != Some(stamp) => *followed = Some(stamp),
            _ => return,
        }
        let (done, finished) = std::sync::mpsc::channel();
        let state = Arc::clone(&self.state);
        let followed = Arc::clone(&self.followed);
        let home = guard_home.to_path_buf();
        let spawned = std::thread::Builder::new()
            .name("cigar-saved-settings".into())
            .spawn(move || {
                let generation = lock(&state).map(|state| state.generation);
                let loaded = generation.and_then(|generation| {
                    let settings = crate::guard_config_load::context_assistance_config(&home)?;
                    configure(&state, settings, Some(generation))
                });
                // A load that failed, or raced another change, is tried again
                // by the next prompt even when the file is unchanged.
                if loaded.is_err() {
                    forget(&followed, stamp);
                }
                let _ = done.send(());
            });
        match spawned {
            Ok(_) => {
                let _ = finished.recv_timeout(FOLLOW_WAIT);
            }
            Err(_) => forget(&self.followed, stamp),
        }
    }

    /// Whether someone turned on project context for their AI apps. Cheap:
    /// a busy lock is waited for a few milliseconds at most. When it stays
    /// busy, the answer is the value last published under the lock, so a
    /// prompt that lands while other hooks hold it still gets its context
    /// and a turned-off choice still reads as off.
    pub(crate) fn prompt_context_chosen(&self) -> bool {
        let until = Instant::now() + CHOSEN_WAIT;
        loop {
            match self.state.try_lock() {
                Ok(state) => return !state.closed && chosen(&state.settings),
                Err(std::sync::TryLockError::WouldBlock) if Instant::now() < until => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    return self.chosen.load(Ordering::Acquire);
                }
                Err(_) => return false,
            }
        }
    }

    /// Starts a resting worker in `guard_home` without waiting for it, so it
    /// is up by the time a prompt asks. Does nothing unless project context
    /// is on, and never turns it on.
    pub(crate) fn warm_prompt_lane(&self, guard_home: &std::path::Path) {
        if self.prompt_may_wake() {
            self.wake(guard_home, chosen);
        }
    }

    /// Whether a prompt should wake a resting worker now. Waits for a busy
    /// lock no longer than [`CHOSEN_WAIT`]: a lock still held means "not
    /// now", so the prompt goes on to its bounded wait (or skips) instead of
    /// queueing behind whatever holds it, and a later prompt wakes the worker.
    fn prompt_may_wake(&self) -> bool {
        let until = Instant::now() + CHOSEN_WAIT;
        loop {
            match self.state.try_lock() {
                Ok(state) => {
                    return wake::resting(&state)
                        && chosen(&state.settings)
                        && state.woke.is_none_or(|at| at.elapsed() >= wake::RETRY);
                }
                Err(std::sync::TryLockError::WouldBlock) if Instant::now() < until => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => return false,
            }
        }
    }

    /// The live worker for a prompt, waking a resting one in `guard_home`
    /// and waiting for it until `deadline` at most.
    pub(crate) fn prompt_lane(
        &self,
        guard_home: &std::path::Path,
        deadline: Instant,
    ) -> Result<PromptLane, LaneMiss> {
        if self.prompt_may_wake() {
            self.wake(guard_home, chosen);
        }
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

fn forget(followed: &Mutex<Option<u64>>, stamp: u64) {
    if let Ok(mut followed) = followed.lock() {
        if *followed == Some(stamp) {
            *followed = None;
        }
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
