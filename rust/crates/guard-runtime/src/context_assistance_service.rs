//! Resident-owned optional service. Verification runs outside resident request
//! workers and policy/evidence locks. The off state allocates no SDK process.
use crate::context_assistance_engine::{Engine, Request as WorkspaceRequest};
use crate::context_assistance_notifications::Notifications;
use crate::guard_config_load::AssistanceSettings;
use guard_context_assistance::{RuntimeActor, RuntimeStatus, StorageMode, VerifiedRuntime};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, Weak,
};
use std::time::{Duration, Instant};
#[path = "context_assistance_service_agents.rs"]
mod agents;
#[path = "context_assistance_service_data.rs"]
mod data;
#[cfg(target_os = "macos")]
#[path = "context_assistance_service_execution.rs"]
mod execution;
#[path = "context_assistance_service_lifecycle.rs"]
mod lifecycle;
#[path = "context_assistance_service_status.rs"]
mod status;
#[cfg(unix)]
#[path = "context_assistance_service_upgrade.rs"]
mod upgrade;
#[path = "context_assistance_service_verification.rs"]
mod verification;
#[path = "context_assistance_service_versions.rs"]
mod versions;
#[path = "context_assistance_service_workspace.rs"]
mod workspace;
use lifecycle::configure;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Check {
    Activate,
    Recheck,
}
impl Check {
    fn name(self) -> &'static str {
        match self {
            Self::Activate => "activate",
            Self::Recheck => "recheck",
        }
    }
}

struct Pending {
    id: u64,
    operation: Check,
    cancel: Arc<AtomicBool>,
}
struct Verified {
    runtime: VerifiedRuntime,
    #[cfg(unix)]
    selection:
        Option<crate::policy_store::context_assistance_registry::switching::ActivationSelection>,
    #[cfg(target_os = "macos")]
    execution_lane: Option<crate::context_assistance_engine::ExecutionLane>,
}
struct State {
    closed: bool,
    settings: AssistanceSettings,
    generation: u64,
    runtime: Option<Arc<RuntimeActor<Engine>>>,
    retiring: Option<Arc<RuntimeActor<Engine>>>,
    notifications: Option<Arc<Notifications>>,
    last_check: Option<RuntimeStatus>,
    error: Option<String>,
    pending: Option<Pending>,
    #[cfg(unix)]
    upgrade: Option<Arc<upgrade::Signal>>,
    #[cfg(unix)]
    cutover: Option<upgrade::Cutover>,
    last_used: Instant,
    maintenance_started: bool,
    stopping: bool,
    epoch: guard_context_assistance::ContextEpoch,
    observations: Arc<crate::context_assistance_execution::Observations>,
    execution_ready: Arc<AtomicBool>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            closed: false,
            settings: AssistanceSettings::default(),
            generation: 1,
            runtime: None,
            retiring: None,
            notifications: None,
            last_check: None,
            error: None,
            pending: None,
            #[cfg(unix)]
            upgrade: None,
            #[cfg(unix)]
            cutover: None,
            last_used: Instant::now(),
            maintenance_started: false,
            stopping: false,
            epoch: Default::default(),
            observations: Default::default(),
            execution_ready: Default::default(),
        }
    }
}
impl Drop for State {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(upgrade) = &self.upgrade {
            upgrade.revoke();
        }
        if let Some(job) = &self.pending {
            job.cancel.store(true, Ordering::Release);
        }
        if let Some(runtime) = &self.runtime {
            runtime.cancel();
        }
        if let Some(runtime) = &self.retiring {
            runtime.cancel();
        }
        if let Some(notifications) = &self.notifications {
            notifications.close();
        }
    }
}

fn revoke_runtime(state: &mut State) -> Option<Arc<RuntimeActor<Engine>>> {
    #[cfg(unix)]
    if let Some(upgrade) = &state.upgrade {
        upgrade.revoke();
    }
    state.epoch.invalidate();
    state.observations.close();
    state.execution_ready.store(false, Ordering::Release);
    if let Some(notifications) = state.notifications.take() {
        notifications.close();
    }
    if let Some(runtime) = &state.runtime {
        runtime.cancel();
        state.retiring = Some(Arc::clone(runtime));
    }
    state.runtime.take()
}

#[cfg(all(test, target_os = "macos"))]
type ExecutionTestHook = Box<dyn FnOnce(&crate::policy_store::PolicySnapshotStore) + Send>;

#[derive(Default)]
pub(crate) struct Service {
    state: Arc<Mutex<State>>,
    updates: crate::policy_store::context_assistance_registry::Jobs,
    #[cfg(unix)]
    switches: upgrade::Jobs,
    #[cfg(all(test, target_os = "macos"))]
    execution_test_hook: Mutex<Option<ExecutionTestHook>>,
}

fn lock(state: &Mutex<State>) -> Result<std::sync::MutexGuard<'_, State>, String> {
    state
        .lock()
        .map_err(|_| "native_context_assistance_state_unavailable".into())
}

impl Service {
    #[cfg(test)]
    pub(crate) fn configure(&self, settings: AssistanceSettings) -> Result<(), String> {
        configure(&self.state, settings, None)
    }

    pub(crate) fn configuration_generation(&self) -> Result<u64, String> {
        Ok(lock(&self.state)?.generation)
    }

    pub(crate) fn configure_at(
        &self,
        settings: AssistanceSettings,
        generation: u64,
    ) -> Result<(), String> {
        configure(&self.state, settings, Some(generation))
    }

    pub(crate) fn schedule(&self, operation: Check, home: PathBuf) -> Result<(), String> {
        let (generation, settings, cancel, old) = {
            let mut state = lock(&self.state)?;
            if state.closed {
                return Err("native_context_assistance_shutdown".into());
            }
            #[cfg(unix)]
            if operation == Check::Activate {
                crate::policy_store::context_assistance_registry::switching::DataRemoval::check_clear(&home)
                    .map_err(|e| format!("native_context_assistance_{}",e.code()))?;
            }
            if state.settings.diagnostic.is_some() {
                return Err("native_context_assistance_configuration_unavailable".into());
            }
            if operation == Check::Activate
                && (!state.settings.requested.enabled || !state.settings.effective.enabled)
            {
                return Err("native_context_assistance_disabled".into());
            }
            if !state.settings.verification_permitted {
                return Err("native_context_assistance_policy_restricted".into());
            }
            if state.settings.effective.runtime_id.is_empty() {
                return Err("native_context_assistance_runtime_not_selected".into());
            }
            #[cfg(unix)]
            if state.upgrade.is_some() || state.cutover.is_some() {
                return Err("native_context_assistance_busy".into());
            }
            if state.pending.is_some() {
                return Err("native_context_assistance_busy".into());
            }
            if state.stopping {
                return Err("native_context_assistance_busy".into());
            }
            if state
                .retiring
                .as_ref()
                .is_some_and(|actor| !actor.cleanup_finished())
            {
                return Err("native_context_assistance_busy".into());
            }
            state.retiring = None;
            if state.settings.effective.storage.mode != StorageMode::Memory && !cfg!(unix) {
                return Err("native_context_assistance_persistence_unavailable".into());
            }
            state.generation = state
                .generation
                .checked_add(1)
                .ok_or("native_context_assistance_generation_exhausted")?;
            let cancel = Arc::new(AtomicBool::new(false));
            let generation = state.generation;
            state.pending = Some(Pending {
                id: generation,
                operation,
                cancel: Arc::clone(&cancel),
            });
            state.error = None;
            (
                generation,
                state.settings.clone(),
                cancel,
                revoke_runtime(&mut state),
            )
        };
        if !lifecycle::await_cleanup(old) {
            let mut state = lock(&self.state)?;
            if state
                .pending
                .as_ref()
                .is_some_and(|job| job.id == generation)
            {
                state.pending = None;
            }
            state.error = Some("cleanup_pending".into());
            return Err("native_context_assistance_busy".into());
        }
        let weak = Arc::downgrade(&self.state);
        let spawned = std::thread::Builder::new()
            .name("guard-cigar-verification".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let installation = crate::policy_store::context_assistance_registry::load(
                        &home,
                        &settings.effective.runtime_id,
                    )?;
                    let runtime = verification::runtime(&installation, &home, &settings.effective, Arc::clone(&cancel))?;
                    #[cfg(target_os = "macos")]
                    let mut runtime = runtime;
                    #[cfg(target_os = "macos")]
                    let execution_lane = if runtime.status().execution_handoff_verified {
                        Engine::prewarm_execution(&mut runtime, &settings.effective).ok()
                    } else {
                        None
                    };
                    if !runtime.status().active {
                        return Err("native_context_assistance_runtime_closed".into());
                    }
                    #[cfg(unix)]
                    let selection = crate::policy_store::context_assistance_registry::switching::prepare_activation(
                        &home, &installation, &runtime, &settings.effective)?;
                    Ok(Verified {
                        runtime,
                        #[cfg(unix)]
                        selection,
                        #[cfg(target_os = "macos")]
                        execution_lane,
                    })
                }))
                .unwrap_or_else(|_| Err("native_context_assistance_verification_failed".into()));
                finish(weak, generation, settings, home, cancel, result);
            });
        if spawned.is_err() {
            let mut state = lock(&self.state)?;
            if state
                .pending
                .as_ref()
                .is_some_and(|job| job.id == generation)
            {
                state.pending = None;
            }
            state.error = Some("verification_thread_unavailable".into());
            return Err("native_context_assistance_verification_unavailable".into());
        }
        Ok(())
    }
}

fn finish(
    weak: Weak<Mutex<State>>,
    generation: u64,
    settings: AssistanceSettings,
    home: PathBuf,
    cancel: Arc<AtomicBool>,
    result: Result<Verified, String>,
) {
    let Some(shared) = weak.upgrade() else {
        return;
    };
    // A file or machine-policy change during verification cannot activate the
    // earlier preference generation, even without an intervening HTTP request.
    let current = crate::guard_config_load::context_assistance_config(&home)
        .unwrap_or_else(|_| AssistanceSettings::unavailable("configuration_unavailable"));
    // Even a cancelled verification must acknowledge its old pending job.
    // A stale settings read must not change the new generation on the way out.
    let _ = configure(&shared, current, Some(generation));
    let Ok(mut state) = lock(&shared) else {
        return;
    };
    if state
        .pending
        .as_ref()
        .is_none_or(|job| job.id != generation)
    {
        return;
    }
    state.pending = None;
    if state.generation != generation
        || state.settings != settings
        || cancel.load(Ordering::Acquire)
    {
        return;
    }
    match result {
        Ok(verified) => {
            let runtime = verified.runtime;
            let mut check = runtime.status().clone();
            check.active = false;
            state.last_check = Some(check);
            if settings.requested.enabled
                && settings.effective.enabled
                && settings.verification_permitted
            {
                let notifications = (settings.effective.sources.sanitized_receipt_facts
                    || settings.effective.sources.native_policy_facts)
                    .then(|| {
                        Arc::new(Notifications::with_sources(
                            settings.effective.sources.native_policy_facts,
                            settings.effective.sources.sanitized_receipt_facts,
                        ))
                    });
                let engine = Engine::new(home.clone(), &settings.effective, notifications.clone());
                #[cfg(unix)]
                let engine = {
                    let mut engine = engine;
                    if let Some(selection) = verified.selection {
                        engine.set_selected_data(selection);
                    }
                    engine
                };
                #[cfg(target_os = "macos")]
                let engine = {
                    let mut engine = engine;
                    state.execution_ready = verified
                        .execution_lane
                        .as_ref()
                        .map(|lane| Arc::clone(&lane.ready))
                        .unwrap_or_default();
                    engine.set_execution_lane(verified.execution_lane);
                    engine
                };
                let actor = match RuntimeActor::start_with_maintenance(
                    runtime,
                    engine,
                    Engine::maintenance,
                ) {
                    Ok(actor) => Arc::new(actor),
                    Err(error) => {
                        state.error = Some(error.code().into());
                        return;
                    }
                };
                if lifecycle::start_watcher(Arc::downgrade(&shared), generation, home.clone())
                    .is_err()
                {
                    state.error = Some("settings_watcher_unavailable".into());
                    actor.cancel();
                    drop(state);
                    return;
                }
                if let Some(notifications) = &notifications {
                    if !crate::context_assistance_notifications::register(home, notifications) {
                        state.error = Some("notifications_unavailable".into());
                        actor.cancel();
                        drop(state);
                        return;
                    }
                }
                state.last_used = Instant::now();
                state.observations = Default::default();
                state.runtime = Some(actor);
                state.notifications = notifications;
            }
        }
        Err(code) => {
            state.error = Some(
                code.strip_prefix("native_context_assistance_")
                    .unwrap_or("verification_failed")
                    .into(),
            )
        }
    }
}

#[cfg(test)]
#[path = "context_assistance_service_tests.rs"]
mod tests;
