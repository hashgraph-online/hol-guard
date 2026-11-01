//! Explicit executor control plane. No service/policy lock spans an SDK wait.
use super::*;
use crate::context_assistance_execution::ExecutionContext;
use crate::native_exact_action_op::bash_context::Facts;

impl Service {
    #[cfg(test)]
    pub(crate) fn set_execution_test_hook(&self, hook: super::ExecutionTestHook) {
        *self.execution_test_hook.lock().unwrap() = Some(hook);
    }
    #[cfg(test)]
    pub(crate) fn run_execution_test_hook(&self, store: &crate::policy_store::PolicySnapshotStore) {
        let hook = self.execution_test_hook.lock().unwrap().take();
        if let Some(hook) = hook {
            hook(store);
        }
    }
    #[cfg(test)]
    pub(crate) fn interrupt_execution_runtime_for_test(&self) {
        let actor = lock(&self.state).unwrap().runtime.clone().unwrap();
        actor.cancel();
    }

    pub(crate) fn execution_requested(&self) -> bool {
        self.state.try_lock().is_ok_and(|state| {
            !state.closed
                && !state.stopping
                && state.settings.requested.enabled
                && state.settings.effective.enabled
                && state.settings.verification_permitted
                && state.settings.diagnostic.is_none()
                && state.settings.effective.features.execution_context
                && state.settings.effective.sources.native_policy_facts
                && state.execution_ready.load(Ordering::Acquire)
                && state
                    .runtime
                    .as_ref()
                    .is_some_and(|a| a.is_active() && a.status().execution_handoff_verified)
        })
    }

    pub(crate) fn prepare_execution(
        &self,
        facts: Facts,
        deadline: Instant,
    ) -> Option<ExecutionContext> {
        let generation = self.configuration_generation().ok()?;
        let settings = crate::guard_config_load::context_assistance_config(&facts.home).ok()?;
        self.configure_at(settings, generation).ok()?;
        if !self.execution_requested() {
            return None;
        }
        let (actor, fence, observations) = {
            let mut state = self.state.try_lock().ok()?;
            state.last_used = Instant::now();
            (
                Arc::clone(state.runtime.as_ref()?),
                state.epoch.fence(),
                Arc::clone(&state.observations),
            )
        };
        let activity = actor.activity();
        let home = facts.home.clone();
        let checked = actor
            .call_until(deadline, move |runtime, engine| {
                engine.execution(runtime, facts)
            })
            .ok()?;
        let settings = crate::guard_config_load::context_assistance_config(&home).ok()?;
        self.configure_at(settings, generation).ok()?;
        if !fence.is_current() || !activity.is_active() {
            return None;
        }
        ExecutionContext::new(checked, fence, activity, observations)
    }
}
