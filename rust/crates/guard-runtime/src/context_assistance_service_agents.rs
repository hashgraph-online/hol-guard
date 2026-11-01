use super::*;
use crate::context_assistance_agents::Input;

impl Service {
    pub(crate) fn agent(
        &self,
        home: &std::path::Path,
        store: &crate::policy_store::PolicySnapshotStore,
        input: Input,
    ) -> Result<Value, String> {
        let (actor, generation) = {
            let mut state = lock(&self.state)?;
            let ready = state.settings.requested.enabled
                && state.settings.effective.enabled
                && state.settings.verification_permitted
                && state.settings.diagnostic.is_none()
                && state.settings.effective.features.agent_context
                && state
                    .runtime
                    .as_ref()
                    .is_some_and(|actor| actor.is_active());
            if matches!(input, Input::Discover {}) {
                return Ok(
                    json!({"schema":"guard-cigar-agent-data.v1","data_role":true,
                    "result":{"available":ready,"tools":if ready { vec!["get_context_status"] } else { Vec::<&str>::new() }}}),
                );
            }
            if !ready {
                return Err("native_context_assistance_disabled".into());
            }
            let actor = state.runtime.as_ref().expect("ready checked above").clone();
            if input.uses_context() {
                state.last_used = Instant::now();
            }
            (actor, state.generation)
        };
        let policy = matches!(&input, Input::ReviewAction { .. })
            .then(|| crate::context_assistance_action_facts::Policy::current(store))
            .transpose()
            .map_err(|_| "native_context_assistance_context_stale")?;
        let fence = policy.clone();
        let result = actor.call(move |runtime, engine| engine.agent(runtime, input, policy));
        let current = crate::guard_config_load::context_assistance_config(home)
            .unwrap_or_else(|_| AssistanceSettings::unavailable("configuration_unavailable"));
        self.configure_at(current, generation)?;
        let state = lock(&self.state)?;
        if state.generation != generation
            || state
                .runtime
                .as_ref()
                .is_none_or(|current| !Arc::ptr_eq(current, &actor))
        {
            return Err("native_context_assistance_context_stale".into());
        }
        drop(state);
        if let Some(fence) = fence {
            if crate::context_assistance_action_facts::Policy::current(store).as_ref() != Ok(&fence)
            {
                return Err("native_context_assistance_context_stale".into());
            }
        }
        result.map_err(|error| format!("native_context_assistance_{}", error.code()))
    }
}
