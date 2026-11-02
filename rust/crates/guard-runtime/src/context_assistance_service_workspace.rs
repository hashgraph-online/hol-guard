//! Authenticated operator context requests and generation/privacy fences.
use super::*;

impl Service {
    pub(crate) fn workspace(
        &self,
        home: &std::path::Path,
        store: &crate::policy_store::PolicySnapshotStore,
        input: Value,
        access_write: bool,
        grant_write: bool,
    ) -> Result<Value, String> {
        let request: WorkspaceRequest = crate::strict_json::from_value(input)
            .map_err(|_| "native_context_assistance_workspace_input_invalid")?;
        let permitted = match &request {
            WorkspaceRequest::Grant { .. }
            | WorkspaceRequest::AuthorizeAgent { .. }
            | WorkspaceRequest::AdmitProposal { .. } => grant_write,
            WorkspaceRequest::List
            | WorkspaceRequest::ListAgents
            | WorkspaceRequest::Compile { .. }
            | WorkspaceRequest::Explain { .. } => true,
            WorkspaceRequest::Action { .. } => true,
            WorkspaceRequest::Data
            | WorkspaceRequest::History { .. }
            | WorkspaceRequest::HistoryDetail { .. }
            | WorkspaceRequest::Proposals { .. }
            | WorkspaceRequest::Proposal { .. } => true,
            _ => access_write,
        };
        if !permitted {
            return Err("native_context_assistance_workspace_input_invalid".into());
        }
        if matches!(
            &request,
            WorkspaceRequest::ClearNotes { .. }
                | WorkspaceRequest::Withdraw { .. }
                | WorkspaceRequest::Revoke { .. }
                | WorkspaceRequest::Clear
                | WorkspaceRequest::ForgetSaved
                | WorkspaceRequest::ResumeErasure
                | WorkspaceRequest::ForgetHistory
                | WorkspaceRequest::Refresh { .. }
        ) {
            self.drain_switch(home)?;
        }
        if let Some(result) = self.offline_data(home, &request)? {
            return Ok(result);
        }
        let (actor, generation) = {
            let mut state = lock(&self.state)?;
            if !state.settings.requested.enabled
                || !state.settings.effective.enabled
                || !state.settings.verification_permitted
                || state.settings.diagnostic.is_some()
            {
                return Err("native_context_assistance_disabled".into());
            }
            let actor = state
                .runtime
                .as_ref()
                .filter(|actor| actor.status().active)
                .cloned()
                .ok_or("native_context_assistance_runtime_not_verified")?;
            if !matches!(
                request,
                WorkspaceRequest::ListAgents
                    | WorkspaceRequest::Data
                    | WorkspaceRequest::History { .. }
                    | WorkspaceRequest::Proposals { .. }
            ) {
                state.last_used = Instant::now();
            }
            (actor, state.generation)
        };
        let policy = matches!(&request, WorkspaceRequest::Action { .. })
            .then(|| crate::context_assistance_action_facts::Policy::current(store))
            .transpose()
            .map_err(|_| "native_context_assistance_context_stale")?;
        let fence = policy.clone();
        let observation_reset = match &request {
            WorkspaceRequest::Refresh { scope_id }
            | WorkspaceRequest::Withdraw { scope_id, .. }
            | WorkspaceRequest::Revoke { scope_id } => Some(Some(scope_id.clone())),
            WorkspaceRequest::Clear
            | WorkspaceRequest::ForgetSaved
            | WorkspaceRequest::ForgetHistory => Some(None),
            _ => None,
        };
        let result = actor.call(move |runtime, engine| engine.workspace(runtime, request, policy));
        // Reload local/managed consent after work, outside every state lock.
        let current = crate::guard_config_load::context_assistance_config(home)
            .unwrap_or_else(|_| AssistanceSettings::unavailable("configuration_unavailable"));
        self.configure_at(current, generation)?;
        let mut state = lock(&self.state)?;
        if state.generation != generation
            || state
                .runtime
                .as_ref()
                .is_none_or(|current| !Arc::ptr_eq(current, &actor))
        {
            return Err("native_context_assistance_context_stale".into());
        }
        if result.is_ok() && observation_reset == Some(None) {
            state.observations.close();
            state.observations = Default::default();
        }
        let observations = Arc::clone(&state.observations);
        drop(state);
        if result.is_ok() {
            if let Some(Some(scope)) = observation_reset {
                observations.forget_scope(&scope)?;
            }
        }
        if let Some(fence) = fence {
            if crate::context_assistance_action_facts::Policy::current(store).as_ref() != Ok(&fence)
            {
                return Err("native_context_assistance_context_stale".into());
            }
        }
        result.map_err(|error| format!("native_context_assistance_{}", error.code()))
    }
}
