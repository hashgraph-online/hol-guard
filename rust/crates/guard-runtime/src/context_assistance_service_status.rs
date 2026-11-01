//! Bounded native status projection; no probe, SDK call or source read.
use super::*;

impl Service {
    pub(crate) fn status(&self) -> Result<Value, String> {
        let state = lock(&self.state)?;
        let effective = state.settings.requested.enabled
            && state.settings.effective.enabled
            && state.settings.verification_permitted
            && state.settings.diagnostic.is_none()
            && state.runtime.as_ref().is_some_and(|runtime| {
                let status = runtime.status();
                status.active
                    && status.compile_verified
                    && (!state.settings.effective.features.shared_agents
                        || status.shared_compile_verified)
                    && (state.settings.effective.storage.mode == StorageMode::Memory
                        || status.persistence_compile_verified)
            });
        let diagnostic = state
            .settings
            .diagnostic
            .as_deref()
            .or(state.error.as_deref());
        let diagnostic = diagnostic.or_else(|| {
            (state.settings.requested.enabled && !state.settings.effective.enabled)
                .then_some("policy_restricted")
        });
        let availability = if diagnostic.is_some() {
            "unavailable"
        } else if !state.settings.requested.enabled {
            "off"
        } else if state.pending.is_some() {
            "checking"
        } else if effective {
            "ready"
        } else {
            "unavailable"
        };
        let diagnostic = diagnostic.or_else(|| {
            if state.settings.requested.enabled && !effective && state.pending.is_none() {
                Some(if state.settings.effective.runtime_id.is_empty() {
                    "runtime_not_selected"
                } else {
                    "runtime_not_verified"
                })
            } else {
                None
            }
        });
        #[cfg(unix)]
        let upgrade = state.upgrade.as_ref().map(|signal| signal.describe());
        #[cfg(not(unix))]
        let upgrade: Option<Value> = None;
        Ok(
            json!({"schema":"guard-context-assistance-status.v2", "availability":availability,
            "requested_enabled":state.settings.requested.enabled, "effective_enabled":effective, "preferences":state.settings.requested,
            "effective_preferences":state.settings.effective, "restriction":state.settings.restriction,
            "verification_permitted":state.settings.verification_permitted,
            "generation":state.generation.to_string(), "diagnostic":diagnostic,
            "runtime":state.runtime.as_ref().map(|actor| actor.status()), "last_check":state.last_check,
            "qualification": state.last_check.as_ref().map(|status| if status.release.is_some() { "guard_qualified" } else { "local_candidate" }),
            "capabilities":{"shared_agents":true,"private_persistence":cfg!(unix),"execution_context":cfg!(target_os = "macos")},
            "execution_observations":state.observations.list(),
            "execution_ready":state.execution_ready.load(Ordering::Acquire)
                && state.runtime.as_ref().is_some_and(|actor| actor.is_active()),
            "installation_options": null, "upgrade":upgrade,
            "job":state.pending.as_ref().map(|job| json!({"id":job.id.to_string(), "operation":job.operation.name(),
                "phase":if job.cancel.load(Ordering::Acquire) { "cancelling" } else { "verifying" }}))}),
        )
    }
}
