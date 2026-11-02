//! Saved-data repair remains available without runtime qualification or opt-in.
//! Read routes cannot delete; authenticated access-reduction routes can.
use super::*;
use crate::context_assistance_data as saved;
#[path = "context_assistance_service_data_removal.rs"]
mod removal;

impl Service {
    pub(crate) fn ensure_housekeeping(&self, home: &std::path::Path) {
        self.arm_housekeeping(home, false);
    }
    /// Called once by the resident constructor, before serving context work.
    /// Absence stays absent; existing saved data gets an immediate native sweep.
    pub(crate) fn startup_housekeeping(&self, home: &std::path::Path) {
        self.arm_housekeeping(home, true);
    }
    fn arm_housekeeping(&self, home: &std::path::Path, immediate: bool) {
        if !cfg!(unix) {
            return;
        }
        let needed = match lock(&self.state) {
            Ok(state) => {
                if state.closed || state.maintenance_started {
                    return;
                }
                state.settings.effective.storage.mode == StorageMode::Sqlite
            }
            Err(_) => return,
        };
        if !needed
            && std::fs::symlink_metadata(home.join("context-assistance/saved-evidence")).is_err()
            && std::fs::symlink_metadata(home.join("context-assistance/evidence-generations"))
                .is_err()
        {
            return;
        }
        {
            let Ok(mut state) = lock(&self.state) else {
                return;
            };
            if state.closed || state.maintenance_started {
                return;
            }
            state.maintenance_started = true;
            if state.error.as_deref() == Some("saved_data_maintenance_unavailable") {
                state.error = None;
            }
        }
        let weak = Arc::downgrade(&self.state);
        let home = home.to_path_buf();
        let mut first = immediate;
        let spawned = std::thread::Builder::new()
            .name("guard-context-retention".into())
            .spawn(move || loop {
                if !first {
                    for _ in 0..30 {
                        std::thread::sleep(Duration::from_secs(1));
                        let Some(shared) = weak.upgrade() else {
                            return;
                        };
                        if lock(&shared).map_or(true, |s| s.closed) {
                            return;
                        }
                    }
                }
                first = false;
                let Some(shared) = weak.upgrade() else {
                    break;
                };
                let retention = {
                    let Ok(state) = lock(&shared) else {
                        break;
                    };
                    if state.closed {
                        break;
                    }
                    state.settings.effective.storage.retention_hours
                };
                // Off-state settings can change without any context request.
                // Only read the retention bound: this cannot opt in, activate,
                // alter a service generation or reverse Stop.
                let retention = crate::guard_config_load::context_assistance_config(&home)
                    .map(|settings| settings.effective.storage.retention_hours)
                    .unwrap_or(retention);
                if lock(&shared).map_or(true, |s| s.closed) {
                    break;
                }
                // Busy means an active actor/owner maintains its own store. Other
                // failures are presented by the explicit saved-data inspection.
                let _outcome = saved::sweep(&home, retention);
                drop(shared);
            });
        if spawned.is_err() {
            if let Ok(mut state) = lock(&self.state) {
                state.maintenance_started = false;
                if state.runtime.is_none() {
                    state.error = Some("saved_data_maintenance_unavailable".into());
                }
            }
        }
    }
    pub(super) fn offline_data(
        &self,
        home: &std::path::Path,
        request: &WorkspaceRequest,
    ) -> Result<Option<Value>, String> {
        if !matches!(
            request,
            WorkspaceRequest::Data
                | WorkspaceRequest::ForgetHistory
                | WorkspaceRequest::Clear
                | WorkspaceRequest::ForgetSaved
                | WorkspaceRequest::ResumeErasure
        ) {
            return Ok(None);
        }
        let resume = matches!(request, WorkspaceRequest::ResumeErasure);
        let force = resume || matches!(request, WorkspaceRequest::ForgetSaved);
        let clear = matches!(
            request,
            WorkspaceRequest::Clear | WorkspaceRequest::ForgetSaved
        );
        let mut removal = None;
        let (old, retiring, retention) = {
            let mut state = lock(&self.state)?;
            if state.closed {
                return Err("native_context_assistance_shutdown".into());
            }
            let active = state.settings.requested.enabled
                && state.settings.effective.enabled
                && state.settings.verification_permitted
                && state.settings.diagnostic.is_none()
                && state
                    .runtime
                    .as_ref()
                    .is_some_and(|actor| actor.status().active);
            if active && !force {
                return Ok(None);
            }
            if clear || resume {
                removal = Some(
                    removal::Removal::acquire(home, resume)
                        .map_err(|e| format!("native_context_assistance_{}", e.code()))?,
                );
            }
            if force || state.runtime.is_some() {
                state.generation = state
                    .generation
                    .checked_add(1)
                    .ok_or("native_context_assistance_generation_exhausted")?;
                if let Some(job) = &state.pending {
                    job.cancel.store(true, Ordering::Release);
                }
                state.last_check = None;
            }
            let old = revoke_runtime(&mut state);
            (
                old,
                state.retiring.clone(),
                state.settings.effective.storage.retention_hours,
            )
        };
        drop(old);
        if !lifecycle::await_cleanup(retiring) {
            return Err("native_context_assistance_context_busy".into());
        }
        let erased = removal
            .map(|removal| removal.run())
            .transpose()
            .map_err(|e| format!("native_context_assistance_{}", e.code()))?;
        let data = if clear || resume {
            saved::inspect(home)
        } else {
            saved::sweep(home, retention).map_or_else(saved::failure, |_| saved::inspect(home))
        };
        let mut result = saved::empty_summary(
            data,
            matches!(request, WorkspaceRequest::ForgetHistory),
            clear,
        );
        if resume {
            result["resumed_erasure"] = json!(true);
            result["scope_erasure"] = serde_json::to_value(erased.flatten())
                .map_err(|_| "native_context_assistance_request_invalid")?;
        }
        Ok(Some(
            json!({"schema":"guard-cigar-workspace-result.v1","data_role":true,"result":result}),
        ))
    }
}
