//! Restore a known unpublished transaction under its original lifecycle lease.
//! Inspect uncertain writes before any effect; no journal value restores grants.
use super::*;

impl Owner {
    pub(crate) fn restore_source(
        &mut self,
        id: &str,
        settings: &SwitchSettings,
    ) -> Result<(), String> {
        self.reload()?;
        let t = self
            .record
            .as_ref()
            .and_then(|r| r.transaction.as_ref())
            .ok_or_else(|| error("switch_transaction_missing"))?;
        if t.request_id != id
            || !settings.matches(t)
            || settings.home() != self.home
            || !matches!(
                t.phase,
                SelectionPhase::StopIntent
                    | SelectionPhase::CommitIntent
                    | SelectionPhase::Committed
                    | SelectionPhase::Healthy
                    | SelectionPhase::RestoreIntent
            )
        {
            return Err(error("switch_recovery_required"));
        }
        settings.check_restore_window()?;
        if t.phase != SelectionPhase::RestoreIntent {
            self.advance_observed(id, SelectionPhase::RestoreIntent)?;
        }
        let lock = WriteLock::acquire(&self.home).map_err(storage_error)?;
        self.check(&lock)?;
        match settings.restore(&lock) {
            Ok(()) => Ok(()),
            // A rename may have succeeded. Inspect exact source bytes instead
            // of replaying a config mutation whose result was not acknowledged.
            Err(code) if code.ends_with("switch_commit_outcome_unknown") => {
                settings.check_current()
            }
            Err(code) => Err(code),
        }
    }
    pub(crate) fn verify_prepared_source(
        &self,
        id: &str,
        installation: &Installation,
        runtime: &VerifiedRuntime,
        config: &guard_context_assistance::ContextAssistanceConfig,
    ) -> Result<(), String> {
        self.verify_source_at(id, SelectionPhase::Prepared, installation, runtime, config)
            .map(|_| ())
    }
    pub(crate) fn verify_restore_source(
        &self,
        id: &str,
        installation: &Installation,
        runtime: &VerifiedRuntime,
        config: &guard_context_assistance::ContextAssistanceConfig,
    ) -> Result<ActivationSelection, String> {
        self.verify_source_at(
            id,
            SelectionPhase::RestoreIntent,
            installation,
            runtime,
            config,
        )
    }
    fn verify_source_at(
        &self,
        id: &str,
        phase: SelectionPhase,
        installation: &Installation,
        runtime: &VerifiedRuntime,
        config: &guard_context_assistance::ContextAssistanceConfig,
    ) -> Result<ActivationSelection, String> {
        let t = self
            .record
            .as_ref()
            .and_then(|r| r.transaction.as_ref())
            .filter(|t| t.request_id == id && t.phase == phase)
            .ok_or_else(|| error("switch_recovery_required"))?;
        if config.runtime_id != t.from.runtime.installation_id {
            return Err(error("switch_selection_conflict"));
        }
        activation::verify_selected(&self.home, &t.from, installation, runtime, config)
    }
    pub(crate) fn finish_restore(
        &mut self,
        id: &str,
        settings: &SwitchSettings,
    ) -> Result<(), String> {
        self.reload()?;
        let t = self
            .record
            .as_ref()
            .and_then(|r| r.transaction.as_ref())
            .filter(|t| t.request_id == id && settings.matches(t) && settings.home() == self.home)
            .ok_or_else(|| error("switch_selection_conflict"))?;
        settings.check_current()?;
        match t.phase {
            SelectionPhase::RestoreIntent => self.advance_observed(id, SelectionPhase::RolledBack),
            SelectionPhase::RolledBack => Ok(()),
            _ => Err(error("switch_recovery_required")),
        }
    }
}
