//! Resolve uncertain acknowledgements by inspecting authenticated current
//! metadata and exact config bytes. These methods never repeat an SDK effect.
use super::*;

impl Owner {
    pub(crate) fn reconcile_committed(
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
        if t.request_id != id || !settings.matches(t) || settings.home() != self.home {
            return Err(error("switch_selection_conflict"));
        }
        settings.check_target_exact()?;
        match t.phase {
            SelectionPhase::CommitIntent => self.advance_observed(id, SelectionPhase::Committed),
            SelectionPhase::Committed => Ok(()),
            _ => Err(error("switch_recovery_required")),
        }
    }
    pub(super) fn advance_observed(
        &mut self,
        id: &str,
        phase: SelectionPhase,
    ) -> Result<(), String> {
        match self.advance(phase) {
            Ok(()) => Ok(()),
            Err(code) if code.ends_with("switch_commit_outcome_unknown") => {
                self.reload()?;
                if self
                    .record
                    .as_ref()
                    .and_then(|r| r.transaction.as_ref())
                    .is_some_and(|t| t.request_id == id && t.phase == phase)
                {
                    Ok(())
                } else {
                    Err(error("switch_recovery_required"))
                }
            }
            Err(code) => Err(code),
        }
    }
    fn checked_advance(
        &mut self,
        id: &str,
        from: SelectionPhase,
        to: SelectionPhase,
    ) -> Result<(), String> {
        let current = self
            .record
            .as_ref()
            .and_then(|r| r.transaction.as_ref())
            .filter(|t| t.request_id == id)
            .ok_or_else(|| error("switch_selection_conflict"))?;
        if current.cancel_requested {
            return Err(error("switch_cancelled"));
        }
        if current.phase == to {
            return Ok(());
        }
        if current.phase != from {
            return Err(error("switch_selection_conflict"));
        }
        self.advance_observed(id, to)
    }
    /// The actual private target was checked. No Service attachment or grant
    /// can be inferred from this durable health observation.
    pub(crate) fn mark_healthy(&mut self, id: &str) -> Result<(), String> {
        self.checked_advance(id, SelectionPhase::Committed, SelectionPhase::Healthy)
    }
    /// The native caller has attached the target, or reverified a live target.
    /// A missing acknowledgement never permits restarting a process.
    pub(crate) fn complete_publication(&mut self, id: &str) -> Result<(), String> {
        self.checked_advance(id, SelectionPhase::Healthy, SelectionPhase::Completed)
    }
    #[cfg(all(test, unix))]
    pub(crate) fn finish_health(&mut self, id: &str) -> Result<(), String> {
        self.mark_healthy(id)?;
        self.complete_publication(id)
    }
}
