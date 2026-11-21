//! Recovery chooses a recorded pair, never a saved process/client/permission.
use crate::{SelectionPhase, SelectionPointer, SelectionRecord, SwitchError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectionRecovery {
    PreservePrevious,
    VerifyTarget,
    KeepTarget,
    RestorePrevious,
    /// A later opt-out wins. Only reconcile which data belongs to the named
    /// installation; do not restore enabled preferences or start a process.
    PreserveDisabled(Box<SelectionPointer>),
    RequireOperatorRecovery,
}
impl SelectionRecord {
    pub fn recovery(
        &self,
        selected: &str,
        settings_sha256: &str,
        enabled: bool,
        target_eligible: bool,
        previous_eligible: bool,
    ) -> Result<SelectionRecovery, SwitchError> {
        self.validate()?;
        use SelectionPhase::*;
        use SelectionRecovery::*;
        let Some(t) = &self.transaction else {
            return if selected != self.current.runtime.installation_id {
                Err(SwitchError::SelectionConflict)
            } else if enabled {
                Ok(KeepTarget)
            } else {
                Ok(PreserveDisabled(Box::new(self.current.clone())))
            };
        };
        let previous = selected == t.from.runtime.installation_id;
        let target = selected == t.to.runtime.installation_id;
        if !previous && !target {
            return Err(SwitchError::SelectionConflict);
        }
        if !enabled {
            return Ok(PreserveDisabled(Box::new(if previous {
                t.from.clone()
            } else {
                t.to.clone()
            })));
        }
        let before = previous && settings_sha256 == t.before_settings_sha256;
        let after = target && settings_sha256 == t.after_settings_sha256;
        let result = match t.phase {
            Prepared | StopIntent | Cancelled if previous && previous_eligible => PreservePrevious,
            CommitIntent if before && previous_eligible => PreservePrevious,
            CommitIntent | Committed | Healthy
                if after && !t.cancel_requested && target_eligible =>
            {
                VerifyTarget
            }
            Completed if target && target_eligible => KeepTarget,
            CommitIntent | Committed | Healthy if after && previous_eligible => RestorePrevious,
            RestoreIntent if before && previous_eligible => PreservePrevious,
            RestoreIntent if after && previous_eligible => RestorePrevious,
            RolledBack if previous && previous_eligible => PreservePrevious,
            _ => RequireOperatorRecovery,
        };
        Ok(result)
    }
}
