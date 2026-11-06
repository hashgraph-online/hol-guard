//! First selection has no previous SDK/data pair. This pure intent is not a
//! grant or verification receipt; native ownership and measured facts bind it.
use crate::types::{hex, identifier};
use crate::{SelectionData, SelectionPointer, SwitchError};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InitialPhase {
    Prepared,
    CommitIntent,
    Committed,
    Healthy,
    Completed,
    Cancelled,
    RecoveryRequired,
}
impl InitialPhase {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InitialSelection {
    pub schema: String,
    pub revision: u64,
    pub request_id: String,
    pub expected_service_generation: u64,
    pub before_settings_sha256: String,
    pub after_settings_sha256: String,
    /// The native caller proves no saved-data selection exists. A digest
    /// supplied by an operator is never sufficient to establish that fact.
    pub empty_data_sha256: String,
    pub target: SelectionPointer,
    pub phase: InitialPhase,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialRecovery {
    CancelUnpublished,
    VerifyTarget,
    CompleteMetadata,
    KeepDisabled,
    RequireOperatorRecovery,
}
impl InitialSelection {
    pub fn validate(&self) -> Result<(), SwitchError> {
        self.target.validate()?;
        if self.schema != "guard-cigar-initial-selection.v1"
            || self.revision == 0
            || !identifier(&self.request_id)
            || self.expected_service_generation == 0
            || [&self.before_settings_sha256, &self.after_settings_sha256, &self.empty_data_sha256]
                .iter().any(|s| !hex(s, 64))
            || self.before_settings_sha256 == self.after_settings_sha256
            // Existing generations require an attributed source/data choice.
            || !matches!(self.target.data, SelectionData::Memory | SelectionData::LegacySaved)
        {
            return Err(SwitchError::InvalidJournal);
        }
        Ok(())
    }
    pub fn advance(&self, phase: InitialPhase) -> Result<Self, SwitchError> {
        self.validate()?;
        use InitialPhase::*;
        let permitted = matches!(
            (self.phase, phase),
            (Prepared, CommitIntent | Cancelled | RecoveryRequired)
                | (CommitIntent, Committed | Cancelled | RecoveryRequired)
                | (Committed, Healthy | RecoveryRequired)
                | (Healthy, Completed | RecoveryRequired)
        );
        if !permitted {
            return Err(SwitchError::InvalidTransition);
        }
        let mut next = self.clone();
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(SwitchError::InvalidJournal)?;
        next.phase = phase;
        next.validate()?;
        Ok(next)
    }
    /// Reconcile only observed facts after the native caller has authenticated
    /// the journal and performed any required target verification. This never
    /// reconstructs a prior SDK, enables a profile or creates app authority.
    pub fn reconcile(
        &self,
        selected: &str,
        settings_sha256: &str,
        enabled: bool,
        current: Option<&SelectionPointer>,
        target_eligible: bool,
    ) -> Result<Self, SwitchError> {
        use InitialRecovery::*;
        let phase =
            match self.recovery(selected, settings_sha256, enabled, current, target_eligible)? {
                CancelUnpublished => InitialPhase::Cancelled,
                VerifyTarget => InitialPhase::Committed,
                CompleteMetadata => InitialPhase::Completed,
                KeepDisabled => return Ok(self.clone()),
                RequireOperatorRecovery => return Err(SwitchError::SelectionConflict),
            };
        if phase == self.phase {
            return Ok(self.clone());
        }
        let mut next = self.clone();
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(SwitchError::InvalidJournal)?;
        next.phase = phase;
        next.validate()?;
        Ok(next)
    }
    /// Decisions only. The native caller still authenticates records, checks
    /// empty data/settings under its lease, and verifies actual target bytes.
    /// An enabled or independently edited profile never becomes a write grant.
    pub fn recovery(
        &self,
        selected: &str,
        settings_sha256: &str,
        enabled: bool,
        current: Option<&SelectionPointer>,
        target_eligible: bool,
    ) -> Result<InitialRecovery, SwitchError> {
        self.validate()?;
        use InitialPhase::*;
        use InitialRecovery::*;
        if enabled || current.is_some_and(|p| p != &self.target) {
            return Ok(RequireOperatorRecovery);
        }
        if selected.is_empty()
            && settings_sha256 == self.before_settings_sha256
            && current.is_none()
        {
            return Ok(
                if matches!(
                    self.phase,
                    Prepared | CommitIntent | Cancelled | RecoveryRequired
                ) {
                    CancelUnpublished
                } else {
                    RequireOperatorRecovery
                },
            );
        }
        if selected != self.target.runtime.installation_id
            || settings_sha256 != self.after_settings_sha256
        {
            return Ok(RequireOperatorRecovery);
        }
        Ok(match self.phase {
            CommitIntent | Committed | RecoveryRequired if target_eligible => VerifyTarget,
            Healthy if current == Some(&self.target) => CompleteMetadata,
            Completed if current == Some(&self.target) => KeepDisabled,
            _ => RequireOperatorRecovery,
        })
    }
}
