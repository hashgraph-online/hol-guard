//! Durable lifecycle records describe effects; they are never execution grants.
//! Native callers must validate current settings, policy and protected bytes.
use crate::types::{hex, identifier};
use crate::BuildIdentity;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataTransition {
    MemoryRebuild,
    ReuseCompatible,
    PreparedCopy,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchPhase {
    Prepared,
    OldRuntimeStopped,
    SelectionCommitted,
    TargetHealthy,
    Completed,
    RollbackSelected,
    RolledBack,
    Cancelled,
    RecoveryRequired,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SwitchJournal {
    pub schema: String,
    pub request_id: String,
    pub expected_generation: u64,
    pub settings_sha256: String,
    pub from_installation: String,
    pub to_installation: String,
    pub from_build: BuildIdentity,
    pub to_build: BuildIdentity,
    pub previous_enabled: bool,
    pub activate_target: bool,
    pub reconnect_acknowledged: bool,
    pub data_transition: DataTransition,
    pub previous_data_generation: Option<String>,
    pub prepared_data_generation: Option<String>,
    pub phase: SwitchPhase,
    pub cancel_requested: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    PreservePrevious,
    RestorePrevious,
    VerifyTarget,
    FinalizeTarget,
    VerifyPrevious,
    Complete,
    RequireOperatorRecovery,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchError {
    InvalidJournal,
    InvalidTransition,
    SelectionConflict,
    SettingsConflict,
}
impl SwitchError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidJournal => "cigar_upgrade_journal_invalid",
            Self::InvalidTransition => "cigar_upgrade_transition_invalid",
            Self::SelectionConflict => "cigar_upgrade_selection_conflict",
            Self::SettingsConflict => "cigar_upgrade_settings_conflict",
        }
    }
}
impl SwitchJournal {
    pub fn validate(&self) -> Result<(), SwitchError> {
        if self.schema != "guard-cigar-switch-journal.v1"
            || !identifier(&self.request_id)
            || self.expected_generation == 0
            || !hex(&self.settings_sha256, 64)
            || !identifier(&self.from_installation)
            || !identifier(&self.to_installation)
            || self.from_installation == self.to_installation
            || self.from_build.validate().is_err()
            || self.to_build.validate().is_err()
            || crate::compare_builds(&self.from_build, &self.to_build).is_err()
            || self
                .previous_data_generation
                .as_deref()
                .is_some_and(|value| !identifier(value))
            || self
                .prepared_data_generation
                .as_deref()
                .is_some_and(|value| !identifier(value))
        {
            return Err(SwitchError::InvalidJournal);
        }
        match self.data_transition {
            DataTransition::MemoryRebuild
                if self.previous_data_generation.is_some()
                    || self.prepared_data_generation.is_some() =>
            {
                return Err(SwitchError::InvalidJournal)
            }
            DataTransition::ReuseCompatible
                if self.previous_data_generation.is_none()
                    || self.prepared_data_generation != self.previous_data_generation =>
            {
                return Err(SwitchError::InvalidJournal)
            }
            DataTransition::PreparedCopy
                if self.previous_data_generation.is_none()
                    || self.prepared_data_generation.is_none()
                    || self.previous_data_generation == self.prepared_data_generation =>
            {
                return Err(SwitchError::InvalidJournal)
            }
            _ => {}
        }
        Ok(())
    }
    /// A preparation result is usable only under the exact source generation
    /// and settings it read. A stale page cannot cut over a changed selection.
    pub fn check_precondition(
        &self,
        generation: u64,
        settings_sha256: &str,
        selected: &str,
    ) -> Result<(), SwitchError> {
        self.validate()?;
        if generation != self.expected_generation || selected != self.from_installation {
            return Err(SwitchError::SelectionConflict);
        }
        if settings_sha256 != self.settings_sha256 {
            return Err(SwitchError::SettingsConflict);
        }
        Ok(())
    }
    /// Persist the next journal before advancing effects. A lost reply must be
    /// reconciled against protected selection; retrying is not a fresh switch.
    pub fn advance(&mut self, next: SwitchPhase) -> Result<(), SwitchError> {
        self.validate()?;
        use SwitchPhase::*;
        let allowed = matches!(
            (self.phase, next),
            (Prepared, OldRuntimeStopped | Cancelled | RecoveryRequired)
                | (
                    OldRuntimeStopped,
                    SelectionCommitted | RolledBack | RecoveryRequired
                )
                | (
                    SelectionCommitted,
                    TargetHealthy | RollbackSelected | RecoveryRequired
                )
                | (
                    TargetHealthy,
                    Completed | RollbackSelected | RecoveryRequired
                )
                | (RollbackSelected, RolledBack | RecoveryRequired)
        );
        if !allowed {
            return Err(SwitchError::InvalidTransition);
        }
        self.phase = next;
        Ok(())
    }
    /// Pure recovery decision. Eligibility is freshly checked by the native
    /// owner; a withdrawn build is never inferred to be a safe rollback.
    pub fn recovery(
        &self,
        selected: &str,
        target_eligible: bool,
        previous_eligible: bool,
    ) -> Result<RecoveryAction, SwitchError> {
        self.validate()?;
        use RecoveryAction::*;
        use SwitchPhase::*;
        let previous = selected == self.from_installation;
        let target = selected == self.to_installation;
        if !previous && !target {
            return Err(SwitchError::SelectionConflict);
        }
        let action = match self.phase {
            Prepared | Cancelled if previous => PreservePrevious,
            OldRuntimeStopped if previous && previous_eligible => RestorePrevious,
            SelectionCommitted if target && !self.cancel_requested && target_eligible => {
                VerifyTarget
            }
            TargetHealthy if target && !self.cancel_requested && target_eligible => FinalizeTarget,
            Completed if target && !self.cancel_requested && target_eligible => Complete,
            SelectionCommitted | TargetHealthy if target && previous_eligible => RestorePrevious,
            RollbackSelected if previous && previous_eligible => VerifyPrevious,
            RolledBack if previous && previous_eligible => Complete,
            _ => RequireOperatorRecovery,
        };
        Ok(action)
    }
}
