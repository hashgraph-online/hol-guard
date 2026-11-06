//! Exact SDK/data pairs and write-ahead switch intent. No record is a grant.
use crate::types::{hex, identifier};
use crate::{ReleaseBinding, SwitchError};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SelectionOrigin {
    Catalog {
        release: Box<ReleaseBinding>,
    },
    /// No upstream revision, manifest or public build ID can be inferred from
    /// a historical enrollment. Its exact local bytes are bound separately.
    Enrolled {
        sdk_version: String,
        core_version: String,
        profile_id: String,
        adapter_id: String,
        adapter_revision: u32,
    },
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionInstallation {
    pub installation_id: String,
    pub installation_sha256: String,
    pub approval_sha256: String,
    pub producer_sha256: String,
    pub origin: SelectionOrigin,
}
impl SelectionInstallation {
    pub fn validate(&self) -> Result<(), SwitchError> {
        if !identifier(&self.installation_id)
            || [
                &self.installation_sha256,
                &self.approval_sha256,
                &self.producer_sha256,
            ]
            .iter()
            .any(|s| !hex(s, 64))
        {
            return Err(SwitchError::InvalidJournal);
        }
        let valid = match &self.origin {
            SelectionOrigin::Catalog { release } => {
                release.identity.validate().is_ok()
                    && identifier(&release.profile_id)
                    && identifier(&release.adapter_id)
                    && release.adapter_revision > 0
                    && identifier(&release.platform)
                    && hex(&release.profile_sha256, 64)
            }
            SelectionOrigin::Enrolled {
                sdk_version,
                core_version,
                profile_id,
                adapter_id,
                adapter_revision,
            } => {
                crate::identity::version(sdk_version).is_ok()
                    && crate::labels::producer_label(core_version)
                    && identifier(profile_id)
                    && identifier(adapter_id)
                    && *adapter_revision > 0
            }
        };
        if valid {
            Ok(())
        } else {
            Err(SwitchError::InvalidJournal)
        }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SelectionData {
    Memory,
    LegacySaved,
    Generation { generation_id: String },
}
impl SelectionData {
    pub fn generation_id(&self) -> Option<&str> {
        match self {
            Self::Generation { generation_id } => Some(generation_id),
            _ => None,
        }
    }
    fn validate(&self) -> bool {
        self.generation_id().is_none_or(|s| hex(s, 64))
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionPointer {
    pub runtime: SelectionInstallation,
    pub data: SelectionData,
}
impl SelectionPointer {
    pub fn validate(&self) -> Result<(), SwitchError> {
        self.runtime.validate()?;
        if self.data.validate() {
            Ok(())
        } else {
            Err(SwitchError::InvalidJournal)
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionPhase {
    Prepared,
    StopIntent,
    CommitIntent,
    Committed,
    Healthy,
    Completed,
    RestoreIntent,
    RolledBack,
    Cancelled,
    RecoveryRequired,
}
impl SelectionPhase {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Completed | Self::RolledBack | Self::Cancelled)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionTransaction {
    pub request_id: String,
    pub expected_service_generation: u64,
    pub before_settings_sha256: String,
    pub after_settings_sha256: String,
    pub source_semantic_sha256: String,
    pub from: SelectionPointer,
    pub to: SelectionPointer,
    pub was_enabled: bool,
    pub activate_target: bool,
    pub reconnect_acknowledged: bool,
    pub cancel_requested: bool,
    pub phase: SelectionPhase,
}
impl SelectionTransaction {
    pub fn validate(&self) -> Result<(), SwitchError> {
        self.from.validate()?;
        self.to.validate()?;
        if !identifier(&self.request_id)
            || self.expected_service_generation == 0
            || [
                &self.before_settings_sha256,
                &self.after_settings_sha256,
                &self.source_semantic_sha256,
            ]
            .iter()
            .any(|s| !hex(s, 64))
            || self.before_settings_sha256 == self.after_settings_sha256
            || self.from.runtime.installation_id == self.to.runtime.installation_id
            || (self.activate_target && !self.was_enabled)
            || (self.activate_target
                && !self.reconnect_acknowledged
                && !matches!(
                    self.phase,
                    SelectionPhase::Prepared
                        | SelectionPhase::Cancelled
                        | SelectionPhase::RecoveryRequired
                ))
            || (self.from.data == self.to.data && self.from.data != SelectionData::Memory)
            || matches!(self.to.data, SelectionData::LegacySaved)
        {
            return Err(SwitchError::InvalidJournal);
        }
        if let (SelectionOrigin::Catalog { release: a }, SelectionOrigin::Catalog { release: b }) =
            (&self.from.runtime.origin, &self.to.runtime.origin)
        {
            crate::compare_builds(&a.identity, &b.identity)
                .map_err(|_| SwitchError::InvalidJournal)?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionRecord {
    pub schema: String,
    pub revision: u64,
    pub current: SelectionPointer,
    pub last_good: Option<SelectionPointer>,
    pub transaction: Option<SelectionTransaction>,
}
impl SelectionRecord {
    pub fn validate(&self) -> Result<(), SwitchError> {
        self.current.validate()?;
        if let Some(previous) = &self.last_good {
            previous.validate()?;
        }
        if self.schema != "guard-cigar-selection.v2" || self.revision == 0 {
            return Err(SwitchError::InvalidJournal);
        }
        if let Some(t) = &self.transaction {
            t.validate()?;
            use SelectionPhase::*;
            let expected = match t.phase {
                Prepared | StopIntent | CommitIntent | RolledBack | Cancelled => &t.from,
                Committed | Healthy | Completed => &t.to,
                RestoreIntent | RecoveryRequired => {
                    if self.current != t.from && self.current != t.to {
                        return Err(SwitchError::InvalidJournal);
                    }
                    &self.current
                }
            };
            if &self.current != expected
                || (t.phase == Completed && self.last_good.as_ref() != Some(&t.from))
            {
                return Err(SwitchError::InvalidJournal);
            }
        }
        Ok(())
    }
    fn next_revision(&mut self) -> Result<(), SwitchError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(SwitchError::InvalidJournal)?;
        Ok(())
    }
    pub fn begin(&self, transaction: SelectionTransaction) -> Result<Self, SwitchError> {
        self.validate()?;
        transaction.validate()?;
        if self
            .transaction
            .as_ref()
            .is_some_and(|t| !t.phase.terminal())
            || transaction.phase != SelectionPhase::Prepared
            || transaction.from != self.current
        {
            return Err(SwitchError::SelectionConflict);
        }
        let mut next = self.clone();
        next.next_revision()?;
        next.transaction = Some(transaction);
        next.validate()?;
        Ok(next)
    }
    pub fn advance(&self, phase: SelectionPhase) -> Result<Self, SwitchError> {
        self.validate()?;
        let t = self
            .transaction
            .as_ref()
            .ok_or(SwitchError::InvalidTransition)?;
        use SelectionPhase::*;
        let allowed = matches!(
            (t.phase, phase),
            (Prepared, StopIntent | Cancelled | RecoveryRequired)
                | (
                    StopIntent,
                    CommitIntent | Cancelled | RestoreIntent | RecoveryRequired
                )
                | (CommitIntent, Committed | RestoreIntent | RecoveryRequired)
                | (Committed, Healthy | RestoreIntent | RecoveryRequired)
                | (Healthy, Completed | RestoreIntent | RecoveryRequired)
                | (RestoreIntent, RolledBack | RecoveryRequired)
        );
        if !allowed {
            return Err(SwitchError::InvalidTransition);
        }
        let mut next = self.clone();
        next.next_revision()?;
        let t = next
            .transaction
            .as_mut()
            .ok_or(SwitchError::InvalidTransition)?;
        t.phase = phase;
        if matches!(phase, Committed | Healthy | Completed) {
            next.current = t.to.clone();
        }
        if matches!(phase, Cancelled | RolledBack) {
            next.current = t.from.clone();
        }
        if phase == Completed {
            next.last_good = Some(t.from.clone());
        }
        next.validate()?;
        Ok(next)
    }
    /// These are retention references, never authority to open a scope.
    pub fn retained_generations(&self) -> Result<Vec<String>, SwitchError> {
        self.validate()?;
        let mut ids = std::collections::BTreeSet::new();
        let mut include = |p: &SelectionPointer| {
            if let Some(id) = p.data.generation_id() {
                ids.insert(id.to_owned());
            }
        };
        include(&self.current);
        if let Some(p) = &self.last_good {
            include(p);
        }
        if let Some(t) = &self.transaction {
            if !t.phase.terminal() {
                include(&t.from);
                include(&t.to);
            }
        }
        Ok(ids.into_iter().collect())
    }
}
