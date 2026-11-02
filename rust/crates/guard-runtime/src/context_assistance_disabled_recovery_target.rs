//! Authenticated committed target while the profile remains disabled. This
//! capsule contains no SDK eligibility, process, workspace or app authority.
use super::*;
use crate::guard_config_load::AssistanceSettings;
use crate::guard_config_update::io::{root_identity_of, RootIdentity};
use guard_context_assistance::{EvidenceGenerationStore, PreparedEvidenceGeneration, StorageMode};

pub(crate) struct DisabledTarget {
    home: PathBuf,
    root_identity: RootIdentity,
    raw: Option<String>,
    settings: AssistanceSettings,
    rules: guard_cigar_release::UpdatePreferences,
    record: SelectionRecord,
    pointer: SelectionPointer,
    generation: Option<PreparedEvidenceGeneration>,
    semantic: Option<String>,
}
impl DisabledTarget {
    fn capture(owner: &Owner, job: &jobs::SwitchJob) -> Result<Self, String> {
        owner.check_initial_clear()?;
        DataRemoval::check_clear(&owner.home).map_err(|e| error(e.code()))?;
        let phase = owner.job_phase(job)?;
        let record = owner
            .record()
            .ok_or_else(|| error("switch_selection_missing"))?
            .clone();
        let t = record
            .transaction
            .as_ref()
            .ok_or_else(|| error("switch_transaction_missing"))?;
        if job.is_initial()
            // The immutable job mode must agree with sealed original intent.
            // A later Stop can make a previously live transaction recoverable
            // without restoring its activation request or app authority.
            || job.source_disabled == t.was_enabled
            || t.cancel_requested
            || !matches!(
                phase,
                SelectionPhase::CommitIntent | SelectionPhase::Committed | SelectionPhase::Healthy
            )
        {
            return Err(error("switch_recovery_required"));
        }
        let pointer = t.to.clone();
        let mut policy = crate::managed_policy_load::ManagedPolicySource::native();
        policy.write_cache = false;
        let settings =
            crate::guard_config_load::context_assistance_from_source(&owner.home, &policy)
                .map_err(|_| error("configuration_unavailable"))?;
        let raw =
            crate::guard_config_update::read_home_config(&owner.home).map_err(storage_error)?;
        let rules = crate::guard_config_load::cigar_updates::selection_rules(&owner.home, &policy)?;
        let generation = pointer
            .data
            .generation_id()
            .map(|id| {
                EvidenceGenerationStore::existing(&owner.home)
                    .map_err(|e| error(e.code()))?
                    .ok_or_else(|| error("switch_data_generation_missing"))?
                    .load(id)
                    .map_err(|e| error(e.code()))
            })
            .transpose()?;
        let semantic = generation
            .as_ref()
            .map(|g| g.semantic_sha256().map_err(|e| error(e.code())))
            .transpose()?;
        let result = Self {
            home: owner.home.clone(),
            root_identity: owner.root_identity,
            raw,
            settings,
            rules,
            record,
            pointer,
            generation,
            semantic,
        };
        result.check()?;
        Ok(result)
    }
    pub(crate) fn settings(&self) -> &AssistanceSettings {
        &self.settings
    }
    pub(crate) fn rules(&self) -> &guard_cigar_release::UpdatePreferences {
        &self.rules
    }
    pub(crate) fn pointer(&self) -> &SelectionPointer {
        &self.pointer
    }
    pub(crate) fn check(&self) -> Result<(), String> {
        if root_identity_of(&self.home).map_err(|_| error("home_invalid"))? != self.root_identity {
            return Err(error("switch_selection_conflict"));
        }
        DataRemoval::check_clear(&self.home).map_err(|e| error(e.code()))?;
        let mut policy = crate::managed_policy_load::ManagedPolicySource::native();
        policy.write_cache = false;
        let settings =
            crate::guard_config_load::context_assistance_from_source(&self.home, &policy)
                .map_err(|_| error("configuration_unavailable"))?;
        let raw =
            crate::guard_config_update::read_home_config(&self.home).map_err(storage_error)?;
        let t = self
            .record
            .transaction
            .as_ref()
            .ok_or_else(|| error("switch_transaction_missing"))?;
        if raw != self.raw
            || settings != self.settings
            || settings.requested.enabled
            || settings.effective.enabled
            || !settings.verification_permitted
            || settings.diagnostic.is_some()
            || settings.requested.runtime_id != self.pointer.runtime.installation_id
            || settings.effective.runtime_id != self.pointer.runtime.installation_id
            // CommitIntent alone cannot establish which configuration write
            // completed. Committed/Healthy already bind the selected SDK/data
            // pair; an explicit recovery snapshots current disabled settings
            // and never restores the old preferences or their authority.
            || (t.phase == SelectionPhase::CommitIntent
                && settings_hash(raw.as_deref()) != t.after_settings_sha256)
            || crate::guard_config_load::cigar_updates::selection_rules(&self.home, &policy)?
                != self.rules
        {
            return Err(error("switch_settings_conflict"));
        }
        if matches!(
            self.pointer.data,
            guard_cigar_release::SelectionData::Memory
        ) != (settings.effective.storage.mode == StorageMode::Memory)
        {
            return Err(error("switch_data_settings_conflict"));
        }
        if let Some(generation) = &self.generation {
            let summary = generation.describe().map_err(|e| error(e.code()))?;
            if summary["phase"] != "ready"
                || summary["target_producer_sha256"] != self.pointer.runtime.producer_sha256
                || Some(generation.semantic_sha256().map_err(|e| error(e.code()))?) != self.semantic
            {
                return Err(error("switch_data_generation_mismatch"));
            }
        }
        Ok(())
    }
    fn check_owner(&self, owner: &Owner) -> Result<(), String> {
        if self.home != owner.home
            || self.root_identity != owner.root_identity
            || owner.record() != Some(&self.record)
        {
            return Err(error("switch_selection_conflict"));
        }
        self.check()
    }
}

/// Retention briefly owns the evidence metadata lock at startup. Retry only
/// this read-only snapshot, before a writer lock, job admission or SDK work.
/// Every non-contention error remains immediate and the monotonic budget is fixed.
pub(super) fn snapshot<T>(mut read: impl FnMut() -> Result<T, String>) -> Result<T, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
    loop {
        match read() {
            Err(code) if code == error("context_busy") && std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            result => return result,
        }
    }
}

impl Owner {
    /// Only renew progress after authenticating the original SDK/data intent
    /// and observing the current disabled preferences for that committed target.
    pub(crate) fn begin_disabled_recovery(
        &mut self,
        job: &jobs::SwitchJob,
        generation: u64,
    ) -> Result<(DisabledTarget, jobs::SwitchJob), String> {
        let target = snapshot(|| DisabledTarget::capture(self, job))?;
        let lock = WriteLock::acquire(&self.home).map_err(storage_error)?;
        self.check(&lock)?;
        target.check_owner(self)?;
        let job = jobs::begin_disabled_recovery(&self.home, job, generation)?;
        Ok((target, job))
    }
    /// The bounded native worker measured and closed the private target.
    /// No preferences, evidence bytes, process or grant are published here.
    pub(crate) fn recover_disabled_target(
        &mut self,
        job: &jobs::SwitchJob,
        target: &DisabledTarget,
        measured: &SelectionPointer,
    ) -> Result<(), String> {
        self.reload()?;
        self.job_phase(job)?;
        let lock = WriteLock::acquire(&self.home).map_err(storage_error)?;
        self.check(&lock)?;
        target.check_owner(self)?;
        if target.pointer() != measured {
            return Err(error("switch_installation_changed"));
        }
        match self.job_phase(job)? {
            SelectionPhase::Committed | SelectionPhase::Healthy => Ok(()),
            SelectionPhase::CommitIntent => {
                let next = self
                    .record()
                    .ok_or_else(|| error("switch_selection_missing"))?
                    .advance(SelectionPhase::Committed)
                    .map_err(state_error)?;
                self.publish_locked(&lock, next)
            }
            _ => Err(error("switch_recovery_required")),
        }
    }
}
