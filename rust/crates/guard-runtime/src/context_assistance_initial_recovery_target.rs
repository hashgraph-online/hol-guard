//! Exact disabled target preferences captured after an interrupted commit.
//! This is not an SDK verification receipt or permission to enable anything.
use super::*;
use crate::guard_config_load::AssistanceSettings;

pub(crate) struct InitialTarget {
    home: PathBuf,
    raw: Option<String>,
    settings: AssistanceSettings,
    rules: guard_cigar_release::UpdatePreferences,
    plan: InitialSelection,
}
impl InitialTarget {
    pub(super) fn capture(owner: &Owner, id: &str) -> Result<Self, String> {
        let plan = owner
            .initial_record()
            .filter(|p| {
                p.request_id == id
                    && matches!(
                        p.phase,
                        InitialPhase::CommitIntent
                            | InitialPhase::Committed
                            | InitialPhase::RecoveryRequired
                    )
            })
            .ok_or_else(|| error("initial_selection_recovery_required"))?
            .clone();
        let mut policy = crate::managed_policy_load::ManagedPolicySource::native();
        policy.write_cache = false;
        let settings =
            crate::guard_config_load::context_assistance_from_source(&owner.home, &policy)
                .map_err(|_| error("configuration_unavailable"))?;
        let raw =
            crate::guard_config_update::read_home_config(&owner.home).map_err(storage_error)?;
        let rules = crate::guard_config_load::cigar_updates::selection_rules(&owner.home, &policy)?;
        let result = Self {
            home: owner.home.clone(),
            raw,
            settings,
            rules,
            plan,
        };
        result.check()?;
        Ok(result)
    }
    pub(crate) fn settings(&self) -> &AssistanceSettings {
        &self.settings
    }
    pub(crate) fn pointer(&self) -> &SelectionPointer {
        &self.plan.target
    }
    pub(crate) fn rules(&self) -> &guard_cigar_release::UpdatePreferences {
        &self.rules
    }
    pub(crate) fn check(&self) -> Result<(), String> {
        let mut policy = crate::managed_policy_load::ManagedPolicySource::native();
        policy.write_cache = false;
        let settings =
            crate::guard_config_load::context_assistance_from_source(&self.home, &policy)
                .map_err(|_| error("configuration_unavailable"))?;
        let raw =
            crate::guard_config_update::read_home_config(&self.home).map_err(storage_error)?;
        if raw != self.raw
            || settings != self.settings
            || settings.requested.enabled
            || settings.effective.enabled
            || !settings.verification_permitted
            || settings.diagnostic.is_some()
            || settings.requested.runtime_id != self.plan.target.runtime.installation_id
            || settings.effective.runtime_id != self.plan.target.runtime.installation_id
            || settings_hash(raw.as_deref()) != self.plan.after_settings_sha256
            || crate::guard_config_load::cigar_updates::selection_rules(&self.home, &policy)?
                != self.rules
        {
            return Err(error("switch_settings_conflict"));
        }
        let data =
            if settings.effective.storage.mode == guard_context_assistance::StorageMode::Memory {
                guard_cigar_release::SelectionData::Memory
            } else {
                guard_cigar_release::SelectionData::LegacySaved
            };
        if data != self.plan.target.data {
            return Err(error("switch_data_settings_conflict"));
        }
        Ok(())
    }
    pub(super) fn check_owner(&self, owner: &Owner) -> Result<(), String> {
        if self.home != owner.home || owner.initial_record() != Some(&self.plan) {
            return Err(error("initial_selection_conflict"));
        }
        self.check()
    }
}
