//! Only the selected runtime ID changes. Byte-level CAS preserves every other
//! preference and detects Stop, external edits and an uncertain prior commit.
use super::*;
use guard_context_assistance::ContextAssistanceConfig;

#[derive(Clone)]
pub(crate) struct SwitchSettings {
    home: PathBuf,
    before: Option<String>,
    after: String,
    source: ContextAssistanceConfig,
    target: ContextAssistanceConfig,
    source_settings: crate::guard_config_load::AssistanceSettings,
    target_settings: crate::guard_config_load::AssistanceSettings,
    update_preferences: guard_cigar_release::UpdatePreferences,
}
pub(crate) fn settings_hash(text: Option<&str>) -> String {
    let mut hash = Sha256::new();
    hash.update(b"guard-cigar-selection-settings.v1\0");
    hash.update([u8::from(text.is_some())]);
    if let Some(text) = text {
        hash.update(text.as_bytes());
    }
    format!("{:x}", hash.finalize())
}
impl SwitchSettings {
    pub(crate) fn capture(
        home: &Path,
        source: &ContextAssistanceConfig,
        target_id: &str,
    ) -> Result<Self, String> {
        let mut policy = crate::managed_policy_load::ManagedPolicySource::native();
        policy.write_cache = false;
        Self::capture_with_policy(home, source, target_id, &policy)
    }
    fn capture_with_policy(
        home: &Path,
        source: &ContextAssistanceConfig,
        target_id: &str,
        policy: &crate::managed_policy_load::ManagedPolicySource,
    ) -> Result<Self, String> {
        if !valid_id(target_id) || target_id == source.runtime_id {
            return Err(error("switch_request_invalid"));
        }
        let home = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
        let before = crate::guard_config_update::read_home_config(&home).map_err(storage_error)?;
        let stored = crate::guard_config_update::assistance_preferences(
            before.as_deref().unwrap_or_default(),
        )
        .map_err(storage_error)?;
        let effective = crate::guard_config_load::context_assistance_from_source(&home, policy)
            .map_err(|_| error("configuration_unavailable"))?;
        if &effective.effective != source
            || effective.diagnostic.is_some()
            || !effective.verification_permitted
            || stored != effective.requested
        {
            return Err(error("switch_settings_conflict"));
        }
        let mut document: toml_edit::DocumentMut = before
            .as_deref()
            .unwrap_or_default()
            .parse()
            .map_err(|_| error("switch_settings_invalid"))?;
        document["context_assistance"]["runtime_id"] = toml_edit::value(target_id);
        let after = document.to_string();
        let mut target = source.clone();
        target.runtime_id = target_id.into();
        let mut expected_requested = stored;
        expected_requested.runtime_id = target_id.into();
        if crate::guard_config_update::assistance_preferences(&after).map_err(storage_error)?
            != expected_requested
        {
            return Err(error("switch_settings_invalid"));
        }
        let target_settings = crate::guard_config_load::context_assistance_target_from_source(
            &home,
            &expected_requested,
            policy,
        )
        .map_err(|_| error("configuration_unavailable"))?;
        if target_settings.effective != target
            || target_settings.diagnostic.is_some()
            || !target_settings.verification_permitted
        {
            return Err(error("switch_target_policy_conflict"));
        }
        let update_preferences =
            crate::guard_config_load::cigar_updates::selection_rules(&home, policy)?;
        Ok(Self {
            update_preferences,
            home,
            before,
            after,
            source: source.clone(),
            target,
            source_settings: effective,
            target_settings,
        })
    }
    pub(crate) fn update_preferences(&self) -> &guard_cigar_release::UpdatePreferences {
        &self.update_preferences
    }
    pub(crate) fn home(&self) -> &Path {
        &self.home
    }
    pub(crate) fn source(&self) -> &ContextAssistanceConfig {
        &self.source
    }
    pub(crate) fn target(&self) -> &ContextAssistanceConfig {
        &self.target
    }
    pub(crate) fn source_settings(&self) -> &crate::guard_config_load::AssistanceSettings {
        &self.source_settings
    }
    pub(crate) fn target_settings(&self) -> &crate::guard_config_load::AssistanceSettings {
        &self.target_settings
    }
    pub(crate) fn before_sha256(&self) -> String {
        settings_hash(self.before.as_deref())
    }
    pub(crate) fn after_sha256(&self) -> String {
        settings_hash(Some(&self.after))
    }
    pub(super) fn matches(&self, t: &SelectionTransaction) -> bool {
        t.before_settings_sha256 == self.before_sha256()
            && t.after_settings_sha256 == self.after_sha256()
            && t.from.runtime.installation_id == self.source.runtime_id
            && t.to.runtime.installation_id == self.target.runtime_id
            && t.was_enabled == self.source.enabled
            && self.source.enabled == self.target.enabled
    }
    pub(crate) fn check_current(&self) -> Result<(), String> {
        let mut policy = crate::managed_policy_load::ManagedPolicySource::native();
        policy.write_cache = false;
        self.check_with_policy(&policy)
    }
    fn check_with_policy(
        &self,
        policy: &crate::managed_policy_load::ManagedPolicySource,
    ) -> Result<(), String> {
        if crate::guard_config_update::read_home_config(&self.home).map_err(storage_error)?
            != self.before
        {
            return Err(error("switch_settings_conflict"));
        }
        let current = crate::guard_config_load::context_assistance_from_source(&self.home, policy)
            .map_err(|_| error("configuration_unavailable"))?;
        let target = crate::guard_config_load::context_assistance_target_from_source(
            &self.home,
            &self.target_settings.requested,
            policy,
        )
        .map_err(|_| error("configuration_unavailable"))?;
        if crate::guard_config_load::cigar_updates::selection_rules(&self.home, policy)?
            != self.update_preferences
        {
            return Err(error("switch_settings_conflict"));
        }
        if current != self.source_settings || target != self.target_settings {
            return Err(error("switch_settings_conflict"));
        }
        Ok(())
    }
    pub(crate) fn preflight_publish(&self) -> Result<(), String> {
        self.check_current()?;
        let lock = WriteLock::acquire(&self.home).map_err(storage_error)?;
        lock.preflight(self.before.as_deref())
            .map_err(storage_error)
    }
    pub(crate) fn check_target_policy(&self) -> Result<(), String> {
        let mut policy = crate::managed_policy_load::ManagedPolicySource::native();
        policy.write_cache = false;
        let current = crate::guard_config_load::context_assistance_from_source(&self.home, &policy)
            .map_err(|_| error("configuration_unavailable"))?;
        if crate::guard_config_load::cigar_updates::selection_rules(&self.home, &policy)?
            != self.update_preferences
        {
            return Err(error("switch_settings_conflict"));
        }
        if current != self.target_settings {
            return Err(error("switch_settings_conflict"));
        }
        Ok(())
    }
    pub(crate) fn check_target_exact(&self) -> Result<(), String> {
        self.check_target_policy()?;
        if crate::guard_config_update::read_home_config(&self.home)
            .map_err(storage_error)?
            .as_deref()
            != Some(self.after.as_str())
        {
            return Err(error("switch_settings_conflict"));
        }
        Ok(())
    }
    /// Only the exact captured source or target bytes are eligible. Even an
    /// unrelated edit requires explicit recovery; Stop/policy narrowing wins.
    pub(super) fn check_restore_window(&self) -> Result<bool, String> {
        let mut policy = crate::managed_policy_load::ManagedPolicySource::native();
        policy.write_cache = false;
        self.check_restore_with_policy(&policy)
    }
    fn check_restore_with_policy(
        &self,
        policy: &crate::managed_policy_load::ManagedPolicySource,
    ) -> Result<bool, String> {
        if !self.source.enabled || !self.source_settings.requested.enabled || self.before.is_none()
        {
            return Err(error("switch_restore_not_enabled"));
        }
        let raw =
            crate::guard_config_update::read_home_config(&self.home).map_err(storage_error)?;
        let target_selected = if raw == self.before {
            false
        } else if raw.as_deref() == Some(self.after.as_str()) {
            true
        } else {
            return Err(error("switch_settings_conflict"));
        };
        let current = crate::guard_config_load::context_assistance_from_source(&self.home, policy)
            .map_err(|_| error("configuration_unavailable"))?;
        let source = crate::guard_config_load::context_assistance_target_from_source(
            &self.home,
            &self.source_settings.requested,
            policy,
        )
        .map_err(|_| error("configuration_unavailable"))?;
        let target = crate::guard_config_load::context_assistance_target_from_source(
            &self.home,
            &self.target_settings.requested,
            policy,
        )
        .map_err(|_| error("configuration_unavailable"))?;
        if source != self.source_settings
            || target != self.target_settings
            || current
                != if target_selected {
                    self.target_settings.clone()
                } else {
                    self.source_settings.clone()
                }
        {
            return Err(error("switch_settings_conflict"));
        }
        Ok(target_selected)
    }
    pub(super) fn restore(&self, lock: &WriteLock) -> Result<(), String> {
        if self.check_restore_window()? {
            lock.publish(
                Some(&self.after),
                self.before
                    .as_deref()
                    .ok_or_else(|| error("switch_settings_conflict"))?,
            )
            .map_err(storage_error)?;
        }
        self.check_current()
    }
    pub(super) fn publish(&self, lock: &WriteLock) -> Result<(), String> {
        self.check_current()?;
        lock.publish(self.before.as_deref(), &self.after)
            .map_err(storage_error)
    }
}

#[cfg(test)]
#[path = "context_assistance_switch_policy_tests.rs"]
mod tests;
