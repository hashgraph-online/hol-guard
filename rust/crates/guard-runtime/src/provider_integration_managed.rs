//! Managed policy for provider capability settings (PRD 6.6, BP-T125).
//!
//! "Enforce provider blocks" (effect level `enforce`) and "Require a fresh check" are per provider
//! and capability, off by default. The person changes them through the protected settings route;
//! an administrator sets them in managed policy under `settings.provider_integrations`:
//!
//! ```json
//! { "settings": { "provider_integrations": [
//!     { "provider_id": "provider.exampleshield", "capability": "browser.origin-reputation",
//!       "effect": "enforce", "require_fresh_check": true } ] },
//!   "lockedSettings": ["provider_integrations"] }
//! ```
//!
//! - Unlocked, a managed entry is a floor: the effective effect level is the stronger of the local
//!   and managed level, and a managed `require_fresh_check: true` cannot be turned off locally.
//! - Locked, a managed entry is exact for the fields it names: the local value is ignored.
//! - A field the entry leaves out keeps the local value.
//! - A provider never sets either value. The effective setting is composed from the local store and
//!   managed policy only; nothing a provider sends reaches this module.
//!
//! A malformed `provider_integrations` value is an error, never an empty list, so a typo in an
//! administrator's policy cannot quietly drop the settings it meant to impose.

use std::collections::BTreeMap;

use guard_contracts::{provider_id_is_valid, ProviderCapabilityV1, ProviderEffectLevelV1};
use serde_json::{Map, Value};

use crate::provider_integration_store::CapabilitySetting;

/// The managed-policy settings key, and the `lockedSettings` path that locks it.
pub const PROVIDER_INTEGRATIONS_SETTING: &str = "provider_integrations";

/// Most entries one policy may carry.
pub const MAX_MANAGED_PROVIDER_ENTRIES: usize = 256;

const ENTRY_KEYS: [&str; 4] = ["provider_id", "capability", "effect", "require_fresh_check"];

/// What managed policy says about one provider capability.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ManagedCapabilitySetting {
    pub effect: Option<ProviderEffectLevelV1>,
    pub require_fresh_check: Option<bool>,
}

/// The provider capability settings managed policy imposes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManagedProviderSettings {
    entries: BTreeMap<(String, ProviderCapabilityV1), ManagedCapabilitySetting>,
    locked: bool,
}

/// Why `settings.provider_integrations` could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedProviderSettingsError(pub String);

impl std::fmt::Display for ManagedProviderSettingsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ManagedProviderSettingsError {}

type ManagedResult<T> = Result<T, ManagedProviderSettingsError>;

fn invalid<T>(message: impl Into<String>) -> ManagedResult<T> {
    Err(ManagedProviderSettingsError(message.into()))
}

impl ManagedProviderSettings {
    /// No managed policy, or one that does not mention provider settings.
    pub fn none() -> Self {
        Self::default()
    }

    /// Read the settings from a managed `settings` mapping. `locked` is whether `lockedSettings`
    /// names [`PROVIDER_INTEGRATIONS_SETTING`].
    pub fn from_settings(settings: &Map<String, Value>, locked: bool) -> ManagedResult<Self> {
        let Some(value) = settings.get(PROVIDER_INTEGRATIONS_SETTING) else {
            return Ok(Self {
                entries: BTreeMap::new(),
                locked,
            });
        };
        let Value::Array(items) = value else {
            return invalid("provider_integrations must be an array of entries");
        };
        if items.len() > MAX_MANAGED_PROVIDER_ENTRIES {
            return invalid("provider_integrations has too many entries");
        }
        let mut entries = BTreeMap::new();
        for item in items {
            let (key, setting) = parse_entry(item)?;
            if entries.insert(key, setting).is_some() {
                return invalid("provider_integrations names a provider capability twice");
            }
        }
        Ok(Self { entries, locked })
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    pub fn entry(
        &self,
        provider_id: &str,
        capability: ProviderCapabilityV1,
    ) -> Option<ManagedCapabilitySetting> {
        self.entries
            .get(&(provider_id.to_owned(), capability))
            .copied()
    }

    /// The setting `decide` applies: the local setting composed with managed policy.
    pub fn effective(
        &self,
        provider_id: &str,
        capability: ProviderCapabilityV1,
        local: CapabilitySetting,
    ) -> CapabilitySetting {
        let Some(managed) = self.entry(provider_id, capability) else {
            return local;
        };
        let effect_level = match managed.effect {
            None => local.effect_level,
            Some(effect) if self.locked => effect,
            Some(effect) => effect.max(local.effect_level),
        };
        let require_fresh = match managed.require_fresh_check {
            None => local.require_fresh,
            Some(required) if self.locked => required,
            Some(required) => required || local.require_fresh,
        };
        CapabilitySetting {
            effect_level,
            require_fresh,
        }
    }

    /// Whether the local setting may still change: false when a locked entry names every field.
    pub fn locally_changeable(&self, provider_id: &str, capability: ProviderCapabilityV1) -> bool {
        match self.entry(provider_id, capability) {
            Some(managed) if self.locked => {
                managed.effect.is_none() || managed.require_fresh_check.is_none()
            }
            _ => true,
        }
    }
}

fn parse_entry(
    item: &Value,
) -> ManagedResult<((String, ProviderCapabilityV1), ManagedCapabilitySetting)> {
    let Value::Object(entry) = item else {
        return invalid("provider_integrations entries must be objects");
    };
    if let Some(unknown) = entry.keys().find(|key| !ENTRY_KEYS.contains(&key.as_str())) {
        return invalid(format!(
            "provider_integrations entry has unknown key {unknown}"
        ));
    }
    let provider_id = match entry.get("provider_id") {
        Some(Value::String(id)) if provider_id_is_valid(id) => id.clone(),
        _ => return invalid("provider_integrations entry needs a provider_id"),
    };
    let capability = match entry.get("capability").cloned() {
        Some(value @ Value::String(_)) => serde_json::from_value(value)
            .or_else(|_| invalid("provider_integrations entry names an unknown capability"))?,
        _ => return invalid("provider_integrations entry needs a capability"),
    };
    let effect = match entry.get("effect").cloned() {
        None => None,
        Some(value @ Value::String(_)) => Some(
            serde_json::from_value(value)
                .or_else(|_| invalid("provider_integrations effect is invalid"))?,
        ),
        Some(_) => return invalid("provider_integrations effect is invalid"),
    };
    let require_fresh_check = match entry.get("require_fresh_check") {
        None => None,
        Some(Value::Bool(required)) => Some(*required),
        Some(_) => return invalid("provider_integrations require_fresh_check must be a boolean"),
    };
    if effect.is_none() && require_fresh_check.is_none() {
        return invalid("provider_integrations entry sets nothing");
    }
    Ok((
        (provider_id, capability),
        ManagedCapabilitySetting {
            effect,
            require_fresh_check,
        },
    ))
}

#[cfg(test)]
#[path = "provider_integration_managed_tests.rs"]
mod tests;
