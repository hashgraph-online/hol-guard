//! Native effective Guard configuration for resident package evaluation.
//!
//! Mirrors the part of `guard/config.py::load_guard_config` that package
//! decisions consume: the Guard home `config.toml` merged with the
//! sanitized workspace override files. Every unreadable, unsafe or malformed
//! source is an error so that callers keep the request blocked.
//!
//! Managed (MDM) policy is composed here as Python composes it: the machine
//! source is loaded, an unreadable one stands in as the fail-closed floor, and
//! the resulting policy is applied to the merged payload before any value is
//! read out of it. A managed requirement can only make the configuration
//! stricter.

use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use guard_command::action_lattice::normalize_guard_action;
use guard_command::effect_decision::GuardAction;
use guard_command::local_supply_chain::{GuardConfig, VALID_RISK_ACTION_KEYS};
use guard_command::supply_chain_package_eval::{ConfigLoaderApi, EvalError, EvalResult};
use guard_secure_fs::read_stable;
use serde_json::{Map, Value};

use crate::guard_config_managed::{apply_managed_policy, ManagedInput};
use crate::managed_policy_floor::effective_managed_policy;
use crate::managed_policy_load::{load_managed_policy, ManagedPolicySource};

pub(crate) const HOME_CONFIG_FILENAME: &str = "config.toml";
pub(crate) const WORKSPACE_CONFIG_FILENAMES: [&str; 2] =
    [".ai-plugin-scanner-guard.toml", ".hol-guard.toml"];
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub(crate) const DEFAULT_SECURITY_LEVEL: &str = "balanced";
pub(crate) const VALID_SECURITY_LEVELS: [&str; 6] = [
    "relaxed", "gentle", "balanced", "strict", "paranoid", "custom",
];
/// `WORKSPACE_BLOCKED_POLICY_KEYS` (config.py): a workspace file can never set
/// these, so it cannot weaken the user's own policy.
const WORKSPACE_BLOCKED_POLICY_KEYS: [&str; 24] = [
    "blocked_request_mode",
    "mode",
    "presentation_mode",
    "presentation_mode_explicit",
    "presentation_schema_version",
    "presentation_revision",
    "presentation_density",
    "display_density",
    "density",
    "protection_posture",
    "watch_auto_revert_hours",
    "harness_postures",
    "harness_watch_entered_at",
    "default_action",
    "unknown_publisher_action",
    "changed_hash_action",
    "new_network_domain_action",
    "subprocess_action",
    "security_level",
    "risk_actions",
    "harness_risk_actions",
    "harnesses",
    "publishers",
    "artifacts",
];

/// Production config seam for the resident package evaluator.
pub(crate) struct ResidentConfigLoader;

impl ConfigLoaderApi for ResidentConfigLoader {
    fn load_guard_config(
        &self,
        guard_home: &Path,
        workspace: Option<&Path>,
        require_canonical_workspace: bool,
    ) -> EvalResult<GuardConfig> {
        load_effective_guard_config(
            guard_home,
            workspace,
            require_canonical_workspace,
            &ManagedPolicySource::native(),
        )
    }
}

pub(crate) fn config_error(reason: &str) -> EvalError {
    EvalError::Internal(format!("guard config unavailable: {reason}"))
}

/// Read one allowed config file. `Ok(None)` means the file does not exist,
/// which Python treats as an empty config.
pub(crate) fn read_config_table(
    directory: &Path,
    filename: &str,
) -> EvalResult<Option<Map<String, Value>>> {
    let path = directory.join(filename);
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(config_error("config_file_unavailable")),
    }
    let read = read_stable(&path, MAX_CONFIG_BYTES, false)
        .map_err(|_| config_error("config_file_unavailable_or_changed"))?;
    let text = std::str::from_utf8(&read.bytes).map_err(|_| config_error("config_not_utf8"))?;
    let table: toml::Table = text.parse().map_err(|_| config_error("config_malformed"))?;
    match serde_json::to_value(table).map_err(|_| config_error("config_malformed"))? {
        Value::Object(map) => Ok(Some(map)),
        _ => Err(config_error("config_malformed")),
    }
}

/// `_merge_config_payload` (config.py): nested objects merge key by key, and an
/// overriding `action`/`default_action` replaces both inherited keys.
pub(crate) fn merge_config_payload(
    base: &Map<String, Value>,
    over: &Map<String, Value>,
) -> Map<String, Value> {
    let mut merged = base.clone();
    for (key, value) in over {
        if let (Some(Value::Object(existing)), Value::Object(incoming)) = (merged.get(key), value) {
            let mut inherited = existing.clone();
            if incoming.contains_key("action") || incoming.contains_key("default_action") {
                inherited.remove("action");
                inherited.remove("default_action");
            }
            merged.insert(
                key.clone(),
                Value::Object(merge_config_payload(&inherited, incoming)),
            );
            continue;
        }
        merged.insert(key.clone(), value.clone());
    }
    merged
}

/// A workspace path that was authorized as canonical must keep that exact
/// path: no existing component, the workspace itself included, may be a
/// symlink. A missing component is an absent workspace, not an alias.
fn reject_symlinked_ancestors(workspace: &Path) -> EvalResult<()> {
    let mut walked = PathBuf::new();
    for component in workspace.components() {
        walked.push(component);
        // A bare Windows drive (`C:`, `\\?\C:`) names no directory entry: it is
        // the drive's current directory, or no path at all once verbatim.
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&walked) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(config_error("config_file_unavailable_or_changed"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(config_error("config_file_unavailable_or_changed")),
        }
    }
    Ok(())
}

pub(crate) fn load_workspace_config(
    workspace: Option<&Path>,
    require_canonical: bool,
) -> EvalResult<Map<String, Value>> {
    let Some(workspace) = workspace else {
        return Ok(Map::new());
    };
    if require_canonical
        && (!workspace.is_absolute() || workspace.components().any(|c| c == Component::ParentDir))
    {
        return Err(config_error("config_directory_not_canonical"));
    }
    if require_canonical {
        reject_symlinked_ancestors(workspace)?;
    }
    let mut merged = Map::new();
    for filename in WORKSPACE_CONFIG_FILENAMES {
        let Some(mut table) = read_config_table(workspace, filename)? else {
            continue;
        };
        table.retain(|key, _| !WORKSPACE_BLOCKED_POLICY_KEYS.contains(&key.as_str()));
        merged = merge_config_payload(&merged, &table);
    }
    Ok(merged)
}

pub(crate) fn coerce_security_level(value: Option<&Value>) -> String {
    match value.and_then(Value::as_str) {
        Some(level) if VALID_SECURITY_LEVELS.contains(&level) => level.to_owned(),
        _ => DEFAULT_SECURITY_LEVEL.to_owned(),
    }
}

/// `normalize_protection_posture` (protection_posture.py).
pub(crate) fn explicit_posture(value: Option<&Value>) -> Option<String> {
    let normalized = value?.as_str()?.trim().replace('-', "_").to_lowercase();
    matches!(normalized.as_str(), "protected" | "extra_careful" | "watch").then_some(normalized)
}

/// `derive_protection_posture` (protection_posture.py).
pub(crate) fn derive_posture(mode: Option<&Value>, security_level: &str) -> &'static str {
    if mode.and_then(Value::as_str) == Some("observe") {
        "watch"
    } else if matches!(security_level, "strict" | "paranoid") {
        "extra_careful"
    } else {
        "protected"
    }
}

fn action_map_value(value: &Value) -> &Value {
    match value {
        Value::Object(map) => map
            .get("action")
            .or_else(|| map.get("default_action"))
            .unwrap_or(value),
        _ => value,
    }
}

pub(crate) fn coerce_risk_action_map(
    payload: Option<&Value>,
) -> std::collections::BTreeMap<String, String> {
    let mut actions = std::collections::BTreeMap::new();
    let Some(Value::Object(map)) = payload else {
        return actions;
    };
    for (key, value) in map {
        if VALID_RISK_ACTION_KEYS.contains(&key.as_str()) {
            let action =
                normalize_guard_action(action_map_value(value), GuardAction::RequireReapproval);
            actions.insert(key.clone(), action.as_str().to_owned());
        }
    }
    actions
}

pub(crate) fn coerce_harness_risk_actions(
    payload: Option<&Value>,
) -> std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>> {
    let mut actions = std::collections::BTreeMap::new();
    let Some(Value::Object(map)) = payload else {
        return actions;
    };
    for (harness, value) in map {
        if harness.trim().is_empty() {
            continue;
        }
        let harness_actions = coerce_risk_action_map(Some(value));
        if !harness_actions.is_empty() {
            actions.insert(harness.clone(), harness_actions);
        }
    }
    actions
}

/// Load the effective config. `managed` names the machine policy source whose
/// document is composed into the local configuration.
pub(crate) fn load_effective_guard_config(
    guard_home: &Path,
    workspace: Option<&Path>,
    require_canonical_workspace: bool,
    managed: &ManagedPolicySource,
) -> EvalResult<GuardConfig> {
    let managed_state = load_managed_policy(managed);
    let managed_policy = effective_managed_policy(&managed_state);
    let home = read_config_table(guard_home, HOME_CONFIG_FILENAME)?.unwrap_or_default();
    let workspace_config = load_workspace_config(workspace, require_canonical_workspace)?;
    let local = merge_config_payload(&home, &workspace_config);
    let merged = match &managed_policy {
        Some(policy) => apply_managed_policy(
            &local,
            &ManagedInput {
                settings: policy.settings.clone(),
                locked_settings: policy.locked_settings.iter().cloned().collect(),
            },
        ),
        None => local,
    };

    let security_level = coerce_security_level(merged.get("security_level"));
    let posture_override = explicit_posture(merged.get("protection_posture"));
    let protection_posture_explicit = posture_override.is_some();
    let protection_posture = posture_override
        .unwrap_or_else(|| derive_posture(merged.get("mode"), &security_level).to_owned());
    Ok(GuardConfig {
        security_level,
        protection_posture,
        protection_posture_explicit,
        managed_locked_settings: managed_policy
            .as_ref()
            .map(|policy| policy.locked_settings.iter().cloned().collect())
            .unwrap_or_default(),
        risk_actions: Some(coerce_risk_action_map(merged.get("risk_actions"))),
        harness_risk_actions: Some(coerce_harness_risk_actions(
            merged.get("harness_risk_actions"),
        )),
        managed_policy_status: managed_state.status.as_str().to_owned(),
        managed_policy_hash: managed_policy
            .as_ref()
            .map(|policy| policy.content_hash.clone()),
        guard_home: Some(guard_home.to_path_buf()),
        extra: Map::new(),
    })
}

#[cfg(test)]
#[path = "package_authority_config_tests.rs"]
mod tests;
