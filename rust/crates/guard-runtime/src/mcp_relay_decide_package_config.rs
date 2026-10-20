//! The Guard configuration a relayed package call is evaluated under.
//!
//! Port of `package_config_policy_context`'s input
//! (`native_package_approval_hash.py:46`). The Python proxy hydrates that
//! context from the `GuardConfig` it loaded and sends it with every package
//! authority request. A relay has no loaded config: it has the harness view
//! the publisher bound, which is `_tool_call_configuration` of
//! `config_for_harness` plus the managed-policy and sandbox fields the
//! approval hash binds. Those are the fields the context reads, so the view is
//! rebuilt into the config mirror here and the context hydrated from it,
//! rather than asked of the proxy.
//!
//! A view field that is absent or of another type is not the view this was
//! written against, and the call defers. Reading a default in its place would
//! answer with the permissive side of every one of them — an absent override
//! map is "no override", an absent `managed_locked_settings` is an unlocked
//! setting — so a view this cannot read is not a config to decide under.

use super::view::HarnessView;
use guard_command::local_supply_chain::{package_config_policy_context, GuardConfig};
use guard_command::package_intent_common::GuardArtifact;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// A bound view whose configuration fields this cannot read.
const CONFIG_INVALID: &str = "mcp_relay_package_config_invalid";

/// `GuardConfig.risk_actions`: an action per risk class.
type RiskActions = BTreeMap<String, String>;

/// `GuardConfig.harness_risk_actions`: the same, per harness.
type HarnessRiskActions = BTreeMap<String, RiskActions>;

/// The hydrated policy view a package request's approval hash is bound to.
pub(super) fn config_policy(
    view: &HarnessView,
    artifact: &GuardArtifact,
) -> Result<Value, &'static str> {
    let config = guard_config(view, artifact)?;
    Ok(Value::Object(package_config_policy_context(
        artifact,
        Some(&config),
    )))
}

/// `GuardConfig.sandbox_analysis`, which the approval hash binds beside the
/// policy view.
pub(super) fn sandbox_analysis(view: &HarnessView) -> Result<String, &'static str> {
    text(&view.hash_config, "sandbox_analysis")
}

/// The config mirror the bound view describes.
///
/// `guard_home` is left unset: it is where a config was read from, not a
/// policy field, and the policy view never reads it.
fn guard_config(view: &HarnessView, artifact: &GuardArtifact) -> Result<GuardConfig, &'static str> {
    let config = &view.config;
    let hash_config = &view.hash_config;
    // An override map this cannot read is not a view without an override: the
    // policy context reports no artifact, publisher, or harness override, so a
    // bound `block` would be dropped from the composed action rather than
    // deferring the call. `mode` reads the same way, through `extra`.
    text(config, "mode")?;
    for key in ["artifact_actions", "publisher_actions", "harness_actions"] {
        actions(config, key)?;
    }
    let mut extra = config.clone();
    extra.insert(
        "resolved_override".to_owned(),
        resolved_override(config, artifact),
    );
    Ok(GuardConfig {
        security_level: text(config, "security_level")?,
        protection_posture: text(config, "protection_posture")?,
        protection_posture_explicit: flag(config, "protection_posture_explicit")?,
        managed_locked_settings: strings(config, "managed_locked_settings")?,
        risk_actions: actions(config, "risk_actions")?,
        harness_risk_actions: harness_risk_actions(config, "harness_risk_actions")?,
        managed_policy_status: text(hash_config, "managed_policy_status")?,
        managed_policy_hash: optional_text(hash_config, "managed_policy_hash")?,
        guard_home: None,
        extra,
    })
}

/// `GuardConfig.resolve_action_override` (config.py:302): the narrowest
/// override naming this artifact, else its publisher, else its harness.
///
/// The value is passed on as it was bound rather than read as an action here.
/// It is folded into the composed action with `most_restrictive`, which
/// answers `block` for anything it cannot read, so a malformed override is
/// restrictive where discarding it would not be.
fn resolved_override(config: &Map<String, Value>, artifact: &GuardArtifact) -> Value {
    let override_for = |key: &str, item: &str| {
        config
            .get(key)
            .and_then(Value::as_object)
            .and_then(|map| map.get(item))
            .cloned()
    };
    override_for("artifact_actions", &artifact.artifact_id)
        .or_else(|| {
            artifact
                .publisher
                .as_deref()
                .and_then(|publisher| override_for("publisher_actions", publisher))
        })
        .or_else(|| override_for("harness_actions", &artifact.harness))
        .unwrap_or(Value::Null)
}

fn text(map: &Map<String, Value>, key: &str) -> Result<String, &'static str> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(CONFIG_INVALID)
}

fn optional_text(map: &Map<String, Value>, key: &str) -> Result<Option<String>, &'static str> {
    match map.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        _ => Err(CONFIG_INVALID),
    }
}

fn flag(map: &Map<String, Value>, key: &str) -> Result<bool, &'static str> {
    map.get(key).and_then(Value::as_bool).ok_or(CONFIG_INVALID)
}

fn strings(map: &Map<String, Value>, key: &str) -> Result<Vec<String>, &'static str> {
    let items = map
        .get(key)
        .and_then(Value::as_array)
        .ok_or(CONFIG_INVALID)?;
    items
        .iter()
        .map(|item| item.as_str().map(str::to_owned).ok_or(CONFIG_INVALID))
        .collect()
}

/// `risk_actions`: an action per risk class, or none bound at all.
fn actions(map: &Map<String, Value>, key: &str) -> Result<Option<RiskActions>, &'static str> {
    match map.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::Object(entries)) => Ok(Some(action_map(entries)?)),
        _ => Err(CONFIG_INVALID),
    }
}

/// `harness_risk_actions`: the same, per harness.
fn harness_risk_actions(
    map: &Map<String, Value>,
    key: &str,
) -> Result<Option<HarnessRiskActions>, &'static str> {
    match map.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::Object(entries)) => entries
            .iter()
            .map(|(harness, actions)| {
                let actions = actions.as_object().ok_or(CONFIG_INVALID)?;
                Ok((harness.clone(), action_map(actions)?))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map(Some),
        _ => Err(CONFIG_INVALID),
    }
}

fn action_map(entries: &Map<String, Value>) -> Result<RiskActions, &'static str> {
    entries
        .iter()
        .map(|(class, action)| {
            let action = action.as_str().ok_or(CONFIG_INVALID)?;
            Ok((class.clone(), action.to_owned()))
        })
        .collect()
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_config_tests.rs"]
mod tests;
