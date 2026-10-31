//! The Guard configuration a package authority request is evaluated under.
//!
//! The policy view an approval hash binds (`package_config_policy_context`)
//! resolves `package_script` for the harness and globally, reads the override
//! maps and reports the managed-policy state. Whoever holds the configuration
//! used to resolve those actions and send the finished view; the resident owns
//! every verdict, so it is sent the fields instead and hydrates the view here.
//!
//! A field that is absent or of another type is not the configuration this was
//! written against, and the caller defers. Reading a default in its place would
//! answer with the permissive side of every one of them — an absent override
//! map is "no override", an absent `managed_locked_settings` is an unlocked
//! setting — so a configuration this cannot read is not one to decide under.

use guard_command::local_supply_chain::{package_config_policy_context_for, GuardConfig};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// `GuardConfig.risk_actions`: an action per risk class.
type RiskActions = BTreeMap<String, String>;

/// `GuardConfig.harness_risk_actions`: the same, per harness.
type HarnessRiskActions = BTreeMap<String, RiskActions>;

/// The artifact fields the policy view reads.
pub(crate) struct ArtifactIdentity<'a> {
    pub(crate) artifact_id: &'a str,
    pub(crate) publisher: Option<&'a str>,
    pub(crate) harness: &'a str,
}

/// The hydrated policy view a package request's approval hash is bound to.
///
/// `config` carries the configuration fields; `hash_config` the managed-policy
/// pair the approval hash binds beside them. A caller holding one map passes it
/// as both.
pub(crate) fn config_policy(
    config: &Map<String, Value>,
    hash_config: &Map<String, Value>,
    artifact: &ArtifactIdentity<'_>,
) -> Option<Value> {
    let mirror = guard_config(config, hash_config, artifact)?;
    Some(Value::Object(package_config_policy_context_for(
        artifact.artifact_id,
        artifact.publisher,
        artifact.harness,
        Some(&mirror),
    )))
}

/// The config mirror the sent fields describe.
///
/// `guard_home` is left unset: it is where a config was read from, not a
/// policy field, and the policy view never reads it.
fn guard_config(
    config: &Map<String, Value>,
    hash_config: &Map<String, Value>,
    artifact: &ArtifactIdentity<'_>,
) -> Option<GuardConfig> {
    // An override map this cannot read is not a configuration without an
    // override: the policy view would report no artifact, publisher, or harness
    // override, so a bound `block` would be dropped from the composed action
    // rather than the call deferring. `mode` reads the same way, through
    // `extra`.
    text(config, "mode")?;
    for key in ["artifact_actions", "publisher_actions", "harness_actions"] {
        actions(config, key)?;
    }
    let mut extra = config.clone();
    extra.insert(
        "resolved_override".to_owned(),
        resolved_override(config, artifact),
    );
    Some(GuardConfig {
        security_level: text(config, "security_level")?,
        protection_posture: text(config, "protection_posture")?,
        protection_posture_explicit: flag(config, "protection_posture_explicit")?,
        managed_locked_settings: strings(config, "managed_locked_settings")?,
        risk_actions: actions(config, "risk_actions")?,
        harness_risk_actions: harness_risk_actions(config, "harness_risk_actions")?,
        // The per-harness posture map, which the risk-action resolver reads
        // for the Extra careful floor. A harness posture override folded into
        // `protection_posture` covers the posture defaults but not an explicit
        // risk action weaker than the floor, so the map is bound too.
        harness_postures: actions(config, "harness_postures")?,
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
/// It is folded into the composed action with `most_restrictive`, which answers
/// `block` for anything it cannot read, so a malformed override is restrictive
/// where discarding it would not be.
fn resolved_override(config: &Map<String, Value>, artifact: &ArtifactIdentity<'_>) -> Value {
    let override_for = |key: &str, item: &str| {
        config
            .get(key)
            .and_then(Value::as_object)
            .and_then(|map| map.get(item))
            .cloned()
    };
    override_for("artifact_actions", artifact.artifact_id)
        .or_else(|| {
            artifact
                .publisher
                .and_then(|publisher| override_for("publisher_actions", publisher))
        })
        .or_else(|| override_for("harness_actions", artifact.harness))
        .unwrap_or(Value::Null)
}

fn text(map: &Map<String, Value>, key: &str) -> Option<String> {
    map.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn optional_text(map: &Map<String, Value>, key: &str) -> Option<Option<String>> {
    match map.get(key) {
        Some(Value::Null) => Some(None),
        Some(Value::String(value)) => Some(Some(value.clone())),
        _ => None,
    }
}

fn flag(map: &Map<String, Value>, key: &str) -> Option<bool> {
    map.get(key).and_then(Value::as_bool)
}

fn strings(map: &Map<String, Value>, key: &str) -> Option<Vec<String>> {
    map.get(key)
        .and_then(Value::as_array)?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect()
}

/// `risk_actions`: an action per risk class, or none bound at all.
fn actions(map: &Map<String, Value>, key: &str) -> Option<Option<RiskActions>> {
    match map.get(key) {
        Some(Value::Null) => Some(None),
        Some(Value::Object(entries)) => action_map(entries).map(Some),
        _ => None,
    }
}

/// `harness_risk_actions`: the same, per harness.
fn harness_risk_actions(map: &Map<String, Value>, key: &str) -> Option<Option<HarnessRiskActions>> {
    match map.get(key) {
        Some(Value::Null) => Some(None),
        Some(Value::Object(entries)) => entries
            .iter()
            .map(|(harness, actions)| Some((harness.clone(), action_map(actions.as_object()?)?)))
            .collect::<Option<BTreeMap<_, _>>>()
            .map(Some),
        _ => None,
    }
}

fn action_map(entries: &Map<String, Value>) -> Option<RiskActions> {
    entries
        .iter()
        .map(|(class, action)| Some((class.clone(), action.as_str()?.to_owned())))
        .collect()
}

#[cfg(test)]
#[path = "package_config_mirror_tests.rs"]
mod tests;
