//! One-shot native composition of the effective policy a publisher snapshots.
//!
//! The publisher hands over the loaded Guard configuration fields (home and
//! each observed workspace). This module derives each effective policy, folds
//! per-harness posture floors into it, and composes several by the lattice
//! maximum. The caller never recalculates a value: every input and every
//! composed result passes the same validation the snapshot builder applies.

use std::collections::BTreeMap;
use std::io::Read;

use guard_command::local_supply_chain::{posture_risk_actions, security_level_risk_actions};
use guard_policy_snapshot::{
    normalized_harness_selector, validate_effective_policy, EffectiveNativePolicyV3,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};

const SCHEMA: &str = "guard-effective-policy.v1";
const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
const POLICY_INVALID: &str = "native_policy_snapshot_policy_invalid";
const CATALOG_INVALID: &str = "native_provider_catalog_hash_invalid";
const POSTURES: [&str; 3] = ["watch", "protected", "extra_careful"];
const SECURITY_LEVELS: [&str; 6] = [
    "relaxed", "gentle", "balanced", "strict", "paranoid", "custom",
];
const SANDBOX: [&str; 3] = ["off", "suspicious", "strict"];
const REDACTION: [&str; 3] = ["none", "partial", "full"];
const ACTIONS: [&str; 6] = [
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
];

type Fail = &'static str;
type StringMap = BTreeMap<String, String>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    /// Fields come from a loaded `GuardConfig` (posture defaults and harness
    /// overlays apply) rather than a bare mapping.
    #[serde(default)]
    guard_config: bool,
    #[serde(default)]
    configs: Vec<Map<String, Value>>,
}

/// An effective policy plus the two side channels the publisher carries.
struct Policy {
    effective: EffectiveNativePolicyV3,
    postures: StringMap,
}

fn rank(table: &[&str], value: &str) -> usize {
    table.iter().position(|item| *item == value).unwrap_or(0)
}

fn action_rank(value: &str) -> usize {
    rank(&ACTIONS, value)
}

fn stricter(left: &str, right: &str) -> String {
    if action_rank(left) >= action_rank(right) {
        left
    } else {
        right
    }
    .to_owned()
}

fn text(config: &Map<String, Value>, name: &str, default: &str) -> Result<String, Fail> {
    match config.get(name) {
        None => Ok(default.to_owned()),
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(POLICY_INVALID),
    }
}

fn map_value(config: &Map<String, Value>, name: &str) -> Value {
    match config.get(name) {
        None | Some(Value::Null) => json!({}),
        Some(value) => value.clone(),
    }
}

fn string_map(value: &Value) -> Result<StringMap, Fail> {
    serde_json::from_value(value.clone()).map_err(|_| POLICY_INVALID)
}

fn defaults(config: &Map<String, Value>, posture: &str, level: &str) -> StringMap {
    let explicit = config
        .get("protection_posture_explicit")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let locked = config
        .get("managed_locked_settings")
        .and_then(Value::as_array)
        .is_some_and(|keys| {
            keys.iter()
                .any(|key| key.as_str() == Some("security_level"))
        });
    if explicit && !locked {
        if let Some(table) = posture_risk_actions(posture) {
            return table;
        }
    }
    security_level_risk_actions(level)
}

/// Per-harness floors for overrides stricter than the global baseline. Watch
/// overrides add nothing: the caller applies those after native evaluation.
fn posture_overlay(
    base: &mut BTreeMap<String, StringMap>,
    overrides: &Map<String, Value>,
    baseline: &str,
) {
    let mut sorted: Vec<(&String, &Value)> = overrides.iter().collect();
    sorted.sort_by(|left, right| left.0.cmp(right.0));
    for (harness, posture) in sorted {
        let Some(posture) = posture.as_str() else {
            continue;
        };
        let Some(floors) = posture_risk_actions(posture) else {
            continue;
        };
        if rank(&POSTURES, posture) <= rank(&POSTURES, baseline) {
            continue;
        }
        let selector = normalized_harness_selector(harness);
        let key = base
            .keys()
            .find(|name| normalized_harness_selector(name) == selector)
            .cloned()
            .unwrap_or_else(|| harness.clone());
        let target = base.entry(key).or_default();
        for (risk, action) in floors {
            let merged = target
                .get(&risk)
                .map_or(action.clone(), |current| stricter(current, &action));
            target.insert(risk, merged);
        }
    }
}

fn catalog_hash(config: &Map<String, Value>) -> Result<Value, Fail> {
    match config.get("mcp_provider_catalog_hash") {
        None | Some(Value::Null) => Ok(Value::Null),
        Some(Value::String(digest))
            if digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
        {
            Ok(Value::String(digest.clone()))
        }
        Some(_) => Err(CATALOG_INVALID),
    }
}

fn typed(mut object: Map<String, Value>) -> Result<EffectiveNativePolicyV3, Fail> {
    object.retain(|_, value| !value.is_null());
    let policy: EffectiveNativePolicyV3 =
        serde_json::from_value(Value::Object(object)).map_err(|_| POLICY_INVALID)?;
    validate_effective_policy(&policy).map_err(|_| POLICY_INVALID)?;
    Ok(policy)
}

fn effective(config: &Map<String, Value>, guard_config: bool) -> Result<Policy, Fail> {
    let posture = text(config, "protection_posture", "protected")?;
    let level = text(config, "security_level", "balanced")?;
    let mut risk = if guard_config {
        defaults(config, &posture, &level)
    } else {
        StringMap::new()
    };
    risk.extend(string_map(&map_value(config, "risk_actions"))?);
    let mut harness_risk: BTreeMap<String, StringMap> =
        serde_json::from_value(map_value(config, "harness_risk_actions"))
            .map_err(|_| POLICY_INVALID)?;
    let overrides = match config.get("harness_postures") {
        Some(Value::Object(map)) => map.clone(),
        _ => Map::new(),
    };
    if guard_config && !overrides.is_empty() {
        let mode = text(config, "mode", "prompt")?;
        let baseline = if posture == "watch" || mode == "observe" {
            "watch"
        } else {
            posture.as_str()
        };
        posture_overlay(&mut harness_risk, &overrides, baseline);
    }
    let mut object = Map::new();
    object.insert("protection_posture".into(), posture.into());
    object.insert("security_level".into(), level.into());
    for (name, default) in [
        ("default_action", "warn"),
        ("unknown_publisher_action", "review"),
        ("changed_hash_action", "require-reapproval"),
        ("new_network_domain_action", "warn"),
        ("subprocess_action", "warn"),
        ("sandbox_analysis", "off"),
    ] {
        object.insert(name.into(), text(config, name, default)?.into());
    }
    object.insert(
        "receipt_redaction_level".into(),
        text(config, "receipt_redaction_level", "full")?.into(),
    );
    object.insert("risk_actions".into(), json!(risk));
    object.insert("harness_risk_actions".into(), json!(harness_risk));
    for name in [
        "harness_actions",
        "publisher_actions",
        "artifact_actions",
        "mcp_tool_actions",
        "mcp_provider_actions",
    ] {
        object.insert(name.into(), map_value(config, name));
    }
    object.insert("mcp_provider_catalog_hash".into(), catalog_hash(config)?);
    Ok(Policy {
        effective: typed(object)?,
        postures: valid_postures(overrides.iter().map(|(k, v)| (k.as_str(), v))),
    })
}

fn valid_postures<'a>(pairs: impl Iterator<Item = (&'a str, &'a Value)>) -> StringMap {
    pairs
        .filter_map(|(harness, posture)| {
            let posture = posture.as_str()?;
            (!harness.is_empty() && POSTURES.contains(&posture))
                .then(|| (harness.to_owned(), posture.to_owned()))
        })
        .collect()
}

fn union_maps(maps: impl Iterator<Item = StringMap>, default: &str) -> StringMap {
    let mut merged = StringMap::new();
    for map in maps {
        for (key, action) in map {
            let current = merged.get(&key).map_or(default, String::as_str);
            let next = stricter(current, &action);
            merged.insert(key, next);
        }
    }
    merged
}

/// Fold aliases of one selector to its strongest value, keeping every alias.
fn by_selector<V: Clone>(
    maps: impl Iterator<Item = BTreeMap<String, V>>,
    combine: impl Fn(Option<&V>, &V) -> V,
) -> Result<BTreeMap<String, V>, Fail> {
    let mut strongest: BTreeMap<String, V> = BTreeMap::new();
    let mut aliases: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for map in maps {
        for (harness, value) in map {
            let selector = normalized_harness_selector(&harness).ok_or(POLICY_INVALID)?;
            let next = combine(strongest.get(&selector), &value);
            strongest.insert(selector.clone(), next);
            let names = aliases.entry(selector).or_default();
            if !names.contains(&harness) {
                names.push(harness);
            }
        }
    }
    Ok(aliases
        .into_iter()
        .flat_map(|(selector, names)| {
            let value = strongest[&selector].clone();
            names.into_iter().map(move |name| (name, value.clone()))
        })
        .collect())
}

fn floor(
    policies: &[Policy],
    table: &[&str],
    pick: fn(&EffectiveNativePolicyV3) -> &String,
) -> String {
    policies
        .iter()
        .map(|policy| pick(&policy.effective))
        .max_by_key(|value| rank(table, value))
        .cloned()
        .unwrap_or_default()
}

fn merge(policies: &[Policy]) -> Result<(EffectiveNativePolicyV3, StringMap), Fail> {
    let first = policies.first().ok_or(POLICY_INVALID)?;
    let mut merged = first.effective.clone();
    let scalar = |pick: fn(&EffectiveNativePolicyV3) -> &String| {
        policies
            .iter()
            .map(|policy| pick(&policy.effective).clone())
            .reduce(|left, right| stricter(&left, &right))
            .unwrap_or_default()
    };
    merged.default_action = scalar(|p| &p.default_action);
    merged.unknown_publisher_action = scalar(|p| &p.unknown_publisher_action);
    merged.changed_hash_action = scalar(|p| &p.changed_hash_action);
    merged.new_network_domain_action = scalar(|p| &p.new_network_domain_action);
    merged.subprocess_action = scalar(|p| &p.subprocess_action);
    merged.risk_actions = union_maps(
        policies.iter().map(|p| p.effective.risk_actions.clone()),
        "allow",
    );
    merged.publisher_actions = union_maps(
        policies
            .iter()
            .map(|p| p.effective.publisher_actions.clone()),
        "allow",
    );
    merged.artifact_actions = union_maps(
        policies
            .iter()
            .map(|p| p.effective.artifact_actions.clone()),
        "allow",
    );
    merged.mcp_tool_actions = union_maps(
        policies
            .iter()
            .map(|p| p.effective.mcp_tool_actions.clone()),
        "allow",
    );
    merged.mcp_provider_actions = union_maps(
        policies
            .iter()
            .map(|p| p.effective.mcp_provider_actions.clone()),
        "allow",
    );
    merged.harness_actions = by_selector(
        policies.iter().map(|p| p.effective.harness_actions.clone()),
        |current, next| current.map_or(next.clone(), |held| stricter(held, next)),
    )?;
    merged.harness_risk_actions = by_selector(
        policies
            .iter()
            .map(|p| p.effective.harness_risk_actions.clone()),
        |current, next| {
            let mut target = current.cloned().unwrap_or_default();
            for (risk, action) in next {
                let value = target
                    .get(risk)
                    .map_or(action.clone(), |held| stricter(held, action));
                target.insert(risk.clone(), value);
            }
            target
        },
    )?;
    merged.protection_posture = floor(policies, &POSTURES, |p| &p.protection_posture);
    merged.security_level = floor(policies, &SECURITY_LEVELS, |p| &p.security_level);
    merged.sandbox_analysis = floor(policies, &SANDBOX, |p| &p.sandbox_analysis);
    merged.receipt_redaction_level = floor(policies, &REDACTION, |p| &p.receipt_redaction_level);
    validate_effective_policy(&merged).map_err(|_| POLICY_INVALID)?;
    let mut postures = StringMap::new();
    for policy in policies {
        for (harness, posture) in &policy.postures {
            let stronger = postures
                .get(harness)
                .is_none_or(|held| rank(&POSTURES, posture) > rank(&POSTURES, held));
            if stronger {
                postures.insert(harness.clone(), posture.clone());
            }
        }
    }
    Ok((merged, postures))
}

fn render(policy: &EffectiveNativePolicyV3, postures: Option<&StringMap>) -> Result<Value, Fail> {
    let mut value = serde_json::to_value(policy).map_err(|_| POLICY_INVALID)?;
    if let (Some(postures), Some(object)) = (postures, value.as_object_mut()) {
        let observe = policy.protection_posture == "watch";
        object.insert(
            "mode".into(),
            if observe { "observe" } else { "enforce" }.into(),
        );
        if !postures.is_empty() {
            object.insert("harness_postures".into(), json!(postures));
        }
    }
    Ok(value)
}

fn run(request: Request) -> Result<Value, Fail> {
    if request.schema != SCHEMA {
        return Err(POLICY_INVALID);
    }
    match request.op.as_str() {
        "effective" => {
            let [config] = request.configs.as_slice() else {
                return Err(POLICY_INVALID);
            };
            render(&effective(config, request.guard_config)?.effective, None)
        }
        "compose" => {
            let policies = request
                .configs
                .iter()
                .map(|config| effective(config, request.guard_config))
                .collect::<Result<Vec<_>, _>>()?;
            let (merged, postures) = merge(&policies)?;
            render(&merged, Some(&postures))
        }
        _ => Err(POLICY_INVALID),
    }
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "policy-effective"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "policy_effective_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("policy_effective_request_too_large".to_owned());
    }
    evaluate(&bytes)
}

fn evaluate(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let request: Request =
        serde_json::from_slice(bytes).map_err(|_| "policy_effective_request_invalid".to_owned())?;
    // A rejected policy is data, not a crash: the caller maps the reason.
    let response = match run(request) {
        Ok(policy) => json!({"ok": true, "policy": policy}),
        Err(reason) => json!({"ok": false, "error": reason}),
    };
    serde_json::to_vec(&response).map_err(|_| "policy_effective_response_encode_failed".to_owned())
}

#[cfg(test)]
#[path = "policy_effective_tests.rs"]
mod tests;
