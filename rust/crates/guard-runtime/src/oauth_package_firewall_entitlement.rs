//! `oauth_package_firewall_entitlement`: the package-firewall entitlement an
//! OAuth token response carries (`build_oauth_package_firewall_entitlement`
//! and `parse_guard_cloud_entitlements`, before they moved here).
//!
//! The response's `guard_local_entitlement` record names a plan in
//! `plan_id`, or else `tier`; a record without one grants nothing. The plan
//! unlocks the firewall when the record's `supply_chain_firewall` says so,
//! otherwise when it is a paid tier, and the grant lasts until the record's
//! `expires_at` or the caller's fallback. When the record also names a
//! canonical Guard Cloud plan, that plan replaces the legacy one, and a
//! boolean `guard.cloud.supply_chain_firewall` feature, or the record's
//! `supplyChainFirewall` flag when no feature names it, decides the firewall.
//!
//! Feature names are read with their surrounding whitespace stripped. Two
//! names that differ only in that whitespace are read in key order, where the
//! Python parser kept the one the server sent last.
//!
//! `{"record": object, "fallback_expires_at": str}` answers
//! `{"entitlement": object|null}`.

use guard_command::local_supply_chain::PACKAGE_FIREWALL_PAID_TIERS;
use guard_contracts::python_strip;
use serde_json::{json, Map, Value};

use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

/// `_GUARD_PLAN_IDS`: the plans Guard Cloud names today.
const GUARD_PLAN_IDS: [&str; 5] = ["free", "solo", "pro", "team", "enterprise"];
const FIREWALL_FEATURE: &str = "guard.cloud.supply_chain_firewall";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    if args.len() != 2 {
        return Err(ERR_INVALID);
    }
    let record = args
        .get("record")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let fallback_expires_at = args
        .get("fallback_expires_at")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(ERR_INVALID)?;
    Ok(json!({ "entitlement": entitlement(record, fallback_expires_at) }))
}

fn entitlement(record: &Map<String, Value>, fallback_expires_at: &str) -> Value {
    // `build_guard_local_entitlement_defaults`.
    let Some(legacy_plan) =
        optional_string(record.get("plan_id")).or_else(|| optional_string(record.get("tier")))
    else {
        return Value::Null;
    };
    let mut plan_id = legacy_plan.to_lowercase();
    let mut firewall = match record.get("supply_chain_firewall") {
        Some(Value::Bool(allowed)) => *allowed,
        _ => PACKAGE_FIREWALL_PAID_TIERS.contains(&plan_id.as_str()),
    };
    let expires_at = optional_string(record.get("expires_at")).unwrap_or(fallback_expires_at);
    if let Some(canonical) = canonical_plan(record) {
        plan_id = canonical;
        if let Some(allowed) = firewall_feature(record) {
            firewall = allowed;
        }
    }
    json!({
        "plan_id": plan_id,
        "supply_chain_entitlement_expires_at": expires_at,
        "supply_chain_firewall": firewall,
        "supply_chain_plan_id": plan_id,
    })
}

/// `_optional_string`: a string with its surrounding whitespace stripped, when
/// anything is left.
fn optional_string(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(python_strip)
        .filter(|value| !value.is_empty())
}

/// `_first_value`: the first of `keys` whose value is present and not null,
/// whatever its type.
fn first_value<'a>(record: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter()
        .find_map(|key| record.get(*key).filter(|value| !value.is_null()))
}

/// `_plan_id`: the canonical plan the record names first, lowercased.
fn canonical_plan(record: &Map<String, Value>) -> Option<String> {
    let plan = optional_string(first_value(record, &["planId", "plan_id", "tier"]))?.to_lowercase();
    GUARD_PLAN_IDS.contains(&plan.as_str()).then_some(plan)
}

/// The `guard.cloud.supply_chain_firewall` value of the parsed features, when
/// it is a boolean.
fn firewall_feature(record: &Map<String, Value>) -> Option<bool> {
    let mut features = feature_values(first_value(record, &["features"]));
    if features.is_empty() {
        features = feature_values(first_value(
            record,
            &["cloudValueGates", "cloud_value_gates"],
        ));
    }
    if !features.contains_key(FIREWALL_FEATURE) {
        if let Some(Value::Bool(allowed)) =
            first_value(record, &["supplyChainFirewall", "supply_chain_firewall"])
        {
            return Some(*allowed);
        }
    }
    features.get(FIREWALL_FEATURE).and_then(Value::as_bool)
}

/// `_feature_values`: the scalar entries of an object, keyed by their
/// stripped, non-blank names.
fn feature_values(value: Option<&Value>) -> Map<String, Value> {
    let mut features = Map::new();
    let Some(source) = value.and_then(Value::as_object) else {
        return features;
    };
    for (name, value) in source {
        let name = python_strip(name);
        if name.is_empty() || value.is_array() || value.is_object() {
            continue;
        }
        features.insert(name.to_owned(), value.clone());
    }
    features
}

#[cfg(test)]
#[path = "oauth_package_firewall_entitlement_tests.rs"]
mod tests;
