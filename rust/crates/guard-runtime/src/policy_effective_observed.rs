//! The operator's exact MCP choices, laid over a composed policy.
//!
//! The publisher reads the observed tool choices, the provider choices and the
//! provider catalog hash from the store and hands them over unchanged. A
//! configured restriction stays a floor: a choice can only tighten it, and an
//! exact allow never opens a hole in a configured namespace block.

use std::collections::BTreeSet;

use guard_policy_snapshot::{
    validate_effective_policy, validate_mcp_provider_actions, EffectiveNativePolicyV3,
    POLICY_SNAPSHOT_MAX_MCP_TOOL_ACTIONS,
};
use serde::Deserialize;

use super::{stricter, Fail, StringMap, ACTIONS, POLICY_INVALID};

const CAPACITY_EXCEEDED: &str = "native_mcp_permission_capacity_exceeded";
const PROVIDER_INVALID: &str = "native_policy_snapshot_provider_actions_invalid";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Observed {
    #[serde(default)]
    mcp_tool_actions: StringMap,
    #[serde(default)]
    mcp_provider_actions: StringMap,
    #[serde(default)]
    mcp_provider_catalog_hash: Option<String>,
}

fn restrictive(action: &str) -> bool {
    matches!(action, "block" | "review")
}

/// Keep every restriction; refuse capacity that would discard one. Allows
/// beyond the bound are dropped in a fixed order, so the result never
/// depends on the order the choices were read in.
fn bound(actions: StringMap, required: &BTreeSet<String>) -> Result<StringMap, Fail> {
    let restrictions = actions
        .values()
        .filter(|action| restrictive(action))
        .count();
    if restrictions > POLICY_SNAPSHOT_MAX_MCP_TOOL_ACTIONS {
        return Err(CAPACITY_EXCEEDED);
    }
    let mut ordered: Vec<(String, String)> = actions.into_iter().collect();
    ordered.sort_by(|(left, left_action), (right, right_action)| {
        let rank = |key: &String, action: &str| {
            (
                !restrictive(action),
                !required.contains(key),
                !key.ends_with('*'),
            )
        };
        rank(left, left_action.as_str())
            .cmp(&rank(right, right_action.as_str()))
            .then_with(|| left.cmp(right))
    });
    ordered.truncate(POLICY_SNAPSHOT_MAX_MCP_TOOL_ACTIONS);
    Ok(ordered.into_iter().collect())
}

fn tool_actions(policy: &mut EffectiveNativePolicyV3, observed: StringMap) -> Result<(), Fail> {
    if observed
        .values()
        .any(|action| !ACTIONS.contains(&action.as_str()))
    {
        return Err(POLICY_INVALID);
    }
    // The bound runs over the operator's choices before they meet the
    // configured map, so their own restrictions alone can exhaust it.
    let observed = bound(observed, &BTreeSet::new())?;
    let required: BTreeSet<String> = policy
        .mcp_tool_actions
        .iter()
        .filter(|(_, action)| *action == "block")
        .map(|(key, _)| key.clone())
        .collect();
    let namespaces: Vec<&str> = required
        .iter()
        .filter_map(|key| key.strip_suffix('*'))
        .collect();
    let mut merged = policy.mcp_tool_actions.clone();
    for (key, action) in observed {
        // An exact local choice is read before a configured namespace block,
        // so anything short of block would carve an exception out of it.
        // Existing configured restrictions remain floors.
        if action != "block" && namespaces.iter().any(|prefix| key.starts_with(*prefix)) {
            continue;
        }
        let next = stricter(merged.get(&key).map_or("allow", String::as_str), &action);
        merged.insert(key, next);
    }
    policy.mcp_tool_actions = bound(merged, &required)?;
    Ok(())
}

fn provider_actions(policy: &mut EffectiveNativePolicyV3, observed: StringMap) -> Result<(), Fail> {
    if !validate_mcp_provider_actions(&observed) {
        return Err(PROVIDER_INVALID);
    }
    let mut merged = policy.mcp_provider_actions.clone();
    for (key, action) in observed {
        let next = stricter(merged.get(&key).map_or("review", String::as_str), &action);
        merged.insert(key, next);
    }
    if !validate_mcp_provider_actions(&merged) {
        return Err(PROVIDER_INVALID);
    }
    policy.mcp_provider_actions = merged;
    Ok(())
}

pub(super) fn overlay(
    policy: &mut EffectiveNativePolicyV3,
    observed: Observed,
) -> Result<(), Fail> {
    if !observed.mcp_tool_actions.is_empty() {
        tool_actions(policy, observed.mcp_tool_actions)?;
    }
    if !observed.mcp_provider_actions.is_empty() {
        provider_actions(policy, observed.mcp_provider_actions)?;
    }
    if let Some(digest) = observed.mcp_provider_catalog_hash {
        policy.mcp_provider_catalog_hash = Some(digest);
    }
    validate_effective_policy(policy).map_err(|_| POLICY_INVALID)
}
