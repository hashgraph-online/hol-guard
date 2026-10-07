use super::*;

/// `_normalize_evaluation_action` — derived: normalize a raw decision string
/// into its canonical action rank bucket ("allow" | "monitor" | "warn" |
/// "ask" | "block"). Unknown values map to "monitor".
// supply_chain_package_eval.py:114
#[allow(dead_code)]
pub(super) fn normalize_evaluation_action(value: &str) -> String {
    if decision_rank_map().contains_key(value) {
        value.to_string()
    } else {
        "monitor".to_string()
    }
}

/// `_evaluation_action_rank` — derived: numeric rank of a normalized
/// evaluation action string.
// supply_chain_package_eval.py:114
#[allow(dead_code)]
pub(super) fn evaluation_action_rank(value: &str) -> u8 {
    decision_rank(&normalize_evaluation_action(value))
}

/// `_highest_risk_action` — derived: pick the most restrictive normalized
/// action from a list of candidate decision strings.
// supply_chain_package_eval.py:114
#[allow(dead_code)]
pub(super) fn highest_risk_action<'a>(actions: impl IntoIterator<Item = &'a str>) -> String {
    actions
        .into_iter()
        .map(normalize_evaluation_action)
        .max_by_key(|a| decision_rank(a))
        .unwrap_or_else(|| "monitor".to_string())
}

/// `_resolve_package_action` — derived: resolve the effective `GuardAction`
/// for a package result by combining the normalized decision and any
/// policy-sourced overrides already on the package payload.
// supply_chain_package_eval.py:154-160
#[allow(dead_code)]
pub(super) fn resolve_package_action(package: &Map<String, Value>) -> GuardAction {
    let decision =
        optional_string(package.get("decision")).unwrap_or_else(|| "monitor".to_string());
    let normalized = normalize_evaluation_action(&decision);
    decision_to_guard_action_variant(&normalized)
}

/// `_risk_to_action` — derived: map a normalized decision string to the
/// `GuardAction` lattice value used for evidence.
// supply_chain_package_eval.py:154-160
#[allow(dead_code)]
pub(super) fn risk_to_action(decision: &str) -> GuardAction {
    decision_to_guard_action_variant(&normalize_evaluation_action(decision))
}

/// `_severity_rank` — alias kept for callers expecting the private name.
// supply_chain_package_eval.py:4828-4829
#[allow(dead_code)]
pub(super) fn severity_rank(value: &str) -> u8 {
    severity_rank_value(value)
}

/// `_normalize_package_action` — derived: normalize the `decision` field on a
/// single package dict to the canonical five-value set.
// supply_chain_package_eval.py:114
#[allow(dead_code)]
pub(super) fn normalize_package_action(package: &Map<String, Value>) -> String {
    optional_string(package.get("decision"))
        .map(|s| normalize_evaluation_action(&s))
        .unwrap_or_else(|| "monitor".to_string())
}

/// `_normalize_package_decision` — derived: same normalization as
/// `_normalize_package_action` but returns the raw decision string.
// supply_chain_package_eval.py:114
#[allow(dead_code)]
pub(super) fn normalize_package_decision(package: &Map<String, Value>) -> String {
    normalize_package_action(package)
}
