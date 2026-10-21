use super::*;

/// `_cached_cloud_validation_error_requires_uncached_retry` (:885-897) —
/// derived from the docstring/behavior: a cached cloud-validation-error eval
/// is only reusable for a short TTL; beyond that the caller must retry
/// uncached. We return `true` when the cached eval has a
/// `cloud_validation_error` reason and is past the TTL.
// supply_chain_package_eval.py:885-897
#[allow(dead_code)]
pub(super) fn cached_cloud_validation_error_requires_uncached_retry(
    cached: &Map<String, Value>,
    now_timestamp: Option<f64>,
) -> bool {
    cached_eval_has_reason_code(cached, "cloud_validation_error")
        && !cached_supply_chain_eval_is_reusable(cached, now_timestamp)
}

/// `_cached_cloud_validation_error_has_saved_policy` (:898-913) —
/// derived: a cached cloud-validation-error eval "has saved policy" when
/// the cached decision dict carries a non-empty `policy_action` value,
/// meaning a previously persisted policy decision exists.
// supply_chain_package_eval.py:898-913
#[allow(dead_code)]
pub(super) fn cached_cloud_validation_error_has_saved_policy(cached: &Map<String, Value>) -> bool {
    optional_string(cached.get("policy_action")).is_some()
}
