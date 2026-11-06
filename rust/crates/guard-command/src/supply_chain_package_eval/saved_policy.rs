use super::*;
use crate::local_supply_chain::stored_package_policy_is_stale_policy_bundle_family;

/// What a cached `cloud_validation_error` evaluation should do.
pub(super) enum SavedPolicyOutcome {
    /// A saved block policy still covers the request: keep the cached error.
    Keep,
    /// Nothing covers it: evaluate again without the cache.
    Retry,
    /// The caller has not hydrated the saved-policy lookup yet.
    Probe,
}

/// `_cached_cloud_validation_error_has_saved_policy` (:903-945), decision half.
///
/// The caller supplies the lookup row; this applies the rules Python applied to
/// it. A stale policy-bundle family row never counts. The probe has no current
/// Guard or sandbox context, so it cannot establish approval reuse: a stored
/// `block` keeps the cached block, and anything else evaluates again.
pub(super) fn saved_policy_keeps_cached_error(
    deps: &SupplyChainEvalDeps<'_>,
    store: &dyn SupplyChainStore,
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
) -> SavedPolicyOutcome {
    if workspace_dir.is_none() {
        return SavedPolicyOutcome::Retry;
    }
    let decision = match deps.saved_policy {
        SavedPolicyProbe::Unsupported | SavedPolicyProbe::Supplied(None) => {
            return SavedPolicyOutcome::Retry;
        }
        SavedPolicyProbe::Required => return SavedPolicyOutcome::Probe,
        SavedPolicyProbe::Supplied(Some(decision)) => decision,
    };
    if !decision.is_object()
        || stored_package_policy_is_stale_policy_bundle_family(store, decision, artifact)
    {
        return SavedPolicyOutcome::Retry;
    }
    if decision.get("action").and_then(Value::as_str) == Some("block") {
        SavedPolicyOutcome::Keep
    } else {
        SavedPolicyOutcome::Retry
    }
}
