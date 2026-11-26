use guard_contracts::PackagePolicyResolveRequestV1;
use serde_json::Value;

/// Ask the authenticated resident daemon for a package-policy decision when
/// the local integrity path cannot use the saved row.
pub(crate) fn resolve(request: &PackagePolicyResolveRequestV1) -> Option<(Value, Value)> {
    if request.policy_workspaces.is_empty() {
        return None;
    }
    let authority = crate::daemon_policy_authority::ResidentPolicyAuthority::new(
        std::path::PathBuf::from(&request.guard_home),
    );
    authority.resolve_package_policy(
        &request.harness,
        Some(&request.artifact_id),
        &request.artifact_hash,
        &request.policy_workspaces,
        request.publisher.as_deref(),
    )
}
