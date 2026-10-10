use super::*;

/// `_cloud_http_fail_closed_evaluation` (:1543-1595) — full form producing a
/// finalized `PackageEvalResult` (or `None` when `fail_closed_decision` is not
/// `block` and status is not 403).
#[allow(clippy::too_many_arguments)]
pub(super) fn cloud_http_fail_closed_evaluation_full(
    deps: &SupplyChainEvalDeps<'_>,
    status_code: u16,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
    workspace_fingerprint: Option<&str>,
    bundle_meta: Option<&BTreeMap<String, String>>,
    fail_closed_decision: &str,
) -> Option<PackageEvalResult> {
    if status_code == 403 {
        return Some(cloud_fail_closed_evaluation_full(
            deps,
            "cloud_auth_error",
            "Guard cloud evaluation was not authorized, so this package request needs review.",
            artifact,
            targets,
            workspace_dir,
            workspace_fingerprint,
            bundle_meta,
            fail_closed_decision,
        ));
    }
    if fail_closed_decision != "block" {
        return None;
    }
    let (code, message) = match status_code {
        401 => (
            "cloud_auth_error",
            "Guard Cloud could not authorize this package check. Guard blocked the install rather than bypassing Cloud package protection.".to_string(),
        ),
        400 | 404 => (
            "cloud_validation_error",
            "Guard Cloud could not validate this package request. Guard blocked the install rather than bypassing Cloud package protection.".to_string(),
        ),
        _ => (
            "cloud_http_error",
            format!(
                "Guard Cloud returned HTTP {status_code} while verifying this package. Guard blocked the install rather than bypassing Cloud package protection."
            ),
        ),
    };
    Some(cloud_fail_closed_evaluation_full(
        deps,
        code,
        &message,
        artifact,
        targets,
        workspace_dir,
        workspace_fingerprint,
        bundle_meta,
        fail_closed_decision,
    ))
}
