use super::*;

/// Code and message for a 403 at Guard Cloud's address. Cloudflare in front of
/// Guard Cloud answers its own 403 when it blocks or challenges a client; that is
/// a network failure, not an expired sign-in, so it must not ask for a reconnect.
pub(super) fn cloud_403_reason(edge_block_reason: Option<&str>) -> (&'static str, String) {
    match edge_block_reason {
        Some(reason) => (
            "cloud_http_error",
            format!(
                "{reason} Guard blocked the install rather than bypassing Cloud package protection."
            ),
        ),
        None => (
            "cloud_auth_error",
            "Guard cloud evaluation was not authorized, so this package request needs review."
                .to_owned(),
        ),
    }
}

/// `_cloud_http_fail_closed_evaluation` (:1543-1595) — full form producing a
/// finalized `PackageEvalResult` (or `None` when `fail_closed_decision` is not
/// `block` and status is not 403).
#[allow(clippy::too_many_arguments)]
pub(super) fn cloud_http_fail_closed_evaluation_full(
    deps: &SupplyChainEvalDeps<'_>,
    status_code: u16,
    edge_block_reason: Option<&str>,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
    workspace_fingerprint: Option<&str>,
    bundle_meta: Option<&BTreeMap<String, String>>,
    fail_closed_decision: &str,
) -> Option<PackageEvalResult> {
    if status_code == 403 {
        let (code, message) = cloud_403_reason(edge_block_reason);
        return Some(cloud_fail_closed_evaluation_full(
            deps,
            code,
            &message,
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

#[cfg(test)]
mod tests {
    use super::cloud_403_reason;

    #[test]
    fn an_edge_block_403_is_a_network_failure_not_a_sign_in_problem() {
        let edge = "Guard Cloud is unreachable from this network: Cloudflare in front of Guard Cloud challenged the request (HTTP 403).";
        let (code, message) = cloud_403_reason(Some(edge));
        assert_eq!(code, "cloud_http_error");
        assert!(message.starts_with(edge), "{message}");
        assert!(!message.contains("not authorized"), "{message}");
        let (code, message) = cloud_403_reason(None);
        assert_eq!(code, "cloud_auth_error");
        assert!(message.contains("not authorized"), "{message}");
    }
}
