use super::*;

/// `_resolve_guard_sync_context` — derive `(auth_context, sync_url,
/// workspace_id)` for the Cloud evaluation request.
#[allow(dead_code)]
pub(super) fn resolve_guard_sync_context(
    deps: &SupplyChainEvalDeps<'_>,
    store: &dyn SupplyChainStore,
    workspace_dir: Option<&Path>,
) -> EvalResult<(Map<String, Value>, String, Option<String>)> {
    let auth_context = deps
        .guard_sync
        .resolve_guard_sync_auth_context(store, false, false)?;
    let sync_url = optional_string(auth_context.get("sync_url"))
        .ok_or_else(|| EvalError::Internal("guard sync URL unavailable".to_string()))?;
    let canonical = deps.guard_sync.validate_guard_sync_url(
        &sync_url,
        optional_string(auth_context.get("issuer")).as_deref(),
    )?;
    let workspace_id = optional_string(auth_context.get("workspace_id"))
        .or_else(|| store.get_cloud_workspace_id())
        .or_else(|| {
            workspace_dir
                .and_then(|dir| dir.file_name())
                .map(|n| n.to_string_lossy().into_owned())
        });
    Ok((auth_context, canonical, workspace_id))
}

/// `_fetch_package_evaluation_response` — POST the evaluation request with the
/// DPoP 401-forced-refresh retry semantics of `_evaluate_with_cloud` (:1336-1380).
#[allow(dead_code)]
pub(super) fn fetch_package_evaluation_response(
    deps: &SupplyChainEvalDeps<'_>,
    store: &dyn SupplyChainStore,
    auth_context: &Value,
    evaluate_url: &str,
    request_data: &[u8],
) -> EvalResult<Map<String, Value>> {
    let request = deps.guard_sync.guard_sync_request(
        auth_context,
        evaluate_url,
        "POST",
        Some(request_data),
        None,
        None,
    )?;
    match deps.guard_sync.urlopen_json_with_timeout_retry(
        &request,
        TIMEOUT_SECONDS,
        RETRY_TIMEOUT_SECONDS,
    ) {
        Ok(response) => Ok(response),
        Err(error) => {
            if error.http_status() == Some(401) {
                if let Ok(fresh) = deps
                    .guard_sync
                    .resolve_guard_sync_auth_context(store, false, true)
                {
                    if let Ok(retry) = deps.guard_sync.guard_sync_request(
                        &Value::Object(fresh),
                        evaluate_url,
                        "POST",
                        Some(request_data),
                        None,
                        None,
                    ) {
                        return deps.guard_sync.urlopen_json_with_timeout_retry(
                            &retry,
                            TIMEOUT_SECONDS,
                            RETRY_TIMEOUT_SECONDS,
                        );
                    }
                }
            }
            Err(error)
        }
    }
}

/// `_cloud_http_fail_closed_evaluation` (:1543-1595) — full form producing a
/// finalized `PackageEvalResult` (or `None` when `fail_closed_decision` is not
/// `block` and status is not 403).
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
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
