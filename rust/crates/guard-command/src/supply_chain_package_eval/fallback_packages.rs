use super::*;

/// `_fallback_package_results` (:3205-3253).
// supply_chain_package_eval.py:3205-3253
#[allow(dead_code)]
pub(super) fn fallback_package_results(
    deps: &SupplyChainEvalDeps<'_>,
    targets: &[Map<String, Value>],
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
    fail_closed_unidentified: bool,
    verify_registry_identity: bool,
) -> Vec<Map<String, Value>> {
    let bun_fallback_packages = bun_lockfile_binary_fallback_packages(
        targets,
        artifact,
        workspace_dir,
        fail_closed_unidentified,
    );
    if !bun_fallback_packages.is_empty() {
        return bun_fallback_packages;
    }
    let lockfile_versions = lockfile_dependency_versions(deps, workspace_dir, artifact, targets);
    let flags: BTreeSet<String> = string_tuple(artifact.metadata.get("flags"))
        .into_iter()
        .collect();
    let alternate_index = command_uses_alternate_package_index(artifact);
    let mut results: Vec<Map<String, Value>> = Vec::new();
    for target in targets {
        if !alternate_index {
            if let Some(reinstall) = installed_release_reinstall_result(deps, target) {
                results.push(reinstall);
                continue;
            }
        }
        let identity_resolved = (optional_string(target.get("ecosystem")).as_deref()
            == Some("npm")
            && flags.contains("--ignore-scripts")
            && lockfile_target_key(target)
                .map(|k| lockfile_versions.contains_key(&k))
                .unwrap_or(false))
            || (verify_registry_identity
                && optional_string(target.get("range")).is_some()
                && registry_resolved_target_version(deps, target).is_some());
        results.push(unknown_package_result(
            deps,
            target,
            fail_closed_unidentified,
            identity_resolved,
        ));
    }
    results
}

// ---------------------------------------------------------------------------
// Batch F ports — `_evaluate_with_cloud` (:1092-1505) and supporting helpers.
// ---------------------------------------------------------------------------

/// `_with_additional_reason` (:5102-5119) — result-level variant: append one
/// reason dict to the evaluation's `reasons` list AND to every package's
/// `reasons`, mirroring how the Python helper stamps the fallback reason onto
/// each package so persisted evidence (`details.reasons` reads the package
/// reasons) carries it.
pub(super) fn with_additional_reason_result(
    mut evaluation: PackageEvalResult,
    reason: Map<String, Value>,
) -> PackageEvalResult {
    evaluation.reasons.push(reason.clone());
    for package in evaluation.packages.iter_mut() {
        match package.get_mut("reasons") {
            Some(Value::Array(existing)) => existing.push(Value::Object(reason.clone())),
            _ => {
                package.insert(
                    "reasons".to_string(),
                    Value::Array(vec![Value::Object(reason.clone())]),
                );
            }
        }
    }
    evaluation
}

/// `_with_cloud_auth_reconnect_copy` (:1658-1683) — result-level variant:
/// appends the `hol-guard connect` reconnect prompt to the user copy and
/// re-normalizes it against the current policy action.
#[allow(dead_code)]
pub(super) fn with_cloud_auth_reconnect_copy_result(
    mut evaluation: PackageEvalResult,
) -> PackageEvalResult {
    let reconnect_command = "hol-guard connect";
    let reconnect_summary = "Guard Cloud needs a fresh sign-in before shared review can resume.";
    let mut summary = evaluation.user_copy.summary.clone();
    if !summary
        .to_ascii_lowercase()
        .contains(&reconnect_summary.to_ascii_lowercase())
    {
        summary = format!("{summary} {reconnect_summary}").trim().to_string();
    }
    let reconnect_message = format!(
        "Guard kept this request local-only because Guard Cloud authorization expired. Run `{reconnect_command}` to restore shared review and sync."
    );
    let mut harness_message = evaluation.user_copy.harness_message.clone();
    if !harness_message
        .to_ascii_lowercase()
        .contains(&reconnect_message.to_ascii_lowercase())
    {
        harness_message = format!("{harness_message} {reconnect_message}")
            .trim()
            .to_string();
    }
    let next_step = evaluation
        .user_copy
        .next_step
        .clone()
        .unwrap_or_else(|| reconnect_command.to_string());
    let candidate = SupplyChainUserCopy {
        title: evaluation.user_copy.title.clone(),
        summary,
        next_step: Some(next_step),
        dashboard_url: evaluation.user_copy.dashboard_url.clone(),
        harness_message,
    };
    let policy_action = decision_to_guard_action_variant(&evaluation.policy_action);
    evaluation.user_copy = normalize_package_user_copy(&candidate, policy_action);
    evaluation
}
