use super::bundle_results::{
    bundle_package, bundle_package_result, emergency_deny_bundle_message, policy_package_result,
    recommended_fix_allow_package_result, typed_bundle,
};
use super::bundle_transitive::{
    lockfile_dependency_versions, offline_decision, package_result_has_incomplete_lockfile,
    resolved_target_version, transitive_lockfile_results,
};
use super::package_results::heuristic_package_result_with;
use super::*;

/// `_evaluate_with_bundle` (:1718-1877): evaluate every target against the cached
/// signed bundle and produce a draft.
pub(super) fn evaluate_with_bundle(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
    response: &SupplyChainBundleResponse,
    workspace_dir: Option<&Path>,
    workspace_id: Option<&str>,
    now_timestamp: Option<f64>,
) -> Option<EvaluationDraft> {
    let bundle = typed_bundle(response)?;
    let meta = bundle_meta(response.to_dict().as_object().unwrap_or(&Map::new()));
    let meta_value = |key: &str| meta.get(key).cloned().unwrap_or_default();
    let mut refresh_required = false;
    let mut packages: Vec<Map<String, Value>> = Vec::new();
    let lockfile_versions = lockfile_dependency_versions(deps, workspace_dir, artifact, targets);
    for target in targets {
        if target.get("manifest_unsynced") == Some(&Value::Bool(true)) {
            let name = optional_string(target.get("package_name")).unwrap_or_default();
            packages.push(heuristic_package_result(
                target,
                "ask",
                "manifest_lockfile_unsynced",
                &format!(
                    "{name} is declared in the project manifest but is not pinned \
                     in the existing lockfile yet, so Guard requires review before install."
                ),
                "high",
            ));
            continue;
        }
        let resolved_version = resolved_target_version(deps, target, &lockfile_versions);
        let package_match = resolved_version
            .as_deref()
            .and_then(|version| bundle_package(deps, &bundle, target, version));
        let ecosystem = optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".into());
        let resolved_npm_version = resolved_version.clone().filter(|_| ecosystem == "npm");
        let policy_target =
            target_for_resolved_npm_policy_match(target, resolved_npm_version.as_deref());
        let matched_rule = matching_policy_rule(
            response,
            &policy_target,
            &artifact.harness,
            package_match.map(|package| package.normalized_severity.as_str()),
            now_timestamp,
        );
        if let Some(rule) = matched_rule {
            let decision =
                normalize_bundle_action(&optional_string(rule.get("action")).unwrap_or_default());
            let rule_id = optional_string(rule.get("ruleId")).unwrap_or_default();
            packages.push(bind_resolved_npm_policy_result(
                policy_package_result(target, &decision, &rule_id),
                resolved_npm_version.as_deref(),
            ));
            continue;
        }
        if let Some(confusion) = dependency_confusion_policy_package_result(response, target) {
            packages.push(confusion);
            continue;
        }
        let Some(resolved_version) = resolved_version else {
            continue;
        };
        let offline = offline_decision(
            deps,
            response,
            &optional_string(target.get("normalized_name")).unwrap_or_default(),
            &resolved_version,
            Some(&ecosystem),
            now_timestamp,
        );
        let denied = offline.emergency_deny && offline.action == "block";
        if denied || (package_match.is_none() && offline.action == "block") {
            packages.push(heuristic_package_result_with(
                target,
                "block",
                &offline.reason,
                &emergency_deny_bundle_message(target, &resolved_version, &offline.reason),
                "critical",
                Some(&resolved_version),
                offline.recommended_fix_version.as_deref(),
            ));
            continue;
        }
        let Some(package) = package_match else {
            if let Some(safe_allow) =
                recommended_fix_allow_package_result(deps, target, &resolved_version, &bundle)
            {
                packages.push(safe_allow);
            }
            continue;
        };
        refresh_required = refresh_required || offline.stale;
        packages.push(bundle_package_result(
            target,
            response,
            package,
            &normalize_bundle_action(&offline.action),
            &offline.reason,
            offline.stale,
            &resolved_version,
        ));
    }
    let direct_identities: Vec<_> = packages
        .iter()
        .map(|package| result_package_identity(deps, package))
        .collect();
    for package in transitive_lockfile_results(
        deps,
        response,
        &bundle,
        artifact,
        workspace_dir,
        now_timestamp,
    ) {
        if package_result_has_incomplete_lockfile(&package)
            || !direct_identities.contains(&result_package_identity(deps, &package))
        {
            packages.push(package);
        }
    }
    if packages.is_empty() {
        return None;
    }
    let rank = |package: &Map<String, Value>| {
        decision_rank(&optional_string(package.get("decision")).unwrap_or_else(|| "monitor".into()))
    };
    packages.sort_by_key(|package| std::cmp::Reverse(rank(package)));
    let decision = optional_string(packages[0].get("decision")).unwrap_or_else(|| "monitor".into());
    let winning_rule_id = optional_string(packages[0].get("ruleId"));
    let reasons = packages
        .iter()
        .flat_map(|package| dict_items(package.get("reasons")))
        .collect();
    Some(EvaluationDraft {
        enforcement: if winning_rule_id.is_some() {
            "policy_override"
        } else {
            "offline_cached"
        }
        .into(),
        entitlement_state: if workspace_id.is_some() {
            "premium"
        } else {
            "free"
        }
        .into(),
        cache_status: if refresh_required { "stale" } else { "miss" }.into(),
        reasons,
        exception_id: winning_rule_id.clone().filter(|_| decision == "allow"),
        matched_rule_id: winning_rule_id,
        refresh_required,
        record_monitor_evidence: decision == "monitor",
        bundle_version: Some(meta_value("bundle_version")),
        policy_version: meta_value("policy_hash"),
        decision,
        packages,
        ..Default::default()
    })
}
