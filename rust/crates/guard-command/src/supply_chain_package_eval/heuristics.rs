use super::*;

/// `_heuristic_result` (:1926-2121) — local/offline evaluation over targets
/// without a bundle; enforces the external-archive budget and fail-closed
/// integrity checks.
// supply_chain_package_eval.py:1926-2121
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(super) fn heuristic_result(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    store: &dyn SupplyChainStore,
    targets: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
    external_archive_network_authorized: bool,
    retain_external_archive_blob: bool,
    external_archive_request_deadline: Option<f64>,
) -> Option<EvaluationDraft> {
    let mut packages: Vec<Map<String, Value>> = Vec::new();
    let mut external_archive_downloads: Vec<RestrictedArchiveDownload> = Vec::new();
    let external_archive_source_hashes: Vec<String> = targets
        .iter()
        .filter(|t| target_is_external_https_archive(t))
        .filter_map(|t| optional_string(t.get("source_url")))
        .map(|u| stable_digest_hex(u.as_bytes()))
        .collect();
    let mut retained_archive_bytes: u64 = 0;
    for target in targets {
        let source_url = optional_string(target.get("source_url"));
        if target.get("external_archive_source_integrity_invalid") == Some(&Value::Bool(true)) {
            packages.push(heuristic_package_result(
                target,
                "block",
                "external_archive_source_integrity_invalid",
                "Package source private data no longer matches its approved public identity.",
                "high",
            ));
            continue;
        }
        if let Some(reason) = optional_string(target.get("source_invalid_reason")) {
            packages.push(heuristic_package_result(
                target,
                "block",
                &reason,
                "Package source syntax is ambiguous or invalid and cannot be authenticated.",
                "high",
            ));
            continue;
        }
        if source_url.is_some() && target_is_external_https_archive(target) {
            let (package_result, download) = external_tarball_dependency_result(
                deps,
                target,
                external_archive_network_authorized,
                retain_external_archive_blob,
                external_archive_request_deadline,
                store.guard_home(),
            );
            if let Some(dl) = download {
                retained_archive_bytes += dl.size;
                if retained_archive_bytes > EXTERNAL_ARCHIVE_MAX_AGGREGATE_BYTES {
                    drop(dl);
                } else {
                    external_archive_downloads.push(dl);
                }
            }
            if let Some(pr) = package_result {
                packages.push(pr);
            }
            continue;
        }
        if target.get("manifest_unsynced") == Some(&Value::Bool(true)) {
            packages.push(heuristic_package_result(
                target,
                "ask",
                "manifest_lockfile_unsynced",
                &format!(
                    "{} is declared in the project manifest but is not pinned \
                     in the existing lockfile yet, so Guard requires review before install.",
                    optional_string(target.get("package_name"))
                        .or_else(|| optional_string(target.get("name")))
                        .unwrap_or_else(|| "package".to_string())
                ),
                "high",
            ));
            continue;
        }
        let lockfile_parse_warning =
            lockfile_parse_warning_result(deps, workspace_dir, artifact, target);
        let ecosystem = optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".into());
        let mut package_result =
            local_package_manifest_result(deps, target, artifact, workspace_dir)
                .or_else(|| local_python_build_result(target, workspace_dir))
                .or_else(|| {
                    matches!(
                        ecosystem.as_str(),
                        "homebrew" | "homebrew-cask" | "homebrew-tap"
                    )
                    .then(|| homebrew_package_monitor_result(deps, target))
                })
                .or_else(|| (ecosystem == "system").then(|| system_package_monitor_result(target)))
                .or_else(|| {
                    (ecosystem == "unsupported").then(|| unsupported_ecosystem_result(deps, target))
                })
                .or_else(|| go_replace_result(deps, target, artifact, workspace_dir))
                .or_else(|| local_source_dependency_result(target));
        if package_result.is_none()
            && source_url
                .as_deref()
                .is_some_and(|url| url.to_ascii_lowercase().starts_with("http:"))
        {
            package_result = Some(heuristic_package_result(
                target,
                "block",
                "insecure_source_url",
                "Package source uses insecure HTTP transport.",
                "high",
            ));
        }
        if package_result.is_none() && source_url.as_deref().is_some_and(is_git_source_url) {
            let repository = optional_string(target.get("source_repository"))
                .unwrap_or_else(|| "Git repository".to_string());
            let revision_kind = optional_string(target.get("source_revision_kind"))
                .unwrap_or_else(|| "missing".to_string());
            package_result = Some(heuristic_package_result(
                target,
                "ask",
                "git_dependency_source",
                &format!("Git package source {repository} ({revision_kind}) requires review before install."),
                "high",
            ));
        }
        match package_result.take() {
            None => {
                if let Some(warning) = lockfile_parse_warning {
                    packages.push(warning);
                }
                continue;
            }
            Some(package_result) => {
                let package_result = if let Some(warning) = lockfile_parse_warning.as_ref() {
                    if let Some(first_reason) =
                        dict_items(warning.get("reasons")).into_iter().next()
                    {
                        with_package_reason(&package_result, first_reason)
                    } else {
                        package_result
                    }
                } else {
                    package_result
                };
                packages.push(package_result);
            }
        }
    }
    if packages.is_empty() {
        return None;
    }
    packages.sort_by(|a, b| {
        let ra = decision_rank(
            optional_string(a.get("decision"))
                .as_deref()
                .unwrap_or("monitor"),
        );
        let rb = decision_rank(
            optional_string(b.get("decision"))
                .as_deref()
                .unwrap_or("monitor"),
        );
        rb.cmp(&ra)
    });
    let decision = optional_string(packages[0].get("decision")).unwrap_or_else(|| "monitor".into());
    if decision == "block" {
        for retained in external_archive_downloads.drain(..) {
            drop(retained);
        }
    }
    let reasons: Vec<Map<String, Value>> = packages
        .iter()
        .flat_map(|p| dict_items(p.get("reasons")))
        .collect();
    Some(EvaluationDraft {
        decision,
        enforcement: "free_local".to_string(),
        entitlement_state: "free".to_string(),
        cache_status: "miss".to_string(),
        packages,
        reasons,
        matched_rule_id: None,
        exception_id: None,
        refresh_required: false,
        record_monitor_evidence: false,
        bundle_version: None,
        policy_version: "local:none".to_string(),
        external_archive_downloads,
        external_archive_source_hashes,
    })
}
