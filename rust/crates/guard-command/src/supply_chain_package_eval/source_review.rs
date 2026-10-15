use super::*;

/// Locally-decided block draft carrying the package's own reasons, mirroring
/// `_EvaluationDraft(..., reasons=tuple(_dict_items(package.get("reasons"))))`.
fn local_block_draft(
    package: Map<String, Value>,
    external_archive_source_hashes: Vec<String>,
) -> EvaluationDraft {
    EvaluationDraft {
        decision: "block".to_string(),
        enforcement: "free_local".to_string(),
        entitlement_state: "free".to_string(),
        cache_status: "miss".to_string(),
        reasons: dict_items(package.get("reasons")),
        packages: vec![package],
        policy_version: "local:none".to_string(),
        external_archive_source_hashes,
        ..Default::default()
    }
}

#[allow(dead_code, clippy::too_many_arguments)]
pub(super) fn evaluate_non_registry_sources(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    store: &dyn SupplyChainStore,
    workspace_dir: Option<&Path>,
    targets: &[Map<String, Value>],
    package_intent_hash: &str,
    now_value: &str,
    external_archive_network_authorized: bool,
    retain_external_archive_blob: bool,
) -> Option<PackageEvalResult> {
    let external_archive_targets: Vec<&Map<String, Value>> = targets
        .iter()
        .filter(|t| target_is_external_https_archive(t))
        .collect();
    let external_archive_source_hashes: Vec<String> = external_archive_targets
        .iter()
        .filter_map(|t| optional_string(t.get("source_url")))
        .map(|u| stable_digest_hex(u.as_bytes()))
        .collect();

    // `external_archive_targets` gate (:365-410) — local two-phase evaluation.
    if !external_archive_targets.is_empty() {
        if external_archive_targets.len() > EXTERNAL_ARCHIVE_MAX_TARGETS {
            let limit_package = heuristic_package_result(
                external_archive_targets[0],
                "block",
                "external_archive_target_limit",
                "External archive request exceeded Guard's per-command target limit.",
                "high",
            );
            let draft = local_block_draft(limit_package, external_archive_source_hashes.clone());
            let result = finalize_evaluation(deps, &draft, package_intent_hash, None);
            persist_evidence(deps, store, artifact, &result, now_value);
            return Some(result);
        }
        if external_archive_targets.len() != targets.len() {
            let mixed_package = heuristic_package_result(
                external_archive_targets[0],
                "block",
                "external_archive_mixed_request_unsupported",
                "External archives must be installed in a separate command so Guard can preserve registry advisory evaluation and bind the inspected blob to execution.",
                "high",
            );
            let draft = local_block_draft(mixed_package, external_archive_source_hashes.clone());
            let result = finalize_evaluation(deps, &draft, package_intent_hash, None);
            persist_evidence(deps, store, artifact, &result, now_value);
            return Some(result);
        }
        let external_archive_draft = heuristic_result(
            deps,
            artifact,
            store,
            targets,
            workspace_dir,
            external_archive_network_authorized,
            retain_external_archive_blob,
            external_archive_network_authorized
                .then(|| monotonic_seconds() + EXTERNAL_ARCHIVE_REQUEST_TIMEOUT_SECONDS),
        )
        .unwrap_or_else(|| EvaluationDraft {
            decision: "block".to_string(),
            enforcement: "free_local".to_string(),
            entitlement_state: "free".to_string(),
            cache_status: "miss".to_string(),
            packages: Vec::new(),
            reasons: vec![{
                let mut r = Map::new();
                r.insert(
                    "code".to_string(),
                    Value::String("external_archive_inspection_incomplete".to_string()),
                );
                r.insert(
                    "message".to_string(),
                    Value::String(
                        "Guard could not establish an external archive evaluation.".to_string(),
                    ),
                );
                r.insert("severity".to_string(), Value::String("high".to_string()));
                r.insert(
                    "source".to_string(),
                    Value::String("guard-local".to_string()),
                );
                r
            }],
            matched_rule_id: None,
            exception_id: None,
            refresh_required: false,
            record_monitor_evidence: false,
            bundle_version: None,
            policy_version: "local:none".to_string(),
            ..Default::default()
        });
        // Ensure source hashes are carried even when heuristic_result produced
        // its own (or none).
        let mut external_archive_draft = external_archive_draft;
        if external_archive_draft
            .external_archive_source_hashes
            .is_empty()
        {
            external_archive_draft.external_archive_source_hashes =
                external_archive_source_hashes.clone();
        }
        let external_archive_result =
            finalize_evaluation(deps, &external_archive_draft, package_intent_hash, None);
        persist_evidence(deps, store, artifact, &external_archive_result, now_value);
        return Some(external_archive_result);
    }

    // `source_review_targets` gate (:411-440) — npm source-review path.
    let source_review_targets: Vec<&Map<String, Value>> = targets
        .iter()
        .filter(|t| target_requires_npm_source_review(t))
        .collect();
    if !source_review_targets.is_empty() {
        if source_review_targets.len() != targets.len() {
            let mixed_source_package = heuristic_package_result(
                source_review_targets[0],
                "block",
                "npm_source_mixed_request_unsupported",
                "npm source dependencies must be installed separately so Guard can preserve registry advisory evaluation and source approval identity.",
                "high",
            );
            let draft = local_block_draft(mixed_source_package, Vec::new());
            let result = finalize_evaluation(deps, &draft, package_intent_hash, None);
            persist_evidence(deps, store, artifact, &result, now_value);
            return Some(result);
        }
        let source_review_draft = heuristic_result(
            deps,
            artifact,
            store,
            targets,
            workspace_dir,
            external_archive_network_authorized,
            retain_external_archive_blob,
            None,
        )
        .unwrap_or_else(|| EvaluationDraft {
            decision: "block".to_string(),
            enforcement: "free_local".to_string(),
            entitlement_state: "free".to_string(),
            cache_status: "miss".to_string(),
            packages: Vec::new(),
            reasons: vec![{
                let mut r = Map::new();
                r.insert(
                    "code".to_string(),
                    Value::String("npm_source_review_incomplete".to_string()),
                );
                r.insert(
                    "message".to_string(),
                    Value::String(
                        "Guard could not complete source review for this npm package.".to_string(),
                    ),
                );
                r.insert("severity".to_string(), Value::String("high".to_string()));
                r.insert(
                    "source".to_string(),
                    Value::String("guard-local".to_string()),
                );
                r
            }],
            matched_rule_id: None,
            exception_id: None,
            refresh_required: false,
            record_monitor_evidence: false,
            bundle_version: None,
            policy_version: "local:none".to_string(),
            ..Default::default()
        });
        let source_review_result =
            finalize_evaluation(deps, &source_review_draft, package_intent_hash, None);
        persist_evidence(deps, store, artifact, &source_review_result, now_value);
        return Some(source_review_result);
    }

    None
}
