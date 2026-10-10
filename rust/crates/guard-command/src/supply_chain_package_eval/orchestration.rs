use super::*;

// ---------------------------------------------------------------------------
// `_evaluate_package_request_artifact_uncached` (:337-795) — orchestration:
// cache check → lockfile parse gate → external-archive two-phase path →
// npm-source-review path → bundle/cloud/heuristic fall-through.
// ---------------------------------------------------------------------------

/// `_evaluate_package_request_artifact_uncached` (:337-795).
///
/// Faithful port of the Python orchestration function. Returns
/// `(Option<PackageEvalResult>, Option<String>)` where the second element is a
/// human-readable note when the result was served from the early-exit paths
/// (parity with the Python early-return tuple shape).
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(super) fn evaluate_package_request_artifact_uncached(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    store: &dyn SupplyChainStore,
    workspace_dir: Option<&Path>,
    now: Option<&str>,
    external_archive_network_authorized: bool,
    retain_external_archive_blob: bool,
) -> (Option<PackageEvalResult>, Option<String>) {
    let now_value = now
        .map(str::to_string)
        .unwrap_or_else(|| crate::local_supply_chain::Timestamp::now_utc().isoformat());
    let now_timestamp = parse_evaluation_timestamp(&now_value);
    let targets = evaluation_targets(deps, artifact, workspace_dir);
    let cloud_targets = cloud_evaluation_targets(deps, artifact, workspace_dir);
    let package_intent_hash = artifact
        .artifact_id
        .rsplit(':')
        .next()
        .map(str::to_string)
        .unwrap_or_else(|| artifact.artifact_id.clone());
    // `incomplete_lockfile` gate (:356-364).
    if let Some(workspace_dir) = workspace_dir {
        let parse_results = lockfile_parse_results(deps, workspace_dir, artifact);
        if let Some(incomplete) = first_incomplete_lockfile_result(&parse_results) {
            let target = targets
                .first()
                .cloned()
                .unwrap_or_else(|| incomplete_lockfile_fallback_target(incomplete));
            return (
                Some(finalize_incomplete_lockfile_evaluation(
                    deps,
                    artifact,
                    store,
                    &target,
                    Some(workspace_dir),
                    incomplete,
                    &package_intent_hash,
                    &now_value,
                )),
                None,
            );
        }
    }

    if let Some(result) = evaluate_non_registry_sources(
        deps,
        artifact,
        store,
        workspace_dir,
        &targets,
        &package_intent_hash,
        &now_value,
        external_archive_network_authorized,
        retain_external_archive_blob,
    ) {
        return (Some(result), None);
    }

    // Auth-context resolution (:441-458).
    let workspace_id = store.get_cloud_workspace_id();
    let bundle_payload = workspace_id
        .as_deref()
        .and_then(|id| store.get_cached_supply_chain_bundle(id))
        .unwrap_or(Value::Null);
    let bundle_response = if bundle_payload.is_null() {
        None
    } else {
        deps.bundle
            .load_supply_chain_bundle_response(&bundle_payload)
            .ok()
    };
    let bundle_meta_map = bundle_response
        .as_ref()
        .map(|r| bundle_meta(&r.to_dict().as_object().cloned().unwrap_or_default()));
    let bundle_meta: Option<BTreeMap<String, String>> = bundle_meta_map;
    let workspace_fingerprint = workspace_id
        .as_deref()
        .map(|id| workspace_fingerprint(deps, id, workspace_dir, artifact, bundle_meta.as_ref()));
    let workspace_fingerprint = workspace_fingerprint.as_deref();

    // Bundle evaluation (:526-536).
    let bundle_evaluation = bundle_response.as_ref().and_then(|response| {
        evaluate_with_bundle(
            deps,
            artifact,
            &targets,
            response,
            workspace_dir,
            workspace_id.as_deref(),
            now_timestamp,
        )
    });

    // `has_package_material` gate (:537-545).
    if !artifact_has_package_material(artifact, &targets) {
        let no_material_result = empty_package_material_result(
            artifact,
            workspace_id.as_deref(),
            bundle_meta
                .as_ref()
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                        .collect::<Map<String, Value>>()
                })
                .as_ref(),
            &package_intent_hash,
            workspace_fingerprint,
        );
        persist_evidence(deps, store, artifact, &no_material_result, &now_value);
        return (Some(no_material_result), None);
    }

    // `bundle_defer_eligible` (:546-548) — `block` decisions always defer;
    // non-block defer only when the bundle is fresh (`!refresh_required`).
    let bundle_defer_eligible = bundle_evaluation
        .as_ref()
        .map(|b| b.decision == "block" || !b.refresh_required)
        .unwrap_or(false);
    let bundle_decision = bundle_evaluation.as_ref().map(|b| b.decision.as_str());

    // Cloud evaluation (:549-570) — returns `(Option<PackageEvalResult>,
    // Option<cloud_fallback_reason>)`.
    let (mut cloud_result, mut cloud_fallback_reason) = evaluate_with_cloud(
        deps,
        store,
        artifact,
        &cloud_targets,
        workspace_dir,
        workspace_id.as_deref(),
        workspace_fingerprint,
        bundle_meta.as_ref(),
        bundle_defer_eligible,
        bundle_decision,
        bundle_evaluation.as_ref(),
    );
    if let Some(ref cloud) = cloud_result {
        if let Some(ref bundle_draft) = bundle_evaluation {
            if cloud_result_should_defer_to_bundle(&evaluation_to_draft(cloud), bundle_draft) {
                if cloud_fallback_reason.is_none() {
                    cloud_fallback_reason = cloud.reasons.first().cloned();
                }
                cloud_result = None;
            }
        }
    }

    if let Some(mut cloud_result) = cloud_result {
        // `upgrade_required` heuristic upgrade (:571-596).
        if cloud_result.enforcement == "upgrade_required" {
            if let Some(heuristic) = heuristic_result(
                deps,
                artifact,
                store,
                &targets,
                workspace_dir,
                external_archive_network_authorized,
                retain_external_archive_blob,
                None,
            ) {
                if decision_rank(&heuristic.decision) > decision_rank(&cloud_result.decision) {
                    let upgrade_draft = EvaluationDraft {
                        decision: heuristic.decision,
                        enforcement: "free_local".to_string(),
                        entitlement_state: "free".to_string(),
                        cache_status: "upgrade-gated".to_string(),
                        packages: heuristic.packages,
                        reasons: heuristic.reasons,
                        matched_rule_id: heuristic.matched_rule_id,
                        exception_id: heuristic.exception_id,
                        refresh_required: false,
                        record_monitor_evidence: heuristic.record_monitor_evidence,
                        bundle_version: None,
                        policy_version: bundle_meta
                            .as_ref()
                            .and_then(|m| m.get("policy_hash").cloned())
                            .unwrap_or_else(|| "local:none".to_string()),
                        ..Default::default()
                    };
                    cloud_result = finalize_evaluation(
                        deps,
                        &upgrade_draft,
                        &package_intent_hash,
                        workspace_fingerprint,
                    );
                }
            }
        }
        cache_reusable_cloud_validation_error(
            deps,
            workspace_id.as_deref(),
            bundle_meta
                .as_ref()
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                        .collect::<Map<String, Value>>()
                })
                .as_ref(),
            &package_intent_hash,
            &cloud_result,
            &now_value,
        );
        persist_evidence(deps, store, artifact, &cloud_result, &now_value);
        return (Some(cloud_result), None);
    }

    // `refresh_required` + no OAuth → fall back to bundle (:597-621).
    if let Some(ref bundle_draft) = bundle_evaluation {
        if bundle_draft.refresh_required
            && !deps
                .store_extras
                .get_oauth_local_credential_health()
                .get("configured")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        {
            let fallback = finalize_evaluation(
                deps,
                bundle_draft,
                &package_intent_hash,
                workspace_fingerprint,
            );
            persist_evidence(deps, store, artifact, &fallback, &now_value);
            let mut event = Map::new();
            event.insert(
                "artifact_id".to_string(),
                Value::String(artifact.artifact_id.clone()),
            );
            event.insert(
                "artifact_name".to_string(),
                Value::String(artifact.name.clone()),
            );
            event.insert(
                "reason".to_string(),
                Value::String("feed_stale".to_string()),
            );
            store.add_event(
                "supply_chain_bundle_refresh_requested",
                &Value::Object(event),
                &now_value,
            );
            return (Some(fallback), None);
        }
    }

    // Bundle fallback (:622-662).
    if let Some(ref bundle_draft) = bundle_evaluation {
        let mut fallback = finalize_evaluation(
            deps,
            bundle_draft,
            &package_intent_hash,
            workspace_fingerprint,
        );
        if let Some(reason) = cloud_fallback_reason.as_ref() {
            fallback = with_additional_reason_result(fallback, reason.clone());
            if cloud_fallback_requires_reconnect_copy(reason) {
                fallback = with_cloud_auth_reconnect_copy_result(fallback);
            }
        }
        if let Some(bundle_meta) = bundle_meta.as_ref() {
            if bundle_draft.decision != "monitor" && fallback.cache_status != "cloud-error" {
                let mut cache_workspace_id = workspace_id.clone();
                if cache_workspace_id.is_none() {
                    if let Some(bundle_section) =
                        bundle_payload.get("bundle").and_then(Value::as_object)
                    {
                        if let Some(id) = optional_string(bundle_section.get("workspaceId")) {
                            cache_workspace_id = Some(id);
                        }
                    }
                }
                if let Some(cache_workspace_id) = cache_workspace_id.as_deref() {
                    deps.store_extras.cache_supply_chain_evaluation(
                        cache_workspace_id,
                        &package_intent_hash,
                        bundle_meta
                            .get("feed_snapshot_hash")
                            .map(String::as_str)
                            .unwrap_or(""),
                        bundle_meta
                            .get("policy_hash")
                            .map(String::as_str)
                            .unwrap_or(""),
                        bundle_meta
                            .get("scoring_version")
                            .map(String::as_str)
                            .unwrap_or(""),
                        bundle_meta
                            .get("bundle_version")
                            .map(String::as_str)
                            .unwrap_or(""),
                        &fallback
                            .to_cache_dict()
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                        &now_value,
                    );
                }
            }
        }
        persist_evidence(deps, store, artifact, &fallback, &now_value);
        if fallback.refresh_required {
            let mut event = Map::new();
            event.insert(
                "artifact_id".to_string(),
                Value::String(artifact.artifact_id.clone()),
            );
            event.insert(
                "artifact_name".to_string(),
                Value::String(artifact.name.clone()),
            );
            event.insert(
                "reason".to_string(),
                Value::String("feed_stale".to_string()),
            );
            store.add_event(
                "supply_chain_bundle_refresh_requested",
                &Value::Object(event),
                &now_value,
            );
        }
        return (Some(fallback), None);
    }

    // Heuristic fallback (:663-795).
    let heuristic = heuristic_result(
        deps,
        artifact,
        store,
        &targets,
        workspace_dir,
        external_archive_network_authorized,
        retain_external_archive_blob,
        None,
    );
    let heuristic = match heuristic {
        Some(h) => h,
        None => {
            let fail_closed_unidentified =
                unidentified_packages_fail_closed(deps, store, workspace_dir);
            let verify_registry_identity = cloud_fallback_reason
                .as_ref()
                .and_then(|r| optional_string(r.get("code")))
                .as_deref()
                == Some("cloud_auth_error");
            let fallback_packages = fallback_package_results(
                deps,
                &targets,
                artifact,
                workspace_dir,
                fail_closed_unidentified,
                verify_registry_identity,
            );
            let fallback_decision = fallback_packages
                .iter()
                .map(|p| {
                    optional_string(p.get("decision")).unwrap_or_else(|| "monitor".to_string())
                })
                .max_by_key(|d| decision_rank(d))
                .unwrap_or_else(|| "monitor".to_string());
            let fallback_reasons: Vec<Map<String, Value>> = fallback_packages
                .iter()
                .flat_map(|p| dict_items(p.get("reasons")))
                .collect();
            EvaluationDraft {
                decision: fallback_decision.clone(),
                enforcement: if workspace_id.is_none() {
                    "free_local".to_string()
                } else {
                    "local_fallback".to_string()
                },
                entitlement_state: if workspace_id.is_none() {
                    "free".to_string()
                } else {
                    "premium".to_string()
                },
                cache_status: "miss".to_string(),
                packages: fallback_packages,
                reasons: fallback_reasons,
                matched_rule_id: None,
                exception_id: None,
                refresh_required: false,
                record_monitor_evidence: fallback_decision == "monitor",
                bundle_version: None,
                policy_version: bundle_meta
                    .as_ref()
                    .and_then(|m| m.get("policy_hash").cloned())
                    .unwrap_or_else(|| "local:none".to_string()),
                ..Default::default()
            }
        }
    };
    let mut result = finalize_evaluation(
        deps,
        &heuristic,
        &package_intent_hash,
        workspace_fingerprint,
    );
    if let Some(reason) = cloud_fallback_reason.as_ref() {
        result = with_additional_reason_result(result, reason.clone());
        if cloud_fallback_requires_reconnect_copy(reason) {
            result = with_cloud_auth_reconnect_copy_result(result);
        }
    }
    persist_evidence(deps, store, artifact, &result, &now_value);
    (Some(result), None)
}
