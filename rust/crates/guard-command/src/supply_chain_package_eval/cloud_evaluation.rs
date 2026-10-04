use super::*;

/// `_evaluate_with_cloud` (:1092-1505) — POST the evaluation request, walk the
/// entitlement/fail-closed/reconnect ladder, and merge the cloud decision.
/// Returns `(evaluation, cloud_fallback_reason)`; `None` evaluation means the
/// caller should fall back to local/bundle evaluation.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(super) fn evaluate_with_cloud(
    deps: &SupplyChainEvalDeps<'_>,
    store: &dyn SupplyChainStore,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
    workspace_id: Option<&str>,
    workspace_fingerprint: Option<&str>,
    bundle_meta: Option<&BTreeMap<String, String>>,
    bundle_defer_eligible: bool,
    bundle_decision: Option<&str>,
    bundle_evaluation: Option<&EvaluationDraft>,
) -> (Option<PackageEvalResult>, Option<Map<String, Value>>) {
    if targets.is_empty() || workspace_id.is_none() || workspace_fingerprint.is_none() {
        return (None, None);
    }
    let workspace_fingerprint = workspace_fingerprint.unwrap();
    let workspace_id = workspace_id.unwrap();

    // `resolve_fail_closed_decision` — resolve on demand (:1128-1133).
    let resolve_fail_closed =
        |deps: &SupplyChainEvalDeps<'_>, store: &dyn SupplyChainStore| -> String {
            cloud_fail_closed_decision(deps, store, workspace_dir)
        };

    // `resolve_cloud_entitlement` (:1124-1150) — "unknown state is protected
    // state" fallback when the entitlement seam errors.
    let cloud_entitlement: Map<String, Value> = deps
        .entitlement
        .resolve_package_firewall_entitlement_with_refresh(store)
        .unwrap_or_else(|_| {
            let mut m = Map::new();
            m.insert("allowed".to_string(), Value::Bool(false));
            m.insert(
                "reason".to_string(),
                Value::String("guard_cloud_connect_required".to_string()),
            );
            m.insert("tier".to_string(), Value::String("unknown".to_string()));
            m
        });
    let cloud_protection_is_explicitly_unpaid = |entitlement: &Map<String, Value>| -> bool {
        optional_string(entitlement.get("reason"))
            .map(|r| r.trim().eq_ignore_ascii_case("paid_guard_cloud_required"))
            .unwrap_or(false)
    };

    // `resolve_cloud_failure_decision` (:1690-1704).
    let resolve_cloud_failure_decision =
        |deps: &SupplyChainEvalDeps<'_>, store: &dyn SupplyChainStore| -> String {
            if cloud_protection_is_explicitly_unpaid(&cloud_entitlement) {
                return resolve_fail_closed(deps, store);
            }
            "block".to_string()
        };

    // Resolve auth context + evaluate URL + request payload (:1318-1336).
    let (auth_context, sync_url) = match resolve_guard_sync_context(deps, store, workspace_dir) {
        Ok((ctx, url, _)) => (Value::Object(ctx), url),
        Err(EvalError::Validation(_)) => {
            // `GuardSyncAuthorizationExpiredError` (:1196-1220). When the
            // account is explicitly unpaid and the local fail-closed decision
            // is not a hard block, an expired sign-in degrades to local-only
            // (`can_fallback_from_cloud_failure`) and the cached bundle /
            // heuristic path produces the package decision — the resident just
            // records a `cloud_auth_error` fallback reason. Otherwise emit a
            // fail-closed evaluation; an expired sign-in is a credential-state
            // failure, not a package verdict, so a configured `block` demotes
            // to `ask` to reach the approval queue.
            let can_fallback = cloud_protection_is_explicitly_unpaid(&cloud_entitlement)
                && resolve_fail_closed(deps, store) != "block";
            if can_fallback {
                // Keep the `cloud_auth_error` code (evidence contract) but use
                // the unreachable phrasing: from the operator's seat an expired
                // sign-in means Guard Cloud could not be reached, which is the
                // copy the hook surfaces in `permissionDecisionReason`.
                let reason = cloud_fallback_reason(
                    "cloud_auth_error",
                    "Guard cloud evaluation could not be reached, so Guard used local package intelligence.",
                );
                return (None, Some(reason));
            }
            let mut failure_decision = resolve_cloud_failure_decision(deps, store);
            if failure_decision == "block" && resolve_fail_closed(deps, store) != "block" {
                failure_decision = "ask".to_string();
            }
            let eval_result = cloud_fail_closed_evaluation_full(
                deps,
                "cloud_auth_error",
                "Guard cloud evaluation was not authorized, so this package request needs review.",
                artifact,
                targets,
                workspace_dir,
                Some(workspace_fingerprint),
                bundle_meta,
                &failure_decision,
            );
            return (Some(eval_result), None);
        }
        Err(EvalError::NotFound(_)) => {
            // `GuardSyncNotConfiguredError`/`GuardSyncEndpointUntrustedError`
            // (:1221-1242 in the Python evaluator): sync is not configured for
            // this store. Do NOT attempt a fetch against an empty URL — mirror
            // Python and resolve the not-configured path directly so a fresh
            // non-block bundle (e.g. a cached `warn`) still governs instead of
            // a phantom cloud-transport block.
            let can_fallback = (bundle_defer_eligible && bundle_decision == Some("block"))
                || (cloud_protection_is_explicitly_unpaid(&cloud_entitlement)
                    && resolve_fail_closed(deps, store) != "block");
            if can_fallback {
                let credentials_configured = deps
                    .store_extras
                    .get_oauth_local_credential_health()
                    .get("configured")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if credentials_configured {
                    return (
                        None,
                        Some(cloud_fallback_reason(
                            "cloud_auth_error",
                            "Guard Cloud credentials were unavailable, so Guard used local package intelligence.",
                        )),
                    );
                }
                return (None, None);
            }
            return (
                Some(cloud_fail_closed_evaluation_full(
                    deps,
                    "cloud_auth_error",
                    "Guard Cloud credentials were unavailable. Guard blocked this package request rather than bypassing Cloud package protection.",
                    artifact,
                    targets,
                    workspace_dir,
                    Some(workspace_fingerprint),
                    bundle_meta,
                    &resolve_cloud_failure_decision(deps, store),
                )),
                None,
            );
        }
        Err(_) => {
            // Any other sync-resolution failure mirrors Python's
            // `GuardSyncEndpointUntrustedError` residual (:1221-1229): fail
            // closed — the request needs review rather than a silent bypass.
            return (
                Some(cloud_fail_closed_evaluation_full(
                    deps,
                    "cloud_validation_error",
                    "Guard cloud evaluation endpoint was not trusted, so this package request needs review.",
                    artifact,
                    targets,
                    workspace_dir,
                    Some(workspace_fingerprint),
                    bundle_meta,
                    &resolve_cloud_failure_decision(deps, store),
                )),
                None,
            );
        }
    };
    let evaluate_url = normalized_supply_chain_evaluate_url(deps, &sync_url, workspace_id);
    let request_payload = build_request_payload(
        deps,
        artifact,
        targets,
        workspace_dir,
        workspace_fingerprint,
        bundle_meta
            .and_then(|m| m.get("policy_hash").cloned())
            .unwrap_or_else(|| "local:none".to_string())
            .as_str(),
    );
    let request_data = serde_json::to_vec(&request_payload).unwrap_or_default();
    let response =
        fetch_package_evaluation_response(deps, store, &auth_context, &evaluate_url, &request_data);

    match response {
        Ok(response_payload) => {
            if !response_payload.contains_key("decision") {
                let eval_result = cloud_fail_closed_evaluation_full(
                    deps,
                    "cloud_validation_error",
                    "Guard cloud evaluation returned an invalid response, so this package request needs review.",
                    artifact,
                    targets,
                    workspace_dir,
                    Some(workspace_fingerprint),
                    bundle_meta,
                    &resolve_cloud_failure_decision(deps, store),
                );
                return (Some(eval_result), None);
            }
            if !response_payload
                .get("packages")
                .map(|v| v.is_array())
                .unwrap_or(false)
            {
                let eval_result = cloud_fail_closed_evaluation_full(
                    deps,
                    "cloud_validation_error",
                    "Guard cloud evaluation returned an invalid package payload, so this package request needs review.",
                    artifact,
                    targets,
                    workspace_dir,
                    Some(workspace_fingerprint),
                    bundle_meta,
                    &resolve_cloud_failure_decision(deps, store),
                );
                return (Some(eval_result), None);
            }
            let decision = optional_string(response_payload.get("decision"))
                .map(|d| normalize_bundle_action(&d))
                .unwrap_or_else(|| "monitor".to_string());
            let reasons: Vec<Map<String, Value>> = response_payload
                .get("reasons")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|v| v.as_object().cloned())
                .collect();
            let packages: Vec<Map<String, Value>> = response_payload
                .get("packages")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|v| v.as_object().cloned())
                .map(|item| package_from_cloud_result(&item))
                .collect();
            let draft = EvaluationDraft {
                decision: decision.clone(),
                enforcement: "premium_cloud".to_string(),
                entitlement_state: "premium".to_string(),
                cache_status: "cloud".to_string(),
                packages,
                reasons,
                matched_rule_id: optional_string(response_payload.get("matched_rule_id")),
                exception_id: optional_string(response_payload.get("exception_id")),
                refresh_required: response_payload
                    .get("refresh_required")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                record_monitor_evidence: decision == "monitor",
                bundle_version: bundle_meta.and_then(|m| m.get("bundle_version").cloned()),
                policy_version: bundle_meta
                    .and_then(|m| m.get("policy_hash").cloned())
                    .unwrap_or_else(|| "local:none".to_string()),
                ..Default::default()
            };
            let package_intent_hash = artifact
                .artifact_id
                .rsplit(':')
                .next()
                .map(str::to_string)
                .unwrap_or_else(|| artifact.artifact_id.clone());
            let mut evaluation = finalize_evaluation(
                deps,
                &draft,
                &package_intent_hash,
                Some(workspace_fingerprint),
            );
            if let Some(user_copy) = response_payload.get("user_copy").and_then(Value::as_object) {
                let title = optional_string(user_copy.get("title"));
                let summary = optional_string(user_copy.get("summary"));
                let updated_summary =
                    summary.unwrap_or_else(|| evaluation.user_copy.summary.clone());
                let mut harness_parts =
                    vec![evaluation.risk_summary.clone(), updated_summary.clone()];
                if let Some(next_step) = evaluation.user_copy.next_step.clone() {
                    harness_parts.push(format!("Fix: run `{next_step}`."));
                }
                let policy_action = decision_to_guard_action_variant(&evaluation.policy_action);
                let candidate = SupplyChainUserCopy {
                    title: title.unwrap_or_else(|| evaluation.user_copy.title.clone()),
                    summary: updated_summary,
                    next_step: evaluation.user_copy.next_step.clone(),
                    dashboard_url: evaluation.user_copy.dashboard_url.clone(),
                    harness_message: harness_parts.join(" "),
                };
                evaluation.user_copy = normalize_package_user_copy(&candidate, policy_action);
            }
            if let Some(bundle_draft) = bundle_evaluation {
                if cloud_result_should_defer_to_bundle(&draft, bundle_draft) {
                    let mut merged = finalize_evaluation(
                        deps,
                        bundle_draft,
                        &package_intent_hash,
                        Some(workspace_fingerprint),
                    );
                    merged.reasons.extend(draft.reasons.clone());
                    return (Some(merged), None);
                }
            }
            (Some(evaluation), None)
        }
        Err(error) => {
            if let Some(status) = error.http_status() {
                let fail_closed_eval = cloud_http_fail_closed_evaluation_full(
                    deps,
                    status,
                    artifact,
                    targets,
                    workspace_dir,
                    Some(workspace_fingerprint),
                    bundle_meta,
                    &resolve_cloud_failure_decision(deps, store),
                );
                if let Some(fail_closed) = fail_closed_eval {
                    return (Some(fail_closed), None);
                }
                return (
                    None,
                    Some(cloud_fallback_reason(
                        match status {
                            401 | 403 => "cloud_auth_error",
                            400 | 404 => "cloud_validation_error",
                            _ => "cloud_http_error",
                        },
                        &format!(
                            "Guard cloud evaluation returned HTTP {status}, so Guard fell back to local intelligence."
                        ),
                    )),
                );
            }
            let failure_decision = resolve_cloud_failure_decision(deps, store);
            let is_timeout = deps.guard_sync.is_timeout_error(&error);
            if is_timeout {
                if failure_decision == "block" {
                    return (
                        Some(cloud_fail_closed_evaluation_full(
                            deps,
                            "cloud_timeout",
                            "Guard Cloud evaluation timed out, so this package request is paused for explicit review.",
                            artifact,
                            targets,
                            workspace_dir,
                            Some(workspace_fingerprint),
                            bundle_meta,
                            "ask",
                        )),
                        None,
                    );
                }
                return (
                    None,
                    Some(cloud_fallback_reason(
                        "cloud_timeout",
                        "Guard cloud evaluation timed out, so Guard fell back to local intelligence.",
                    )),
                );
            }
            if failure_decision == "block" {
                return (
                    Some(cloud_fail_closed_evaluation_full(
                        deps,
                        "cloud_http_error",
                        "Guard Cloud evaluation could not be reached, so Guard blocked the install rather than bypassing Cloud package protection.",
                        artifact,
                        targets,
                        workspace_dir,
                        Some(workspace_fingerprint),
                        bundle_meta,
                        "block",
                    )),
                    None,
                );
            }
            (
                None,
                Some(cloud_fallback_reason(
                    "cloud_http_error",
                    "Guard Cloud evaluation could not be reached, so Guard used local package intelligence.",
                )),
            )
        }
    }
}
