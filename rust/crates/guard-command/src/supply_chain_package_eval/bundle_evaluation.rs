use super::*;

/// `_evaluate_with_bundle` (:1719-1877) — evaluate all targets against a
/// cached/advisory bundle payload and produce a draft.
// supply_chain_package_eval.py:1719-1877
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(super) fn evaluate_with_bundle(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
    bundle_response: &SupplyChainBundleResponse,
    workspace_dir: Option<&Path>,
    workspace_id: Option<&str>,
    now_timestamp: Option<f64>,
) -> Option<EvaluationDraft> {
    let bundle_payload = bundle_response.to_dict();
    let bundle_obj = bundle_payload.as_object().cloned().unwrap_or_default();
    let bundle_meta_map = deps
        .bundle
        .supply_chain_bundle_meta(&bundle_obj)
        .unwrap_or_default();
    let bundle_meta = |k: &str| bundle_meta_map.get(k).cloned().unwrap_or_default();

    let mut refresh_required = false;
    let mut packages: Vec<Map<String, Value>> = Vec::new();
    let lockfile_versions = lockfile_dependency_versions(deps, workspace_dir, artifact, targets);
    for target in targets {
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
        let resolved_version = resolved_target_version(deps, target, &lockfile_versions);
        let package_match = resolved_version
            .as_deref()
            .and_then(|version| bundle_package(bundle_response, target, version));
        let resolved_npm_version = resolved_version.clone().filter(|_| {
            (optional_string(target.get("ecosystem"))
                .as_deref()
                .unwrap_or("npm"))
                == "npm"
        });
        let policy_target =
            target_for_resolved_npm_policy_match(target, resolved_npm_version.as_deref());
        let matched_rule = matching_policy_rule(bundle_response, &policy_target);
        if let Some(rule) = matched_rule {
            let decision =
                normalize_bundle_action(rule.get("action").and_then(Value::as_str).unwrap_or(""));
            let policy = policy_package_result(&policy_target, &decision, &rule);
            let package_result =
                bind_resolved_npm_policy_result(policy, resolved_npm_version.as_deref());
            packages.push(package_result);
            continue;
        }
        if let Some(confusion) = dependency_confusion_policy_package_result(bundle_response, target)
        {
            packages.push(confusion);
            continue;
        }
        let Some(resolved_version) = resolved_version else {
            continue;
        };
        let offline = deps
            .bundle
            .evaluate_cached_supply_chain_bundle(
                bundle_response,
                &optional_string(target.get("package_name"))
                    .or_else(|| optional_string(target.get("name")))
                    .unwrap_or_default(),
                Some(resolved_version.as_str()),
                optional_string(target.get("ecosystem")).as_deref(),
                now_timestamp,
            )
            .unwrap_or_default();
        let offline_action = optional_string(offline.get("action")).unwrap_or_default();
        let offline_deny = offline.get("emergency_deny") == Some(&Value::Bool(true));
        if offline_deny && offline_action == "block" {
            let mut pkg = Map::new();
            pkg.insert("decision".to_string(), Value::String("block".into()));
            pkg.insert(
                "message".to_string(),
                Value::String(emergency_deny_bundle_message(target)),
            );
            packages.push(pkg);
            continue;
        }
        if package_match.is_none() {
            if offline_action == "block" {
                let empty_match: Map<String, Value> = Map::new();
                packages.push(block_package_from_offline(
                    &offline,
                    bundle_response,
                    &empty_match,
                    None,
                ));
            }
            continue;
        }
        refresh_required = refresh_required || offline.get("stale") == Some(&Value::Bool(true));
        if let Some(package) = bundle_package_result(
            deps,
            target,
            package_match.as_ref().unwrap(),
            bundle_response,
            resolved_npm_version.as_deref(),
            now_timestamp,
        ) {
            packages.push(package);
        }
    }
    let _direct_identities: HashSet<String> = packages
        .iter()
        .map(|p| {
            let id = result_package_identity(deps, p);
            format!("{id:?}")
        })
        .collect();
    for transitive in transitive_lockfile_results(deps, workspace_dir, artifact, targets) {
        packages.push(transitive);
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
    let winning_rule_id = optional_string(packages[0].get("ruleId"));
    let reasons: Vec<Map<String, Value>> = packages
        .iter()
        .flat_map(|p| dict_items(p.get("reasons")))
        .collect();
    let first_decision_is_allow = packages
        .first()
        .and_then(|p| p.get("decision"))
        .and_then(Value::as_str)
        == Some("allow");
    Some(EvaluationDraft {
        decision,
        enforcement: if winning_rule_id.is_some() {
            "policy_override".to_string()
        } else {
            "offline_cached".to_string()
        },
        entitlement_state: if workspace_id.is_some() {
            "premium".to_string()
        } else {
            "free".to_string()
        },
        cache_status: if refresh_required {
            "stale".to_string()
        } else {
            "miss".to_string()
        },
        packages,
        reasons,
        matched_rule_id: winning_rule_id.clone(),
        exception_id: if winning_rule_id.is_some() && first_decision_is_allow {
            winning_rule_id
        } else {
            None
        },
        refresh_required,
        record_monitor_evidence: false,
        bundle_version: Some(bundle_meta("bundle_version")),
        policy_version: bundle_meta("policy_hash"),
        ..Default::default()
    })
}
