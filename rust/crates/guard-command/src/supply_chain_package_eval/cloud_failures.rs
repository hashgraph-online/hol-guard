use super::*;

// ---------------------------------------------------------------------------
// Batch B — cloud fail-closed, bundle eval, heuristic eval, evidence persist,
// target resolution, lockfile parse results, request payload helpers.
// ---------------------------------------------------------------------------

/// `_cloud_http_fail_closed_evaluation` (:1543-1593) — build the fail-closed
/// draft for a cloud HTTP/connect failure. `payload` is the parsed
/// `errorPayload` body (may be absent); `status` is the HTTP status code.
// supply_chain_package_eval.py:1543-1593
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(super) fn cloud_http_fail_closed_evaluation(
    status: u16,
    payload: Option<&Map<String, Value>>,
    decision: &str,
) -> EvaluationDraft {
    let code = payload
        .and_then(|p| optional_string(p.get("code")))
        .unwrap_or_else(|| format!("cloud_http_{status}"));
    let message = payload
        .and_then(|p| optional_string(p.get("message")))
        .unwrap_or_else(|| "Guard Cloud evaluation request failed.".to_string());
    let mut reason = Map::new();
    reason.insert("code".to_string(), Value::String(code));
    reason.insert("message".to_string(), Value::String(message));
    reason.insert("severity".to_string(), Value::String("high".to_string()));
    reason.insert(
        "source".to_string(),
        Value::String("cloud_evaluate".to_string()),
    );
    if let Some(p) = payload {
        if let Some(eid) = optional_string(p.get("evaluationId")) {
            reason.insert("evaluationId".to_string(), Value::String(eid));
        }
    }
    EvaluationDraft {
        decision: decision.to_string(),
        enforcement: "cloud_fail_closed".to_string(),
        entitlement_state: "premium".to_string(),
        cache_status: "unavailable".to_string(),
        reasons: vec![reason],
        refresh_required: false,
        record_monitor_evidence: decision == "monitor",
        policy_version: "cloud:http".to_string(),
        ..Default::default()
    }
}

/// `_cloud_fail_closed_evaluation` (:1596-1655) — cloud-unavailable fallback
/// evaluation (narrow form retained for existing callers; this wrapper builds
/// one fail-closed draft without artifact/workspace context).
// supply_chain_package_eval.py:1596-1655
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(super) fn cloud_fail_closed_evaluation(
    decision: &str,
    reason_code: &str,
    message: &str,
) -> EvaluationDraft {
    let mut reason = Map::new();
    reason.insert("code".to_string(), Value::String(reason_code.to_string()));
    reason.insert("message".to_string(), Value::String(message.to_string()));
    reason.insert("severity".to_string(), Value::String("high".to_string()));
    reason.insert(
        "source".to_string(),
        Value::String("cloud_evaluate".to_string()),
    );
    EvaluationDraft {
        decision: decision.to_string(),
        enforcement: "cloud_fail_closed".to_string(),
        entitlement_state: "premium".to_string(),
        cache_status: "unavailable".to_string(),
        reasons: vec![reason],
        refresh_required: false,
        record_monitor_evidence: decision == "monitor",
        policy_version: "cloud:offline".to_string(),
        ..Default::default()
    }
}

/// `_cloud_fail_closed_evaluation` (:1596-1655) — full form matching the
/// Python signature; produces a finalized `PackageRequestEvaluation` carrying
/// heuristic per-target results (or the unidentified-package fallback) plus
/// the cloud fallback reason.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(super) fn cloud_fail_closed_evaluation_full(
    deps: &SupplyChainEvalDeps<'_>,
    code: &str,
    message: &str,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
    workspace_fingerprint: Option<&str>,
    bundle_meta: Option<&BTreeMap<String, String>>,
    fail_closed_decision: &str,
) -> PackageEvalResult {
    let reason = cloud_fallback_reason(code, message);
    let decision = if fail_closed_decision == "block" {
        "block"
    } else {
        "ask"
    };
    let severity = if decision == "block" {
        "critical"
    } else {
        "high"
    };
    let mut packages: Vec<Map<String, Value>> = targets
        .iter()
        .map(|target| heuristic_package_result(target, decision, code, message, severity))
        .collect();
    if packages.is_empty() {
        packages = fallback_package_results(deps, targets, artifact, workspace_dir, false, false)
            .into_iter()
            .map(|mut package| {
                package.insert("decision".to_string(), Value::String(decision.to_string()));
                package.insert(
                    "reasons".to_string(),
                    Value::Array(vec![Value::Object(reason.clone())]),
                );
                package
            })
            .collect();
    }
    let policy_version = bundle_meta
        .and_then(|m| m.get("policy_hash").cloned())
        .unwrap_or_else(|| "local:none".to_string());
    let bundle_version = bundle_meta.and_then(|m| m.get("bundle_version").cloned());
    let draft = EvaluationDraft {
        decision: decision.to_string(),
        enforcement: "premium_cloud".to_string(),
        entitlement_state: "premium".to_string(),
        cache_status: "cloud-error".to_string(),
        packages,
        reasons: vec![reason],
        matched_rule_id: None,
        exception_id: None,
        refresh_required: false,
        record_monitor_evidence: false,
        bundle_version,
        policy_version,
        ..Default::default()
    };
    let package_intent_hash = artifact
        .artifact_id
        .rsplit(':')
        .next()
        .map(str::to_string)
        .unwrap_or_else(|| artifact.artifact_id.clone());
    let evaluation = finalize_evaluation(deps, &draft, &package_intent_hash, workspace_fingerprint);
    if code == "cloud_auth_error" {
        with_cloud_auth_reconnect_copy_result(evaluation)
    } else {
        evaluation
    }
}

/// `_with_cloud_auth_reconnect_copy` (:1658-1683) — append a reconnect prompt
/// to the user copy when the cloud auth token is expired/invalid.
// supply_chain_package_eval.py:1658-1683
#[allow(dead_code)]
pub(super) fn with_cloud_auth_reconnect_copy(
    mut draft: EvaluationDraft,
    reconnect_required: bool,
) -> EvaluationDraft {
    if !reconnect_required {
        return draft;
    }
    draft.reasons.iter_mut().for_each(|reason| {
        reason.insert("requires_reconnect".to_string(), Value::Bool(true));
    });
    draft
}

/// `_cloud_fallback_requires_reconnect_copy` (:1686-1687).
// supply_chain_package_eval.py:1686-1687
#[allow(dead_code)]
pub(super) fn cloud_fallback_requires_reconnect_copy(reason: &Map<String, Value>) -> bool {
    optional_string(reason.get("code")).as_deref() == Some("cloud_auth_error")
}

/// `_cloud_fail_closed_decision` (:1690-1697).
// supply_chain_package_eval.py:1690-1697
#[allow(dead_code)]
pub(super) fn cloud_fail_closed_decision(
    deps: &SupplyChainEvalDeps<'_>,
    store: &dyn SupplyChainStore,
    workspace_dir: Option<&Path>,
) -> String {
    let config = deps
        .config
        .load_guard_config(store.guard_home(), workspace_dir, false)
        .unwrap_or_else(|_| GuardConfig::default());
    let cloud_action =
        resolve_risk_action(&config, Some("cloud_advisory"), None).unwrap_or_default();
    if config.security_level == "strict" || config.security_level == "paranoid" {
        return "block".to_string();
    }
    if cloud_action == "block" {
        return "block".to_string();
    }
    "ask".to_string()
}

/// `_unidentified_packages_fail_closed` (:1700-1702).
// supply_chain_package_eval.py:1700-1702
#[allow(dead_code)]
pub(super) fn unidentified_packages_fail_closed(
    deps: &SupplyChainEvalDeps<'_>,
    store: &dyn SupplyChainStore,
    workspace_dir: Option<&Path>,
) -> bool {
    let config = deps
        .config
        .load_guard_config(store.guard_home(), workspace_dir, false)
        .unwrap_or_else(|_| GuardConfig::default());
    config.security_level == "strict" || config.security_level == "paranoid"
}

/// `_unidentified_package_decision` (:1705-1716).
// supply_chain_package_eval.py:1705-1716
#[allow(dead_code)]
pub(super) fn unidentified_package_decision(
    ecosystem: &str,
    fail_closed: bool,
    identity_resolved: bool,
) -> String {
    let support = crate::local_supply_chain::ecosystem_support_metadata(ecosystem);
    let support_level = value_str(&Value::Object(support), "support_level")
        .unwrap_or("monitor-only")
        .to_string();
    if support_level != "protected" && support_level != "beta" {
        return "monitor".to_string();
    }
    if fail_closed {
        return "block".to_string();
    }
    if identity_resolved {
        "monitor".to_string()
    } else {
        "ask".to_string()
    }
}
