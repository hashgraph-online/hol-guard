use super::*;

/// `_finalize_evaluation` (:972-1089).
// supply_chain_package_eval.py:972-1089
pub(super) fn finalize_evaluation(
    deps: &SupplyChainEvalDeps<'_>,
    draft: &EvaluationDraft,
    package_intent_hash: &str,
    workspace_fingerprint: Option<&str>,
) -> PackageEvalResult {
    let packages: Vec<Map<String, Value>> =
        draft.packages.iter().map(with_support_metadata).collect();
    let primary_package: Map<String, Value> = packages.first().cloned().unwrap_or_default();
    let package_display = package_display_name(&primary_package);
    let requested_version = optional_string(primary_package.get("requestedVersion"))
        .or_else(|| optional_string(primary_package.get("resolvedVersion")));
    let package_ref = match &requested_version {
        Some(v) => format!("{package_display}@{v}"),
        None => package_display.clone(),
    };
    let prefix = match draft.decision.as_str() {
        "block" => "HOL Guard blocked",
        "ask" => "HOL Guard paused",
        "warn" => "HOL Guard found risk signals for",
        _ => "HOL Guard recorded",
    };
    let risk_summary = match draft.decision.as_str() {
        "block" => format!("{prefix} `{package_ref}` before install."),
        "ask" => format!("{prefix} `{package_ref}` for review before install."),
        "warn" => format!("{prefix} `{package_ref}` before install."),
        "monitor" => format!("{prefix} `{package_ref}` for continued monitoring."),
        _ => format!("{prefix} `{package_ref}` as trusted by policy."),
    };
    let reason_message = draft
        .reasons
        .first()
        .and_then(|r| optional_string(r.get("message")));
    let mut reason_code = draft
        .reasons
        .first()
        .and_then(|r| optional_string(r.get("code")));
    let mut risk_summary = risk_summary;
    if reason_code.as_deref() == Some("installed_release_reinstall") && draft.decision != "allow" {
        if let Some(restrictive_reason) = draft.reasons.iter().find(|r| {
            optional_string(r.get("code"))
                .map(|c| c != "installed_release_reinstall")
                .unwrap_or(false)
        }) {
            reason_code = optional_string(restrictive_reason.get("code"));
        }
    }
    let policy_action =
        if draft.decision == "ask" && reason_code.as_deref() == Some("external_tarball_source") {
            GuardAction::Review
        } else {
            decision_to_guard_action_variant(&normalize_bundle_action(&draft.decision))
        };
    let source_risk_summaries: HashMap<&str, &str> = HashMap::from([
        (
            "dependency_confusion",
            "matches a known dependency-confusion risk",
        ),
        (
            "malicious_package",
            "matches a known malicious-package risk",
        ),
    ]);
    if let Some(code) = &reason_code {
        if let Some(summary) = source_risk_summaries.get(code.as_str()) {
            if reason_message.is_some() {
                risk_summary = format!("{prefix} `{package_ref}` {summary}.");
            }
        }
    }
    if reason_code.as_deref() == Some("installed_release_reinstall") && draft.decision == "allow" {
        risk_summary = format!(
            "HOL Guard allowed `{package_ref}` because it reinstalls the release already running on this device."
        );
    }
    let fix_command = fix_command(&primary_package);
    let title = match draft.decision.as_str() {
        "block" => "Critical install blocked",
        "ask" => "Review required",
        "warn" => "Proceed with caution",
        "monitor" => "Monitoring this package",
        _ => "Allowed by policy",
    }
    .to_string();
    let mut summary = match draft.decision.as_str() {
        "block" => "Guard blocked this package before install.".to_string(),
        "ask" => "Guard paused this package for review before install.".to_string(),
        "warn" => "Guard found risk signals for this package.".to_string(),
        "monitor" => "Guard recorded this package for continued monitoring.".to_string(),
        _ => "Guard recorded this package as trusted by policy.".to_string(),
    };
    if draft.packages.len() > 1 {
        let others: Vec<String> = draft
            .packages
            .iter()
            .skip(1)
            .take(2)
            .map(package_display_name)
            .collect();
        let others_joined = others.join(", ");
        if !others_joined.is_empty() {
            summary = format!("{summary} Also flagged: {others_joined}.");
        }
    }
    let mut harness_parts = vec![risk_summary.clone()];
    if let Some(msg) = &reason_message {
        harness_parts.push(format!("Reason: {}", ensure_terminal_punctuation(msg)));
    }
    if let Some(cmd) = &fix_command {
        harness_parts.push(format!("Fix: install `{cmd}` or choose a team exception."));
    }
    let user_copy = normalize_package_user_copy(
        &SupplyChainUserCopy {
            title,
            summary,
            next_step: None,
            dashboard_url: None,
            harness_message: harness_parts.join(" "),
        },
        policy_action,
    );
    let evidence_ids: Vec<String> = draft
        .packages
        .iter()
        .filter(|p| should_record_package(p, &draft.decision))
        .map(|p| evidence_id(deps, package_intent_hash, p))
        .collect();
    PackageEvalResult {
        decision: draft.decision.clone(),
        policy_action: policy_action.as_str().to_string(),
        enforcement: draft.enforcement.clone(),
        entitlement_state: draft.entitlement_state.clone(),
        cache_status: draft.cache_status.clone(),
        package_intent_hash: package_intent_hash.to_string(),
        policy_version: draft.policy_version.clone(),
        bundle_version: draft.bundle_version.clone(),
        workspace_fingerprint: workspace_fingerprint.map(str::to_string),
        reasons: draft.reasons.clone(),
        packages,
        risk_summary,
        user_copy,
        matched_rule_id: draft.matched_rule_id.clone(),
        exception_id: draft.exception_id.clone(),
        refresh_required: draft.refresh_required,
        record_monitor_evidence: draft.record_monitor_evidence,
        evidence_ids,
        external_archive_downloads: draft
            .external_archive_downloads
            .iter()
            .map(|d| {
                let mut m = Map::new();
                m.insert("sha256".to_string(), Value::String(d.sha256.clone()));
                m.insert("size".to_string(), Value::Number(d.size.into()));
                m.insert(
                    "source_url".to_string(),
                    Value::String(d.source_url.clone()),
                );
                m.insert("final_url".to_string(), Value::String(d.final_url.clone()));
                m
            })
            .collect(),
        external_archive_source_hashes: draft.external_archive_source_hashes.clone(),
    }
}

/// `finalize_evaluation` as a method on `EvaluationDraft` for ergonomic
/// parity with the Python `_EvaluationDraft` → `PackageRequestEvaluation`
/// conversion.
// supply_chain_package_eval.py:972-1089
impl EvaluationDraft {
    /// `_finalize_evaluation` (:972-1089) — promote this draft into the final
    /// `PackageRequestEvaluation` using the same logic as the Python helper.
    pub fn finalize(
        &self,
        deps: &SupplyChainEvalDeps<'_>,
        package_intent_hash: &str,
        workspace_fingerprint: Option<&str>,
    ) -> PackageEvalResult {
        finalize_evaluation(deps, self, package_intent_hash, workspace_fingerprint)
    }
}
