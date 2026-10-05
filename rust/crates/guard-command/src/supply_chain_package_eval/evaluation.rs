use super::*;

// ---------------------------------------------------------------------------
// Evaluation draft + dependency bundle
// ---------------------------------------------------------------------------

/// `_EvaluationDraft` dataclass mirror (:962-975) — the intermediate mutable
/// evaluation state folded into a `PackageRequestEvaluation` by
/// `_finalize_evaluation` (:978).
#[derive(Debug, Clone, Default)]
pub struct EvaluationDraft {
    pub decision: String,
    pub enforcement: String,
    pub entitlement_state: String,
    pub cache_status: String,
    pub packages: Vec<Map<String, Value>>,
    pub reasons: Vec<Map<String, Value>>,
    pub matched_rule_id: Option<String>,
    pub exception_id: Option<String>,
    pub refresh_required: bool,
    pub record_monitor_evidence: bool,
    pub bundle_version: Option<String>,
    pub policy_version: String,
    pub external_archive_downloads: Vec<RestrictedArchiveDownload>,
    pub external_archive_source_hashes: Vec<String>,
}

/// Aggregated dependency seams for the evaluator — one injection point so
/// ported fns take `deps: &SupplyChainEvalDeps` instead of a dozen trait
/// objects. Mirrors the Python module-level imports (:31-110).
pub struct SupplyChainEvalDeps<'a> {
    pub guard_sync: &'a dyn GuardSyncRunnerApi,
    pub lockfile: &'a dyn LockfileParseApi,
    pub bundle: &'a dyn SupplyChainBundleApi,
    pub semver: &'a dyn JsSemverApi,
    pub risk: &'a dyn RiskDetectApi,
    pub manifest: &'a dyn ManifestDepsApi,
    pub identity: &'a dyn PackageIdentityApi,
    pub archive: &'a dyn RestrictedArchiveApi,
    pub native_archive: &'a dyn NativeArchiveApi,
    pub workspace_io: &'a dyn WorkspaceIoApi,
    pub store_extras: &'a dyn StoreExtrasApi,
    pub entitlement: &'a dyn EntitlementRefreshApi,
    pub config: &'a dyn ConfigLoaderApi,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// `evaluate_package_request_artifact` (:314) — evaluate one package-request
/// artifact against local bundle/cache/risk signals and return the typed
/// result. `now` is the ISO-8601 UTC timestamp the Python signature accepts.
///
/// TODO: implement — wraps `_evaluate_package_request_artifact_uncached`
/// (:337) inside the `_LOCKFILE_PARSE_CACHE` contextvar scope.
pub fn evaluate_package_request_artifact(
    artifact: &GuardArtifact,
    store: &dyn SupplyChainStore,
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: Option<&Path>,
    now: Option<&str>,
    external_archive_network_authorized: bool,
    retain_external_archive_blob: bool,
) -> EvalResult<PackageEvalResult> {
    // Python wraps the call in `_LOCKFILE_PARSE_CACHE` contextvar scope; the
    // Rust equivalent is the seam-owned cache inside `deps.lockfile`, so the
    // wrapper is a straight delegation.
    let (result, error) = evaluate_package_request_artifact_uncached(
        deps,
        artifact,
        store,
        workspace_dir,
        now,
        external_archive_network_authorized,
        retain_external_archive_blob,
    );
    match (result, error) {
        (Some(result), _) => Ok(result),
        (None, Some(message)) => Err(EvalError::Internal(message)),
        (None, None) => Err(EvalError::Internal(
            "evaluate_package_request_artifact: no result".into(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Batch A ports — decision/action normalization, cache reuse, draft plumbing.
// Each fn carries a `// supply_chain_package_eval.py:N-M` anchor comment.
// ---------------------------------------------------------------------------

/// `decision_to_guard_action` — map a decision string to a `GuardAction`.
///
/// Derived from `_DECISION_TO_GUARD_ACTION` (:154-160):
///   `{"allow": "allow", "monitor": "allow", "warn": "warn",
///     "ask": "require-reapproval", "block": "block"}`.
// supply_chain_package_eval.py:154-160
pub(super) fn decision_to_guard_action_variant(decision: &str) -> GuardAction {
    let mapped = decision_to_guard_action()
        .get(decision)
        .copied()
        .unwrap_or("allow");
    match mapped {
        "warn" => GuardAction::Warn,
        "review" => GuardAction::Review,
        "require-reapproval" => GuardAction::RequireReapproval,
        "sandbox-required" => GuardAction::SandboxRequired,
        "block" => GuardAction::Block,
        _ => GuardAction::Allow,
    }
}

/// `_decision_rank` (:4945-4946).
// supply_chain_package_eval.py:4945-4946
#[allow(dead_code)]
pub(super) fn decision_rank(value: &str) -> u8 {
    decision_rank_map().get(value).copied().unwrap_or(1)
}

/// `_severity_rank_value` (:4828-4829).
// supply_chain_package_eval.py:4828-4829
#[allow(dead_code)]
pub(super) fn severity_rank_value(value: &str) -> u8 {
    severity_rank_map()
        .get(value.trim().to_ascii_lowercase().as_str())
        .copied()
        .unwrap_or_else(|| severity_rank_map()["unknown"])
}

/// `_reason_severity` (:5044-5052).
// supply_chain_package_eval.py:5044-5052
#[allow(dead_code)]
pub(super) fn reason_severity(package: &Map<String, Value>) -> String {
    if let Some(reasons) = package.get("reasons") {
        if let Some(items) = reasons.as_array() {
            for item in items {
                if let Some(obj) = item.as_object() {
                    if let Some(severity) = optional_string(obj.get("severity")) {
                        return severity;
                    }
                }
            }
        }
    }
    "unknown".to_string()
}

/// `_normalize_package_name` (:4998-5002).
// supply_chain_package_eval.py:4998-5002
#[allow(dead_code)]
pub(super) fn normalize_package_name(
    deps: &SupplyChainEvalDeps<'_>,
    ecosystem: &str,
    package_name: &str,
) -> String {
    deps.identity
        .normalize_qualified_package_name(ecosystem, package_name)
        .unwrap_or_else(|_| package_name.trim().to_string())
}

/// `_normalize_evaluation_timestamp` — parse an ISO-8601 timestamp string
/// into epoch seconds. Returns `None` on empty or unparseable input.
///
/// Derived: wraps `local_supply_chain::parse_timestamp` (:4533-4547 in
/// `local_supply_chain.py`) which normalizes "Z" → "+00:00" and converts to
/// UTC epoch seconds.
// supply_chain_package_eval.py:2803-2807
#[allow(dead_code)]
pub(super) fn normalize_evaluation_timestamp(now_value: &str) -> Option<f64> {
    crate::local_supply_chain::parse_timestamp(now_value).map(|t| t.unix_seconds() as f64)
}

/// `_parse_evaluation_timestamp` (:2803-2807) — alias kept for callers that
/// expect the private name.
// supply_chain_package_eval.py:2803-2807
#[allow(dead_code)]
pub(super) fn parse_evaluation_timestamp(now_value: &str) -> Option<f64> {
    normalize_evaluation_timestamp(now_value)
}

/// `_artifact_has_flag` (:3489-3491).
// supply_chain_package_eval.py:3489-3491
#[allow(dead_code)]
pub(super) fn artifact_has_flag(artifact: &GuardArtifact, flag: &str) -> bool {
    artifact
        .metadata
        .get("flags")
        .and_then(Value::as_array)
        .is_some_and(|flags| flags.iter().any(|v| v.as_str() == Some(flag)))
}

/// `_has_non_empty_string_item` (:788-791).
// supply_chain_package_eval.py:788-791
#[allow(dead_code)]
pub(super) fn has_non_empty_string_item(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .any(|v| matches!(v, Value::String(s) if !s.is_empty())),
        _ => false,
    }
}

/// `_artifact_has_package_material` (:780-785).
// supply_chain_package_eval.py:780-785
#[allow(dead_code)]
pub(super) fn artifact_has_package_material(
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
) -> bool {
    if !targets.is_empty() {
        return true;
    }
    has_non_empty_string_item(artifact.metadata.get("manifest_paths"))
        || has_non_empty_string_item(artifact.metadata.get("lockfile_paths"))
}

/// `_empty_package_material_result` (:794-827).
// supply_chain_package_eval.py:794-827
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(super) fn empty_package_material_result(
    _artifact: &GuardArtifact,
    workspace_id: Option<&str>,
    bundle_meta: Option<&Map<String, Value>>,
    package_intent_hash: &str,
    workspace_fingerprint: Option<&str>,
) -> PackageEvalResult {
    let mut reason_map = Map::new();
    reason_map.insert(
        "code".to_string(),
        Value::String("no_package_material".into()),
    );
    reason_map.insert(
        "message".to_string(),
        Value::String(
            "Guard found no package targets, manifests, or lockfiles to evaluate for this request."
                .into(),
        ),
    );
    reason_map.insert("severity".to_string(), Value::String("unknown".into()));
    reason_map.insert("source".to_string(), Value::String("guard-local".into()));
    let reasons = vec![reason_map];
    let decision = "monitor".to_string();
    let policy_action = decision_to_guard_action_variant(&decision);
    let title = "No package material".to_string();
    let summary =
        "Guard found no package targets, manifests, or lockfiles to evaluate.".to_string();
    let enforcement = if workspace_id.is_none() {
        "free_local"
    } else {
        "local_fallback"
    };
    let entitlement_state = if workspace_id.is_none() {
        "free"
    } else {
        "premium"
    };
    let policy_version = bundle_meta
        .and_then(|m| optional_string(m.get("policy_hash")))
        .unwrap_or_else(|| "local:none".to_string());
    let bundle_version = bundle_meta.and_then(|m| optional_string(m.get("bundle_version")));
    let user_copy = SupplyChainUserCopy {
        title: title.clone(),
        summary: summary.clone(),
        next_step: None,
        dashboard_url: None,
        harness_message: format!("{summary} No action needed."),
    };
    PackageEvalResult {
        decision,
        policy_action: policy_action.as_str().to_string(),
        enforcement: enforcement.to_string(),
        entitlement_state: entitlement_state.to_string(),
        cache_status: "empty".to_string(),
        package_intent_hash: package_intent_hash.to_string(),
        policy_version,
        bundle_version,
        workspace_fingerprint: workspace_fingerprint.map(str::to_string),
        reasons,
        packages: Vec::new(),
        risk_summary: summary,
        user_copy,
        matched_rule_id: None,
        exception_id: None,
        refresh_required: false,
        record_monitor_evidence: false,
        evidence_ids: Vec::new(),
        external_archive_downloads: Vec::new(),
        external_archive_source_hashes: Vec::new(),
    }
}

/// `_empty_evaluation` — derived: builds a minimal allow result with no
/// reasons and no packages, used when the request artifact yields nothing to
/// evaluate.
// supply_chain_package_eval.py:794-827
#[allow(dead_code)]
pub(super) fn empty_evaluation(
    _artifact: &GuardArtifact,
    package_intent_hash: &str,
    workspace_fingerprint: Option<&str>,
) -> PackageEvalResult {
    let decision = "allow".to_string();
    let policy_action = decision_to_guard_action_variant(&decision);
    PackageEvalResult {
        decision,
        policy_action: policy_action.as_str().to_string(),
        enforcement: "free_local".to_string(),
        entitlement_state: "free".to_string(),
        cache_status: "empty".to_string(),
        package_intent_hash: package_intent_hash.to_string(),
        policy_version: "local:none".to_string(),
        bundle_version: None,
        workspace_fingerprint: workspace_fingerprint.map(str::to_string),
        reasons: Vec::new(),
        packages: Vec::new(),
        risk_summary: "HOL Guard recorded the request as trusted by policy.".to_string(),
        user_copy: SupplyChainUserCopy {
            title: "Request allowed".to_string(),
            summary: "HOL Guard recorded the request as trusted by policy.".to_string(),
            next_step: None,
            dashboard_url: None,
            harness_message: "HOL Guard recorded the request as trusted by policy.".to_string(),
        },
        matched_rule_id: None,
        exception_id: None,
        refresh_required: false,
        record_monitor_evidence: false,
        evidence_ids: Vec::new(),
        external_archive_downloads: Vec::new(),
        external_archive_source_hashes: Vec::new(),
    }
}

/// `_no_change_evaluation` — derived: produces a `monitor`-decision result
/// when the package material has not changed since the last evaluation.
// supply_chain_package_eval.py:794-827
#[allow(dead_code)]
pub(super) fn no_change_evaluation(
    _artifact: &GuardArtifact,
    package_intent_hash: &str,
    workspace_fingerprint: Option<&str>,
    matched_rule_id: Option<&str>,
    exception_id: Option<&str>,
) -> PackageEvalResult {
    let decision = "monitor".to_string();
    let policy_action = decision_to_guard_action_variant(&decision);
    PackageEvalResult {
        decision,
        policy_action: policy_action.as_str().to_string(),
        enforcement: "local_fallback".to_string(),
        entitlement_state: "premium".to_string(),
        cache_status: "empty".to_string(),
        package_intent_hash: package_intent_hash.to_string(),
        policy_version: "local:none".to_string(),
        bundle_version: None,
        workspace_fingerprint: workspace_fingerprint.map(str::to_string),
        reasons: Vec::new(),
        packages: Vec::new(),
        risk_summary: "HOL Guard recorded the request for continued monitoring.".to_string(),
        user_copy: SupplyChainUserCopy {
            title: "Request monitored".to_string(),
            summary: "HOL Guard recorded the request for continued monitoring.".to_string(),
            next_step: None,
            dashboard_url: None,
            harness_message: "HOL Guard recorded the request for continued monitoring.".to_string(),
        },
        matched_rule_id: matched_rule_id.map(str::to_string),
        exception_id: exception_id.map(str::to_string),
        refresh_required: false,
        record_monitor_evidence: true,
        evidence_ids: Vec::new(),
        external_archive_downloads: Vec::new(),
        external_archive_source_hashes: Vec::new(),
    }
}

/// `_evaluation_has_reason_code` (:851-855 on `_cached_eval_has_reason_code`
/// but operates on a `PackageRequestEvaluation` payload map).
// supply_chain_package_eval.py:851-855
#[allow(dead_code)]
pub(super) fn evaluation_has_reason_code(evaluation: &Value, code: &str) -> bool {
    evaluation
        .get("reasons")
        .and_then(Value::as_array)
        .map(|v| v.as_slice())
        .unwrap_or(&[])
        .iter()
        .any(|r| {
            r.as_object()
                .and_then(|o| o.get("code"))
                .and_then(Value::as_str)
                == Some(code)
        })
}

/// `_cached_eval_has_reason_code` (:851-855).
// supply_chain_package_eval.py:851-855
#[allow(dead_code)]
pub(super) fn cached_eval_has_reason_code(cached: &Map<String, Value>, code: &str) -> bool {
    cached
        .get("reasons")
        .and_then(Value::as_array)
        .map(|v| v.as_slice())
        .unwrap_or(&[])
        .iter()
        .any(|r| {
            r.as_object()
                .and_then(|o| o.get("code"))
                .and_then(Value::as_str)
                == Some(code)
        })
}

/// `_cached_supply_chain_eval_is_reusable` (:830-848).
// supply_chain_package_eval.py:830-848
#[allow(dead_code)]
pub(super) fn cached_supply_chain_eval_is_reusable(
    cached: &Map<String, Value>,
    now_timestamp: Option<f64>,
) -> bool {
    if !cached_eval_has_reason_code(cached, "cloud_validation_error") {
        return true;
    }
    let Some(now_ts) = now_timestamp else {
        return false;
    };
    let updated_at = match optional_string(cached.get("updated_at")) {
        Some(v) => v,
        None => return false,
    };
    let cached_at = match parse_evaluation_timestamp(&updated_at) {
        Some(v) => v,
        None => return false,
    };
    (now_ts - cached_at) <= (15 * 60) as f64
}

/// `_cache_reusable_cloud_validation_error` (:858-882).
// supply_chain_package_eval.py:858-882
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(super) fn cache_reusable_cloud_validation_error(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_id: Option<&str>,
    bundle_meta: Option<&Map<String, Value>>,
    package_intent_hash: &str,
    evaluation: &PackageEvalResult,
    now: &str,
) {
    let Some(ws) = workspace_id else { return };
    let Some(meta) = bundle_meta else { return };
    if !evaluation_has_reason_code(&evaluation.to_cache_dict(), "cloud_validation_error") {
        return;
    }
    let decision_map = match evaluation.to_cache_dict() {
        Value::Object(m) => m,
        _ => return,
    };
    deps.store_extras.cache_supply_chain_evaluation(
        ws,
        package_intent_hash,
        &optional_string(meta.get("feed_snapshot_hash")).unwrap_or_default(),
        &optional_string(meta.get("policy_hash")).unwrap_or_default(),
        &optional_string(meta.get("scoring_version")).unwrap_or_default(),
        &optional_string(meta.get("bundle_version")).unwrap_or_default(),
        &decision_map,
        now,
    );
}
