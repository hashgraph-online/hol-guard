use super::*;

/// `_lockfile_parse_results` (:2335-2344).
// supply_chain_package_eval.py:2335-2344
#[allow(dead_code)]
pub(super) fn lockfile_parse_results(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: &Path,
    artifact: &GuardArtifact,
) -> Vec<LockfileParseResult> {
    let lockfile_paths = artifact.metadata.get("lockfile_paths");
    deps.lockfile.collect_lockfile_parse_results(
        Some(workspace_dir),
        lockfile_paths,
        lockfile_parse_budget_seconds().unwrap_or(0.5),
        &|path, bytes| parse_lockfile_text_result(deps, path, bytes),
    )
}

/// `_parse_lockfile_text_result` (:2347-2370) — dispatch to the per-format
/// lockfile parser over raw bytes.
// supply_chain_package_eval.py:2347-2370
#[allow(dead_code)]
pub(super) fn parse_lockfile_text_result(
    deps: &SupplyChainEvalDeps<'_>,
    path: &str,
    text: &[u8],
) -> LockfileParseResult {
    deps.lockfile
        .parse_lockfile_with_budget(path, text, LOCKFILE_PARSE_BUDGET_SECONDS)
}

/// `_lockfile_parse_budget_seconds` (:2373-2378).
// supply_chain_package_eval.py:2373-2378
#[allow(dead_code)]
pub(super) fn lockfile_parse_budget_seconds() -> Option<f64> {
    Some(LOCKFILE_PARSE_BUDGET_SECONDS)
}

/// `_first_incomplete_lockfile_result` (:2381-2385).
// supply_chain_package_eval.py:2381-2385
#[allow(dead_code)]
pub(super) fn first_incomplete_lockfile_result(
    results: &[LockfileParseResult],
) -> Option<&LockfileParseResult> {
    results.iter().find(|r| !r.complete)
}

/// `_finalize_incomplete_lockfile_evaluation` (:2388-2431).
// supply_chain_package_eval.py:2388-2431
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(super) fn finalize_incomplete_lockfile_evaluation(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    _store: &dyn SupplyChainStore,
    parse_result: &LockfileParseResult,
    _workspace_id: Option<&str>,
    workspace_fingerprint: &str,
    _now: &str,
) -> PackageEvalResult {
    let package = incomplete_lockfile_package_result(artifact, parse_result);
    let mut reasons = Vec::new();
    let mut r = Map::new();
    r.insert(
        "code".to_string(),
        Value::String("lockfile_parse_incomplete".to_string()),
    );
    r.insert(
        "message".to_string(),
        Value::String(
            optional_string(
                parse_result
                    .error_reason
                    .clone()
                    .map(Value::String)
                    .as_ref(),
            )
            .unwrap_or_else(|| "Lockfile could not be parsed completely.".to_string()),
        ),
    );
    r.insert("severity".to_string(), Value::String("high".to_string()));
    reasons.push(r);
    let mut draft = EvaluationDraft {
        decision: "block".to_string(),
        enforcement: "free_local".to_string(),
        entitlement_state: "free".to_string(),
        cache_status: "miss".to_string(),
        packages: vec![package],
        reasons,
        refresh_required: false,
        record_monitor_evidence: false,
        bundle_version: None,
        policy_version: "local:none".to_string(),
        ..Default::default()
    };
    draft.refresh_required = false;
    finalize_evaluation(
        deps,
        &draft,
        &artifact.artifact_id,
        Some(workspace_fingerprint),
    )
}

/// `_incomplete_lockfile_package_result` (:2434-2456).
// supply_chain_package_eval.py:2434-2456
#[allow(dead_code)]
pub(super) fn incomplete_lockfile_package_result(
    artifact: &GuardArtifact,
    parse_result: &LockfileParseResult,
) -> Map<String, Value> {
    let target = incomplete_lockfile_fallback_target(parse_result);
    let mut package = Map::new();
    package.insert("decision".to_string(), Value::String("block".into()));
    package.insert(
        "ecosystem".to_string(),
        target
            .get("ecosystem")
            .cloned()
            .unwrap_or(Value::String("npm".into())),
    );
    package.insert(
        "name".to_string(),
        target
            .get("name")
            .cloned()
            .unwrap_or(Value::String("unresolved-lockfile".into())),
    );
    package.insert(
        "namespace".to_string(),
        target.get("namespace").cloned().unwrap_or(Value::Null),
    );
    package.insert(
        "requestedVersion".to_string(),
        target.get("version").cloned().unwrap_or(Value::Null),
    );
    package.insert(
        "resolvedVersion".to_string(),
        target.get("version").cloned().unwrap_or(Value::Null),
    );
    package.insert(
        "range".to_string(),
        target.get("range").cloned().unwrap_or(Value::Null),
    );
    let mut reasons = Vec::new();
    let mut r = Map::new();
    r.insert(
        "code".to_string(),
        Value::String("lockfile_parse_incomplete".to_string()),
    );
    r.insert(
        "message".to_string(),
        Value::String(
            optional_string(
                parse_result
                    .error_reason
                    .clone()
                    .map(Value::String)
                    .as_ref(),
            )
            .unwrap_or_else(|| "Lockfile could not be parsed completely.".to_string()),
        ),
    );
    r.insert("severity".to_string(), Value::String("high".to_string()));
    reasons.push(r);
    package.insert(
        "reasons".to_string(),
        Value::Array(reasons.into_iter().map(Value::Object).collect()),
    );
    package.insert(
        "package_manager".to_string(),
        target
            .get("package_manager")
            .cloned()
            .unwrap_or(Value::String("npm".into())),
    );
    package.insert(
        "redacted_command".to_string(),
        optional_string(artifact.metadata.get("redacted_command"))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    package
}
