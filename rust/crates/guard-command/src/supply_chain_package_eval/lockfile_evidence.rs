use super::*;

/// `_lockfile_parse_results` (:2335-2344).
// supply_chain_package_eval.py:2335-2344
pub(super) fn lockfile_parse_results(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: &Path,
    artifact: &GuardArtifact,
) -> Vec<LockfileParseResult> {
    let lockfile_paths = artifact.metadata.get("lockfile_paths");
    deps.lockfile.collect_lockfile_parse_results(
        Some(workspace_dir),
        lockfile_paths,
        LOCKFILE_PARSE_BUDGET_SECONDS * 1000.0,
        &|path, bytes| parse_lockfile_text_result(deps, path, bytes),
    )
}

/// `_parse_lockfile_text_result` (:2347-2370) — complete-or-fail parse of one
/// lockfile with the size-scaled budget.
// supply_chain_package_eval.py:2347-2370
pub(super) fn parse_lockfile_text_result(
    deps: &SupplyChainEvalDeps<'_>,
    path: &str,
    text: &[u8],
) -> LockfileParseResult {
    deps.lockfile.parse_lockfile_with_budget(
        path,
        text,
        lockfile_parse::lockfile_parse_budget_for_bytes(text.len()),
    )
}

/// `_first_incomplete_lockfile_result` (:2381-2385).
// supply_chain_package_eval.py:2381-2385
#[allow(dead_code)]
pub(super) fn first_incomplete_lockfile_result(
    results: &[LockfileParseResult],
) -> Option<&LockfileParseResult> {
    results.iter().find(|r| !r.complete)
}

/// `incomplete_lockfile_metadata` (lockfile_evaluation_support.py:96).
pub(super) fn incomplete_lockfile_metadata(
    parse_result: &LockfileParseResult,
) -> Map<String, Value> {
    let mut metadata = Map::new();
    metadata.insert(
        "lockfileHash".into(),
        Value::String(parse_result.source_hash.clone()),
    );
    metadata.insert(
        "lockfileParserVersion".into(),
        Value::String(parse_result.parser_version.clone()),
    );
    metadata.insert(
        "lockfileFormat".into(),
        Value::String(parse_result.format.clone()),
    );
    metadata.insert("lockfileParseComplete".into(), Value::Bool(false));
    metadata.insert(
        "lockfileParseError".into(),
        Value::String(
            parse_result
                .error_reason
                .clone()
                .filter(|reason| !reason.is_empty())
                .unwrap_or_else(|| "parse_error".to_owned()),
        ),
    );
    metadata.insert(
        "lockfileParseElapsedMs".into(),
        json!((parse_result.elapsed_ms * 1000.0).round() / 1000.0),
    );
    metadata.insert(
        "lockfileParseBudgetMs".into(),
        json!(parse_result.budget_ms),
    );
    metadata.insert(
        "lockfileParseWarnings".into(),
        Value::Array(
            parse_result
                .warnings
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    metadata
}

/// `_finalize_incomplete_lockfile_evaluation` (:2388-2431).
// supply_chain_package_eval.py:2388-2431
#[allow(clippy::too_many_arguments)]
pub(super) fn finalize_incomplete_lockfile_evaluation(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    store: &dyn SupplyChainStore,
    target: &Map<String, Value>,
    workspace_dir: Option<&Path>,
    parse_result: &LockfileParseResult,
    package_intent_hash: &str,
    now: &str,
) -> PackageEvalResult {
    // Fail closed: only a successfully loaded, non-strict configuration may
    // downgrade an incomplete lockfile to an approvable pause. When the
    // configuration cannot be read (the resident has no config loader), keep
    // the request blocked rather than weakening it for strict users.
    let decision = match deps
        .config
        .load_guard_config(store.guard_home(), workspace_dir, false)
    {
        Ok(config) if !matches!(config.security_level.as_str(), "strict" | "paranoid") => "ask",
        _ => "block",
    };
    let package = incomplete_lockfile_package_result(target, parse_result, decision);
    let reasons = dict_items(package.get("reasons"));
    let draft = EvaluationDraft {
        decision: decision.to_owned(),
        enforcement: "free_local".to_owned(),
        entitlement_state: "free".to_owned(),
        cache_status: "miss".to_owned(),
        packages: vec![package],
        reasons,
        refresh_required: false,
        record_monitor_evidence: false,
        bundle_version: None,
        policy_version: "local:none".to_owned(),
        ..Default::default()
    };
    let fingerprint = stable_hash(&json!({
        "lockfile_hash": parse_result.source_hash,
        "lockfile_parser_version": parse_result.parser_version,
    }));
    let evaluation = finalize_evaluation(deps, &draft, package_intent_hash, Some(&fingerprint));
    persist_evidence(deps, store, artifact, &evaluation, now);
    evaluation
}

/// `_incomplete_lockfile_package_result` (:2434-2456).
// supply_chain_package_eval.py:2434-2456
pub(super) fn incomplete_lockfile_package_result(
    target: &Map<String, Value>,
    parse_result: &LockfileParseResult,
    decision: &str,
) -> Map<String, Value> {
    let error_reason = parse_result
        .error_reason
        .clone()
        .filter(|reason| !reason.is_empty())
        .unwrap_or_else(|| "parse_error".to_owned());
    // The wording follows the decision: only an approvable `ask` is a pause.
    let outcome = if decision == "ask" {
        "paused"
    } else {
        "blocked"
    };
    let message = format!(
        "Guard could not completely parse the existing {} lockfile ({error_reason}), \
         so this package request is {outcome}. Repair the lockfile, then retry.",
        parse_result.format
    );
    let mut package = heuristic_package_result(
        target,
        decision,
        "lockfile_parse_incomplete",
        &message,
        "high",
    );
    let metadata = incomplete_lockfile_metadata(parse_result);
    for (key, value) in &metadata {
        package.insert(key.clone(), value.clone());
    }
    if let Some(mut first_reason) = first_dict_item(package.get("reasons")) {
        for (key, value) in metadata {
            first_reason.insert(key, value);
        }
        package.insert(
            "reasons".to_owned(),
            Value::Array(vec![Value::Object(first_reason)]),
        );
    }
    package
}
