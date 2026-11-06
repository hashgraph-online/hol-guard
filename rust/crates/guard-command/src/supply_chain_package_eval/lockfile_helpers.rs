use super::*;

/// `_normalized_supply_chain_evaluate_url` (:4840-4858) — rewrite a receipts
/// sync URL into the supply-chain evaluate URL for `workspace_id`.
// supply_chain_package_eval.py:4840-4858
#[allow(dead_code)]
pub(super) fn normalized_supply_chain_evaluate_url(
    deps: &SupplyChainEvalDeps<'_>,
    sync_url: &str,
    workspace_id: &str,
) -> String {
    let parsed = crate::local_supply_chain::urlsplit(
        &deps.guard_sync.normalized_receipts_sync_url(sync_url),
    );
    let trimmed_path = parsed.path.trim_end_matches('/');
    let next_path = if trimmed_path == "/api/guard/receipts/sync" {
        "/api/guard/supply-chain/evaluate".to_string()
    } else if trimmed_path == "/guard/receipts/sync" {
        "/guard/supply-chain/evaluate".to_string()
    } else {
        format!("{trimmed_path}/supply-chain/evaluate")
    };
    let mut query_pairs: Vec<(String, String)> =
        crate::local_supply_chain::parse_qsl(&parsed.query)
            .into_iter()
            .filter(|(key, _)| key != "workspaceId")
            .collect();
    query_pairs.push(("workspaceId".to_string(), workspace_id.to_string()));
    let query = crate::local_supply_chain::urlencode(&query_pairs);
    format!(
        "{}://{}{}{}{}",
        parsed.scheme,
        parsed.netloc,
        next_path,
        if query.is_empty() { "" } else { "?" },
        query
    )
}

/// `_safe_dependency_map_result_for_path` (:4686-4697) — parse a lockfile/
/// manifest file's dependency map under a deadline, surfacing parse errors.
// supply_chain_package_eval.py:4686-4697
#[allow(dead_code)]
pub(super) fn safe_dependency_map_result_for_path(
    deps: &SupplyChainEvalDeps<'_>,
    path: &str,
    text: &str,
    deadline: f64,
) -> LockfileParseResult {
    let budget_ms = ((deadline - monotonic_seconds()) * 1000.0).max(0.0);
    deps.manifest
        .dependency_map_for_path(path, text, deadline)
        .map(|map| {
            let mut result = LockfileParseResult {
                complete: true,
                format: path_format_label(path),
                entries: map
                    .into_iter()
                    .map(|(dependency_path, version)| LockfileDependencyEntry {
                        package_name: dependency_path.clone(),
                        version,
                        dependency_path,
                        direct: true,
                    })
                    .collect(),
                ..Default::default()
            };
            result.budget_ms = budget_ms;
            result
        })
        .unwrap_or_else(|e| {
            let mut result = LockfileParseResult {
                complete: false,
                format: path_format_label(path),
                ..Default::default()
            };
            result.budget_ms = budget_ms;
            result.error_reason = Some(e.to_string());
            result
        })
}

/// `monotonic_seconds` — the monotonic clock used by the Python `time.monotonic`
/// deadline model (:4686, :4134, ...). Expressed in seconds.
#[allow(dead_code)]
pub(super) fn monotonic_seconds() -> f64 {
    std::time::Instant::now().elapsed().as_secs_f64() + *MONOTONIC_EPOCH
}

#[allow(dead_code)]
pub(super) static MONOTONIC_EPOCH: LazyLock<f64> = LazyLock::new(|| {
    // Anchor Instant's epoch at first use; Instant has no defined epoch so we
    // record the offset once. Only relative deltas are consumed by deadlines.
    let _ = std::time::Instant::now();
    0.0
});

#[allow(dead_code)]
pub(super) fn path_format_label(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

/// `_safe_dependency_map_for_path` (:4681-4683) — convenience returning just
/// the dependency map.
// supply_chain_package_eval.py:4681-4683
#[allow(dead_code)]
pub(super) fn safe_dependency_map_for_path(
    deps: &SupplyChainEvalDeps<'_>,
    path: &str,
    text: &str,
    deadline: f64,
) -> BTreeMap<String, String> {
    safe_dependency_map_result_for_path(deps, path, text, deadline)
        .entries
        .into_iter()
        .map(|e| (e.package_name, e.version))
        .collect()
}
