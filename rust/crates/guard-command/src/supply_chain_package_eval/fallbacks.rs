use super::*;

#[allow(dead_code)]
pub(super) fn lockfile_parse_warning_result(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: Option<&Path>,
    artifact: &GuardArtifact,
    target: &Map<String, Value>,
) -> Option<Map<String, Value>> {
    let ws = workspace_dir?;
    let results = lockfile_parse_results(deps, ws, artifact);
    let incomplete = results.iter().find(|r| !r.complete)?;
    let mut reason = Map::new();
    reason.insert(
        "code".to_string(),
        Value::String("lockfile_parse_incomplete".into()),
    );
    reason.insert(
        "message".to_string(),
        Value::String(format!(
            "Lockfile {} could not be parsed completely; package version resolution may be inaccurate.",
            incomplete.format
        )),
    );
    reason.insert("severity".to_string(), Value::String("medium".into()));
    let mut pkg = package_target_result(target, "warn", vec![reason], None);
    if let Some(err) = &incomplete.error_reason {
        pkg.insert("lockfileParseError".to_string(), Value::String(err.clone()));
    }
    Some(pkg)
}

#[allow(dead_code)]
pub(super) fn lockfile_ecosystem(file_name: &str) -> String {
    let name = std::path::Path::new(file_name)
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if name.contains("package-lock")
        || name.contains("npm-shrinkwrap")
        || name.contains("pnpm")
        || name.contains("yarn")
        || name.contains("bun")
    {
        "npm".into()
    } else if name.contains("cargo") {
        "cargo".into()
    } else if name.contains("composer") {
        "composer".into()
    } else if name.contains("gemfile") {
        "gem".into()
    } else if name.contains("poetry") || name.contains("pipfile") || name.contains("uv") {
        "pypi".into()
    } else {
        "npm".into()
    }
}

#[allow(dead_code)]
pub(super) fn package_has_incomplete_lockfile(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: Option<&Path>,
    artifact: &GuardArtifact,
) -> bool {
    let Some(ws) = workspace_dir else {
        return false;
    };
    lockfile_parse_results(deps, ws, artifact)
        .iter()
        .any(|r| !r.complete)
}

// `block_package_from_offline` — builds a block result from the offline bundle evaluation.
#[allow(dead_code)]
pub(super) fn block_package_from_offline(
    offline: &Map<String, Value>,
    bundle_response: &SupplyChainBundleResponse,
    package_match: &Map<String, Value>,
    resolved_version: Option<&str>,
) -> Map<String, Value> {
    let mut r = offline.clone();
    if let Some(v) = resolved_version {
        r.insert("resolvedVersion".to_string(), Value::String(v.to_string()));
    }
    let _ = (bundle_response, package_match);
    r
}

// `_bundle_package_result` — build a package result from a bundle package match.
#[allow(dead_code)]
pub(super) fn bundle_package_result(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
    package_match: &Map<String, Value>,
    bundle_response: &SupplyChainBundleResponse,
    resolved_version: Option<&str>,
    _now_timestamp: Option<f64>,
) -> Option<Map<String, Value>> {
    let action = optional_string_map(package_match, "defaultAction")
        .unwrap_or_else(|| "monitor".to_string());
    let decision = match action.as_str() {
        "block" | "deny" => "block",
        "ask" => "ask",
        "warn" => "warn",
        _ => "monitor",
    };
    let mut reason = Map::new();
    reason.insert("code".to_string(), Value::String("bundle_package".into()));
    reason.insert(
        "message".to_string(),
        Value::String(format!(
            "Bundle {} signals {} for {}.",
            bundle_response.payload_hash,
            decision,
            bundle_package_label(package_match)
        )),
    );
    reason.insert("severity".to_string(), Value::String("medium".into()));
    let mut pkg = package_target_result(target, decision, vec![reason], None);
    if let Some(fix) = optional_string_map(package_match, "recommendedFixVersion") {
        if !fix.is_empty() {
            pkg.insert("recommendedFixVersion".to_string(), Value::String(fix));
        }
    }
    if let Some(v) = resolved_version {
        pkg.insert("resolvedVersion".to_string(), Value::String(v.to_string()));
    }
    let _ = deps;
    Some(pkg)
}

// `_incomplete_lockfile_fallback_target`
#[allow(dead_code)]
pub(super) fn incomplete_lockfile_fallback_target(
    parse_result: &LockfileParseResult,
) -> Map<String, Value> {
    let mut target = Map::new();
    target.insert(
        "ecosystem".to_string(),
        Value::String(lockfile_ecosystem(&parse_result.format)),
    );
    target.insert(
        "name".to_string(),
        Value::String("unresolved-lockfile".into()),
    );
    target.insert("namespace".to_string(), Value::Null);
    target.insert("version".to_string(), Value::Null);
    target.insert("range".to_string(), Value::Null);
    target.insert("package_manager".to_string(), Value::String("npm".into()));
    target.insert(
        "package_name".to_string(),
        Value::String("unresolved-lockfile".into()),
    );
    target
}

// ---------------------------------------------------------------------------
// Batch-D ports — leaf helpers first so dependents resolve.
// ---------------------------------------------------------------------------

/// `_target_candidate_names` (:5005-5025) — every name spelling a target may
/// resolve under: alias, qualified `namespace/name`, its normalized form, then
/// raw `package_name` and its normalized form.
// supply_chain_package_eval.py:5005-5025
#[allow(dead_code)]
pub(super) fn target_candidate_names(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
) -> Vec<String> {
    let alias = optional_string(target.get("alias"));
    let namespace = optional_string(target.get("namespace"));
    let ecosystem = optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".into());
    let name = optional_string(target.get("name")).unwrap_or_default();
    let mut candidates: Vec<String> = Vec::new();
    if let Some(alias) = alias {
        candidates.push(alias);
    }
    let qualified_name = match &namespace {
        Some(ns) => format!("{ns}/{name}"),
        None => name.clone(),
    };
    candidates.push(qualified_name.clone());
    let normalized = normalize_package_name(deps, &ecosystem, &qualified_name);
    if !candidates.iter().any(|c| c == &normalized) {
        candidates.push(normalized);
    }
    if let Some(raw) = optional_string(target.get("package_name")) {
        if !candidates.iter().any(|c| c == &raw) {
            candidates.push(raw.clone());
            let raw_normalized = normalize_package_name(deps, &ecosystem, &raw);
            if !candidates.iter().any(|c| c == &raw_normalized) {
                candidates.push(raw_normalized);
            }
        }
    }
    candidates
}

/// `_python_lockfile_version` (:5027-5041) — normalize a PEP-440 lockfile
/// `version` field to a canonical exact version, `None` on non-string or
/// invalid input.
// supply_chain_package_eval.py:5027-5041
#[allow(dead_code)]
pub(super) fn python_lockfile_version(
    deps: &SupplyChainEvalDeps<'_>,
    value: Option<&Value>,
) -> Option<String> {
    let raw = value?.as_str()?;
    let mut normalized = raw.trim().trim_matches('"').trim_matches('\'').to_string();
    if let Some((head, _)) = normalized.split_once(';') {
        normalized = head.trim().to_string();
    }
    if normalized.starts_with("==") || normalized.starts_with("===") {
        normalized = normalized.trim_start_matches('=').to_string();
    }
    if normalized.is_empty() {
        return None;
    }
    deps.semver.version(&normalized).ok().map(|v| v.normalized)
}

/// `_with_additional_reason` (:5102-5119) — append one reason dict to the
/// evaluation's `reasons` list.
// supply_chain_package_eval.py:5102-5119
#[allow(dead_code)]
pub(super) fn with_additional_reason(
    mut evaluation: EvaluationDraft,
    reason: Map<String, Value>,
) -> EvaluationDraft {
    evaluation.reasons.push(reason);
    evaluation
}

/// `_cloud_result_should_defer_to_bundle` (:5123-5137) — whether a cloud
/// result carrying an auth/http/timeout fallback reason should yield to the
/// stricter local bundle decision.
// supply_chain_package_eval.py:5123-5137
#[allow(dead_code)]
pub(super) fn cloud_result_should_defer_to_bundle(
    evaluation: &EvaluationDraft,
    bundle_evaluation: &EvaluationDraft,
) -> bool {
    if evaluation.decision == "allow" {
        return false;
    }
    let reason_codes: std::collections::HashSet<String> = evaluation
        .reasons
        .iter()
        .map(|r| optional_string_map(r, "code").unwrap_or_default())
        .collect();
    if evaluation.decision == "block" && evaluation.enforcement == "block" {
        return false;
    }
    let defer_codes = ["cloud_auth_error", "cloud_http_error", "cloud_timeout"];
    if !reason_codes
        .iter()
        .any(|c| defer_codes.contains(&c.as_str()))
    {
        return false;
    }
    decision_rank(&bundle_evaluation.decision) > decision_rank(&evaluation.decision)
}

/// `_cloud_fallback_reason` (:5141-5147) — reason dict recorded when cloud
/// validation could not run and the result fell back to local heuristics.
// supply_chain_package_eval.py:5141-5147
#[allow(dead_code)]
pub(super) fn cloud_fallback_reason(code: &str, message: &str) -> Map<String, Value> {
    let mut reason = Map::new();
    reason.insert("code".into(), Value::String(code.to_string()));
    reason.insert("message".into(), Value::String(message.to_string()));
    reason.insert("severity".into(), Value::String("unknown".into()));
    reason.insert("source".into(), Value::String("guard-cloud".into()));
    reason
}

/// `_bundle_reason_message` (:5166-5186) — human-readable message for a bundle
/// package decision reason.
// supply_chain_package_eval.py:5166-5186
#[allow(dead_code)]
pub(super) fn bundle_reason_message(
    package: &Map<String, Value>,
    decision: &str,
    reason: &str,
    stale: bool,
) -> String {
    let package_label = bundle_package_label(package);
    if stale {
        return match decision {
            "block" => format!(
                "Cached bundle is stale, but Guard still blocked {package_label} from advisory intelligence."
            ),
            "ask" => format!(
                "Cached bundle is stale, so Guard still requires approval for {package_label}."
            ),
            "warn" => format!("Cached bundle is stale, so Guard still warns on {package_label}."),
            _ => format!("Cached bundle is stale, so Guard kept {package_label} in monitor mode."),
        };
    }
    match reason {
        "known_malware_or_kev" => {
            format!("Cached bundle flagged {package_label} from advisory intelligence.")
        }
        "maintainer_compromise" => {
            format!("Cached bundle flagged {package_label} for probable maintainer compromise.")
        }
        _ => format!("Cached bundle matched {package_label}."),
    }
}
