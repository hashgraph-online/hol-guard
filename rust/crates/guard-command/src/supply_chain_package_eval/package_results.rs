use super::*;

#[allow(dead_code)]
pub(super) fn package_target_result(
    target: &Map<String, Value>,
    decision: &str,
    reasons: Vec<Map<String, Value>>,
    rule_id: Option<&str>,
) -> Map<String, Value> {
    let mut r = Map::new();
    r.insert("decision".to_string(), Value::String(decision.to_string()));
    r.insert(
        "ecosystem".to_string(),
        target.get("ecosystem").cloned().unwrap_or(Value::Null),
    );
    r.insert(
        "name".to_string(),
        target.get("name").cloned().unwrap_or(Value::Null),
    );
    r.insert(
        "namespace".to_string(),
        target.get("namespace").cloned().unwrap_or(Value::Null),
    );
    r.insert(
        "requestedVersion".to_string(),
        optional_string(target.get("range"))
            .or_else(|| optional_string(target.get("version")))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    r.insert(
        "resolvedVersion".to_string(),
        optional_string(target.get("version"))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    r.insert("recommendedFixVersion".to_string(), Value::Null);
    r.insert("riskScore".to_string(), Value::Null);
    r.insert("direct".to_string(), Value::Bool(true));
    r.insert("dependencyPath".to_string(), Value::Null);
    r.insert(
        "packageManager".to_string(),
        optional_string(target.get("package_manager"))
            .map(Value::String)
            .unwrap_or_else(|| Value::String("npm".into())),
    );
    r.insert(
        "redactedCommand".to_string(),
        optional_string(target.get("redacted_command"))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    r.insert(
        "alias".to_string(),
        optional_string(target.get("alias"))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    if let Some(rid) = rule_id {
        r.insert("ruleId".to_string(), Value::String(rid.to_string()));
    }
    r.insert(
        "reasons".to_string(),
        Value::Array(reasons.into_iter().map(Value::Object).collect()),
    );
    r
}

#[allow(dead_code)]
pub(super) fn heuristic_package_result(
    target: &Map<String, Value>,
    decision: &str,
    code: &str,
    message: &str,
    severity: &str,
) -> Map<String, Value> {
    let mut reason = Map::new();
    reason.insert("code".to_string(), Value::String(code.to_string()));
    reason.insert("message".to_string(), Value::String(message.to_string()));
    reason.insert("severity".to_string(), Value::String(severity.to_string()));
    package_target_result(target, decision, vec![reason], None)
}

#[allow(dead_code)]
pub(super) fn lockfile_dependency_versions(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: Option<&Path>,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    let Some(ws) = workspace_dir else {
        return BTreeMap::new();
    };
    let results = lockfile_parse_results(deps, ws, artifact);
    let mut out = BTreeMap::new();
    for result in &results {
        if !result.complete {
            continue;
        }
        for entry in &result.entries {
            let eco = lockfile_ecosystem(&result.format);
            let name = entry.package_name.clone();
            let version = entry.version.clone();
            if !name.is_empty() && !version.is_empty() {
                out.entry(format!("{eco}:{name}"))
                    .or_insert_with(|| version.clone());
                out.entry(name).or_insert(version);
            }
        }
    }
    let _ = targets;
    out
}

#[allow(dead_code)]
pub(super) fn transitive_lockfile_results(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: Option<&Path>,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
) -> Vec<Map<String, Value>> {
    let versions = lockfile_dependency_versions(deps, workspace_dir, artifact, targets);
    targets
        .iter()
        .filter_map(|t| {
            let resolved = resolved_target_version(deps, t, &versions)?;
            let mut pkg = Map::new();
            pkg.insert(
                "name".to_string(),
                t.get("package_name").cloned().unwrap_or(Value::Null),
            );
            pkg.insert("version".to_string(), Value::String(resolved));
            pkg.insert("decision".to_string(), Value::String("monitor".into()));
            Some(pkg)
        })
        .collect()
}

#[allow(dead_code)]
pub(super) fn transitive_lockfile_decision(_results: &[Map<String, Value>]) -> Option<String> {
    None
}

#[allow(dead_code)]
pub(super) fn target_is_external_https_archive(target: &Map<String, Value>) -> bool {
    let Some(url) = optional_string(target.get("source_url")) else {
        return false;
    };
    url.starts_with("https://")
        && (url.ends_with(".tar.gz")
            || url.ends_with(".tgz")
            || url.ends_with(".tar")
            || url.ends_with(".zip"))
}
