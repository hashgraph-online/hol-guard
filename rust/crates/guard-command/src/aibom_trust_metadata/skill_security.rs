use super::*;

/// `_local_skill_security_for_artifact(...)`
pub(super) fn _local_skill_security_for_artifact(
    artifact: &Map<String, Value>,
    deps: &TrustDeps<'_>,
    item_kind: &str,
    metadata: &Map<String, Value>,
    captured_at: &str,
    cisco_runs: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
) -> Option<Map<String, Value>> {
    if item_kind != "skill" || metadata.get("artifactType").and_then(Value::as_str) != Some("skill")
    {
        return None;
    }

    let trust_root = _trust_root_for_artifact(artifact, item_kind, workspace_dir)?;
    let run = cisco_runs.iter().find(|candidate| {
        a_str(candidate, "source") == Some("cisco-skill-scanner")
            && _matches_skill_cisco_run(artifact, item_kind, candidate, workspace_dir)
    })?;

    let (status, normalized_captured_at, findings, safety, mut metadata_payload) =
        _cisco_local_security_payload(
            run,
            _local_skill_security_findings(run, &trust_root),
            deps,
            captured_at,
            _local_skill_scripts_total(run),
            None,
        );

    if let Some(run_metadata) = run_meta(run) {
        for key in [
            "analyzersUsed",
            "policyName",
            "mode",
            "skillsScanned",
            "skillsSkipped",
        ] {
            if let Some(value) = run_metadata.get(key) {
                metadata_payload.insert(key.into(), value.clone());
            }
        }
    }

    let evidence_for_hash = json!({
        "capturedAt": normalized_captured_at,
        "entityType": "skill",
        "findings": findings,
        "provider": "cisco-skill-scanner",
        "safety": safety,
        "source": "local_indexed",
        "status": status,
    });
    let evidence_map = evidence_for_hash.as_object().cloned().unwrap_or_default();
    metadata_payload.insert(
        "evidenceHash".into(),
        json!(deps.evidence_hash.guard_evidence_hash(&evidence_map)),
    );

    let mut out = Map::new();
    out.insert("entityType".into(), json!("skill"));
    out.insert("source".into(), json!("local_indexed"));
    out.insert("provider".into(), json!("cisco-skill-scanner"));
    out.insert("status".into(), json!(status));
    out.insert("capturedAt".into(), normalized_captured_at);
    match safety {
        Some(s) => {
            out.insert("safety".into(), Value::Object(s));
        }
        None => {
            out.insert("safety".into(), Value::Null);
        }
    }
    out.insert(
        "findings".into(),
        Value::Array(findings.into_iter().map(Value::Object).collect()),
    );
    out.insert("metadata".into(), Value::Object(metadata_payload));
    Some(out)
}

/// `_local_skill_security_findings(run, *, skill_root)`
pub(super) fn _local_skill_security_findings(
    run: &Map<String, Value>,
    skill_root: &Path,
) -> Vec<Map<String, Value>> {
    let resolved_root = skill_root
        .canonicalize()
        .unwrap_or_else(|_| skill_root.to_path_buf());
    let mut results = Vec::new();
    for finding in run_findings(run) {
        let finding = match finding.as_object() {
            Some(f) => f,
            None => continue,
        };
        let file_path = finding_str(finding, "file_path");
        let relative_file = if let Some(file_path) = file_path {
            if file_path.trim().is_empty() {
                "SKILL.md".to_string()
            } else {
                let path = PathBuf::from(file_path);
                if !_paths_related(skill_root, &path) {
                    continue;
                }
                let resolved = path.canonicalize().unwrap_or_else(|_| path.clone());
                resolved
                    .strip_prefix(&resolved_root)
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| {
                        path.file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| path.to_string_lossy().into_owned())
                    })
            }
        } else {
            "SKILL.md".to_string()
        };
        let mut row = Map::new();
        row.insert(
            "ruleId".into(),
            json!(finding_str(finding, "rule_id").map_or("unknown", |s| s)),
        );
        row.insert(
            "severity".into(),
            json!(_local_skill_security_severity(
                finding.get("severity").and_then(Value::as_str)
            )),
        );
        row.insert("file".into(), json!(relative_file));
        row.insert(
            "message".into(),
            json!(_local_skill_security_message(finding)),
        );
        results.push(row);
    }
    results
}

/// `_local_skill_security_severity(severity)`
///
/// Python accepts `Severity` enum members or arbitrary strings; anything not a
/// known severity folds to `"low"`.
pub(super) fn _local_skill_security_severity(severity: Option<&str>) -> String {
    match severity {
        Some("critical") => "critical".into(),
        Some("high") => "high".into(),
        Some("medium") => "medium".into(),
        Some("low") => "low".into(),
        _ => "low".into(),
    }
}

/// `_local_skill_security_message(finding)`
pub(super) fn _local_skill_security_message(finding: &Map<String, Value>) -> String {
    if let Some(description) = finding_str(finding, "description") {
        let trimmed = description.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Some(title) = finding_str(finding, "title") {
        let trimmed = title.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "Skill security finding".to_string()
}

/// `_local_skill_security_label(score)`
pub(super) fn _local_skill_security_label(score: i64) -> &'static str {
    if score >= 90 {
        "safe"
    } else if score >= 70 {
        "review"
    } else if score >= 45 {
        "caution"
    } else {
        "unsafe"
    }
}

/// `_local_skill_scripts_total(run)`
pub(super) fn _local_skill_scripts_total(run: &Map<String, Value>) -> i64 {
    if let Some(metadata) = run_meta(run) {
        if let Some(value) = metadata.get("skillsScanned").and_then(Value::as_i64) {
            return value.max(0);
        }
    }
    0
}
