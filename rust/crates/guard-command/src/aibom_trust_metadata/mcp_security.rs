use super::*;

/// `_local_mcp_security_for_artifact(...)`
pub(super) fn _local_mcp_security_for_artifact(
    artifact: &Map<String, Value>,
    deps: &TrustDeps<'_>,
    item_kind: &str,
    captured_at: &str,
    cisco_runs: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
) -> Option<Map<String, Value>> {
    if !(item_kind == "mcp_server" || item_kind == "mcp_tool")
        || !matches!(
            a_str(artifact, "artifact_type"),
            Some("mcp_server" | "mcp_tool")
        )
    {
        return None;
    }

    let trust_root = _trust_root_for_artifact(artifact, item_kind, workspace_dir)?;
    let run = cisco_runs.iter().find(|candidate| {
        a_str(candidate, "source") == Some("cisco-mcp-scanner")
            && _matches_mcp_cisco_run(artifact, candidate)
    })?;

    let scan_root = _cisco_run_target_path(run).unwrap_or_else(|| trust_root.clone());
    let targets_total = _local_mcp_targets_total(run);
    let mut extra = Map::new();
    extra.insert("targetsScanned".into(), json!(targets_total));
    let (status, normalized_captured_at, findings, safety, mut metadata_payload) =
        _cisco_local_security_payload(
            run,
            _local_mcp_security_findings(run, &scan_root),
            deps,
            captured_at,
            targets_total,
            Some(extra),
        );

    if let Some(run_metadata) = run_meta(run) {
        for key in ["analyzersUsed", "scanMode", "mode", "targetsScanned"] {
            if let Some(value) = run_metadata.get(key) {
                metadata_payload.insert(key.into(), value.clone());
            }
        }
    }

    let evidence_for_hash = json!({
        "capturedAt": normalized_captured_at,
        "entityType": item_kind,
        "findings": findings,
        "provider": "cisco-mcp-scanner",
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
    out.insert("entityType".into(), json!(item_kind));
    out.insert("source".into(), json!("local_indexed"));
    out.insert("provider".into(), json!("cisco-mcp-scanner"));
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

/// `_local_mcp_security_findings(run, *, scan_root)`
pub(super) fn _local_mcp_security_findings(
    run: &Map<String, Value>,
    scan_root: &Path,
) -> Vec<Map<String, Value>> {
    let resolved_scan_root = scan_root
        .canonicalize()
        .unwrap_or_else(|_| scan_root.to_path_buf());
    let mut results = Vec::new();
    for finding in run_findings(run) {
        let finding = match finding.as_object() {
            Some(f) => f,
            None => continue,
        };
        let file_path = finding_str(finding, "file_path");
        let relative_file = if let Some(file_path) = file_path {
            if file_path.trim().is_empty() {
                ".mcp.json".to_string()
            } else {
                let raw = PathBuf::from(file_path);
                let path = if raw.is_absolute() {
                    raw
                } else {
                    scan_root.join(raw)
                };
                if !_paths_related(scan_root, &path) {
                    continue;
                }
                let resolved = path.canonicalize().unwrap_or_else(|_| path.clone());
                resolved
                    .strip_prefix(&resolved_scan_root)
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| {
                        path.file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| path.to_string_lossy().into_owned())
                    })
            }
        } else {
            ".mcp.json".to_string()
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
            json!(_local_mcp_security_message(finding)),
        );
        results.push(row);
    }
    results
}

/// `_local_mcp_security_message(finding)`
pub(super) fn _local_mcp_security_message(finding: &Map<String, Value>) -> String {
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
    "MCP security finding".to_string()
}

/// `_local_mcp_targets_total(run)`
pub(super) fn _local_mcp_targets_total(run: &Map<String, Value>) -> i64 {
    if let Some(metadata) = run_meta(run) {
        if let Some(value) = metadata.get("targetsScanned").and_then(Value::as_i64) {
            return value.max(0);
        }
    }
    0
}
