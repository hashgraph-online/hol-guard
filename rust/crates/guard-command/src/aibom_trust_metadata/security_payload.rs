use super::*;

/// `_local_security_for_artifact(...)`
pub(super) fn _local_security_for_artifact(
    artifact: &Map<String, Value>,
    deps: &TrustDeps<'_>,
    item_kind: &str,
    metadata: &Map<String, Value>,
    captured_at: &str,
    cisco_runs: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
) -> Option<Map<String, Value>> {
    let skill_security = _local_skill_security_for_artifact(
        artifact,
        deps,
        item_kind,
        metadata,
        captured_at,
        cisco_runs,
        workspace_dir,
    );
    if skill_security.is_some() {
        return skill_security;
    }
    _local_mcp_security_for_artifact(
        artifact,
        deps,
        item_kind,
        captured_at,
        cisco_runs,
        workspace_dir,
    )
}

/// `_cisco_local_security_payload(run, findings, *, captured_at, scripts_total, extra_safety_fields=None)`
///
/// Returns `(status, normalized_captured_at, findings, safety, metadata_payload)`.
#[allow(clippy::type_complexity)]
pub(super) fn _cisco_local_security_payload(
    run: &Map<String, Value>,
    mut findings: Vec<Map<String, Value>>,
    _deps: &TrustDeps<'_>,
    captured_at: &str,
    scripts_total: i64,
    extra_safety_fields: Option<Map<String, Value>>,
) -> (
    String,
    Value,
    Vec<Map<String, Value>>,
    Option<Map<String, Value>>,
    Map<String, Value>,
) {
    let status = a_str(run, "status").map_or_else(|| "unknown".to_string(), str::to_string);
    let normalized_captured_at =
        normalize_inventory_datetime(&Value::String(captured_at.to_string()));
    findings.sort_by(|a, b| {
        let key = |f: &Map<String, Value>| {
            (
                f.get("file")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                f.get("ruleId")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                f.get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            )
        };
        key(a).cmp(&key(b))
    });
    let severity_counts = _cisco_severity_counts(run);
    let analyzers_used = _cisco_analyzers_used(run);
    let score: Option<i64> = if status == "enabled" {
        Some(_cisco_layer_score(&severity_counts, &analyzers_used))
    } else {
        None
    };
    let mut safety: Option<Map<String, Value>> = None;
    if let Some(score) = score {
        let high_findings = findings
            .iter()
            .filter(|f| f.get("severity").and_then(Value::as_str) == Some("high"))
            .count() as i64;
        let mut s = Map::new();
        s.insert("score".into(), json!(score));
        s.insert("label".into(), json!(_local_skill_security_label(score)));
        s.insert("findingsTotal".into(), json!(findings.len() as i64));
        s.insert("highFindings".into(), json!(high_findings));
        s.insert("scriptsTotal".into(), json!(scripts_total));
        if let Some(extra) = extra_safety_fields {
            for (k, v) in extra {
                s.insert(k, v);
            }
        }
        s.insert("permissionsMissing".into(), json!([]));
        safety = Some(s);
    }

    let mut metadata_payload = Map::new();
    metadata_payload.insert(
        "scannerSource".into(),
        json!(a_str(run, "source").map_or("unknown", |s| s)),
    );
    metadata_payload.insert(
        "message".into(),
        json!(a_str(run, "message").map_or("", |s| s)),
    );
    metadata_payload.insert(
        "findingsBySeverity".into(),
        Value::Object(severity_counts.clone()),
    );
    metadata_payload.insert("totalFindings".into(), json!(findings.len() as i64));
    if let Some(d) = run.get("duration_ms").and_then(Value::as_i64) {
        metadata_payload.insert("durationMs".into(), json!(d));
    }
    (
        status,
        normalized_captured_at,
        findings,
        safety,
        metadata_payload,
    )
}
