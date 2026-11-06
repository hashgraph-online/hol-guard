use super::*;

/// `_cisco_trust_layer(run, *, captured_at, layer_id, component_id, label)`
pub(super) fn _cisco_trust_layer(
    run: &Map<String, Value>,
    deps: &TrustDeps<'_>,
    captured_at: &str,
    layer_id: &str,
    component_id: &str,
    label: &str,
) -> Map<String, Value> {
    let status = a_str(run, "status").map_or("unknown".to_string(), str::to_string);
    let message = a_str(run, "message").map_or("".to_string(), str::to_string);
    let severity_counts = _cisco_severity_counts(run);
    let analyzers_used = _cisco_analyzers_used(run);
    let trust_score: Option<i64> = if status == "enabled" {
        Some(_cisco_layer_score(&severity_counts, &analyzers_used))
    } else {
        None
    };
    let mut trust_components: Vec<Map<String, Value>> = Vec::new();
    if let Some(score) = trust_score {
        let component_status = if score < 40 {
            "critical"
        } else if score < 70 {
            "warning"
        } else {
            "positive"
        };
        let analyzer_confidence = (90 + (analyzers_used.len() as i64 - 1) * 5).min(99);
        let total_findings: i64 = severity_counts
            .values()
            .map(|v| v.as_i64().unwrap_or(0))
            .sum();
        let mut row = Map::new();
        row.insert("componentId".into(), json!(component_id));
        row.insert("confidence".into(), json!(analyzer_confidence));
        row.insert("label".into(), json!(label));
        row.insert("score".into(), json!(score));
        row.insert("status".into(), json!(component_status));
        row.insert(
            "summary".into(),
            json!(if !message.is_empty() {
                message.clone()
            } else {
                format!(
                    "{} completed with {} findings using {} analyzer(s).",
                    label,
                    total_findings,
                    analyzers_used.len()
                )
            }),
        );
        row.insert("weight".into(), json!(1.0));
        trust_components.push(row);
    }

    let run_metadata = run_meta(run);
    let mut safe_metadata = Map::new();
    safe_metadata.insert(
        "scannerSource".into(),
        json!(a_str(run, "source").map_or("unknown", |s| s)),
    );
    safe_metadata.insert("message".into(), json!(message));
    let total_findings: i64 = severity_counts
        .values()
        .map(|v| v.as_i64().unwrap_or(0))
        .sum();
    safe_metadata.insert("totalFindings".into(), json!(total_findings));
    safe_metadata.insert(
        "findingsBySeverity".into(),
        Value::Object(severity_counts.clone()),
    );
    if let Some(d) = run.get("duration_ms").and_then(Value::as_i64) {
        safe_metadata.insert("durationMs".into(), json!(d));
    }
    if let Some(run_metadata) = run_metadata {
        for key in [
            "analyzersUsed",
            "policyName",
            "scanMode",
            "mode",
            "targetsScanned",
            "skillsScanned",
            "skillsSkipped",
        ] {
            if let Some(value) = run_metadata.get(key) {
                safe_metadata.insert(key.into(), value.clone());
            }
        }
    }
    safe_metadata.insert("attestationStatus".into(), json!("unsigned"));
    safe_metadata.insert("evidenceAuthority".into(), json!("device_claim"));
    safe_metadata.insert("affectsV4Score".into(), json!(false));
    safe_metadata.insert(
        "evidenceSchemaVersion".into(),
        json!("guard-aibom-cisco-scanner-evidence.v1"),
    );
    let normalized_captured_at =
        normalize_inventory_datetime(&Value::String(captured_at.to_string()));
    let evidence_payload = _cisco_evidence_payload(
        layer_id,
        label,
        &status,
        &message,
        &normalized_captured_at,
        trust_score,
        &trust_components,
        &safe_metadata,
    );
    safe_metadata.insert("evidence".into(), Value::Object(evidence_payload.clone()));
    safe_metadata.insert(
        "evidenceHash".into(),
        json!(_trust_evidence_hash(&evidence_payload, deps)),
    );

    let mut out = Map::new();
    out.insert("layerId".into(), json!(layer_id));
    out.insert("layerType".into(), json!(layer_id));
    out.insert("status".into(), json!(status));
    out.insert("evidenceAuthority".into(), json!("device_claim"));
    out.insert("affectsV4Score".into(), json!(false));
    match trust_score {
        Some(s) => {
            out.insert("trustScore".into(), json!(s));
        }
        None => {
            out.insert("trustScore".into(), Value::Null);
        }
    }
    out.insert(
        "trustComponents".into(),
        Value::Array(trust_components.into_iter().map(Value::Object).collect()),
    );
    out.insert("capturedAt".into(), normalized_captured_at);
    let scanner_source = safe_metadata
        .get("scannerSource")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(layer_id);
    out.insert(
        "provenance".into(),
        Value::Object(_local_claim_provenance(scanner_source)),
    );
    out.insert("metadata".into(), Value::Object(safe_metadata));
    out
}

/// `_cisco_evidence_payload(*, layer_id, label, status, message, captured_at, trust_score, trust_components, metadata)`
#[allow(clippy::too_many_arguments)]
pub(super) fn _cisco_evidence_payload(
    layer_id: &str,
    label: &str,
    status: &str,
    message: &str,
    captured_at: &Value,
    trust_score: Option<i64>,
    trust_components: &[Map<String, Value>],
    metadata: &Map<String, Value>,
) -> Map<String, Value> {
    let mut payload = Map::new();
    payload.insert(
        "source".into(),
        metadata
            .get("scannerSource")
            .cloned()
            .unwrap_or_else(|| json!("unknown")),
    );
    payload.insert("layerId".into(), json!(layer_id));
    payload.insert("label".into(), json!(label));
    payload.insert("status".into(), json!(status));
    payload.insert("message".into(), json!(message));
    payload.insert("capturedAt".into(), captured_at.clone());
    match trust_score {
        Some(s) => {
            payload.insert("trustScore".into(), json!(s));
        }
        None => {
            payload.insert("trustScore".into(), Value::Null);
        }
    }
    payload.insert(
        "componentCount".into(),
        json!(trust_components.len() as i64),
    );
    payload.insert(
        "totalFindings".into(),
        metadata.get("totalFindings").cloned().unwrap_or(json!(0)),
    );
    payload.insert(
        "findingsBySeverity".into(),
        metadata
            .get("findingsBySeverity")
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new())),
    );
    for key in [
        "analyzersUsed",
        "policyName",
        "scanMode",
        "mode",
        "targetsScanned",
        "skillsScanned",
        "skillsSkipped",
        "durationMs",
    ] {
        if let Some(value) = metadata.get(key) {
            payload.insert(key.into(), value.clone());
        }
    }
    payload
}

/// `_cisco_severity_counts(run)`
pub(super) fn _cisco_severity_counts(run: &Map<String, Value>) -> Map<String, Value> {
    let mut counts = Map::new();
    for key in ["critical", "high", "medium", "low"] {
        counts.insert(key.into(), json!(0));
    }
    if let Some(metadata) = run_meta(run) {
        if let Some(raw_counts) = metadata
            .get("findingsBySeverity")
            .and_then(Value::as_object)
        {
            let mut resolved = Map::new();
            for key in ["critical", "high", "medium", "low"] {
                let value = raw_counts
                    .get(key)
                    .and_then(Value::as_i64)
                    .filter(|v| *v >= 0)
                    .unwrap_or(0);
                resolved.insert(key.into(), json!(value));
            }
            return resolved;
        }
    }
    for finding in run_findings(run) {
        let severity = finding
            .as_object()
            .and_then(|f| f.get("severity"))
            .and_then(|s| {
                s.as_str().map(str::to_string).or_else(|| {
                    // `Severity` enum mirrors carry `.value` → lowercase token.
                    s.get("value").and_then(Value::as_str).map(str::to_string)
                })
            });
        if let Some(severity) = severity {
            if let Some(entry) = counts.get_mut(&severity) {
                *entry = json!(entry.as_i64().unwrap_or(0) + 1);
            }
        }
    }
    counts
}

/// `_cisco_analyzers_used(run)`
pub(super) fn _cisco_analyzers_used(run: &Map<String, Value>) -> Vec<String> {
    if let Some(metadata) = run_meta(run) {
        if let Some(raw) = metadata.get("analyzersUsed").and_then(Value::as_array) {
            return raw
                .iter()
                .filter_map(|a| {
                    // `str(a)` keeps only genuine JSON strings verbatim;
                    // non-strings serialize, but Python `str(a)` on non-str
                    // scalars is a display string — mirror strings only.
                    a.as_str().map(str::to_string)
                })
                .filter(|a| !a.is_empty())
                .collect();
        }
    }
    vec!["yara".to_string()]
}

/// `_cisco_layer_score(severity_counts, *, analyzers_used=("yara",))`
pub(super) fn _cisco_layer_score(
    severity_counts: &Map<String, Value>,
    analyzers_used: &[String],
) -> i64 {
    let get = |k: &str| severity_counts.get(k).and_then(Value::as_i64).unwrap_or(0);
    let raw_score =
        100 - (30 * get("critical") + 12 * get("high") + 4 * get("medium") + get("low"));
    let analyzer_count = analyzers_used.len();
    let ceiling = if analyzer_count >= 3 {
        100
    } else if analyzer_count == 2 {
        95
    } else {
        90
    };
    raw_score.max(0).min(ceiling)
}
