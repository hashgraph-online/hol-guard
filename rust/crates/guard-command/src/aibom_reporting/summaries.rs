use super::*;

// ---------------------------------------------------------------------------
// defmap order
// ---------------------------------------------------------------------------

/// `summarize_aibom_layers(snapshots, *, generated_at)`
///
/// Returns `(layer_summary, trust, drift)`.
pub fn summarize_aibom_layers(
    snapshots: &[GuardAgentInventorySnapshot],
    _deps: &ReportingDeps<'_>,
    generated_at: &str,
) -> (Map<String, Value>, Map<String, Value>, Map<String, Value>) {
    let mut counts: std::collections::BTreeMap<String, i64> = [
        ("instructions", 0),
        ("skills", 0),
        ("mcp", 0),
        ("plugins", 0),
        ("policies", 0),
        ("findings", 0),
        ("trust", 0),
        ("sources", 0),
        ("configSources", 0),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    for snapshot in snapshots {
        *counts.get_mut("findings").unwrap() += snapshot.findings.len() as i64;
        *counts.get_mut("configSources").unwrap() += snapshot.sources.len() as i64;
        for item in &snapshot.items {
            match item.item_kind.as_str() {
                "overlay" | "prompt_pack" => *counts.get_mut("instructions").unwrap() += 1,
                "skill" => *counts.get_mut("skills").unwrap() += 1,
                "mcp_server" | "mcp_tool" => *counts.get_mut("mcp").unwrap() += 1,
                "plugin" | "daemon_plugin" => *counts.get_mut("plugins").unwrap() += 1,
                "policy" => *counts.get_mut("policies").unwrap() += 1,
                _ => {}
            }
            if item
                .metadata
                .get("trustResolution")
                .is_some_and(Value::is_object)
            {
                *counts.get_mut("trust").unwrap() += 1;
            }
            let source_links = item.metadata.get("sourceLinks");
            let source_of_truth = item.metadata.get("sourceOfTruth");
            if let Some(links) = source_links.and_then(Value::as_array) {
                if !links.is_empty() {
                    *counts.get_mut("sources").unwrap() += links.len() as i64;
                    continue;
                }
            }
            if source_of_truth.is_some_and(Value::is_object) {
                *counts.get_mut("sources").unwrap() += 1;
            }
        }
    }
    let drift = summarize_aibom_drift(snapshots);
    let trust = summarize_aibom_trust(snapshots);
    let mut layer_summary = Map::new();
    for (k, v) in &counts {
        layer_summary.insert(k.clone(), json!(v));
    }
    layer_summary.insert(
        "driftCount".into(),
        drift.get("total").cloned().unwrap_or(json!(0)),
    );
    layer_summary.insert(
        "highRiskCount".into(),
        drift.get("high_risk").cloned().unwrap_or(json!(0)),
    );
    layer_summary.insert(
        "lowTrustCount".into(),
        trust.get("low_trust").cloned().unwrap_or(json!(0)),
    );
    layer_summary.insert("generatedAt".into(), json!(generated_at));
    layer_summary.insert("staleSnapshot".into(), json!(false));
    (layer_summary, trust, drift)
}

/// `summarize_aibom_trust(snapshots)`
pub fn summarize_aibom_trust(snapshots: &[GuardAgentInventorySnapshot]) -> Map<String, Value> {
    let mut covered = 0i64;
    let mut eligible = 0i64;
    let mut low_trust = 0i64;
    let mut scores: Vec<i64> = Vec::new();
    for snapshot in snapshots {
        for item in &snapshot.items {
            if !matches!(item.item_kind.as_str(), "skill" | "plugin" | "mcp_server") {
                continue;
            }
            eligible += 1;
            let trust = item.metadata.get("trustResolution");
            let trust = match trust.and_then(Value::as_object) {
                Some(t) => t,
                None => continue,
            };
            covered += 1;
            if let Some(score) = trust.get("trustScore").and_then(Value::as_i64) {
                scores.push(score);
                if score < 70 {
                    low_trust += 1;
                }
            }
        }
    }
    let coverage_percent = if eligible != 0 {
        py_round_f64((covered as f64 / eligible as f64) * 100.0)
    } else {
        100
    };
    let average_score = if scores.is_empty() {
        Value::Null
    } else {
        json!(py_round_f64(
            scores.iter().sum::<i64>() as f64 / scores.len() as f64
        ))
    };
    let mut out = Map::new();
    out.insert("eligible".into(), json!(eligible));
    out.insert("covered".into(), json!(covered));
    out.insert("coverage_percent".into(), json!(coverage_percent));
    out.insert("low_trust".into(), json!(low_trust));
    out.insert("average_score".into(), average_score);
    out
}

/// `summarize_aibom_drift(snapshots)`
pub fn summarize_aibom_drift(snapshots: &[GuardAgentInventorySnapshot]) -> Map<String, Value> {
    let mut counts: std::collections::BTreeMap<String, i64> = [
        ("new", 0),
        ("changed", 0),
        ("removed", 0),
        ("unchanged", 0),
        ("high_risk", 0),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    for snapshot in snapshots {
        for item in &snapshot.items {
            let state = item.drift_state.as_str();
            if let Some(entry) = counts.get_mut(state) {
                *entry += 1;
            }
            if matches!(item.risk_level.as_str(), "critical" | "high") {
                *counts.get_mut("high_risk").unwrap() += 1;
            }
        }
        for drift in &snapshot.drift {
            if let Some(entry) = counts.get_mut(drift.state.as_str()) {
                *entry += 1;
            }
        }
    }
    let total = counts["new"] + counts["changed"] + counts["removed"];
    let mut out = Map::new();
    for key in ["new", "changed", "removed", "unchanged", "high_risk"] {
        out.insert(key.into(), json!(counts[key]));
    }
    out.insert("total".into(), json!(total));
    out
}

/// `_metadata_lookup_from_snapshots(snapshots)`
pub fn _metadata_lookup_from_snapshots(
    snapshots: &[GuardAgentInventorySnapshot],
    deps: &ReportingDeps<'_>,
) -> Map<String, Value> {
    let mut lookup = Map::new();
    for snapshot in snapshots {
        let harness = snapshot.agent_type.clone();
        for item in &snapshot.items {
            let extensions = deps.api.extract_aibom_metadata_extensions(&item.metadata);
            if extensions.is_empty() {
                continue;
            }
            let key = format!("{}\u{1f}{}", harness, item.item_id);
            lookup.insert(key, Value::Object(extensions));
        }
    }
    lookup
}
