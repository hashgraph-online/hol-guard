//! Per-artifact result rows for the consumer evaluation.
//!
//! The rows are what `guard run`, `guard scan` and the dashboard render: the
//! authoritative decision projection, the scoring recommendation, the
//! evidence the decision rested on, and the incident copy. They are assembled
//! here from the decision pieces Python already holds so the shaping of what a
//! person is told never depends on a second implementation.

use serde_json::{json, Map, Value};

use crate::consumer_incident::{build as build_incident, IncidentInput};

const TRUSTED_REQUEST_OVERRIDE_REASON: &str = "trusted_request_override_exact_context";
const REMOVED_RISK_SUMMARY: &str = "Artifact was removed from the harness configuration.";
const REMOVED_RISK_SIGNAL: &str = "artifact removed from local harness configuration";
const INVALID: &str = "native_consumer_artifact_project_request_invalid";

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn non_empty<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    text(value, key).filter(|text| !text.is_empty())
}

fn merge(target: &mut Map<String, Value>, source: &Value) {
    if let Some(items) = source.as_object() {
        for (key, value) in items {
            target.insert(key.clone(), value.clone());
        }
    }
}

fn incident(input: &IncidentInput<'_>) -> Result<Map<String, Value>, &'static str> {
    match build_incident(input) {
        Some(Value::Object(fields)) => Ok(fields),
        _ => Err(INVALID),
    }
}

/// `_launch_target_from_artifact`: the most specific launch description.
pub(crate) fn launch_target(artifact: &Value) -> Option<String> {
    let metadata = artifact.get("metadata").unwrap_or(&Value::Null);
    if let Some(summary) =
        non_empty(metadata, "request_summary").or(non_empty(metadata, "prompt_summary"))
    {
        return Some(summary.to_owned());
    }
    if let Some(url) = non_empty(artifact, "url") {
        return Some(url.to_owned());
    }
    let command = non_empty(artifact, "command")?;
    let mut parts = vec![command];
    if let Some(args) = artifact.get("args").and_then(Value::as_array) {
        parts.extend(args.iter().filter_map(Value::as_str));
    }
    Some(parts.join(" ").trim().to_owned())
}

fn trusted_override(runtime: &Value) -> Value {
    let applied = runtime.get("trusted_request_override") == Some(&Value::Bool(true));
    json!({
        "applied": applied,
        "reason_code": applied.then_some(TRUSTED_REQUEST_OVERRIDE_REASON),
    })
}

/// Fields shared by the detected and removed rows.
fn decision_fields(target: &mut Map<String, Value>, query: &Value) {
    let runtime = &query["runtime"];
    target.insert(
        "approval_context_hash".to_owned(),
        query["approval_context_hash"].clone(),
    );
    target.insert(
        "effective_workspace".to_owned(),
        query["effective_workspace"].clone(),
    );
    target.insert(
        "approval_reuse_status".to_owned(),
        runtime["approval_reuse"]["status"].clone(),
    );
    target.insert(
        "approval_reuse_reason_code".to_owned(),
        runtime["approval_reuse"]["reason_code"].clone(),
    );
    target.insert(
        "approval_reuse".to_owned(),
        runtime["approval_reuse"].clone(),
    );
    target.insert(
        "scanner_evidence".to_owned(),
        runtime["scanner_evidence"].clone(),
    );
    target.insert(
        "trusted_request_override".to_owned(),
        trusted_override(runtime),
    );
    if !runtime["approval_claim"].is_null() {
        target.insert(
            "approval_claim".to_owned(),
            runtime["approval_claim"].clone(),
        );
    }
}

fn changed_fields(evidence: &Value) -> Vec<String> {
    evidence["changed_fields"]
        .as_array()
        .map(|fields| {
            fields
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Result row of a detected artifact.
pub(crate) fn artifact_result(query: &Value) -> Result<Value, &'static str> {
    let artifact = &query["artifact"];
    let evidence = &query["evidence"];
    let verdict = &query["verdict"];
    let fields = changed_fields(evidence);
    let launch = launch_target(artifact);
    let incident = incident(&IncidentInput {
        harness: text(query, "harness").ok_or(INVALID)?,
        artifact,
        artifact_id: text(artifact, "artifact_id").ok_or(INVALID)?,
        artifact_name: text(artifact, "name").unwrap_or(""),
        artifact_type: text(artifact, "artifact_type"),
        source_scope: text(artifact, "source_scope"),
        config_path: text(artifact, "config_path"),
        changed_fields: &fields,
        policy_action: text(query, "policy_action").ok_or(INVALID)?,
        launch_target: launch.as_deref(),
        risk_summary: text(query, "risk_summary"),
    })?;
    let mut row = Map::new();
    row.insert("artifact_id".to_owned(), artifact["artifact_id"].clone());
    row.insert("artifact_name".to_owned(), artifact["name"].clone());
    row.insert("changed".to_owned(), evidence["changed"].clone());
    row.insert(
        "changed_fields".to_owned(),
        evidence["changed_fields"].clone(),
    );
    merge(&mut row, &query["projection"]);
    row.insert("artifact_hash".to_owned(), evidence["current_hash"].clone());
    decision_fields(&mut row, query);
    row.insert(
        "scoring_recommendation".to_owned(),
        json!({
            "non_authoritative": true,
            "action": verdict["action"],
            "mapped_guard_action": query["scanner_action"],
            "reasons": verdict["reasons"],
            "confidence": verdict["confidence"],
            "severity": verdict["severity"],
            "evidence_sources": verdict["evidence_sources"],
        }),
    );
    for (key, value) in [
        ("risk_signals", query["risk_signals"].clone()),
        ("risk_summary", query["risk_summary"].clone()),
        ("signals", query["signals"].clone()),
        ("confidence", verdict["confidence"].clone()),
        ("severity", verdict["severity"].clone()),
        ("evidence_sources", verdict["evidence_sources"].clone()),
        ("provenance_state", verdict["provenance_state"].clone()),
        ("provenance", evidence["provenance"].clone()),
        ("history_context", evidence["history_context"].clone()),
        (
            "capability_snapshot",
            evidence["capability_snapshot"].clone(),
        ),
        ("capability_delta", evidence["capability_delta"].clone()),
        ("remediation", verdict["recommended_next_actions"].clone()),
        ("suppressibility", verdict["suppressible"].clone()),
        ("review_priority", verdict["review_priority"].clone()),
        ("artifact_type", artifact["artifact_type"].clone()),
        ("config_path", artifact["config_path"].clone()),
        ("source_scope", artifact["source_scope"].clone()),
    ] {
        row.insert(key.to_owned(), value);
    }
    row.extend(incident);
    Ok(Value::Object(row))
}

/// Receipt strings and result row of an artifact removed from the harness.
pub(crate) fn removed_result(query: &Value) -> Result<Value, &'static str> {
    let previous = &query["previous"];
    let artifact_id = text(query, "artifact_id").ok_or(INVALID)?;
    let name = text(previous, "name").unwrap_or(artifact_id);
    let artifact_type = text(previous, "artifact_type");
    let source_scope = text(previous, "source_scope");
    let config_path = text(previous, "config_path");
    let risk_summary = if query["has_runtime_authority"] == Value::Bool(true) {
        query["dashboard_detail"].clone()
    } else {
        json!(REMOVED_RISK_SUMMARY)
    };
    let incident = incident(&IncidentInput {
        harness: text(query, "harness").ok_or(INVALID)?,
        artifact: &Value::Null,
        artifact_id,
        artifact_name: name,
        artifact_type: Some(artifact_type.unwrap_or("artifact")),
        source_scope,
        config_path,
        changed_fields: &["removed".to_owned()],
        policy_action: text(query, "policy_action").ok_or(INVALID)?,
        launch_target: None,
        risk_summary: risk_summary.as_str(),
    })?;
    let mut parts = Vec::new();
    parts.extend(artifact_type.map(|kind| kind.replace('_', " ")));
    parts.extend(source_scope.map(|scope| format!("{scope} artifact")));
    let capabilities_summary = if parts.is_empty() {
        "removed artifact".to_owned()
    } else {
        parts.join(" \u{2022} ")
    };
    let removed_signals: Vec<Value> = query["risk_signals"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut row = Map::new();
    row.insert("artifact_id".to_owned(), json!(artifact_id));
    row.insert("artifact_name".to_owned(), json!(name));
    row.insert("changed".to_owned(), json!(true));
    row.insert("changed_fields".to_owned(), json!(["removed"]));
    merge(&mut row, &query["projection"]);
    row.insert("artifact_hash".to_owned(), query["previous_hash"].clone());
    decision_fields(&mut row, query);
    for (key, value) in [
        (
            "scoring_recommendation",
            json!({
                "non_authoritative": true,
                "action": "warn",
                "mapped_guard_action": "warn",
                "reasons": ["Artifact removal should be reviewed for intentionality."],
                "confidence": 0.7,
                "severity": 3,
                "evidence_sources": ["history"],
            }),
        ),
        ("removed", json!(true)),
        (
            "risk_signals",
            if removed_signals.is_empty() {
                json!([REMOVED_RISK_SIGNAL])
            } else {
                json!(removed_signals)
            },
        ),
        ("risk_summary", risk_summary.clone()),
        ("signals", query["signals"].clone()),
        ("confidence", json!(0.7)),
        ("severity", json!(3)),
        ("evidence_sources", json!(["history"])),
        ("provenance_state", json!("none")),
        (
            "provenance",
            crate::consumer_evidence::provenance_bundle(None, &[]),
        ),
        ("history_context", empty_history()),
        ("capability_snapshot", json!({})),
        ("capability_delta", json!([])),
        ("remediation", json!(["defer_and_notify_team"])),
        ("suppressibility", json!(true)),
        ("review_priority", json!("low")),
        ("artifact_type", json!(artifact_type.unwrap_or("artifact"))),
        ("config_path", json!(config_path)),
        ("source_scope", json!(source_scope)),
    ] {
        row.insert(key.to_owned(), value);
    }
    row.extend(incident);
    Ok(json!({
        "receipt": {
            "capabilities_summary": capabilities_summary,
            "provenance_summary": format!(
                "{} artifact removed from {}",
                source_scope.unwrap_or("unknown"),
                config_path.unwrap_or("unknown config"),
            ),
            "artifact_name": name,
            "source_scope": source_scope,
        },
        "result": Value::Object(row),
    }))
}

fn empty_history() -> Value {
    json!({
        "first_seen_at": null,
        "last_seen_at": null,
        "prior_approvals": 0,
        "prior_incidents": 0,
        "prior_blocks": 0,
        "publisher_trust": "unknown",
    })
}

/// Incident copy for one artifact decision.
pub(crate) fn incident_context(query: &Value) -> Result<Value, &'static str> {
    let fields: Vec<String> = changed_fields(query);
    let artifact = &query["artifact"];
    Ok(Value::Object(incident(&IncidentInput {
        harness: text(query, "harness").ok_or(INVALID)?,
        artifact,
        artifact_id: text(query, "artifact_id").ok_or(INVALID)?,
        artifact_name: text(query, "artifact_name").ok_or(INVALID)?,
        artifact_type: text(query, "artifact_type"),
        source_scope: text(query, "source_scope"),
        config_path: text(query, "config_path"),
        changed_fields: &fields,
        policy_action: text(query, "policy_action").ok_or(INVALID)?,
        launch_target: text(query, "launch_target"),
        risk_summary: text(query, "risk_summary"),
    })?))
}
