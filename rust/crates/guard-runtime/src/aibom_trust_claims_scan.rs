//! The Cisco scanner claims of `aibom_trust_claims`: the trust layer each
//! skill or MCP scan run becomes, and the `localSecurity` summary of an
//! item's scan.

use guard_command::attestation_timestamp::python_strip;
use guard_command::evidence_hash::guard_evidence_hash;
use serde_json::{json, Map, Value};

use super::{component_status, provenance, string_field, Fields, Scanner};
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const CISCO_SCHEMA: &str = "guard-aibom-cisco-scanner-evidence.v1";
const SEVERITIES: [&str; 4] = ["critical", "high", "medium", "low"];
const CISCO_LAYER_METADATA_KEYS: [&str; 7] = [
    "analyzersUsed",
    "policyName",
    "scanMode",
    "mode",
    "targetsScanned",
    "skillsScanned",
    "skillsSkipped",
];

/// One Cisco scanner run as Python projects it.
pub(super) struct Run<'a> {
    status: &'a str,
    message: &'a str,
    source: &'a str,
    duration_ms: Option<&'a Value>,
    metadata: Option<&'a Fields>,
    finding_severities: &'a [Value],
}

impl<'a> Run<'a> {
    pub(super) fn parse(value: Option<&'a Value>) -> Result<Self, &'static str> {
        let run = value.and_then(Value::as_object).ok_or(ERR_INVALID)?;
        let metadata = match run.get("metadata") {
            None | Some(Value::Null) => None,
            Some(Value::Object(metadata)) => Some(metadata),
            Some(_) => return Err(ERR_INVALID),
        };
        Ok(Self {
            status: string_field(run, "status")?,
            message: string_field(run, "message")?,
            source: string_field(run, "source")?,
            duration_ms: run
                .get("duration_ms")
                .filter(|value| value.is_i64() || value.is_u64()),
            metadata,
            finding_severities: run
                .get("finding_severities")
                .and_then(Value::as_array)
                .ok_or(ERR_INVALID)?,
        })
    }

    fn metadata_value(&self, key: &str) -> Option<&'a Value> {
        self.metadata
            .and_then(|metadata| metadata.get(key))
            .filter(|value| !value.is_null())
    }

    /// Findings by severity: the counts the scanner reported, or a count of
    /// the findings it returned.
    fn severity_counts(&self) -> [u64; 4] {
        let mut counts = [0u64; 4];
        if let Some(Value::Object(reported)) = self.metadata_value("findingsBySeverity") {
            for (count, key) in counts.iter_mut().zip(SEVERITIES) {
                *count = reported.get(key).and_then(Value::as_u64).unwrap_or(0);
            }
            return counts;
        }
        for severity in self.finding_severities.iter().filter_map(Value::as_str) {
            if let Some(index) = SEVERITIES.iter().position(|known| *known == severity) {
                counts[index] = counts[index].saturating_add(1);
            }
        }
        counts
    }

    /// How many analyzers ran; a run that names none is the YARA-only scan.
    fn analyzer_count(&self) -> usize {
        match self.metadata_value("analyzersUsed") {
            Some(Value::Array(names)) => names.iter().filter(|name| py_truthy(name)).count(),
            _ => 1,
        }
    }

    /// The layer score of an enabled run; other runs have none.
    fn score(&self, counts: [u64; 4]) -> Option<u64> {
        if self.status != "enabled" {
            return None;
        }
        let [critical, high, medium, low] = counts;
        let penalty = critical
            .saturating_mul(30)
            .saturating_add(high.saturating_mul(12))
            .saturating_add(medium.saturating_mul(4))
            .saturating_add(low);
        // More analyzers raise the ceiling: a clean YARA-only scan stops at 90.
        let ceiling = match self.analyzer_count() {
            0 | 1 => 90,
            2 => 95,
            _ => 100,
        };
        Some(100u64.saturating_sub(penalty).min(ceiling))
    }

    fn count_metadata(&self, key: &str) -> i64 {
        self.metadata_value(key)
            .and_then(Value::as_i64)
            .map_or(0, |count| count.max(0))
    }
}

fn severity_object(counts: [u64; 4]) -> Value {
    let mut object = Map::new();
    for (count, key) in counts.iter().zip(SEVERITIES) {
        object.insert(key.to_owned(), json!(count));
    }
    Value::Object(object)
}

pub(super) fn cisco_layer(run: &Run<'_>, scanner: Scanner, captured_at: &Value) -> Value {
    let counts = run.severity_counts();
    let total = counts
        .iter()
        .fold(0u64, |sum, count| sum.saturating_add(*count));
    let analyzers = run.analyzer_count();
    let trust_score = run.score(counts);
    let mut components = Vec::new();
    if let Some(score) = trust_score {
        // One analyzer is 90% confident, each more adds 5, up to 99.
        let confidence = analyzers.saturating_mul(5).saturating_add(85).min(99);
        let summary = if run.message.is_empty() {
            format!(
                "{} completed with {total} findings using {analyzers} analyzer(s).",
                scanner.label()
            )
        } else {
            run.message.to_owned()
        };
        components.push(json!({
            "componentId": scanner.component_id(),
            "confidence": confidence,
            "label": scanner.label(),
            "score": score,
            "status": component_status(i64::try_from(score).unwrap_or(i64::MAX)),
            "summary": summary,
            "weight": 1.0,
        }));
    }

    let mut metadata = Map::new();
    metadata.insert("scannerSource".to_owned(), json!(run.source));
    metadata.insert("message".to_owned(), json!(run.message));
    metadata.insert("totalFindings".to_owned(), json!(total));
    metadata.insert("findingsBySeverity".to_owned(), severity_object(counts));
    if let Some(duration) = run.duration_ms {
        metadata.insert("durationMs".to_owned(), duration.clone());
    }
    for key in CISCO_LAYER_METADATA_KEYS {
        if let Some(value) = run.metadata_value(key) {
            metadata.insert(key.to_owned(), value.clone());
        }
    }
    let mut evidence = Map::new();
    evidence.insert("source".to_owned(), json!(run.source));
    evidence.insert("layerId".to_owned(), json!(scanner.layer_id()));
    evidence.insert("label".to_owned(), json!(scanner.label()));
    evidence.insert("status".to_owned(), json!(run.status));
    evidence.insert("message".to_owned(), json!(run.message));
    evidence.insert("capturedAt".to_owned(), captured_at.clone());
    evidence.insert("trustScore".to_owned(), json!(trust_score));
    evidence.insert("componentCount".to_owned(), json!(components.len()));
    evidence.insert("totalFindings".to_owned(), json!(total));
    evidence.insert("findingsBySeverity".to_owned(), severity_object(counts));
    for key in CISCO_LAYER_METADATA_KEYS.iter().chain(&["durationMs"]) {
        if let Some(value) = metadata.get(*key) {
            evidence.insert((*key).to_owned(), value.clone());
        }
    }
    metadata.insert("attestationStatus".to_owned(), json!("unsigned"));
    metadata.insert("evidenceAuthority".to_owned(), json!("device_claim"));
    metadata.insert("affectsV4Score".to_owned(), json!(false));
    metadata.insert("evidenceSchemaVersion".to_owned(), json!(CISCO_SCHEMA));
    metadata.insert(
        "evidenceHash".to_owned(),
        json!(guard_evidence_hash(&evidence)),
    );
    metadata.insert("evidence".to_owned(), Value::Object(evidence));

    let derivation = if run.source.is_empty() {
        scanner.layer_id()
    } else {
        run.source
    };
    json!({
        "layerId": scanner.layer_id(),
        "layerType": scanner.layer_id(),
        "status": run.status,
        "evidenceAuthority": "device_claim",
        "affectsV4Score": false,
        "trustScore": trust_score,
        "trustComponents": components,
        "capturedAt": captured_at,
        "provenance": provenance(derivation),
        "metadata": metadata,
    })
}

/// Later layers replace earlier ones of the same type in place.
pub(super) fn merge_layers(layers: Vec<Value>) -> Vec<Value> {
    let mut merged: Vec<Value> = Vec::new();
    for layer in layers {
        let Some(layer_type) = layer
            .get("layerType")
            .and_then(Value::as_str)
            .filter(|layer_type| !layer_type.is_empty())
        else {
            continue;
        };
        match merged.iter().position(|existing| {
            existing.get("layerType").and_then(Value::as_str) == Some(layer_type)
        }) {
            Some(index) => merged[index] = layer,
            None => merged.push(layer),
        }
    }
    merged
}

fn finding_severity(raw: &str) -> &'static str {
    match raw.to_lowercase().as_str() {
        "critical" | "high" => "high",
        "medium" => "medium",
        _ => "low",
    }
}

fn finding_message(finding: &Fields, scanner: Scanner) -> String {
    ["description", "title"]
        .iter()
        .filter_map(|key| finding.get(*key).and_then(Value::as_str))
        .map(python_strip)
        .find(|text| !text.is_empty())
        .unwrap_or(scanner.default_message())
        .to_owned()
}

fn security_findings(raw: &[Value], scanner: Scanner) -> Result<Vec<Fields>, &'static str> {
    let mut findings = raw
        .iter()
        .map(|finding| -> Result<Fields, &'static str> {
            let finding = finding.as_object().ok_or(ERR_INVALID)?;
            let mut row = Map::new();
            row.insert(
                "ruleId".to_owned(),
                json!(string_field(finding, "rule_id")?),
            );
            row.insert(
                "severity".to_owned(),
                json!(finding_severity(string_field(finding, "severity")?)),
            );
            row.insert("file".to_owned(), json!(string_field(finding, "file")?));
            row.insert(
                "message".to_owned(),
                json!(finding_message(finding, scanner)),
            );
            Ok(row)
        })
        .collect::<Result<Vec<Fields>, &'static str>>()?;
    let sort_key = |row: &Fields| {
        ["file", "ruleId", "message"].map(|key| {
            row.get(key)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        })
    };
    findings.sort_by_key(sort_key);
    Ok(findings)
}

fn security_label(score: u64) -> &'static str {
    match score {
        90.. => "safe",
        70..=89 => "review",
        45..=69 => "caution",
        _ => "unsafe",
    }
}

/// The `localSecurity` summary of a skill or MCP scan.
pub(super) fn local_security(security: &Fields, captured_at: &Value) -> KindResult {
    let scanner = Scanner::parse(security.get("scanner"))?;
    let entity_type = string_field(security, "entity_type")?;
    let run = Run::parse(security.get("run"))?;
    let findings = security_findings(
        security
            .get("findings")
            .and_then(Value::as_array)
            .ok_or(ERR_INVALID)?,
        scanner,
    )?;
    let counts = run.severity_counts();
    let safety = match run.score(counts) {
        None => Value::Null,
        Some(score) => {
            let scripts_total = run.count_metadata(scanner.scripts_total_key());
            let high = findings
                .iter()
                .filter(|finding| finding.get("severity").and_then(Value::as_str) == Some("high"))
                .count();
            let mut safety = json!({
                "score": score,
                "label": security_label(score),
                "findingsTotal": findings.len(),
                "highFindings": high,
                "scriptsTotal": scripts_total,
                "permissionsMissing": [],
            });
            if let Scanner::Mcp = scanner {
                safety["targetsScanned"] = json!(scripts_total);
            }
            safety
        }
    };

    let mut metadata = Map::new();
    metadata.insert("scannerSource".to_owned(), json!(run.source));
    metadata.insert("message".to_owned(), json!(run.message));
    metadata.insert("findingsBySeverity".to_owned(), severity_object(counts));
    metadata.insert("totalFindings".to_owned(), json!(findings.len()));
    if let Some(duration) = run.duration_ms {
        metadata.insert("durationMs".to_owned(), duration.clone());
    }
    for key in scanner.security_metadata_keys() {
        if let Some(value) = run.metadata_value(key) {
            metadata.insert((*key).to_owned(), value.clone());
        }
    }
    let findings: Vec<Value> = findings.into_iter().map(Value::Object).collect();
    let hashed = json!({
        "capturedAt": captured_at,
        "entityType": entity_type,
        "findings": findings,
        "provider": scanner.provider(),
        "safety": safety,
        "source": "local_indexed",
        "status": run.status,
    });
    let Value::Object(hashed) = hashed else {
        return Err(ERR_INVALID);
    };
    metadata.insert(
        "evidenceHash".to_owned(),
        json!(guard_evidence_hash(&hashed)),
    );
    Ok(json!({
        "entityType": entity_type,
        "source": "local_indexed",
        "provider": scanner.provider(),
        "status": run.status,
        "capturedAt": captured_at,
        "safety": safety,
        "findings": findings,
        "metadata": metadata,
    }))
}

/// Python truthiness for a JSON value.
fn py_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}
