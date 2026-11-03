//! `consumer_mode_contract` runner-authority kind: the `guard-consumer.v2`
//! payload `hol-guard scan`, `preflight` and `explain` print for a local
//! artifact. Ported from `schemas/consumer_mode.build_consumer_mode_contract`.
//!
//! Python runs the scanner and ships what it found:
//!
//! - `target`, the scanned path, and `target_name`, its final component;
//! - `intended_harness`, the harness named on the command line, or `null`;
//! - `scan`, the scan result: `score`, `grade`, `timestamp`, `plugin_dir`,
//!   `scope`, `ecosystems`, `packages`, `category_names`, `findings` as
//!   `{title, severity}` rows, `severity_counts`, `integrations` and
//!   `trust_total` (the trust report's total, or `null`).
//!
//! The answer is `{"contract": ...}`. The artifact hash is the SHA-256 of
//! `json.dumps(summary, sort_keys=True)` over the path, score, grade,
//! ecosystems and packages, so it matches the hash earlier releases printed.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::daemon_lifecycle_text::python_int;
use crate::guard_store_json::dumps_default;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const SCHEMA_VERSION: &str = "guard-consumer.v2";
const FINDING_TITLES: usize = 10;
const CISCO_MCP_SCANNER: &str = "cisco-mcp-scanner";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let target = string(args.get("target"))?;
    let target_name = string(args.get("target_name"))?;
    let intended_harness = match args.get("intended_harness") {
        Some(Value::Null) => Value::Null,
        Some(Value::String(harness)) => Value::String(harness.clone()),
        _ => return Err(ERR_INVALID),
    };
    let scan = args
        .get("scan")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let scan = Scan::read(scan)?;
    Ok(json!({ "contract": contract(target, target_name, intended_harness, &scan)? }))
}

struct Scan<'a> {
    score: i64,
    grade: &'a str,
    timestamp: &'a str,
    plugin_dir: &'a str,
    scope: &'a str,
    ecosystems: &'a Vec<Value>,
    packages: &'a Vec<Value>,
    category_names: &'a Vec<Value>,
    findings: Vec<(&'a str, Severity)>,
    severity_counts: &'a Map<String, Value>,
    integrations: Vec<&'a Map<String, Value>>,
    trust_total: &'a Value,
}

impl<'a> Scan<'a> {
    fn read(scan: &'a Map<String, Value>) -> Result<Self, &'static str> {
        let findings = list(scan, "findings")?
            .iter()
            .map(|finding| {
                let finding = finding.as_object().ok_or(ERR_INVALID)?;
                let title = string(finding.get("title"))?;
                let severity = Severity::parse(string(finding.get("severity"))?)?;
                Ok((title, severity))
            })
            .collect::<Result<Vec<_>, &'static str>>()?;
        let integrations = list(scan, "integrations")?
            .iter()
            .map(|integration| integration.as_object().ok_or(ERR_INVALID))
            .collect::<Result<Vec<_>, &'static str>>()?;
        let trust_total = scan.get("trust_total").ok_or(ERR_INVALID)?;
        if !(trust_total.is_null() || trust_total.is_number()) {
            return Err(ERR_INVALID);
        }
        Ok(Self {
            score: scan
                .get("score")
                .and_then(Value::as_i64)
                .ok_or(ERR_INVALID)?,
            grade: string(scan.get("grade"))?,
            timestamp: string(scan.get("timestamp"))?,
            plugin_dir: string(scan.get("plugin_dir"))?,
            scope: string(scan.get("scope"))?,
            ecosystems: strings(scan, "ecosystems")?,
            packages: list(scan, "packages")?,
            category_names: strings(scan, "category_names")?,
            findings,
            severity_counts: scan
                .get("severity_counts")
                .and_then(Value::as_object)
                .ok_or(ERR_INVALID)?,
            integrations,
            trust_total,
        })
    }
}

/// `models.Severity`, ordered as `SEVERITY_ORDER` ranks it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn parse(value: &str) -> Result<Self, &'static str> {
        Ok(match value {
            "info" => Self::Info,
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            _ => return Err(ERR_INVALID),
        })
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

fn contract(
    target: &str,
    target_name: &str,
    intended_harness: Value,
    scan: &Scan<'_>,
) -> Result<Value, &'static str> {
    let summary = json!({
        "path": target,
        "score": scan.score,
        "grade": scan.grade,
        "ecosystems": scan.ecosystems,
        "packages": scan.packages,
    });
    let artifact_hash = hex::encode(Sha256::digest(
        dumps_default(&summary).ok_or(ERR_INVALID)?.as_bytes(),
    ));
    let finding_titles: Vec<&str> = scan
        .findings
        .iter()
        .take(FINDING_TITLES)
        .map(|(title, _)| *title)
        .collect();
    let highest_severity = scan
        .findings
        .iter()
        .map(|(_, severity)| *severity)
        .max()
        .unwrap_or(Severity::Info);
    let (action, reason) = install_recommendation(highest_severity, scan.score, &finding_titles);
    let mut contract = json!({
        "schema_version": SCHEMA_VERSION,
        "generated_at": scan.timestamp,
        "install_target": {
            "path": target,
            "intended_harness": intended_harness,
        },
        "artifact_snapshot": {
            "path": target,
            "artifact_hash": artifact_hash,
            "score": scan.score,
            "grade": scan.grade,
        },
        "capability_manifest": {
            "ecosystems": scan.ecosystems,
            "packages": scan.packages,
            "category_names": scan.category_names,
        },
        "artifact_diff": {
            "changed": false,
            "changed_fields": [],
        },
        "provenance_record": {
            "scope": scan.scope,
            "plugin_dir": scan.plugin_dir,
            "trust_score": scan.trust_total,
        },
        "trust_evidence_bundle": {
            "findings": finding_titles,
            "severity_counts": scan.severity_counts,
            "integrations": scan.integrations,
        },
        "policy_recommendation": {
            "action": action,
            "reason": reason,
        },
        "install_verdict": {
            "action": action,
            "reason": reason,
            "can_install": action == "allow",
        },
        "abom_entry": {
            "artifact_id": format!("preflight:{target_name}"),
            "artifact_name": target_name,
            "artifact_type": scan.scope,
            "path": target,
            "ecosystems": scan.ecosystems,
            "packages": scan.packages,
        },
        "threat_intelligence": {
            "verdict_source": "local-scan",
            "highest_severity": highest_severity.as_str(),
            "finding_count": scan.findings.len(),
        },
    });
    if let Some(evidence) = cisco_evidence(&scan.integrations)? {
        contract
            .as_object_mut()
            .expect("contract is an object")
            .insert("cisco_evidence".to_owned(), evidence);
    }
    Ok(contract)
}

fn install_recommendation(
    highest_severity: Severity,
    score: i64,
    finding_titles: &[&str],
) -> (&'static str, &'static str) {
    if highest_severity >= Severity::High || score < 60 {
        return (
            "block",
            "Install-time scan found severe findings that need review before you trust this artifact.",
        );
    }
    if !finding_titles.is_empty() {
        return (
            "review",
            "Install-time scan found non-blocking findings that should be reviewed before install.",
        );
    }
    (
        "allow",
        "Install-time scan found no blocking issues in the local artifact.",
    )
}

/// The offline Cisco MCP scan evidence, when a Cisco MCP integration scanned
/// local targets.
fn cisco_evidence(integrations: &[&Map<String, Value>]) -> Result<Option<Value>, &'static str> {
    let applicable: Vec<&Map<String, Value>> = integrations
        .iter()
        .copied()
        .filter(|integration| is_applicable_cisco_mcp(integration))
        .collect();
    if applicable.is_empty() {
        return Ok(None);
    }
    let mut finding_count: i64 = 0;
    let mut target_count: i64 = 0;
    for integration in &applicable {
        let findings = integration
            .get("findings_count")
            .and_then(Value::as_i64)
            .ok_or(ERR_INVALID)?;
        finding_count = finding_count.checked_add(findings).ok_or(ERR_INVALID)?;
        if let Some(targets) = target_count_of(integration)? {
            target_count = target_count.checked_add(targets).ok_or(ERR_INVALID)?;
        }
    }
    let status = cisco_status(&applicable);
    Ok(Some(json!({
        "mode": "offline-only",
        "status": status,
        "finding_count": finding_count,
        "target_count": target_count,
        "summary": cisco_summary(status, finding_count, target_count),
        "integrations": applicable,
    })))
}

fn is_applicable_cisco_mcp(integration: &Map<String, Value>) -> bool {
    let named = integration
        .get("name")
        .and_then(Value::as_str)
        .is_some_and(|name| name.contains(CISCO_MCP_SCANNER));
    let metadata = integration.get("metadata").and_then(Value::as_object);
    named
        && metadata.is_some_and(|metadata| {
            metadata.contains_key("targets_scanned") || metadata.contains_key("scan_mode")
        })
}

/// `int(metadata["targets_scanned"])`: `None` when the entry is missing,
/// `null`, or text `int()` cannot parse. Any other non-number is refused, as
/// `int()` raises outside the `ValueError` the scan skips.
fn target_count_of(integration: &Map<String, Value>) -> Result<Option<i64>, &'static str> {
    let raw = integration
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("targets_scanned"));
    match raw {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(flag)) => Ok(Some(i64::from(*flag))),
        Some(Value::String(text)) => Ok(python_int(text)),
        Some(Value::Number(number)) => number
            .as_i64()
            .or_else(|| {
                number
                    .as_f64()
                    .filter(|value| value.is_finite() && value.abs() < 9.2e18)
                    .map(|value| value.trunc() as i64)
            })
            .map(Some)
            .ok_or(ERR_INVALID),
        Some(_) => Err(ERR_INVALID),
    }
}

/// The most severe status any applicable integration reported.
fn cisco_status(integrations: &[&Map<String, Value>]) -> &'static str {
    let reported = |status: &str| {
        integrations
            .iter()
            .any(|integration| integration.get("status").and_then(Value::as_str) == Some(status))
    };
    ["failed", "unavailable", "enabled", "skipped"]
        .into_iter()
        .find(|status| reported(status))
        .unwrap_or("skipped")
}

fn cisco_summary(status: &str, finding_count: i64, target_count: i64) -> String {
    match status {
        "enabled" if finding_count == 1 => {
            format!("{finding_count} finding across {target_count} local MCP target(s)")
        }
        "enabled" => format!("{finding_count} findings across {target_count} local MCP target(s)"),
        "skipped" => format!("Cisco MCP scanning disabled for {target_count} local MCP target(s)"),
        "unavailable" => {
            format!("Cisco MCP scanner unavailable for {target_count} local MCP target(s)")
        }
        _ => format!("Cisco MCP scan failed for {target_count} local MCP target(s)"),
    }
}

fn string(value: Option<&Value>) -> Result<&str, &'static str> {
    value.and_then(Value::as_str).ok_or(ERR_INVALID)
}

fn list<'a>(scan: &'a Map<String, Value>, key: &str) -> Result<&'a Vec<Value>, &'static str> {
    scan.get(key).and_then(Value::as_array).ok_or(ERR_INVALID)
}

fn strings<'a>(scan: &'a Map<String, Value>, key: &str) -> Result<&'a Vec<Value>, &'static str> {
    let items = list(scan, key)?;
    if items.iter().all(Value::is_string) {
        Ok(items)
    } else {
        Err(ERR_INVALID)
    }
}

#[cfg(test)]
#[path = "consumer_mode_contract_tests.rs"]
mod tests;
