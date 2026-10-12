//! Maps Cisco scanner findings to runtime risk signals and resolves the
//! policy action those signals carry.

use std::sync::OnceLock;

use guard_contracts::{
    most_restrictive_guard_action, CiscoFindingV1, CiscoPolicyQueryV1, CiscoStepV1, GuardAction,
    GuardRiskSignalV3, RiskConfidenceLabel, RiskRedactionLevel, RiskSeverityLabel,
    RiskSignalCategory, RiskSignalSource, ScannerStatusLabel,
};
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const MAX_TEXT: usize = 280;
const FALLBACK_TITLE: &str = "Cisco scanner finding";

fn secret_like() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"\b[A-Za-z0-9_./+=-]{32,}\b").expect("static pattern"))
}

/// Python `str.isspace` also counts the four ASCII separators.
fn py_space(ch: char) -> bool {
    ch.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&ch)
}

fn safe_text(value: &str, fallback: &str) -> String {
    let normalized = value
        .split(py_space)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if normalized.is_empty() {
        return fallback.to_owned();
    }
    let redacted = secret_like()
        .replace_all(&normalized, "[redacted]")
        .into_owned();
    if redacted.chars().count() <= MAX_TEXT {
        return redacted;
    }
    let head: String = redacted.chars().take(MAX_TEXT - 1).collect();
    format!("{}…", head.trim_end_matches(py_space))
}

fn signal_id(finding: &CiscoFindingV1) -> String {
    let source = Some(finding.source.as_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("cisco-scanner");
    let path = finding
        .file_path
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown");
    if let Some(line) = finding.line_number {
        return format!("{source}:{}:{path}:{line}", finding.rule_id);
    }
    let material = [
        finding.rule_id.as_str(),
        path,
        finding.title.as_str(),
        finding.description.as_str(),
        finding.remediation.as_deref().unwrap_or(""),
    ]
    .join("|");
    let suffix = hex::encode(Sha256::digest(material.as_bytes()));
    format!("{source}:{}:{path}:{}", finding.rule_id, &suffix[..12])
}

fn source_of(finding: &CiscoFindingV1) -> RiskSignalSource {
    let source = finding.source.to_lowercase();
    let category = finding.category.to_lowercase();
    if source.contains("mcp") {
        RiskSignalSource::CiscoMcp
    } else if source.contains("skill") {
        RiskSignalSource::CiscoSkill
    } else if category.contains("mcp") {
        RiskSignalSource::CiscoMcp
    } else if category.contains("skill") {
        RiskSignalSource::CiscoSkill
    } else {
        RiskSignalSource::Native
    }
}

fn category_of(finding: &CiscoFindingV1, source: RiskSignalSource) -> RiskSignalCategory {
    match source {
        RiskSignalSource::CiscoMcp => return RiskSignalCategory::Mcp,
        RiskSignalSource::CiscoSkill => return RiskSignalCategory::Skill,
        _ => {}
    }
    let category = finding.category.to_lowercase();
    if category.contains("secret") {
        RiskSignalCategory::Secret
    } else if category.contains("network") {
        RiskSignalCategory::Network
    } else if category.contains("prompt") {
        RiskSignalCategory::Prompt
    } else if category.contains("supply") {
        RiskSignalCategory::SupplyChain
    } else {
        RiskSignalCategory::Policy
    }
}

fn severity_of(value: &str) -> Result<RiskSeverityLabel, &'static str> {
    RiskSeverityLabel::parse(&Value::String(value.to_owned()))
        .map_err(|_| "unknown finding severity")
}

pub(crate) fn finding_signal(
    finding: &CiscoFindingV1,
    status: ScannerStatusLabel,
    scanner_name: &str,
) -> Result<GuardRiskSignalV3, &'static str> {
    let source = source_of(finding);
    let category = category_of(finding, source);
    let severity = severity_of(&finding.severity)?;
    let confidence = match severity {
        RiskSeverityLabel::Critical | RiskSeverityLabel::High => RiskConfidenceLabel::Strong,
        RiskSeverityLabel::Medium => RiskConfidenceLabel::Likely,
        _ => RiskConfidenceLabel::Weak,
    };
    let evidence_ref = match (&finding.file_path, finding.line_number) {
        (None, _) => None,
        (Some(path), None) => Some(path.clone()),
        (Some(path), Some(line)) => Some(format!("{path}:{line}")),
    };
    Ok(GuardRiskSignalV3 {
        signal_id: signal_id(finding),
        source,
        source_version: "unknown".to_owned(),
        category,
        severity,
        confidence,
        title: safe_text(&finding.title, FALLBACK_TITLE),
        plain_language_summary: safe_text(
            &finding.description,
            &format!(
                "{scanner_name} reported a potential {} risk.",
                category.as_str()
            ),
        ),
        technical_detail: Some(format!(
            "{scanner_name} rule {} reported {} evidence.",
            finding.rule_id, finding.category
        )),
        evidence_ref,
        scanner_name: Some(scanner_name.to_owned()),
        scanner_status: status,
        scanner_rule_id: Some(finding.rule_id.clone()),
        redaction_level: RiskRedactionLevel::Summary,
        source_path: finding.file_path.clone(),
        source_line: finding.line_number,
        data_source: None,
        data_sink: None,
        recommended_action: finding
            .remediation
            .as_deref()
            .map(|text| safe_text(text, "")),
    })
}

/// Final signals of a plan whose scan steps carry the analyzers' results.
pub(crate) fn evidence(steps: &[CiscoStepV1]) -> Result<Value, &'static str> {
    let mut signals = Vec::new();
    for step in steps {
        match step {
            CiscoStepV1::Signal { signal } => {
                GuardRiskSignalV3::decode(signal).map_err(|_| "invalid signal step")?;
                signals.push(signal.clone());
            }
            CiscoStepV1::Scan {
                kind,
                status,
                findings,
                ..
            } => {
                let name = match kind.as_str() {
                    "skill" => "Cisco skill scanner",
                    "mcp" => "Cisco MCP scanner",
                    _ => return Err("unknown scan kind"),
                };
                let status = match status.as_deref() {
                    None => ScannerStatusLabel::Failed,
                    Some(value) => ScannerStatusLabel::parse(&Value::String(value.to_owned()))
                        .map_err(|_| "unknown scanner status")?,
                };
                for finding in findings {
                    signals.push(finding_signal(finding, status, name)?.to_value());
                }
            }
        }
    }
    Ok(json!({ "signals": signals }))
}

fn risk_class(source: &str) -> &'static str {
    if source == "cisco_skill" {
        "malicious_skill"
    } else {
        "mcp_dangerous_tool"
    }
}

/// Most restrictive of the configured actions for the signals' sources.
pub(crate) fn policy_action(query: &CiscoPolicyQueryV1) -> Result<Value, &'static str> {
    let mut resolved = vec![Value::String("allow".to_owned())];
    for source in &query.signal_sources {
        let configured = query
            .configured_actions
            .get(risk_class(source))
            .ok_or("missing configured action")?;
        if let Some(action) = configured {
            resolved.push(Value::String(action.clone()));
        }
    }
    let action = if query.signal_sources.is_empty() {
        GuardAction::Allow
    } else {
        most_restrictive_guard_action(&resolved, GuardAction::Review)
    };
    Ok(json!({ "policy_action": action.as_str() }))
}
