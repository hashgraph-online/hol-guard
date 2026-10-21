//! Typed runtime risk-signal contract for Guard decisions.
//!
//! Port of `runtime/signals.py`: the `RiskSignalV2` and `GuardRiskSignalV3`
//! value types plus their six label enums, the label-from-score thresholds,
//! the `GuardSignal` -> `RiskSignalV2` mapping, and strict-key decode.
//!
//! Byte-parity rules preserved:
//!   * to_dict key order and field names match `to_dict()` exactly.
//!   * strict decoders raise on missing required fields and unknown enums.
//!   * severity/confidence thresholds match the score->label boundaries.
//!
//! Error shape: every validator returns `( &'static str reason )` matching the
//! Python `ValueError` message prefix so callers surface identical reasons.

use serde_json::{json, Map, Value};

/// A strict-decode / validation failure. `reason` is the stable machine code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalContractError(pub &'static str);

impl std::fmt::Display for SignalContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for SignalContractError {}

type Res<T> = Result<T, SignalContractError>;

// ---------------------------------------------------------------------------
// Label enums
// ---------------------------------------------------------------------------

macro_rules! label_enum {
    ($name:ident, $reason:literal, $( $v:ident => $s:literal ),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $name {
            $( $v ),+
        }
        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$v => $s ),+
                }
            }
            pub fn parse(value: &Value) -> Res<Self> {
                let s = value.as_str().ok_or(SignalContractError($reason))?;
                Ok(match s {
                    $( $s => Self::$v, )+
                    _ => return Err(SignalContractError($reason)),
                })
            }
        }
        impl From<$name> for Value {
            fn from(v: $name) -> Value {
                Value::String(v.as_str().to_string())
            }
        }
    };
}

label_enum!(RiskSignalCategory, "category must be a known risk signal category",
    Secret => "secret", Network => "network", Prompt => "prompt", Mcp => "mcp",
    Skill => "skill", SupplyChain => "supply_chain", Encoded => "encoded",
    Persistence => "persistence", Bypass => "bypass", FalsePositive => "false_positive",
    Filesystem => "filesystem", Execution => "execution", Publisher => "publisher",
    Policy => "policy", Provenance => "provenance",
);

label_enum!(RiskSeverityLabel, "severity must be a known severity label",
    Info => "info", Low => "low", Medium => "medium", High => "high", Critical => "critical",
);

label_enum!(RiskConfidenceLabel, "confidence must be a known confidence label",
    Weak => "weak", Likely => "likely", Strong => "strong",
);

label_enum!(RiskRedactionLevel, "redaction_level must be a known redaction level",
    None => "none", Summary => "summary", Redacted => "redacted",
);

label_enum!(RiskSignalSource, "source must be a known risk signal source",
    Native => "native", CiscoMcp => "cisco_mcp", CiscoSkill => "cisco_skill",
    ThreatIntel => "threat_intel", RuntimeDetector => "runtime_detector",
);

label_enum!(ScannerStatusLabel, "scanner_status must be a known scanner status",
    Enabled => "enabled", Skipped => "skipped", Unavailable => "unavailable",
    Failed => "failed", TimedOut => "timed_out",
);

/// `parse_risk_confidence` alias (public in Python; `_parse_confidence` = same fn).
pub fn parse_risk_confidence(value: &Value) -> Res<RiskConfidenceLabel> {
    RiskConfidenceLabel::parse(value)
}

// ---------------------------------------------------------------------------
// Score -> label thresholds
// ---------------------------------------------------------------------------

/// severity_label_from_score — score >= 9 critical, >=7 high, >=5 medium, >=3 low, else info.
pub fn severity_label_from_score(score: f64) -> RiskSeverityLabel {
    if score >= 9.0 {
        RiskSeverityLabel::Critical
    } else if score >= 7.0 {
        RiskSeverityLabel::High
    } else if score >= 5.0 {
        RiskSeverityLabel::Medium
    } else if score >= 3.0 {
        RiskSeverityLabel::Low
    } else {
        RiskSeverityLabel::Info
    }
}

/// confidence_label_from_score — >=0.85 strong, >=0.5 likely, else weak.
pub fn confidence_label_from_score(score: f64) -> RiskConfidenceLabel {
    if score >= 0.85 {
        RiskConfidenceLabel::Strong
    } else if score >= 0.5 {
        RiskConfidenceLabel::Likely
    } else {
        RiskConfidenceLabel::Weak
    }
}

// ---------------------------------------------------------------------------
// Coercion helpers (payload_coercion parity)
// ---------------------------------------------------------------------------

fn required_string(payload: &Map<String, Value>, key: &str) -> Res<String> {
    let v = payload.get(key).cloned().unwrap_or(Value::Null);
    match v {
        Value::String(s) if !s.trim().is_empty() => Ok(s),
        _ => Err(SignalContractError(
            "required string field missing or empty",
        )),
    }
}

fn optional_string(payload: &Map<String, Value>, key: &str) -> Res<Option<String>> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        _ => Err(SignalContractError(
            "optional string field must be a string or null",
        )),
    }
}

fn optional_i64(payload: &Map<String, Value>, key: &str) -> Res<Option<i64>> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n.as_i64().map(Some).ok_or(SignalContractError(
            "source_line must be an integer or null",
        )),
        _ => Err(SignalContractError(
            "source_line must be an integer or null",
        )),
    }
}

fn obj(v: &Value) -> Res<&Map<String, Value>> {
    v.as_object()
        .ok_or(SignalContractError("payload must be an object"))
}

// ---------------------------------------------------------------------------
// RiskSignalV2
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct RiskSignalV2 {
    pub signal_id: String,
    pub category: RiskSignalCategory,
    pub severity: RiskSeverityLabel,
    pub confidence: RiskConfidenceLabel,
    pub detector: String,
    pub title: String,
    pub plain_reason: String,
    pub technical_detail: Option<String>,
    pub evidence_ref: Option<String>,
    pub redaction_level: RiskRedactionLevel,
    pub false_positive_hint: Option<String>,
    pub advisory_id: Option<String>,
}

impl RiskSignalV2 {
    /// to_dict — key order matches the Python dict literal.
    pub fn to_value(&self) -> Value {
        json!({
            "signal_id": self.signal_id,
            "category": self.category.as_str(),
            "severity": self.severity.as_str(),
            "confidence": self.confidence.as_str(),
            "detector": self.detector,
            "title": self.title,
            "plain_reason": self.plain_reason,
            "technical_detail": self.technical_detail,
            "evidence_ref": self.evidence_ref,
            "redaction_level": self.redaction_level.as_str(),
            "false_positive_hint": self.false_positive_hint,
            "advisory_id": self.advisory_id,
        })
    }

    /// from_dict — strict decode; required strings non-empty, enums validated.
    pub fn decode(payload: &Value) -> Res<Self> {
        let p = obj(payload)?;
        Ok(Self {
            signal_id: required_string(p, "signal_id")?,
            category: RiskSignalCategory::parse(p.get("category").unwrap_or(&Value::Null))?,
            severity: RiskSeverityLabel::parse(p.get("severity").unwrap_or(&Value::Null))?,
            confidence: RiskConfidenceLabel::parse(p.get("confidence").unwrap_or(&Value::Null))?,
            detector: required_string(p, "detector")?,
            title: required_string(p, "title")?,
            plain_reason: required_string(p, "plain_reason")?,
            technical_detail: optional_string(p, "technical_detail")?,
            evidence_ref: optional_string(p, "evidence_ref")?,
            redaction_level: RiskRedactionLevel::parse(
                p.get("redaction_level").unwrap_or(&Value::Null),
            )?,
            false_positive_hint: optional_string(p, "false_positive_hint")?,
            advisory_id: optional_string(p, "advisory_id")?,
        })
    }
}

/// The legacy `GuardSignal` shape consumed by `from_guard_signal`.
/// `family` is a `SignalFamily` literal; only the fields the mapping reads are
/// required to build a `RiskSignalV2`.
#[derive(Debug, Clone)]
pub struct GuardSignalRef<'a> {
    pub signal_id: &'a str,
    pub family: &'a str,
    pub severity: i64,
    pub confidence: f64,
    pub rule_version: &'a str,
    pub explanation: &'a str,
    pub matched_text: Option<&'a str>,
    pub evidence_source: &'a str,
    pub remediation: Option<&'a str>,
}

fn family_category(family: &str) -> RiskSignalCategory {
    match family {
        "network" => RiskSignalCategory::Network,
        "filesystem" => RiskSignalCategory::Filesystem,
        "secret" => RiskSignalCategory::Secret,
        "execution" => RiskSignalCategory::Execution,
        "publisher" => RiskSignalCategory::Publisher,
        "prompt" => RiskSignalCategory::Prompt,
        "provenance" => RiskSignalCategory::Provenance,
        _ => RiskSignalCategory::Policy,
    }
}

fn category_from_guard_signal(signal_id: &str, family: &str) -> RiskSignalCategory {
    let id = signal_id.to_lowercase();
    if id.contains(":bypass:") || id.starts_with("policy:bypass") {
        return RiskSignalCategory::Bypass;
    }
    if id.contains(":encoded:") {
        return RiskSignalCategory::Encoded;
    }
    family_category(family)
}

fn title_from_reason(reason: &str) -> String {
    let stripped = reason.trim();
    if stripped.is_empty() {
        return "Guard risk signal".to_string();
    }
    let mut chars = stripped.chars();
    let first = chars.next().unwrap().to_uppercase().collect::<String>();
    format!("{}{}", first, chars.as_str())
}

/// `RiskSignalV2.from_guard_signal` — derive a product-facing signal from the
/// legacy `GuardSignal` shape.
pub fn risk_signal_from_guard_signal(signal: &GuardSignalRef<'_>) -> RiskSignalV2 {
    RiskSignalV2 {
        signal_id: signal.signal_id.to_string(),
        category: category_from_guard_signal(signal.signal_id, signal.family),
        severity: severity_label_from_score(signal.severity as f64),
        confidence: confidence_label_from_score(signal.confidence),
        detector: signal.rule_version.to_string(),
        title: title_from_reason(signal.explanation),
        plain_reason: signal.explanation.to_string(),
        technical_detail: signal
            .matched_text
            .map(|m| format!("matched {} evidence: {}", signal.evidence_source, m)),
        evidence_ref: Some(signal.evidence_source.to_string()),
        redaction_level: RiskRedactionLevel::Summary,
        false_positive_hint: signal.remediation.map(str::to_string),
        advisory_id: None,
    }
}

// ---------------------------------------------------------------------------
// GuardRiskSignalV3
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct GuardRiskSignalV3 {
    pub signal_id: String,
    pub source: RiskSignalSource,
    pub source_version: String,
    pub category: RiskSignalCategory,
    pub severity: RiskSeverityLabel,
    pub confidence: RiskConfidenceLabel,
    pub title: String,
    pub plain_language_summary: String,
    pub technical_detail: Option<String>,
    pub evidence_ref: Option<String>,
    pub scanner_name: Option<String>,
    pub scanner_status: ScannerStatusLabel,
    pub scanner_rule_id: Option<String>,
    pub redaction_level: RiskRedactionLevel,
    pub source_path: Option<String>,
    pub source_line: Option<i64>,
    pub data_source: Option<String>,
    pub data_sink: Option<String>,
    pub recommended_action: Option<String>,
}

impl GuardRiskSignalV3 {
    pub fn to_value(&self) -> Value {
        json!({
            "signal_id": self.signal_id,
            "source": self.source.as_str(),
            "source_version": self.source_version,
            "category": self.category.as_str(),
            "severity": self.severity.as_str(),
            "confidence": self.confidence.as_str(),
            "title": self.title,
            "plain_language_summary": self.plain_language_summary,
            "technical_detail": self.technical_detail,
            "evidence_ref": self.evidence_ref,
            "scanner_name": self.scanner_name,
            "scanner_status": self.scanner_status.as_str(),
            "scanner_rule_id": self.scanner_rule_id,
            "redaction_level": self.redaction_level.as_str(),
            "source_path": self.source_path,
            "source_line": self.source_line,
            "data_source": self.data_source,
            "data_sink": self.data_sink,
            "recommended_action": self.recommended_action,
        })
    }

    pub fn decode(payload: &Value) -> Res<Self> {
        let p = obj(payload)?;
        Ok(Self {
            signal_id: required_string(p, "signal_id")?,
            source: RiskSignalSource::parse(p.get("source").unwrap_or(&Value::Null))?,
            source_version: required_string(p, "source_version")?,
            category: RiskSignalCategory::parse(p.get("category").unwrap_or(&Value::Null))?,
            severity: RiskSeverityLabel::parse(p.get("severity").unwrap_or(&Value::Null))?,
            confidence: RiskConfidenceLabel::parse(p.get("confidence").unwrap_or(&Value::Null))?,
            title: required_string(p, "title")?,
            plain_language_summary: required_string(p, "plain_language_summary")?,
            technical_detail: optional_string(p, "technical_detail")?,
            evidence_ref: optional_string(p, "evidence_ref")?,
            scanner_name: optional_string(p, "scanner_name")?,
            scanner_status: ScannerStatusLabel::parse(
                p.get("scanner_status").unwrap_or(&Value::Null),
            )?,
            scanner_rule_id: optional_string(p, "scanner_rule_id")?,
            redaction_level: RiskRedactionLevel::parse(
                p.get("redaction_level").unwrap_or(&Value::Null),
            )?,
            source_path: optional_string(p, "source_path")?,
            source_line: optional_i64(p, "source_line")?,
            data_source: optional_string(p, "data_source")?,
            data_sink: optional_string(p, "data_sink")?,
            recommended_action: optional_string(p, "recommended_action")?,
        })
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn severity_label_thresholds() {
        assert_eq!(severity_label_from_score(9.0), RiskSeverityLabel::Critical);
        assert_eq!(severity_label_from_score(9.5), RiskSeverityLabel::Critical);
        assert_eq!(severity_label_from_score(7.0), RiskSeverityLabel::High);
        assert_eq!(severity_label_from_score(5.0), RiskSeverityLabel::Medium);
        assert_eq!(severity_label_from_score(3.0), RiskSeverityLabel::Low);
        assert_eq!(severity_label_from_score(2.9), RiskSeverityLabel::Info);
        assert_eq!(severity_label_from_score(0.0), RiskSeverityLabel::Info);
    }

    #[test]
    fn confidence_label_thresholds() {
        assert_eq!(
            confidence_label_from_score(0.85),
            RiskConfidenceLabel::Strong
        );
        assert_eq!(
            confidence_label_from_score(0.9),
            RiskConfidenceLabel::Strong
        );
        assert_eq!(
            confidence_label_from_score(0.5),
            RiskConfidenceLabel::Likely
        );
        assert_eq!(
            confidence_label_from_score(0.84),
            RiskConfidenceLabel::Likely
        );
        assert_eq!(confidence_label_from_score(0.1), RiskConfidenceLabel::Weak);
    }

    fn v2_json() -> Value {
        json!({
            "signal_id": "sig-1",
            "category": "secret",
            "severity": "high",
            "confidence": "strong",
            "detector": "det-v1",
            "title": "Title",
            "plain_reason": "reason",
            "technical_detail": null,
            "evidence_ref": "file.py:1",
            "redaction_level": "summary",
            "false_positive_hint": null,
            "advisory_id": null,
        })
    }

    #[test]
    fn v2_roundtrip() {
        let decoded = RiskSignalV2::decode(&v2_json()).unwrap();
        assert_eq!(decoded.signal_id, "sig-1");
        assert_eq!(decoded.category, RiskSignalCategory::Secret);
        assert_eq!(decoded.severity, RiskSeverityLabel::High);
        assert_eq!(decoded.confidence, RiskConfidenceLabel::Strong);
        assert_eq!(decoded.redaction_level, RiskRedactionLevel::Summary);
        // to_dict key order/shape parity
        let value = decoded.to_value();
        assert_eq!(value["signal_id"], "sig-1");
        assert_eq!(value["category"], "secret");
    }

    #[test]
    fn v2_decode_rejects_unknown_enum_and_blank_required() {
        let mut bad = v2_json();
        bad["category"] = json!("bogus");
        assert_eq!(
            RiskSignalV2::decode(&bad).unwrap_err().0,
            "category must be a known risk signal category"
        );
        let mut blank = v2_json();
        blank["signal_id"] = json!("   ");
        assert!(RiskSignalV2::decode(&blank).is_err());
    }

    #[test]
    fn category_from_guard_signal_overrides() {
        assert_eq!(
            category_from_guard_signal("policy:bypass:x", "policy"),
            RiskSignalCategory::Bypass
        );
        assert_eq!(
            category_from_guard_signal("a:bypass:b", "network"),
            RiskSignalCategory::Bypass
        );
        assert_eq!(
            category_from_guard_signal("a:encoded:b", "network"),
            RiskSignalCategory::Encoded
        );
        assert_eq!(
            category_from_guard_signal("x", "filesystem"),
            RiskSignalCategory::Filesystem
        );
        assert_eq!(
            category_from_guard_signal("x", "unmapped"),
            RiskSignalCategory::Policy
        );
    }

    #[test]
    fn risk_signal_from_guard_signal_maps_fields() {
        let gs = GuardSignalRef {
            signal_id: "policy:bypass:attempt",
            family: "policy",
            severity: 9,
            confidence: 0.9,
            rule_version: "rule-v2",
            explanation: "blocked bypass",
            matched_text: Some("sudo"),
            evidence_source: "cmd",
            remediation: Some("don't"),
        };
        let s = risk_signal_from_guard_signal(&gs);
        assert_eq!(s.category, RiskSignalCategory::Bypass);
        assert_eq!(s.severity, RiskSeverityLabel::Critical);
        assert_eq!(s.confidence, RiskConfidenceLabel::Strong);
        assert_eq!(s.detector, "rule-v2");
        assert_eq!(s.title, "Blocked bypass");
        assert_eq!(
            s.technical_detail.as_deref(),
            Some("matched cmd evidence: sudo")
        );
        assert_eq!(s.evidence_ref.as_deref(), Some("cmd"));
        assert_eq!(s.redaction_level, RiskRedactionLevel::Summary);
        assert_eq!(s.false_positive_hint.as_deref(), Some("don't"));
    }

    #[test]
    fn title_from_reason_capitalizes() {
        assert_eq!(title_from_reason("  hello world"), "Hello world");
        assert_eq!(title_from_reason("   "), "Guard risk signal");
    }

    #[test]
    fn v3_roundtrip_and_source_line_typing() {
        let v = json!({
            "signal_id": "s3",
            "source": "native",
            "source_version": "v1",
            "category": "filesystem",
            "severity": "low",
            "confidence": "likely",
            "title": "T",
            "plain_language_summary": "sum",
            "technical_detail": null,
            "evidence_ref": null,
            "scanner_name": "semgrep",
            "scanner_status": "enabled",
            "scanner_rule_id": "r1",
            "redaction_level": "none",
            "source_path": "a.py",
            "source_line": 3,
            "data_source": null,
            "data_sink": null,
            "recommended_action": "block",
        });
        let d = GuardRiskSignalV3::decode(&v).unwrap();
        assert_eq!(d.source, RiskSignalSource::Native);
        assert_eq!(d.scanner_status, ScannerStatusLabel::Enabled);
        assert_eq!(d.source_line, Some(3));
        assert_eq!(d.to_value()["scanner_status"], "enabled");

        // non-integer source_line rejected
        let mut bad = v.clone();
        bad["source_line"] = json!("three");
        assert_eq!(
            GuardRiskSignalV3::decode(&bad).unwrap_err().0,
            "source_line must be an integer or null"
        );
        // unknown scanner_status rejected
        let mut bad2 = v.clone();
        bad2["scanner_status"] = json!("mystery");
        assert!(GuardRiskSignalV3::decode(&bad2).is_err());
    }
}
