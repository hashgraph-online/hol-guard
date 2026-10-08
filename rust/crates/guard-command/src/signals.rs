//! `runtime/signals.py` — typed runtime risk signals for Guard decisions.
//!
//! The value types and label enums already live in `guard-contracts` (added by
//! RTM-023 for cross-crate reuse). This module owns the byte-parity port of the
//! function surface defined in `signals.py` (12 fns), re-exporting the contract
//! types so the rest of `guard-command` binds against `crate::signals::*`.
//!
//! Byte-parity rules preserved:
//!   * severity/confidence score thresholds match `severity_label_from_score`
//!     and `confidence_label_from_score` exactly.
//!   * the `GuardSignal -> RiskSignalV2` mapping (`category_from_guard_signal`,
//!     `technical_detail`, `title_from_reason`) is identical to the Python
//!     helpers.
//!   * strict enum parsers raise `ValueError`-equivalent `SignalContractError`
//!     with the same reason strings.

use guard_contracts::{self, GuardSignalRef};
use serde_json::Value;

// Re-export the value types + label enums so `crate::signals::RiskSignalV2`
// mirrors `signals.RiskSignalV2`.
pub use guard_contracts::{
    GuardRiskSignalV3, RiskConfidenceLabel, RiskRedactionLevel, RiskSeverityLabel,
    RiskSignalCategory, RiskSignalSource, RiskSignalV2, ScannerStatusLabel, SignalContractError,
};

/// `GuardSignal` (types.py:56) — the legacy Guard signal shape consumed by the
/// `RiskSignalV2` mapping. Modeled as an owned struct here so callers can keep
/// signals alive without a borrow of the wire payload.
#[derive(Debug, Clone, PartialEq)]
pub struct GuardSignal {
    pub signal_id: String,
    pub family: String,
    pub severity: i64,
    pub confidence: f64,
    pub evidence_source: String,
    pub matched_text: Option<String>,
    pub explanation: String,
    pub remediation: Option<String>,
    pub rule_version: String,
}

impl GuardSignal {
    /// View as the contracts `GuardSignalRef` borrowed shape.
    pub fn as_ref(&self) -> GuardSignalRef<'_> {
        GuardSignalRef {
            signal_id: &self.signal_id,
            family: &self.family,
            severity: self.severity,
            confidence: self.confidence,
            rule_version: &self.rule_version,
            explanation: &self.explanation,
            matched_text: self.matched_text.as_deref(),
            evidence_source: &self.evidence_source,
            remediation: self.remediation.as_deref(),
        }
    }
}

// ---------------------------------------------------------------------------
// severity_label_from_score / confidence_label_from_score
// ---------------------------------------------------------------------------

/// `severity_label_from_score` — score >= 9 critical, >=7 high, >=5 medium,
/// >=3 low, else info.
pub fn severity_label_from_score(score: f64) -> RiskSeverityLabel {
    guard_contracts::severity_label_from_score(score)
}

/// `confidence_label_from_score` — >=0.85 strong, >=0.5 likely, else weak.
pub fn confidence_label_from_score(score: f64) -> RiskConfidenceLabel {
    guard_contracts::confidence_label_from_score(score)
}

// ---------------------------------------------------------------------------
// GuardSignal -> RiskSignalV2 mapping
// ---------------------------------------------------------------------------

/// `_category_from_guard_signal` — signal_id overrides for bypass/encoded,
/// else the `family` -> category table with `policy` fallback.
pub fn category_from_guard_signal(signal: &GuardSignal) -> RiskSignalCategory {
    let id = signal.signal_id.to_lowercase();
    if id.contains(":bypass:") || id.starts_with("policy:bypass") {
        return RiskSignalCategory::Bypass;
    }
    if id.contains(":encoded:") {
        return RiskSignalCategory::Encoded;
    }
    match signal.family.as_str() {
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

/// `_technical_detail_from_guard_signal` — `matched {source} evidence: {text}`
/// when the signal carries matched text, else `None`.
pub fn technical_detail_from_guard_signal(signal: &GuardSignal) -> Option<String> {
    signal
        .matched_text
        .as_ref()
        .map(|m| format!("matched {} evidence: {}", signal.evidence_source, m))
}

/// `_title_from_reason` — first char uppercased, else a stable fallback title.
pub fn title_from_reason(reason: &str) -> String {
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
pub fn risk_signal_from_guard_signal(signal: &GuardSignal) -> RiskSignalV2 {
    guard_contracts::risk_signal_from_guard_signal(&signal.as_ref())
}

// ---------------------------------------------------------------------------
// Strict enum parsers / coercions
// ---------------------------------------------------------------------------

/// `_optional_int` — null or non-negative int64; `ValueError`-equivalent
/// `SignalContractError`. The Python error interpolates `{key}`; the wire-level
/// error strings in `guard-contracts` use the concrete field name, so this port
/// emits the literal contract message for the known keys.
pub fn optional_int(
    payload: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<i64>, SignalContractError> {
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

/// `_parse_source` — strict `RiskSignalSource` parser.
pub fn parse_source(value: &Value) -> Result<RiskSignalSource, SignalContractError> {
    RiskSignalSource::parse(value)
}

/// `_parse_category` — strict `RiskSignalCategory` parser.
pub fn parse_category(value: &Value) -> Result<RiskSignalCategory, SignalContractError> {
    RiskSignalCategory::parse(value)
}

/// `_parse_severity` — strict `RiskSeverityLabel` parser.
pub fn parse_severity(value: &Value) -> Result<RiskSeverityLabel, SignalContractError> {
    RiskSeverityLabel::parse(value)
}

/// `parse_risk_confidence` — strict `RiskConfidenceLabel` parser (public; the
/// `_parse_confidence` alias points at this same fn).
pub fn parse_risk_confidence(value: &Value) -> Result<RiskConfidenceLabel, SignalContractError> {
    guard_contracts::parse_risk_confidence(value)
}

/// `_parse_redaction_level` — strict `RiskRedactionLevel` parser.
pub fn parse_redaction_level(value: &Value) -> Result<RiskRedactionLevel, SignalContractError> {
    RiskRedactionLevel::parse(value)
}

/// `_parse_scanner_status` — strict `ScannerStatusLabel` parser.
pub fn parse_scanner_status(value: &Value) -> Result<ScannerStatusLabel, SignalContractError> {
    ScannerStatusLabel::parse(value)
}
