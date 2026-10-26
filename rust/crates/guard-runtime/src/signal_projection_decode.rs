//! Compatibility decoding uses the existing native signal labels and factories.
use guard_command::signals::{self, RiskSignalV2};
use serde_json::{Map, Value};

pub(crate) fn python_trim(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || ('\u{001c}'..='\u{001f}').contains(&c))
}

fn text(p: &Map<String, Value>, key: &str, required: bool) -> Result<Option<String>, String> {
    match p.get(key) {
        Some(Value::String(value)) if !required || !python_trim(value).is_empty() => {
            Ok(Some(value.clone()))
        }
        None | Some(Value::Null) if !required => Ok(None),
        _ => Err(if required {
            format!("{key} must be a non-empty string")
        } else {
            format!("{key} must be a string or null")
        }),
    }
}

pub(crate) fn decode_v2(payload: &Value) -> Result<RiskSignalV2, String> {
    let p = payload.as_object().ok_or("payload must be an object")?;
    let get = |key| p.get(key).unwrap_or(&Value::Null);
    Ok(RiskSignalV2 {
        signal_id: text(p, "signal_id", true)?.unwrap(),
        category: signals::parse_category(get("category")).map_err(|e| e.to_string())?,
        severity: signals::parse_severity(get("severity")).map_err(|e| e.to_string())?,
        confidence: signals::parse_risk_confidence(get("confidence")).map_err(|e| e.to_string())?,
        detector: text(p, "detector", true)?.unwrap(),
        title: text(p, "title", true)?.unwrap(),
        plain_reason: text(p, "plain_reason", true)?.unwrap(),
        technical_detail: text(p, "technical_detail", false)?,
        evidence_ref: text(p, "evidence_ref", false)?,
        redaction_level: signals::parse_redaction_level(get("redaction_level"))
            .map_err(|e| e.to_string())?,
        false_positive_hint: text(p, "false_positive_hint", false)?,
        advisory_id: text(p, "advisory_id", false)?,
    })
}
