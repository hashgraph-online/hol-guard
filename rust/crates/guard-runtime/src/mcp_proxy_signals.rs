//! Risk signals projected from the reasons of a package evaluation.

use guard_command::workspace_inventory::python_strip;
use guard_contracts::McpPackageReasonSignalsQueryV1;
use serde_json::{json, Value};

const FALSE_POSITIVE_HINT: &str =
    "Review the package request or add a scoped exception only for a verified false positive.";

/// `_optional_text`: a stripped, non-empty string.
fn optional_text(value: Option<&Value>) -> Option<String> {
    let text = python_strip(value?.as_str()?);
    (!text.is_empty()).then(|| text.to_owned())
}

fn severity(value: Option<String>) -> &'static str {
    match value.as_deref() {
        Some("info") => "info",
        Some("low") => "low",
        Some("high") => "high",
        Some("critical") => "critical",
        _ => "medium",
    }
}

pub(crate) fn reason_signals(query: &McpPackageReasonSignalsQueryV1) -> Value {
    let signals: Vec<Value> = query
        .reasons
        .iter()
        .filter_map(Value::as_object)
        .map(|reason| {
            let code = optional_text(reason.get("code")).unwrap_or_else(|| "package-risk".into());
            let message =
                optional_text(reason.get("message")).unwrap_or_else(|| code.replace('_', " "));
            let level = severity(optional_text(reason.get("severity")));
            json!({
                "signal_id": format!("supply-chain.{code}"),
                "category": "supply_chain",
                "severity": level,
                "confidence": if matches!(level, "high" | "critical") { "strong" } else { "likely" },
                "detector": optional_text(reason.get("source"))
                    .unwrap_or_else(|| "guard.supply-chain".into()),
                "title": message,
                "plain_reason": message,
                "technical_detail": message,
                "evidence_ref": null,
                "redaction_level": "summary",
                "false_positive_hint": FALSE_POSITIVE_HINT,
                "advisory_id": null,
            })
        })
        .collect();
    json!({ "signals": signals })
}
