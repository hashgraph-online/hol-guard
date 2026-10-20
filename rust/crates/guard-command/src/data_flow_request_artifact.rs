//! The artifact a shell action's data-flow signals earn
//! (`cli/commands_support_runtime_artifacts.py::_runtime_data_flow_artifact`).
//!
//! The id this builds is the key the review is saved under, so it is the one
//! place that decides what a later approval for the same exfiltrating command
//! matches. It rides back with the signals from `DataFlowAnalyze`: the signals
//! and the artifact are one answer to one question, and asking twice would
//! let the two drift.

use guard_contracts::{RiskSignalCategory, RiskSignalV2};
use serde_json::{json, Value};

use crate::launch_identity_common::sha256_hex;
use crate::sfrs_json::dumps_sorted;
use crate::sfrs_requests::request_artifact_wire;

/// `data_flow_sink_type` (`runtime/data_flow_sink.py`) — the stable sink label
/// the summaries name.
fn sink_type(signals: &[RiskSignalV2]) -> &'static str {
    if signals
        .iter()
        .any(|signal| signal.category == RiskSignalCategory::Network)
    {
        return "network host";
    }
    let has = |needle: &str| signals.iter().any(|signal| signal.signal_id == needle);
    if has("data-flow:clipboard-secret") {
        return "clipboard";
    }
    if has("data-flow:world-readable-temp-secret") {
        return "world-readable temp file";
    }
    if has("data-flow:git-remote-token") {
        return "git remote configuration";
    }
    "external sink"
}

/// `_runtime_data_flow_summary`. The signals are never empty where this is
/// reached — an action with no data flow earns no artifact — so the sentence
/// always carries the clause about evidence redaction.
fn summary(signals: &[RiskSignalV2]) -> String {
    format!(
        "This command sends local secret to {}. Guard kept raw secret contents out of the evidence.",
        sink_type(signals)
    )
}

/// `_runtime_data_flow_artifact`. `command_text` is the action's command, or
/// its tool name, or its action type, in that order — the caller resolves it,
/// because only the caller has the envelope.
pub fn build_data_flow_request_artifact(
    harness: &str,
    tool_name: Option<&str>,
    command_text: &str,
    signals: &[RiskSignalV2],
    config_path: &str,
    source_scope: &str,
) -> Value {
    let signal_ids: Vec<&str> = signals
        .iter()
        .map(|signal| signal.signal_id.as_str())
        .collect();
    let fingerprint = sha256_hex(
        dumps_sorted(&json!({
            "command_text": command_text,
            "signal_ids": signal_ids,
            "source_scope": source_scope,
        }))
        .as_bytes(),
    );
    let request_summary = summary(signals);
    let metadata = json!({
        "action_class": "credential exfiltration shell command",
        "command_text": command_text,
        "guard_default_action": "require-reapproval",
        "risk_classes": ["data_flow_exfiltration"],
        "request_summary": request_summary,
        "runtime_request_signals": signals
            .iter()
            .map(|signal| signal.plain_reason.as_str())
            .collect::<Vec<&str>>(),
        "runtime_request_summary": request_summary,
        "runtime_request_reason":
            "Guard detected local-secret data flow in the runtime action before the command could send it away.",
    });
    request_artifact_wire(
        format!("{harness}:{source_scope}:data-flow:{fingerprint}"),
        format!(
            "{} data-flow exfiltration",
            tool_name
                .filter(|name| !name.is_empty())
                .unwrap_or("runtime")
        ),
        harness,
        "tool_action_request",
        source_scope,
        config_path,
        metadata,
    )
}

#[cfg(test)]
#[path = "data_flow_request_artifact_tests.rs"]
mod tests;
