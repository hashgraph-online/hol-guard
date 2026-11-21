//! Artifact risk signals: typed signals, their V2 projection and the summary
//! for one Guard artifact launch definition.
//!
//! This replaces the Python `guard/risk.py` derivation. The input is the
//! artifact's name, command, URL, arguments and the metadata keys the
//! derivation reads; non-`str`, non-`bool` metadata values arrive as their
//! Python `str()` and truthiness. Any malformed input is an error, never a
//! shorter signal list.

mod hosts;
mod patterns;
mod python_text;
mod url_host;
mod wire;

use std::collections::HashSet;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};

use patterns::{Detector, BYPASS, ENCODED, EXFIL, STAGED};
use python_text::{capitalize, path_name, title_from_reason};
use wire::{items, python_str, text, truthy, WireArtifact, WireMetadata, WireScalar};

const RULE_VERSION: &str = "guard-risk-v2";
const NO_SIGNAL_SUMMARY: &str =
    "No obvious secret-access or network signal was detected in the launch definition.";
const LEGACY_CLASSIFICATION_BUDGET: Duration = Duration::from_secs(30);

struct Signal {
    signal_id: String,
    family: &'static str,
    severity: u8,
    confidence: f64,
    evidence_source: &'static str,
    matched_text: Option<String>,
    explanation: String,
    remediation: &'static str,
}

impl Signal {
    fn artifact(
        signal_id: impl Into<String>,
        (family, severity, confidence): (&'static str, u8, f64),
        matched_text: Option<String>,
        explanation: impl Into<String>,
        remediation: &'static str,
    ) -> Self {
        Self {
            signal_id: signal_id.into(),
            family,
            severity,
            confidence,
            evidence_source: "artifact",
            matched_text,
            explanation: explanation.into(),
            remediation,
        }
    }

    fn to_value(&self) -> Value {
        json!({
            "signal_id": self.signal_id,
            "family": self.family,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence_source": self.evidence_source,
            "matched_text": self.matched_text,
            "explanation": self.explanation,
            "remediation": self.remediation,
            "rule_version": RULE_VERSION,
        })
    }

    /// `RiskSignalV2.from_guard_signal`.
    fn to_v2_value(&self) -> Value {
        let lowered_id = self.signal_id.to_lowercase();
        let category = if lowered_id.contains(":bypass:") || lowered_id.starts_with("policy:bypass")
        {
            "bypass"
        } else if lowered_id.contains(":encoded:") {
            "encoded"
        } else {
            match self.family {
                "network" | "filesystem" | "secret" | "execution" | "publisher" | "prompt"
                | "policy" | "provenance" => self.family,
                _ => "policy",
            }
        };
        let severity = if self.severity >= 9 {
            "critical"
        } else if self.severity >= 7 {
            "high"
        } else if self.severity >= 5 {
            "medium"
        } else if self.severity >= 3 {
            "low"
        } else {
            "info"
        };
        let confidence = if self.confidence >= 0.85 {
            "strong"
        } else if self.confidence >= 0.5 {
            "likely"
        } else {
            "weak"
        };
        let technical_detail = self
            .matched_text
            .as_ref()
            .map(|matched| format!("matched {} evidence: {matched}", self.evidence_source));
        json!({
            "signal_id": self.signal_id,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "detector": RULE_VERSION,
            "title": title_from_reason(&self.explanation),
            "plain_reason": self.explanation,
            "technical_detail": technical_detail,
            "evidence_ref": self.evidence_source,
            "redaction_level": "summary",
            "false_positive_hint": self.remediation,
            "advisory_id": null,
        })
    }
}

/// `{signals, signals_v2, summary}` for one wire artifact, which may be the
/// packed large-input form.
pub fn artifact_risk(artifact: &Value) -> Result<Value, &'static str> {
    let decoded = crate::content_sensitivity::decode_input(artifact)
        .map_err(|_| "artifact_risk_input_invalid")?;
    let artifact =
        WireArtifact::deserialize(&*decoded).map_err(|_| "artifact_risk_input_invalid")?;
    let signals = signals(&artifact)?;
    let metadata = &artifact.metadata;
    let summary = text(metadata.runtime_request_summary.as_ref())
        .or_else(|| text(metadata.prompt_summary.as_ref()))
        .map_or_else(|| summarize(&signals), str::to_owned);
    Ok(json!({
        "signals": signals.iter().map(Signal::to_value).collect::<Vec<_>>(),
        "signals_v2": signals.iter().map(Signal::to_v2_value).collect::<Vec<_>>(),
        "summary": summary,
    }))
}

fn signals(artifact: &WireArtifact) -> Result<Vec<Signal>, &'static str> {
    let metadata = &artifact.metadata;
    let env_keys = items(metadata.env_keys.as_ref());
    let mut terms = vec![
        artifact.name.as_str(),
        artifact.command.as_deref().unwrap_or_default(),
        artifact.url.as_deref().unwrap_or_default(),
    ];
    terms.extend(artifact.args.iter().map(String::as_str));
    terms.extend(env_keys.iter().copied());
    terms.extend(text(metadata.request_summary.as_ref()));
    terms.extend(text(metadata.runtime_request_reason.as_ref()));
    terms.retain(|term| !term.is_empty());
    let combined = terms.join(" ");
    let lowered = combined.to_lowercase();
    let command_name = path_name(artifact.command.as_deref().unwrap_or_default()).to_lowercase();
    let named_command = (!command_name.is_empty()).then(|| command_name.clone());

    let mut signals = metadata_signals(metadata);
    if let Some(url) = artifact
        .url
        .as_ref()
        .filter(|url| url.starts_with("http://") || url.starts_with("https://"))
    {
        signals.push(Signal::artifact(
            "network:remote-server",
            ("network", 6, 0.92),
            Some(url.clone()),
            "connects to a remote server",
            "Review remote host trust and scope before allowing.",
        ));
    }
    for host in hosts::extract_network_hosts(&combined) {
        signals.push(Signal::artifact(
            format!("network:host:{host}"),
            ("network", 5, 0.78),
            Some(host.clone()),
            format!("references network host `{host}`"),
            "Confirm host ownership and allowed transport.",
        ));
    }
    let traffic = [
        "http://",
        "https://",
        "curl ",
        "wget ",
        "fetch(",
        "axios.",
        "requests.",
    ];
    if traffic.iter().any(|token| lowered.contains(token)) {
        signals.push(Signal::artifact(
            "network:traffic",
            ("network", 5, 0.86),
            None,
            "can send or receive network traffic",
            "Restrict network access to known destinations.",
        ));
    }
    if !env_keys.is_empty() {
        let shown = env_keys[..env_keys.len().min(3)].join(", ");
        signals.push(Signal::artifact(
            "secret:env-keys",
            ("secret", 5, 0.8),
            Some(shown.clone()),
            "receives environment variables that may contain secrets",
            "Minimize env exposure and redact sensitive keys.",
        ));
        let sensitive = ["token", "secret", "password", "key", "credential", "auth"];
        if env_keys.iter().any(|key| {
            let lowered_key = key.to_lowercase();
            sensitive.iter().any(|token| lowered_key.contains(token))
        }) {
            signals.push(Signal::artifact(
                "secret:env-semantic",
                ("secret", 7, 0.84),
                Some(shown),
                "uses environment key names that imply credentials or auth material",
                "Pass scoped tokens only when required.",
            ));
        }
    }
    let env_reads = [
        ".env",
        "dotenv",
        "printenv",
        "process.env",
        "os.environ",
        "getenv(",
    ];
    if env_reads.iter().any(|token| lowered.contains(token)) {
        signals.push(Signal::artifact(
            "secret:env-read",
            ("secret", 7, 0.9),
            None,
            "can read local environment secrets",
            "Prefer explicit per-command secret injection over broad env reads.",
        ));
    }
    let secret_classes = legacy_secret_path_families(&combined)?;
    for secret_class in &secret_classes {
        signals.push(Signal::artifact(
            format!("secret:path:{secret_class}"),
            ("secret", 8, 0.88),
            Some(secret_class.clone()),
            format!("mentions sensitive local file family: {secret_class}"),
            "Confirm file-read necessity and scope before approval.",
        ));
    }
    if !secret_classes.is_empty() {
        signals.push(Signal::artifact(
            "secret:sensitive-local-files",
            ("secret", 7, 0.82),
            None,
            "mentions sensitive local files",
            "Verify file path access scope before allowing.",
        ));
    }
    let has_arg = |flags: &[&str]| {
        artifact
            .args
            .iter()
            .any(|arg| flags.contains(&arg.as_str()))
    };
    if ["bash", "sh", "zsh", "powershell", "cmd"].contains(&command_name.as_str())
        || has_arg(&["-c", "-lc", "/c"])
    {
        signals.push(Signal::artifact(
            "execution:shell-wrapper",
            ("execution", 6, 0.83),
            named_command.clone(),
            "runs through a shell wrapper",
            "Prefer direct executable invocation over shell wrappers.",
        ));
    }
    if artifact.command.is_some()
        && ["python", "python3", "node", "ruby", "perl"].contains(&command_name.as_str())
        && has_arg(&["-c", "-e"])
    {
        signals.push(Signal::artifact(
            "execution:inline-code",
            ("execution", 7, 0.87),
            named_command,
            "executes inline code at launch",
            "Pin script source and review inline code payload.",
        ));
    }
    for detector in [&ENCODED, &STAGED, &BYPASS] {
        signals.extend(detected(detector, detector.reasons(&lowered)));
    }
    signals.extend(detected(&EXFIL, patterns::exfil_reasons(&lowered)));
    Ok(dedupe(signals))
}

fn detected(detector: &Detector, reasons: Vec<&'static str>) -> Vec<Signal> {
    reasons
        .into_iter()
        .map(|reason| {
            Signal::artifact(
                format!("{}:{}", detector.prefix, reason.replace(' ', "-")),
                (detector.family, detector.severity, detector.confidence),
                Some(reason.to_owned()),
                detector.explanation,
                detector.remediation,
            )
        })
        .collect()
}

/// The legacy secret-path families, sorted, from the existing classifier.
fn legacy_secret_path_families(combined: &str) -> Result<Vec<String>, &'static str> {
    let deadline = Instant::now() + LEGACY_CLASSIFICATION_BUDGET;
    let result =
        crate::content_sensitivity::evaluate("legacy", &json!({ "text": combined }), deadline)
            .map_err(|_| "artifact_risk_secret_paths_unavailable")?;
    result["ok"]
        .as_array()
        .ok_or("artifact_risk_secret_paths_unavailable")?
        .iter()
        .map(|family| {
            family
                .as_str()
                .map(str::to_owned)
                .ok_or("artifact_risk_secret_paths_unavailable")
        })
        .collect()
}

fn metadata_signals(metadata: &WireMetadata) -> Vec<Signal> {
    let mut signals = Vec::new();
    if matches!(metadata.inspection_complete, Some(WireScalar::Flag(false)))
        || matches!(
            metadata.config_parse_complete,
            Some(WireScalar::Flag(false))
        )
    {
        let reason = [&metadata.inspection_reason, &metadata.config_reason]
            .into_iter()
            .map(Option::as_ref)
            .find(|value| truthy(*value))
            .map_or_else(|| "unknown".to_owned(), python_str);
        signals.push(Signal::artifact(
            "inspection:incomplete",
            ("execution", 8, 0.98),
            Some(reason),
            "artifact inspection is incomplete",
            "Repair or reduce the input, then run a complete inspection before approval.",
        ));
    } else if matches!(metadata.analysis_truncated, Some(WireScalar::Flag(true))) {
        signals.push(Signal::artifact(
            "inspection:analysis-truncated",
            ("execution", 6, 0.95),
            None,
            "artifact risk preview is truncated",
            "Review the complete content before approval.",
        ));
    }
    let keyed = [
        ("runtime_request_signals", &metadata.runtime_request_signals),
        ("prompt_signals", &metadata.prompt_signals),
    ];
    for (key, values) in keyed {
        let prompt = key == "prompt_signals";
        for item in items(values.as_ref()) {
            let short = item.chars().take(32).collect::<String>().to_lowercase();
            signals.push(Signal {
                signal_id: format!("metadata:{key}:{}", short.replace(' ', "-")),
                family: if prompt { "prompt" } else { "execution" },
                severity: if prompt { 7 } else { 6 },
                confidence: 0.85,
                evidence_source: if prompt { "prompt" } else { "artifact" },
                matched_text: Some(item.to_owned()),
                explanation: item.to_owned(),
                remediation: "Review request intent before approving.",
            });
        }
    }
    signals
}

/// Keep the first signal for each `signal_id:explanation`.
fn dedupe(signals: Vec<Signal>) -> Vec<Signal> {
    let mut seen = HashSet::new();
    signals
        .into_iter()
        .filter(|signal| seen.insert(format!("{}:{}", signal.signal_id, signal.explanation)))
        .collect()
}

/// `summarize_signals`: the network and secret candidates together, else the
/// two highest-impact signals.
fn summarize(signals: &[Signal]) -> String {
    if signals.is_empty() {
        return NO_SIGNAL_SUMMARY.to_owned();
    }
    let candidate = |family: &str| {
        signals
            .iter()
            .find(|signal| {
                signal.family == family && signal.explanation.to_lowercase().contains(family)
            })
            .or_else(|| signals.iter().find(|signal| signal.family == family))
    };
    if let (Some(network), Some(secret)) = (candidate("network"), candidate("secret")) {
        return format!(
            "{}, and it also {}.",
            capitalize(&network.explanation),
            secret.explanation
        );
    }
    let mut ranked = signals.iter().collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then(right.confidence.total_cmp(&left.confidence))
    });
    match ranked.as_slice() {
        [only] => format!("{}.", capitalize(&only.explanation)),
        [first, second, ..] => format!(
            "{}, and it also {}.",
            capitalize(&first.explanation),
            second.explanation
        ),
        [] => NO_SIGNAL_SUMMARY.to_owned(),
    }
}
