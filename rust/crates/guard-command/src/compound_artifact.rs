//! One runtime artifact for a compound command
//! (`commands_support_runtime_artifacts.py::_compound_runtime_artifact`).
//!
//! The hook collects one artifact per finding. When the command has more than
//! one segment, a redirect, an embedded command, a wrapper or an inexact parse,
//! or when several findings apply, the resident parses the raw text, models
//! its working directories and binds every finding to the whole command, so
//! one approval cannot cover a command it never saw. Python sends the
//! findings and applies the reply; it never decides whether binding applies.

use std::path::Path;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::codex_output_env::Ctx;
use crate::command_action_risk_classes::risk_classes_for_command_action;
use crate::command_model::{parse_shell_command, CanonicalCommand};
use crate::sfrs_quote_parsing::literal_cd_execution_context;
use crate::shell_execution_context::shell_execution_context_metadata;
use crate::unmodeled_shell_artifact::request_shell_context;

#[cfg(all(test, unix))]
#[path = "compound_artifact_tests.rs"]
mod tests;

const INVALID: &str = "native_sensitive_request_input_invalid";

struct Finding<'a> {
    artifact_id: &'a str,
    artifact_type: &'a str,
    name: &'a str,
    metadata: &'a Map<String, Value>,
}

fn finding(value: &Value) -> Result<Finding<'_>, &'static str> {
    let text = |key: &str| value.get(key).and_then(Value::as_str).ok_or(INVALID);
    Ok(Finding {
        artifact_id: text("artifact_id")?,
        artifact_type: text("artifact_type")?,
        name: text("name")?,
        metadata: value
            .get("metadata")
            .and_then(Value::as_object)
            .ok_or(INVALID)?,
    })
}

/// `_optional_string`: a stripped, non-blank string.
fn optional_string(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

fn non_blank_strings(value: Option<&Value>) -> impl Iterator<Item = &str> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|text| !text.trim().is_empty())
}

fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}

/// `_runtime_artifact_declared_risk_classes`.
fn declared_risk_classes(finding: &Finding) -> Vec<String> {
    let mut classes = Vec::new();
    match finding.artifact_type {
        "package_request" => classes.push("package_script".to_owned()),
        "file_read_request" => classes.push("local_secret_read".to_owned()),
        _ => {}
    }
    for class in non_blank_strings(finding.metadata.get("risk_classes")) {
        classes.push(class.trim().to_owned());
    }
    if finding.artifact_type == "tool_action_request" {
        if let Some(action_class) = finding.metadata.get("action_class").and_then(Value::as_str) {
            classes.extend(
                risk_classes_for_command_action(action_class)
                    .iter()
                    .map(|class| (*class).to_owned()),
            );
        }
    }
    let mut unique = Vec::new();
    for class in classes {
        push_unique(&mut unique, class);
    }
    unique
}

fn canonical_text(value: &Value) -> Result<String, &'static str> {
    let mut out = Vec::new();
    guard_contracts::write_canonical_json(value, &mut out).map_err(|_| INVALID)?;
    String::from_utf8(out).map_err(|_| INVALID)
}

fn requires_full_command_binding(findings: usize, command: Option<&CanonicalCommand>) -> bool {
    findings > 1
        || command.is_some_and(|command| {
            command.segments.len() > 1
                || !command.redirects.is_empty()
                || !command.embedded_commands.is_empty()
                || !command.wrapper_chain.is_empty()
                || command.confidence != "exact"
        })
}

/// Compose the findings. `primary` is the finding the reply binds; a `null`
/// `metadata` keeps it unchanged. Otherwise `metadata` is the ordered list of
/// `[key, value]` updates and `artifact_id` and `name` replace the primary's.
pub fn compound_artifact(
    input: &Value,
    workspace: Option<&Path>,
    home: Option<&Path>,
    ctx: &Ctx,
) -> Result<Value, &'static str> {
    let findings = input
        .get("artifacts")
        .and_then(Value::as_array)
        .filter(|findings| !findings.is_empty())
        .ok_or(INVALID)?
        .iter()
        .map(finding)
        .collect::<Result<Vec<_>, _>>()?;
    let command_text = match input.get("command_text") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) if !text.trim().is_empty() => Some(text.as_str()),
        Some(_) => return Err(INVALID),
    };
    let decision = match input.get("decision") {
        None | Some(Value::Null) => None,
        Some(Value::Object(decision)) => Some(decision),
        Some(_) => return Err(INVALID),
    };
    let home = home.ok_or(INVALID)?;
    let primary = findings
        .iter()
        .position(|finding| finding.artifact_type == "package_request")
        .unwrap_or(0);
    let command = command_text.map(|text| {
        parse_shell_command(
            text,
            workspace,
            Some(home),
            "posix",
            "shell_string",
            "guard-shell",
            true,
        )
    });
    if !requires_full_command_binding(findings.len(), command.as_ref()) {
        return Ok(json!({"primary": primary, "metadata": null}));
    }

    let mut signals = Vec::new();
    let mut summaries = Vec::new();
    let mut reasons = Vec::new();
    let mut risk_classes = Vec::new();
    let mut rule_matches: Vec<(String, &Value)> = Vec::new();
    let mut finding_wire = Vec::new();
    for finding in &findings {
        let classes = declared_risk_classes(finding);
        for class in &classes {
            push_unique(&mut risk_classes, class.clone());
        }
        for signal in non_blank_strings(finding.metadata.get("runtime_request_signals")) {
            push_unique(&mut signals, signal);
        }
        let summary = optional_string(finding.metadata.get("runtime_request_summary"));
        if let Some(summary) = summary {
            push_unique(&mut summaries, summary);
        }
        if let Some(reason) = optional_string(finding.metadata.get("runtime_request_reason")) {
            push_unique(&mut reasons, reason);
        }
        if let Some(matches) = finding
            .metadata
            .get("command_rule_matches")
            .and_then(Value::as_array)
        {
            for rule_match in matches.iter().filter(|item| item.is_object()) {
                // Python keeps the first position and the last equal value.
                let key = canonical_text(rule_match)?;
                match rule_matches.iter_mut().find(|(seen, _)| *seen == key) {
                    Some(slot) => slot.1 = rule_match,
                    None => rule_matches.push((key, rule_match)),
                }
            }
        }
        finding_wire.push(json!({
            "artifact_id": finding.artifact_id,
            "artifact_type": finding.artifact_type,
            "risk_classes": classes,
            "summary": summary.unwrap_or(finding.name),
        }));
    }
    let segments = command.as_ref().map_or_else(Vec::new, |command| {
        command
            .segments
            .iter()
            .enumerate()
            .map(|(index, segment)| {
                json!({
                    "index": index,
                    "execution_context": segment.execution_context,
                    "pipeline_index": segment.pipeline_index,
                    "executable": segment.executable,
                    "span": {"source": "normalized", "start": segment.start, "end": segment.end},
                })
            })
            .collect()
    });
    let compound_summary = format!("Compound command findings: {}", summaries.join(" "));
    let security_identity = command.as_ref().map_or_else(
        || "command-security-unavailable".to_owned(),
        CanonicalCommand::security_identity,
    );
    let mut complete = command
        .as_ref()
        .is_some_and(|command| command.confidence == "exact");
    let mut context_metadata = Vec::new();
    if let Some(text) = command_text {
        let mut context = request_shell_context(text, workspace, workspace, None, ctx);
        if !context.complete {
            context = literal_cd_execution_context(text, home, ctx).unwrap_or(context);
        }
        complete = complete && context.complete;
        if let Value::Object(metadata) = shell_execution_context_metadata(&context) {
            context_metadata.extend(metadata);
        }
    }

    let mut metadata: Vec<(String, Value)> = vec![
        ("compound_complete".into(), json!(complete)),
        ("compound_findings".into(), json!(finding_wire)),
        ("compound_finding_count".into(), json!(findings.len())),
        ("compound_segments".into(), json!(segments)),
        ("compound_segment_count".into(), json!(segments.len())),
        ("risk_classes".into(), json!(risk_classes)),
        ("request_summary".into(), json!(compound_summary)),
        ("runtime_request_signals".into(), json!(signals)),
        ("runtime_request_summary".into(), json!(compound_summary)),
        ("runtime_request_reason".into(), json!(reasons.join(" "))),
        (
            "command_rule_matches".into(),
            json!(rule_matches
                .iter()
                .map(|(_, value)| *value)
                .collect::<Vec<_>>()),
        ),
        ("command_security_identity".into(), json!(security_identity)),
        (
            "command_parse_confidence".into(),
            json!(command
                .as_ref()
                .map_or("uncertain", |command| command.confidence.as_str())),
        ),
        (
            "command_uncertainty_reason".into(),
            command.as_ref().map_or_else(
                || json!("command_text_unavailable"),
                |command| json!(command.uncertainty_reason),
            ),
        ),
    ];
    if command_text.is_some() {
        metadata.extend(
            decision
                .into_iter()
                .flatten()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
    }
    metadata.extend(context_metadata);
    if !complete {
        metadata.push(("guard_default_action".into(), json!("require-reapproval")));
    }
    let identity = json!({
        "version": 1,
        "primary_artifact_id": findings[primary].artifact_id,
        "finding_artifact_ids": findings.iter().map(|finding| finding.artifact_id).collect::<Vec<_>>(),
        "command_security_identity": security_identity,
    });
    let fingerprint = format!(
        "{:x}",
        Sha256::digest(canonical_text(&identity)?.as_bytes())
    );
    let primary_id = findings[primary].artifact_id;
    let prefix = primary_id
        .rsplit_once(':')
        .map_or(primary_id, |(prefix, _)| prefix);
    Ok(json!({
        "primary": primary,
        "artifact_id": format!("{prefix}:{fingerprint}"),
        "name": format!("compound {}", findings[primary].name),
        "metadata": metadata.into_iter().map(|(key, value)| json!([key, value])).collect::<Vec<_>>(),
    }))
}
