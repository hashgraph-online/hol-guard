//! Harness documents for the in-process `guard hook` command.
//!
//! The CLI composes a policy action and a reason after the edge decision. This
//! module turns that composed outcome into the exact protocol document each
//! harness reads. It is pure: no IO, no state, no policy decision.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Value};

use super::{canonical_hook_harness, Object};

const DAEMON_UNREACHABLE_MARKER: &str = "daemon was unreachable";
const CODEX_REVIEW_NOTICE: &str = "HOL Guard is reviewing this Codex approval request. Codex will show its normal approval prompt; choose allow only if you trust the exact tool action.";

/// What the CLI should emit for one composed outcome.
#[derive(Debug, PartialEq)]
pub enum CliOutcome {
    /// Nothing to write; the harness contract for this outcome is silence.
    Silent,
    /// The caller falls back to the generic envelope or adapter emit path.
    Fallback,
    /// Write this document.
    Document(Object),
}

fn text<'a>(params: &'a Object, key: &str) -> Option<&'a str> {
    params.get(key).and_then(Value::as_str)
}

fn trimmed<'a>(params: &'a Object, key: &str) -> Option<&'a str> {
    text(params, key)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn flag(params: &Object, key: &str) -> bool {
    params.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// Encoded-execution-looking markers in a command the document describes.
///
/// A presentation signal, not a verdict: encoded-adjacent content is worth
/// surfacing in the structured document even when the action is verified inert
/// and allowed. It is deliberately lighter than the policy detector, which is
/// tuned to avoid false positives on quoted literals and stdin-mode scripts.
static ENCODED_CONTENT_MARKER_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\b(?:base64|b64decode|frombase64string|encodedcommand|openssl|gpg|xxd)\b",
        r"|\bencoded\b",
        // CPython `\s` is `\p{White_Space}` plus the C0 separators Rust excludes.
        r"|\b(?:ba|da|z|a)?sh[\s\x{1c}-\x{1f}]+-\w*s\b",
    ))
    .expect("encoded content marker pattern compiles")
});

fn content_flagged(params: &Object) -> bool {
    text(params, "command_text")
        .is_some_and(|command| ENCODED_CONTENT_MARKER_PATTERN.is_match(command))
}

fn blocking(action: &str) -> bool {
    matches!(
        action,
        "review" | "require-reapproval" | "sandbox-required" | "block"
    )
}

fn terminal(action: &str) -> bool {
    matches!(action, "block" | "sandbox-required")
}

fn permission_decision(action: &str, canonical: &str) -> Option<&'static str> {
    match action {
        "block" | "sandbox-required" => Some("deny"),
        "review" | "require-reapproval" => Some(
            if matches!(canonical, "codex" | "kimi" | "grok" | "devin") {
                "deny"
            } else {
                "ask"
            },
        ),
        _ if canonical == "codex" => None,
        _ => Some("allow"),
    }
}

fn with_reason(output: &mut Object, decision: &str, reason: &str) {
    output.insert("permissionDecision".into(), json!(decision));
    if decision != "allow" || reason.to_lowercase().contains(DAEMON_UNREACHABLE_MARKER) {
        output.insert("permissionDecisionReason".into(), json!(reason));
    }
}

fn hook_output(event: &str) -> Object {
    super::hook_output(event)
        .as_object()
        .cloned()
        .unwrap_or_default()
}

fn with_output(mut payload: Object, output: Object) -> Object {
    payload.insert("hookSpecificOutput".into(), Value::Object(output));
    payload
}

fn with_context(mut payload: Object, event: &str, context: &str) -> Object {
    let mut output = hook_output(event);
    output.insert("additionalContext".into(), json!(context));
    payload.insert("hookSpecificOutput".into(), Value::Object(output));
    payload
}

/// The response the CLI writes for one event (`_emit_native_hook_response`).
pub fn cli_response(harness: &str, params: &Object) -> Option<Object> {
    let canonical = text(params, "canonical_harness").unwrap_or(harness);
    let event = text(params, "event_name").unwrap_or("PreToolUse");
    let action = text(params, "policy_action").unwrap_or("allow");
    let reason = text(params, "reason").unwrap_or("");
    let context = text(params, "additional_context").filter(|value| !value.is_empty());
    let mut payload = Object::new();
    if let Some(message) = trimmed(params, "system_message") {
        payload.insert("systemMessage".into(), json!(message));
    }
    let codex = canonical == "codex";
    let non_empty = |payload: Object| (!payload.is_empty()).then_some(payload);
    match event {
        "UserPromptSubmit" => {
            if blocking(action) && context.is_none() {
                payload.insert("decision".into(), json!("block"));
                payload.insert("reason".into(), json!(reason));
                if codex {
                    payload.insert("continue".into(), json!(false));
                    payload.insert("stopReason".into(), json!(reason));
                    payload = with_context(payload, event, reason);
                }
            } else if let Some(context) = context {
                payload = with_context(payload, event, context);
            } else if matches!(canonical, "claude-code" | "codex") {
                payload = with_output(payload, hook_output(event));
            }
            non_empty(payload)
        }
        "Notification" | "PermissionRequest" => {
            if event == "PermissionRequest" && terminal(action) {
                let mut decision = Object::new();
                decision.insert("behavior".into(), json!("deny"));
                decision.insert("message".into(), json!(context.unwrap_or(reason)));
                if !codex {
                    decision.insert("interrupt".into(), json!(false));
                }
                let mut output = hook_output(event);
                output.insert("decision".into(), Value::Object(decision));
                return Some(with_output(payload, output));
            }
            if event == "PermissionRequest" && codex {
                if matches!(action, "review" | "require-reapproval") {
                    payload.insert("systemMessage".into(), json!(CODEX_REVIEW_NOTICE));
                }
                return non_empty(payload);
            }
            if event == "PermissionRequest" && canonical == "claude-code" {
                let message = text(params, "system_message")
                    .filter(|value| !value.is_empty())
                    .or((!reason.is_empty()).then_some(reason));
                if let Some(message) = message {
                    payload.insert("systemMessage".into(), json!(message));
                }
                return if let Some(context) = context {
                    non_empty(with_context(payload, event, context))
                } else if message.is_some() {
                    non_empty(with_output(payload, hook_output(event)))
                } else {
                    non_empty(payload)
                };
            }
            match context {
                Some(context) => non_empty(with_context(payload, event, context)),
                None => non_empty(payload),
            }
        }
        "PostToolUse" => {
            if blocking(action) {
                payload.insert("decision".into(), json!("block"));
                payload.insert("reason".into(), json!(reason));
                payload.insert("continue".into(), json!(true));
                payload.insert("stopReason".into(), json!(reason));
            } else {
                payload.insert("continue".into(), json!(true));
                payload.insert("policy_action".into(), json!(action));
                if let Some(decision) = permission_decision(action, canonical) {
                    let mut output = hook_output(event);
                    with_reason(&mut output, decision, reason);
                    payload = with_output(payload, output);
                }
            }
            Some(payload)
        }
        _ => {
            let decision = permission_decision(action, canonical);
            if harness == "codex" && event == "PreToolUse" && decision.is_none() {
                return None;
            }
            let mut output = hook_output(event);
            if let Some(decision) = decision {
                with_reason(&mut output, decision, reason);
            }
            Some(with_output(payload, output))
        }
    }
}

fn decisional_evidence(entry: &Value) -> bool {
    let Some(entry) = entry.as_object() else {
        return true;
    };
    let source = entry.get("source").and_then(Value::as_str);
    let status = entry.get("status").and_then(Value::as_str);
    match source {
        Some("approval_reuse" | "policy_composition" | "embedded_script") => false,
        Some("hook_payload_trust") if status == Some("ignored") => false,
        Some("configured_default") if status == Some("relaxed_verified_benign") => false,
        Some("trusted_local_tool") => entry.get("eligible") != Some(&Value::Bool(true)),
        _ => true,
    }
}

fn benign_evidence(entry: &Value) -> bool {
    let Some(entry) = entry.as_object() else {
        return false;
    };
    let source = entry.get("source").and_then(Value::as_str);
    (source == Some("configured_default")
        && entry.get("status").and_then(Value::as_str) == Some("relaxed_verified_benign"))
        || (source == Some("trusted_local_tool")
            && entry.get("eligible") == Some(&Value::Bool(true)))
}

fn copilot_document(
    params: &Object,
    mut base: Object,
    event: &str,
    action: &str,
    reason: &str,
    has_extra_evidence: bool,
) -> CliOutcome {
    if event != "PreToolUse" {
        return CliOutcome::Fallback;
    }
    if !blocking(action) {
        if flag(params, "generic_path")
            && !content_flagged(params)
            && (action == "allow" || !has_extra_evidence)
        {
            let mut document = Object::new();
            document.insert("permissionDecision".into(), json!("allow"));
            return CliOutcome::Document(document);
        }
        base.insert("continue".into(), json!(true));
        let mut output = hook_output(event);
        output.insert("permissionDecision".into(), json!("allow"));
        return CliOutcome::Document(with_output(base, output));
    }
    base.insert("continue".into(), json!(true));
    let mut output = hook_output(event);
    output.insert("permissionDecision".into(), json!("deny"));
    output.insert("permissionDecisionReason".into(), json!(reason));
    CliOutcome::Document(with_output(base, output))
}

fn prompt_document(
    params: &Object,
    mut base: Object,
    canonical: &str,
    action: &str,
    reason: &str,
) -> Object {
    let event = "UserPromptSubmit";
    if !blocking(action) {
        return with_output(base, hook_output(event));
    }
    if canonical == "codex" {
        // Codex prompt payloads never echo the submitted prompt back.
        let mut document = Object::new();
        document.insert("decision".into(), json!("block"));
        document.insert("reason".into(), json!(reason));
        document.insert("policy_action".into(), json!(action));
        document.insert("continue".into(), json!(false));
        document.insert("stopReason".into(), json!(reason));
        let mut document = with_context(document, event, reason);
        let edge_code = ["reason_code", "native_edge_reason_code"]
            .iter()
            .find_map(|key| text(&base, key).filter(|value| !value.is_empty()));
        if let Some(code) = edge_code.filter(|code| !code.trim().is_empty()) {
            document.insert("reason_code".into(), json!(code));
        }
        if let Some(message) = trimmed(params, "system_message") {
            document.insert("systemMessage".into(), json!(message));
        }
        return document;
    }
    base.insert("decision".into(), json!("block"));
    base.insert("reason".into(), json!(reason));
    base.insert("continue".into(), json!(true));
    if terminal(action) && !flag(params, "generic_path") {
        if let Some(message) = trimmed(params, "system_message") {
            base.insert("systemMessage".into(), json!(message));
        }
    }
    base
}

/// The flat line the CLI writes for Copilot's command hook
/// (`_emit_copilot_hook_response`).
///
/// Copilot's command-hook contract only accepts its native transport fields,
/// so this carries the binary disposition and nothing of the exact Guard
/// action; that action stays in Guard's receipts and events.
pub fn copilot_hook_response(params: &Object) -> Object {
    let denied = blocking(text(params, "policy_action").unwrap_or("allow"));
    let mut payload = Object::new();
    payload.insert(
        "permissionDecision".into(),
        json!(if denied { "deny" } else { "allow" }),
    );
    if denied {
        payload.insert(
            "permissionDecisionReason".into(),
            json!(text(params, "reason").unwrap_or("")),
        );
    }
    if let Some(reuse) = params.get("approval_reuse").and_then(Value::as_object) {
        payload.insert("approval_reuse".into(), Value::Object(reuse.clone()));
    }
    match params.get("scanner_evidence").and_then(Value::as_array) {
        Some(evidence) if !evidence.is_empty() => {
            payload.insert("scanner_evidence".into(), Value::Array(evidence.clone()));
        }
        _ => {}
    }
    payload
}

/// The `--json` protocol document for native harnesses (`_native_hook_json_document`).
pub fn cli_document(harness: &str, params: &Object) -> CliOutcome {
    let canonical = text(params, "canonical_harness")
        .map(str::to_owned)
        .unwrap_or_else(|| canonical_hook_harness(harness));
    let event = text(params, "event_name").unwrap_or("PreToolUse");
    let action = text(params, "policy_action").unwrap_or("allow");
    let reason = text(params, "reason").unwrap_or("");
    if event == "PostToolUse" || !matches!(canonical.as_str(), "copilot" | "claude-code" | "codex")
    {
        return CliOutcome::Fallback;
    }
    let base = params
        .get("envelope")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let evidence = base.get("scanner_evidence").and_then(Value::as_array);
    let has_extra_evidence = evidence.is_some_and(|list| list.iter().any(decisional_evidence));
    let has_benign_evidence = evidence.is_some_and(|list| list.iter().any(benign_evidence));
    if canonical == "copilot" {
        return copilot_document(params, base, event, action, reason, has_extra_evidence);
    }
    if event == "UserPromptSubmit" {
        return CliOutcome::Document(prompt_document(params, base, &canonical, action, reason));
    }
    let decision = permission_decision(action, &canonical);
    let silent_codex_allow = canonical == "codex"
        && event == "PreToolUse"
        && flag(params, "native_protocol_payload")
        && flag(params, "generic_path")
        && flag(params, "command_surface")
        && !blocking(action)
        && (action == "allow" || has_benign_evidence || flag(params, "verified_benign"))
        && decision.is_none();
    if silent_codex_allow {
        return CliOutcome::Silent;
    }
    let mut base = base;
    base.insert("continue".into(), json!(true));
    let message = trimmed(params, "system_message");
    if let Some(message) = message {
        base.insert("systemMessage".into(), json!(message));
    }
    let mut output = hook_output(event);
    if event == "PermissionRequest" {
        if terminal(action) {
            output.insert(
                "decision".into(),
                json!({ "behavior": "deny", "message": reason }),
            );
        } else if canonical == "claude-code" {
            // The system message above is already applied.
        } else if matches!(action, "review" | "require-reapproval") {
            base.insert("systemMessage".into(), json!(CODEX_REVIEW_NOTICE));
        } else {
            return CliOutcome::Silent;
        }
        return CliOutcome::Document(with_output(base, output));
    }
    if blocking(action) {
        base.insert("decision".into(), json!("block"));
        base.insert("reason".into(), json!(reason));
    }
    let decision = decision
        .or(
            (canonical == "codex" && event == "PreToolUse" && !blocking(action)).then_some("allow"),
        );
    if let Some(decision) = decision {
        output.insert("permissionDecision".into(), json!(decision));
        if decision != "allow"
            || action == "warn"
            || reason.to_lowercase().contains(DAEMON_UNREACHABLE_MARKER)
        {
            output.insert("permissionDecisionReason".into(), json!(reason));
        }
    }
    CliOutcome::Document(with_output(base, output))
}

#[cfg(test)]
#[path = "cli_documents_tests.rs"]
mod tests;
