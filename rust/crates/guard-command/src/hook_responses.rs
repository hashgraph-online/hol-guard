//! Harness response rendering for native hook decisions.
//!
//! The resident turns a Rust verdict into the exact JSON each harness expects,
//! so no Python layer interprets a verdict to build a response. Key sets and
//! values are byte-parity-critical: vectors recorded from the previous renderer bind every shape.

use serde_json::{json, Map, Value};

mod containment;

/// JSON object used for verdicts and rendered responses.
pub type Object = Map<String, Value>;

const REVIEW_DEFAULT_REASON: &str = "HOL Guard requires native review before execution.";
const REVIEW_PAUSE_REASON: &str = "HOL Guard requires review before this action can execute.";
const WATCH_REASON: &str = "Watch recorded this action without stopping it.";
const POST_BLOCK_REASON: &str =
    "HOL Guard blocked this tool output because it could not be proven safe.";
const POST_WARN_REASON: &str =
    "HOL Guard raised a non-blocking warning under the installed native policy.";
const PROMPT_UNAVAILABLE_REASON: &str = "HOL Guard could not complete native prompt review safely.";
const SILENT_WARNING_CODES: [&str; 1] = ["native_policy_observed"];
const PROMPT_RISK_CLASSES: [(&str, &str); 7] = [
    ("local_env_read", "Prompt requests a local .env file."),
    (
        "sensitive_material",
        "Prompt requests potentially sensitive local material.",
    ),
    (
        "exfil_intent",
        "Prompt includes exfiltration-oriented transfer intent.",
    ),
    (
        "destructive_intent",
        "Prompt includes a destructive local action.",
    ),
    ("subprocess_intent", "Prompt requests subprocess execution."),
    (
        "guard_bypass_intent",
        "Prompt includes Guard bypass intent.",
    ),
    (
        "prompt_injection_intent",
        "Prompt asks to override trusted instructions.",
    ),
];

/// Lower-cased, dash-normalised harness name used to select an envelope.
pub fn canonical_hook_harness(harness: &str) -> String {
    harness.trim().to_lowercase().replace('_', "-")
}

fn is_decision_style(canonical: &str) -> bool {
    matches!(canonical, "pi" | "omp")
}

fn is_grok_decision(canonical: &str) -> bool {
    matches!(canonical, "grok" | "openclaw")
}

fn text(response: &Object, key: &str) -> Option<String> {
    match response.get(key) {
        Some(Value::String(value)) if !value.is_empty() => Some(value.clone()),
        _ => None,
    }
}

fn text_or(response: &Object, key: &str, default: &str) -> String {
    text(response, key).unwrap_or_else(|| default.to_owned())
}

fn is_str(response: &Object, key: &str, expected: &str) -> bool {
    response.get(key).and_then(Value::as_str) == Some(expected)
}

fn object(entries: Vec<(&str, Value)>) -> Object {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

fn hook_output(event: &str) -> Value {
    json!({ "hookEventName": event })
}

fn is_allow(response: &Object) -> bool {
    response.get("decision").and_then(Value::as_str) == Some("allow")
}

fn is_allow_floor(response: &Object) -> bool {
    matches!(
        response.get("minimum_action").and_then(Value::as_str),
        Some("allow" | "warn")
    ) && is_allow(response)
}

/// Render a PreToolUse verdict without changing its policy floor.
pub fn pre_tool(harness: &str, response: &Object) -> Object {
    let action = response.get("minimum_action").and_then(Value::as_str);
    let reason = text_or(response, "reason", REVIEW_DEFAULT_REASON);
    let reason_code = text_or(response, "reason_code", "native_pre_tool_review");
    let canonical = canonical_hook_harness(harness);
    if let Some(receipt) = containment::receipt(&canonical, response, &reason, &reason_code) {
        return receipt;
    }
    let warns = action == Some("warn") && !SILENT_WARNING_CODES.contains(&reason_code.as_str());
    if is_allow_floor(response) {
        if is_decision_style(&canonical) {
            let mut output = object(vec![
                ("decision", json!("allow")),
                ("policy_action", json!(action)),
                ("reason_code", json!(reason_code)),
            ]);
            if warns {
                output.insert("reason".into(), json!(reason));
                output.insert("notice".into(), json!("warning"));
            }
            return output;
        }
        let mut specific = object(vec![
            ("hookEventName", json!("PreToolUse")),
            ("permissionDecision", json!("allow")),
        ]);
        if warns {
            specific.insert("permissionDecisionReason".into(), json!(reason));
        }
        if is_grok_decision(&canonical) {
            let mut allow = object(vec![
                ("decision", json!("allow")),
                ("policy_action", json!(action)),
                ("reason_code", json!(reason_code)),
                ("hookSpecificOutput", Value::Object(specific)),
            ]);
            if warns {
                allow.insert("reason".into(), json!(reason));
            }
            return allow;
        }
        return object(vec![
            ("continue", json!(true)),
            ("policy_action", json!(action)),
            ("reason_code", json!(reason_code)),
            ("hookSpecificOutput", Value::Object(specific)),
        ]);
    }
    if is_decision_style(&canonical) {
        return object(vec![
            ("decision", json!("deny")),
            ("reason", json!(reason)),
            ("model_output_action", json!("block")),
            ("notice", json!("warning")),
            ("policy_action", json!("block")),
            ("reason_code", json!(reason_code)),
        ]);
    }
    let specific = json!({
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    });
    if is_grok_decision(&canonical) {
        return object(vec![
            ("decision", json!("deny")),
            ("reason", json!(reason)),
            ("policy_action", json!("block")),
            ("reason_code", json!(reason_code)),
            ("hookSpecificOutput", specific),
        ]);
    }
    object(vec![
        ("policy_action", json!("block")),
        ("reason_code", json!(reason_code)),
        ("hookSpecificOutput", specific),
    ])
}

fn review_permission_decision(canonical: &str) -> &'static str {
    // zcode opens its native permission prompt for review-tier decisions, so
    // its envelope must ask rather than deny.
    match canonical {
        "codex" | "kimi" | "grok" | "hermes" | "devin" => "deny",
        _ => "ask",
    }
}

fn trimmed(approval: Option<&Object>, key: &str) -> Option<String> {
    match approval?.get(key) {
        Some(Value::String(value)) if !value.trim().is_empty() => Some(value.trim().to_owned()),
        _ => None,
    }
}

/// Pause a PreToolUse review without treating it as a terminal block.
///
/// `linked_reason` is the review reason with the signed approval link already
/// applied; it is used only when the approval carries a link.
pub fn pre_tool_review(
    harness: &str,
    response: &Object,
    approval: Option<&Object>,
    linked_reason: Option<&str>,
) -> Object {
    let mut reason = text_or(response, "reason", REVIEW_PAUSE_REASON);
    let reason_code = text_or(response, "reason_code", "native_pre_tool_review");
    let canonical = canonical_hook_harness(harness);
    let approval_url = trimmed(approval, "approval_url");
    let approval_request_id = trimmed(approval, "request_id");
    if let (Some(_), Some(linked)) = (&approval_url, linked_reason) {
        reason = linked.to_owned();
    }
    let mut rendered = if is_decision_style(&canonical) {
        object(vec![
            ("decision", json!("deny")),
            ("reason", json!(reason)),
            ("model_output_action", json!("block")),
            ("notice", json!("warning")),
            ("policy_action", json!("review")),
            ("reason_code", json!(reason_code)),
        ])
    } else {
        let mut output = object(vec![
            ("policy_action", json!("review")),
            ("reason_code", json!(reason_code)),
            ("reason", json!(reason)),
            (
                "hookSpecificOutput",
                json!({
                    "hookEventName": "PreToolUse",
                    "permissionDecision": review_permission_decision(&canonical),
                    "permissionDecisionReason": reason,
                }),
            ),
        ]);
        if is_grok_decision(&canonical) {
            output.insert("decision".into(), json!("deny"));
        }
        output
    };
    if let Some(url) = &approval_url {
        rendered.insert("approval_url".into(), json!(url));
    }
    if let Some(id) = &approval_request_id {
        rendered.insert("approval_request_id".into(), json!(id));
    }
    if let (Some(id), Some(url)) = (&approval_request_id, &approval_url) {
        rendered.insert("primary_approval_request_id".into(), json!(id));
        rendered.insert("primary_approval_url".into(), json!(url));
        rendered.insert("guardApprovalRequestId".into(), json!(id));
        rendered.insert("guardApprovalUrl".into(), json!(url));
        rendered.insert(
            "approval_requests".into(),
            json!([{ "request_id": id, "approval_url": url }]),
        );
    }
    rendered
}

/// Pause-or-continue response for a prompt that Rust could not clear.
fn observe_lifecycle(canonical: &str, event_name: &str, reason_code: &str) -> Object {
    match canonical {
        // Grok honors only "block" on a prompt; empty JSON is success.
        "grok" => Object::new(),
        "hermes" | "openclaw" | "pi" | "omp" => object(vec![
            ("decision", json!("allow")),
            ("policy_action", json!("allow")),
            ("reason_code", json!(reason_code)),
        ]),
        _ => object(vec![
            ("continue", json!(true)),
            ("policy_action", json!("allow")),
            ("reason_code", json!(reason_code)),
            ("hookSpecificOutput", hook_output(event_name)),
        ]),
    }
}

fn prompt_risk_signals(response: &Object) -> Vec<&'static str> {
    let Some(Value::Array(classes)) = response.get("prompt_risk_classes") else {
        return Vec::new();
    };
    let order = |item: &Value| {
        PROMPT_RISK_CLASSES
            .iter()
            .position(|(code, _)| item.as_str() == Some(code))
    };
    let indexes: Option<Vec<usize>> = classes.iter().map(order).collect();
    match indexes {
        Some(indexes)
            if (1..=6).contains(&indexes.len()) && indexes.windows(2).all(|w| w[0] < w[1]) =>
        {
            indexes
                .into_iter()
                .map(|index| PROMPT_RISK_CLASSES[index].1)
                .collect()
        }
        _ => Vec::new(),
    }
}

/// Render a UserPromptSubmit verdict.
pub fn prompt(harness: &str, response: &Object) -> Object {
    let canonical = canonical_hook_harness(harness);
    let action = response.get("minimum_action").and_then(Value::as_str);
    let reason_code = text_or(response, "reason_code", "native_prompt_unavailable");
    let signals = prompt_risk_signals(response);
    if is_allow(response) && matches!(action, Some("allow" | "warn")) {
        if canonical == "grok" {
            return Object::new();
        }
        if canonical == "codex" {
            return object(vec![(
                "hookSpecificOutput",
                hook_output("UserPromptSubmit"),
            )]);
        }
        let mut output = object(vec![
            ("policy_action", json!(action)),
            ("reason_code", json!(reason_code)),
            ("hookSpecificOutput", hook_output("UserPromptSubmit")),
        ]);
        if is_decision_style(&canonical) {
            output.insert("decision".into(), json!("allow"));
        }
        if !signals.is_empty() && canonical != "copilot" {
            output.insert("risk_signals".into(), json!(signals));
        }
        return output;
    }
    let reason = text_or(response, "reason", PROMPT_UNAVAILABLE_REASON);
    let policy_action = action
        .filter(|a| {
            matches!(
                *a,
                "review" | "require-reapproval" | "sandbox-required" | "block"
            )
        })
        .unwrap_or("block");
    if canonical == "copilot" {
        return object(vec![
            ("behavior", json!("deny")),
            ("message", json!(reason)),
            ("interrupt", json!(false)),
            ("policy_action", json!(policy_action)),
            ("reason_code", json!(reason_code)),
        ]);
    }
    let mut output = object(vec![
        ("decision", json!("block")),
        ("reason", json!(reason)),
        ("systemMessage", json!(reason)),
        ("policy_action", json!(policy_action)),
        ("reason_code", json!(reason_code)),
        ("hookSpecificOutput", hook_output("UserPromptSubmit")),
    ]);
    if !signals.is_empty() {
        output.insert("risk_signals".into(), json!(signals));
    }
    if canonical == "codex" {
        output.insert("continue".into(), json!(false));
        output.insert("stopReason".into(), json!(reason));
        output.insert(
            "hookSpecificOutput".into(),
            json!({ "hookEventName": "UserPromptSubmit", "additionalContext": reason }),
        );
    }
    output
}

/// Render a blocked PostToolUse verdict.
fn post_tool_block(reason: &str, reason_code: &str) -> Object {
    object(vec![
        ("decision", json!("block")),
        ("reason", json!(reason)),
        ("continue", json!(true)),
        ("stopReason", json!(reason)),
        ("policy_action", json!("block")),
        ("risk_summary", json!(reason)),
        ("model_output_action", json!("block")),
        ("notice", json!("warning")),
        ("reason_code", json!(reason_code)),
        (
            "hookSpecificOutput",
            json!({ "hookEventName": "PostToolUse", "additionalContext": reason }),
        ),
    ])
}

/// Render a PostToolUse verdict.
pub fn post_tool(harness: &str, response: &Object) -> Object {
    let canonical = canonical_hook_harness(harness);
    if is_decision_style(&canonical) {
        return response.clone();
    }
    if canonical == "cline" {
        // The managed AgentPlugin can replace the model-visible result. Keep
        // the reviewed-output directive and digest intact for that seam; the
        // native Cline hook itself remains observation-only.
        return [
            "decision",
            "model_output_action",
            "reviewed_output_sha256",
            "reviewed_excerpt",
            "policy_action",
        ]
        .into_iter()
        .filter_map(|key| {
            response
                .get(key)
                .map(|value| (key.to_owned(), value.clone()))
        })
        .collect();
    }
    if is_allow(response) && is_str(response, "model_output_action", "allow_original") {
        let action = response
            .get("policy_action")
            .and_then(Value::as_str)
            .filter(|a| matches!(*a, "allow" | "warn"))
            .unwrap_or("allow");
        let mut specific = hook_output("PostToolUse");
        if action == "warn" {
            specific = json!({
                "hookEventName": "PostToolUse",
                "permissionDecisionReason": text_or(response, "reason", POST_WARN_REASON),
            });
        }
        return object(vec![
            ("policy_action", json!(action)),
            ("hookSpecificOutput", specific),
        ]);
    }
    post_tool_block(
        &text_or(response, "reason", POST_BLOCK_REASON),
        &text_or(response, "reason_code", "native_hook_edge_block"),
    )
}

/// Watch posture: continue a PreToolUse that Rust would have paused.
pub fn recording_only_pre_tool(harness: &str, reason_code: &str, reason: &str) -> Object {
    let canonical = canonical_hook_harness(harness);
    if matches!(
        canonical.as_str(),
        "grok" | "hermes" | "openclaw" | "pi" | "omp"
    ) {
        return object(vec![
            ("decision", json!("allow")),
            ("policy_action", json!("warn")),
            ("reason_code", json!(reason_code)),
            ("reason", json!(reason)),
        ]);
    }
    pre_tool(
        harness,
        &object(vec![
            ("decision", json!("allow")),
            ("minimum_action", json!("warn")),
            ("policy_action", json!("warn")),
            ("reason_code", json!(reason_code)),
            ("reason", json!(reason)),
        ]),
    )
}

/// Render the harness response for one Rust edge result.
///
/// `recording_only` is the acknowledged Watch posture: it never lowers a
/// verdict, it only chooses a continuing envelope for a result that would
/// otherwise pause the harness.
pub fn render_edge_response(
    harness: &str,
    event_name: &str,
    result: &Value,
    recording_only: bool,
) -> Option<Object> {
    let result = result.as_object()?;
    Some(match event_name {
        "UserPromptSubmit" if recording_only => observe_lifecycle(
            &canonical_hook_harness(harness),
            event_name,
            "watch_recording_only",
        ),
        "UserPromptSubmit" => prompt(harness, result),
        "PreToolUse" if recording_only && !is_benign_allow(result) => recording_only_pre_tool(
            harness,
            &text_or(result, "reason_code", "watch_recording_only"),
            &text_or(result, "reason", WATCH_REASON),
        ),
        "PreToolUse" => pre_tool(harness, result),
        "PostToolUse" => post_tool(harness, result),
        _ => return None,
    })
}

fn is_benign_allow(result: &Object) -> bool {
    is_str(result, "minimum_action", "allow") && is_allow(result)
}

#[cfg(test)]
#[path = "hook_responses_tests.rs"]
mod tests;
