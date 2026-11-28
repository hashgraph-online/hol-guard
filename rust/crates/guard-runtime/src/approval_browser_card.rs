//! The native browser approval card on a stored approval row (BP-T046).
//!
//! The approval read model attaches `browser_card` when the row's action envelope names a tool
//! that a first-party browser driver profile lists. The card is projected from the stored, already
//! redacted tool input, so it never holds more than the row does, and it never carries typed text.
//! A call no profile classifies has no card: the dashboard shows the generic MCP card for it and
//! never guesses from the tool's name.

use serde_json::{Map, Value};

use guard_command::browser_action_project::{
    project_screened_browser_action, BrowserProjection, BrowserProjectionContext,
};
use guard_command::browser_card::browser_card;
use guard_command::browser_driver_match::{match_browser_driver, BrowserToolCallIdentity};
use guard_command::browser_first_party_drivers::first_party_browser_drivers;
use guard_contracts::{
    BrowserCardProviderFindingV1, BrowserCardRequestV1, BrowserInputPreviewClassV1,
};

/// The cached provider rows for one origin. The approval read model passes the provider cache;
/// a caller without one passes a closure that lists nothing.
pub(crate) type ProviderRows<'a> = &'a dyn Fn(&str) -> Vec<BrowserCardProviderFindingV1>;

/// Where the harness payload keeps the tool input, in the order the dashboard reads them.
const TOOL_INPUT_KEYS: [&str; 4] = ["tool_input", "toolInput", "toolArgs", "arguments"];
/// What hook and serializer redaction leave in place of a value: the key-based marker and the
/// asterisk masks the hook writes over secret-looking text (`*****`, `sk-*****`, `Bearer *****`).
const REDACTION_MARKERS: [&str; 3] = ["[redacted]", "[REDACTED]", "*****"];
/// What the hook appends to a stored excerpt it cut short; the stored length is not the real one.
const TRUNCATION_MARKER: char = '\u{2026}';

pub(crate) fn envelope_text<'a>(envelope: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    envelope
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(crate) fn tool_input(envelope: &Map<String, Value>) -> Map<String, Value> {
    let Some(Value::Object(raw)) = envelope.get("raw_payload_redacted") else {
        return Map::new();
    };
    for key in TOOL_INPUT_KEYS {
        match raw.get(key) {
            Some(Value::Object(input)) => return input.clone(),
            Some(Value::String(encoded)) => {
                if let Ok(Value::Object(input)) = serde_json::from_str(encoded) {
                    return input;
                }
            }
            _ => {}
        }
    }
    Map::new()
}

fn holds_redaction(value: &Value) -> bool {
    match value {
        Value::String(text) => {
            REDACTION_MARKERS.iter().any(|marker| text.contains(marker))
                || text.ends_with(TRUNCATION_MARKER)
        }
        Value::Array(items) => items.iter().any(holds_redaction),
        Value::Object(fields) => fields.values().any(holds_redaction),
        _ => false,
    }
}

/// The user-facing name of a harness id, as the approval copy names it.
fn agent_name(harness: &str) -> &'static str {
    match harness {
        "claude-code" => "Claude Code",
        "codex" => "Codex",
        "copilot" => "Copilot",
        "cursor" => "Cursor",
        "devin" => "Devin",
        "opencode" => "OpenCode",
        "kimi" => "Kimi",
        "grok" => "Grok",
        "pi" => "Pi",
        "omp" => "Oh My Pi",
        "hermes" => "Hermes",
        "gemini" => "Gemini",
        _ => "The agent",
    }
}

/// The card for one stored approval, or `None` when no first-party profile classifies the call.
pub(crate) fn approval_browser_card(
    envelope: &Value,
    harness: &str,
    provider_rows: ProviderRows<'_>,
) -> Option<Value> {
    let envelope = envelope.as_object()?;
    let tool_name = envelope_text(envelope, "tool_name");
    let mcp_server = envelope_text(envelope, "mcp_server");
    let mcp_tool = envelope_text(envelope, "mcp_tool");
    let harness_tool_name = tool_name.or(mcp_tool)?;
    let call = BrowserToolCallIdentity {
        harness_tool_name,
        mcp_server_name: mcp_server,
        mcp_tool_name: mcp_tool,
        package: None,
    };
    let matched = match_browser_driver(first_party_browser_drivers(), &call)?;
    let arguments = tool_input(envelope);
    let context = BrowserProjectionContext {
        harness,
        ..BrowserProjectionContext::default()
    };
    let BrowserProjection::Classified(mut action) =
        project_screened_browser_action(&matched, &arguments, &Map::new(), &context)
    else {
        return None;
    };
    // A redacted value was a secret when the hook saw it. Its stored stand-in has neither the
    // secret's class nor its length, so the card masks the input and names no length. A value the
    // hook cut short is treated the same way, because its stored length is not the real one.
    let redacted = holds_redaction(&Value::Object(arguments));
    if redacted {
        if let Some(input) = action.input.as_mut() {
            input.preview_class = BrowserInputPreviewClassV1::LooksLikeSecret;
        }
    }
    let provider_findings = action
        .target
        .origin
        .as_deref()
        .map(provider_rows)
        .unwrap_or_default();
    let request = BrowserCardRequestV1 {
        action: *action,
        agent: agent_name(harness).to_owned(),
        first_visit_in_task: false,
        left_granted_site: false,
        provider_findings,
    };
    let mut card = browser_card(&request).ok()?;
    if redacted {
        card.detail.input_length = None;
    }
    serde_json::to_value(card).ok()
}

#[cfg(test)]
#[path = "approval_browser_card_tests.rs"]
mod tests;
