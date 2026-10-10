//! Browser intent projection, exact-match context and temporary-grant
//! selectors for routine browser MCP calls.

use guard_command::browser_mcp_intent::evaluate_browser_mcp;
use guard_command::mcp_tool_signals::browser_arguments;
use guard_contracts::{
    BrowserAutomationIntentV1, BrowserMcpRequestV1, BrowserMcpResultV1, McpToolPolicySubjectV1,
};
use serde_json::{json, Value};

use crate::context_digest::python_strip;

const SELECTOR_PREFIX: &str = "mcp-temporary-grant:v1";
const INFORMATIONAL_CATEGORY: &str = "browser_external_domain";

pub(crate) fn browser_intent(
    subject: &McpToolPolicySubjectV1,
) -> Result<Option<BrowserAutomationIntentV1>, &'static str> {
    let result = evaluate_browser_mcp(&BrowserMcpRequestV1::Normalize {
        artifact: subject.artifact.clone(),
        arguments: browser_arguments(&subject.arguments),
    })?;
    match result {
        BrowserMcpResultV1::Normalize { intent } => Ok(intent.map(|boxed| *boxed)),
        _ => Err("native_mcp_tool_policy_decide_browser_invalid"),
    }
}

fn enum_text<T: serde::Serialize>(value: &T) -> Option<String> {
    match serde_json::to_value(value).ok()? {
        Value::String(text) => Some(text),
        _ => None,
    }
}

/// The exact-match context a saved browser approval is stored under.
pub(crate) fn exact_match_context(intent: Option<&BrowserAutomationIntentV1>) -> Option<String> {
    let intent = intent?;
    let kind = enum_text(&intent.intent).unwrap_or_default();
    if kind.is_empty() && intent.operation.is_empty() && intent.target_origin.is_none() {
        return None;
    }
    let mut flags: Vec<String> = intent
        .sensitive_surface_flags
        .iter()
        .filter_map(enum_text)
        .filter(|flag| !flag.is_empty())
        .collect();
    flags.sort();
    let payload = json!({
        "intent": kind,
        "operation": intent.operation,
        "target_origin": intent.target_origin,
        "target_path_prefix": intent.target_path_prefix,
        "profile_mode": enum_text(&intent.profile_mode),
        "server_identity_hash": intent.mcp_server_identity_hash,
        "tool_identity_hash": intent.mcp_tool_identity_hash,
        "schema_hash": intent.mcp_schema_hash,
        "sensitive_surface_flags": flags,
    });
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&payload, &mut bytes, usize::MAX)
        .ok()?;
    String::from_utf8(bytes).ok()
}

fn category_for(intent: &str) -> Option<&'static str> {
    match intent {
        "browser.navigation" => Some("browser_navigation"),
        "browser.inspect" => Some("browser_inspection"),
        "browser.interact" => Some("browser_interaction"),
        _ => None,
    }
}

/// Grant selectors, most specific first, for a routine browser capability.
/// Anything that adds risk beyond the routine category yields none.
pub(crate) fn grant_selectors(
    intent: Option<&BrowserAutomationIntentV1>,
    risk_categories: &[String],
    artifact_id: &str,
    artifact_hash: &str,
) -> Vec<String> {
    let Some(intent) = intent else {
        return Vec::new();
    };
    let identity = intent
        .mcp_server_identity_hash
        .as_deref()
        .map(python_strip)
        .filter(|hash| !hash.is_empty());
    let named = python_strip(&intent.mcp_server_name);
    let category = enum_text(&intent.intent).as_deref().and_then(category_for);
    let (Some(identity), Some(category)) = (identity, category) else {
        return Vec::new();
    };
    if named.is_empty()
        || !risk_categories.iter().any(|item| item == category)
        || risk_categories
            .iter()
            .any(|item| item != category && item != INFORMATIONAL_CATEGORY)
    {
        return Vec::new();
    }
    let digest =
        guard_policy_snapshot::digest_bytes(format!("{artifact_id}\0{artifact_hash}").as_bytes());
    vec![
        format!("{SELECTOR_PREFIX}:exact:{digest}"),
        format!("{SELECTOR_PREFIX}:{identity}:category:{category}"),
        format!("{SELECTOR_PREFIX}:{identity}:server"),
    ]
}
