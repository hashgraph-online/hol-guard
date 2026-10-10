//! MCP tool-call risk signals and summary text.
//!
//! Port of the Python `_risk_signals_from_categories`,
//! `_risk_summary_from_signals` and the policy `summary_code` mapping in
//! `mcp_tool_calls.py`. Category extraction, browser scope, target redaction
//! and sensitive-surface detection stay in `mcp_tool_risk` and
//! `browser_mcp_intent`; this module only composes them into display text.

use guard_contracts::{
    BrowserIntentV1, BrowserMcpArgumentsV1, BrowserMcpDisplayIntentV1, BrowserMcpRequestV1,
    BrowserMcpResultV1, McpToolArgumentsV1, McpToolRiskInputV1,
};
use serde_json::{json, Map, Value};

use crate::browser_mcp_intent::evaluate_browser_mcp;
use crate::mcp_tool_risk::evaluate_tool_risk;

const ERR_CATEGORY: &str = "native_mcp_tool_evidence_unknown_category";
const ERR_SUMMARY: &str = "native_mcp_tool_evidence_unknown_summary_code";

/// The value the risk classifier reads, shaped like the Python argument.
fn risk_arguments(arguments: &McpToolArgumentsV1) -> Value {
    match arguments {
        McpToolArgumentsV1::Mapping { entries } => {
            Value::Object(entries.iter().cloned().collect::<Map<String, Value>>())
        }
        McpToolArgumentsV1::Json { text } => Value::String(text.clone()),
        McpToolArgumentsV1::Other { value } => value.clone(),
    }
}

fn browser_arguments(arguments: &McpToolArgumentsV1) -> BrowserMcpArgumentsV1 {
    match arguments {
        McpToolArgumentsV1::Mapping { entries } => BrowserMcpArgumentsV1::Mapping {
            entries: entries.clone(),
        },
        McpToolArgumentsV1::Json { text } => BrowserMcpArgumentsV1::Json { text: text.clone() },
        McpToolArgumentsV1::Other { .. } => BrowserMcpArgumentsV1::Other,
    }
}

struct BrowserSignalContext {
    target: String,
    surfaces: Vec<String>,
}

fn browser_context(
    input: &McpToolRiskInputV1,
) -> Result<Option<BrowserSignalContext>, &'static str> {
    let arguments = browser_arguments(&input.arguments);
    let normalized = evaluate_browser_mcp(&BrowserMcpRequestV1::Normalize {
        artifact: input.artifact.clone(),
        arguments: arguments.clone(),
    })?;
    let BrowserMcpResultV1::Normalize {
        intent: Some(intent),
    } = normalized
    else {
        return Ok(None);
    };
    let display_intent: BrowserIntentV1 = intent.intent;
    let displayed = evaluate_browser_mcp(&BrowserMcpRequestV1::Display {
        intent: BrowserMcpDisplayIntentV1 {
            intent: display_intent,
            operation: intent.operation.clone(),
            target_domain: intent.target_domain.clone(),
            target_origin: intent.target_origin.clone(),
        },
        arguments,
    })?;
    let BrowserMcpResultV1::Display { target } = displayed else {
        return Err("native_mcp_tool_evidence_browser_display_invalid");
    };
    let surfaces = intent
        .sensitive_surface_flags
        .iter()
        .filter_map(|flag| serde_json::to_value(flag).ok())
        .filter_map(|flag| flag.as_str().map(str::to_owned))
        .collect();
    Ok(Some(BrowserSignalContext { target, surfaces }))
}

fn signal_for(category: &str, browser: Option<&BrowserSignalContext>) -> Option<String> {
    let fixed = match category {
        "filesystem_access" => Some("call shape implies filesystem path access"),
        "destructive_mutation" => Some("tool name implies destructive file or system changes"),
        "command_execution" => Some("tool name implies shell or command execution"),
        "outbound_network" => Some("call arguments imply outbound network activity"),
        "secret_access" => Some("call arguments mention sensitive local files or secrets"),
        "privileged_system_mutation" => Some("call arguments imply privileged system mutation"),
        "tool_schema_mismatch" => Some("tool name understates dangerous schema capabilities"),
        "browser_shared_profile" => {
            browser.map(|_| "browser MCP uses a shared or remote-debugging profile")
        }
        _ => None,
    };
    if let Some(text) = fixed {
        return Some(text.to_owned());
    }
    let browser = browser?;
    let target = &browser.target;
    Some(match category {
        "browser_navigation" => format!("browser navigation to {target}"),
        "browser_inspection" => format!("browser inspection of {target}"),
        "browser_interaction" => format!("browser interaction on {target}"),
        "browser_transfer" => format!("browser file transfer involving {target}"),
        "browser_privileged" => format!("privileged browser access to {target}"),
        "browser_external_domain" => format!("first navigation to external domain {target}"),
        "browser_sensitive_surface" => format!(
            "browser action touches sensitive surfaces: {}",
            browser.surfaces.join(", ")
        ),
        _ => return None,
    })
}

/// Python `str.capitalize`: first character upper-cased, the rest lower-cased.
fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first
            .to_uppercase()
            .chain(chars.as_str().chars().flat_map(char::to_lowercase))
            .collect(),
    }
}

fn risk_summary(signals: &[String]) -> String {
    match signals {
        [] => "No high-risk signal was detected in this tool call.".to_owned(),
        [only] => format!("{}.", capitalize(only)),
        [first, rest @ ..] => format!(
            "{}, and it also {}.",
            capitalize(first),
            rest.join(", and it also ")
        ),
    }
}

/// `{risk_categories, signals, summary}` for one tool call.
pub fn evaluate_risk_evidence(input: &McpToolRiskInputV1) -> Result<Value, &'static str> {
    let categories = match &input.risk_categories {
        Some(categories) => categories.clone(),
        None => evaluate_tool_risk(&input.artifact, &risk_arguments(&input.arguments))?,
    };
    let browser = browser_context(input)?;
    let signals = categories
        .iter()
        .map(|category| signal_for(category, browser.as_ref()).ok_or(ERR_CATEGORY))
        .collect::<Result<Vec<_>, _>>()?;
    let summary = match input.summary_code.as_deref() {
        None | Some("risk") => risk_summary(&signals),
        Some("no_risk") => "Guard did not detect a high-risk signal in this tool call.".to_owned(),
        Some("configuration_stricter") => {
            "Local Guard's current configuration is stricter than the tool-call-specific recommendation."
                .to_owned()
        }
        Some(_) => return Err(ERR_SUMMARY),
    };
    Ok(json!({
        "risk_categories": categories,
        "signals": signals,
        "summary": summary,
    }))
}
