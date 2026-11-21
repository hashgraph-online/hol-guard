//! `call_projection`: what the MCP proxy shows and binds for one `tools/call`
//! (masked arguments and params, the launch target, the browser intent and
//! the risk evidence), answered in one round trip.

use guard_command::browser_mcp_intent::evaluate_browser_mcp;
use guard_command::mcp_arguments::mcp_safe_arguments;
use guard_command::mcp_tool_signals::evaluate_risk_evidence;
use guard_contracts::{
    BrowserMcpArgumentsV1, BrowserMcpRequestV1, BrowserMcpResultV1, McpCallProjectionQueryV1,
    McpToolArgumentsV1, McpToolRiskInputV1,
};
use serde_json::{json, Value};

use crate::context_digest::mcp_arguments_projection;

const ERR_ARGUMENTS: &str = "native_mcp_arguments_invalid";
const ERR_BROWSER: &str = "native_mcp_browser_intent_invalid";

pub(crate) fn call_projection(query: &McpCallProjectionQueryV1) -> Result<Value, &'static str> {
    let arguments = query
        .params
        .get("arguments")
        .filter(|value| !value.is_null());
    let projection = mcp_arguments_projection(&query.tool_name, arguments)?;
    let safe_params = mcp_safe_arguments(&query.params).map_err(|_| ERR_ARGUMENTS)?;
    let (browser, risk) = match &query.risk {
        None => (Value::Null, Value::Null),
        Some(input) => (browser_projection(input)?, risk_projection(input)?),
    };
    Ok(json!({
        "safe_arguments": projection.safe,
        "safe_params": safe_params,
        "launch_target": projection.launch_target,
        "browser": browser,
        "risk": risk,
    }))
}

/// The browser launch label and masked intent, or `null` for a call that is
/// not a browser navigation the normalizer recognizes.
fn browser_projection(input: &McpToolRiskInputV1) -> Result<Value, &'static str> {
    let arguments = match &input.arguments {
        McpToolArgumentsV1::Mapping { entries } => BrowserMcpArgumentsV1::Mapping {
            entries: entries.clone(),
        },
        McpToolArgumentsV1::Json { text } => BrowserMcpArgumentsV1::Json { text: text.clone() },
        McpToolArgumentsV1::Other { .. } => BrowserMcpArgumentsV1::Other,
    };
    let request = BrowserMcpRequestV1::Normalize {
        artifact: input.artifact.clone(),
        arguments,
    };
    let BrowserMcpResultV1::Normalize {
        intent: Some(intent),
    } = evaluate_browser_mcp(&request)?
    else {
        return Ok(Value::Null);
    };
    let target = [&intent.target_domain, &intent.target_origin]
        .into_iter()
        .flatten()
        .find(|value| !value.is_empty())
        .map_or("unknown", String::as_str);
    let launch_target = format!("{} {} {target}", intent.mcp_server_name, intent.operation);
    let intent = serde_json::to_value(&intent).map_err(|_| ERR_BROWSER)?;
    let intent = mcp_safe_arguments(&intent).map_err(|_| ERR_ARGUMENTS)?;
    Ok(json!({"launch_target": launch_target, "intent": intent}))
}

fn risk_projection(input: &McpToolRiskInputV1) -> Result<Value, &'static str> {
    let evidence = evaluate_risk_evidence(input)?;
    Ok(json!({
        "risk_categories": evidence["risk_categories"],
        "summary": evidence["summary"],
    }))
}
