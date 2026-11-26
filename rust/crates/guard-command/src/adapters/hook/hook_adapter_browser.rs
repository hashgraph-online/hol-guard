//! The browser action one harness hook call carries (BP-T025).
//!
//! Harness built-in browser tools (`browser`, `browser_action`, `open_url`, `visit_url`) and MCP
//! browser tools go through the same driver matcher as any other browser call, so one hook payload
//! yields a [`BrowserActionV2`] when a profile names the tool. The envelope is unchanged: these
//! built-ins stay `network_request` with their hosts, which is the fallback when no profile matches
//! or the profile does not list the call's action.

use serde_json::{Map, Value};

use crate::browser_action_project::{
    project_screened_browser_action, BrowserProjection, BrowserProjectionContext,
};
use crate::browser_driver_match::{match_browser_driver, BrowserToolCallIdentity};
use crate::browser_first_party_drivers::first_party_browser_drivers;
use crate::hook_adapter_envelope::{canonical_harness, EnvelopeRequest};
use crate::hook_adapter_envelope_text::{
    mcp_details, payload_with_default_event, tool_call_from_payload, tool_input_from_payload,
    tool_name_from_payload,
};
use crate::hook_adapter_prepare::{prepare_payload, string_value, AdapterError};
use crate::hook_adapter_pytext::{py_lower, py_strip};
use crate::hook_adapter_value::OValue;

/// The browser projection for one hook payload: `None` when no driver profile names the tool,
/// otherwise the classified action or the reason the profile could not classify it.
pub fn hook_browser_action(
    request: &EnvelopeRequest<'_>,
) -> Result<Option<BrowserProjection>, AdapterError> {
    let Some(canonical) = canonical_harness(request.harness) else {
        return Err(AdapterError::UnsupportedHarness(request.harness.to_owned()));
    };
    let payload = payload_with_default_event(request.payload, request.event_name);
    let prepared = prepare_payload(canonical, &payload, request.devin_project_dir)?;
    let explicit_tool = tool_name_from_payload(&prepared);
    let (call_name, call_input) =
        tool_call_from_payload(prepared.get("toolCalls"), explicit_tool.as_deref())?;
    let tool_name = explicit_tool.or(call_name);
    let mut tool_input = tool_input_from_payload(&prepared)?;
    if tool_input.is_empty() {
        if let Some(call_input) = call_input {
            tool_input = call_input;
        }
    }
    // Cline renames its network tools to `network_request` and keeps the original name beside
    // the input. Its MCP calls already carry their `mcp__server__tool` name.
    let harness_tool = if canonical == "cline" && tool_name.as_deref() == Some("network_request") {
        string_value(tool_input.get("cline_tool_name"))
    } else {
        tool_name
    };
    let Some(harness_tool) = harness_tool else {
        return Ok(None);
    };
    let harness_tool_name = py_lower(py_strip(&harness_tool));
    let (mcp_server, mcp_tool) = mcp_details(&prepared, Some(&harness_tool));
    let call = BrowserToolCallIdentity {
        harness_tool_name: &harness_tool_name,
        mcp_server_name: mcp_server.as_deref(),
        mcp_tool_name: mcp_tool.as_deref(),
        package: None,
    };
    let Some(matched) = match_browser_driver(first_party_browser_drivers(), &call) else {
        return Ok(None);
    };
    // A Cline MCP call wraps the tool's own arguments in `arguments`.
    let arguments = match tool_input.get("arguments") {
        Some(OValue::Map(inner)) if canonical == "cline" && mcp_server.is_some() => inner.clone(),
        _ => tool_input,
    };
    let Value::Object(arguments) = plain_json(&OValue::Map(arguments)) else {
        return Ok(None);
    };
    Ok(Some(project_screened_browser_action(
        &matched,
        &arguments,
        &Map::new(),
        &BrowserProjectionContext::default(),
    )))
}

/// Plain JSON for a hook value. `OValue::to_wire` is the tagged-array form the Python bridge reads,
/// which the profile pointers cannot walk.
fn plain_json(value: &OValue) -> Value {
    match value {
        OValue::Null => Value::Null,
        OValue::Bool(flag) => Value::Bool(*flag),
        OValue::Int(token) | OValue::Float(token) => token
            .parse::<serde_json::Number>()
            .map(Value::Number)
            .unwrap_or(Value::Null),
        OValue::Str(text) => Value::String(text.clone()),
        OValue::List(items) => Value::Array(items.iter().map(plain_json).collect()),
        OValue::Map(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.to_owned(), plain_json(item)))
                .collect(),
        ),
    }
}
