//! The MCP relay view the publisher binds with the direct lane.
//!
//! The proxy evaluates a call under `config_for_harness` of the config it
//! loaded, and binds the approval hash to that config plus the managed-policy
//! and sandbox fields. The publisher binds a harness only when every config
//! the lane settles agrees on those fields, and binds the extension-control
//! layers the store verified. Without either the call defers.

use guard_contracts::ContributedMcpLayerV1;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

const VIEW_SCHEMA: &str = "guard-mcp-relay-view.v1";
const VIEW_MISSING: &str = "mcp_relay_view_missing";
const VIEW_INVALID: &str = "mcp_relay_view_invalid";
const HARNESS_UNBOUND: &str = "mcp_relay_harness_unbound";
const LAYERS_UNAVAILABLE: &str = "mcp_relay_layers_unavailable";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayViewV1 {
    schema: String,
    harnesses: BTreeMap<String, HarnessViewV1>,
    #[serde(default)]
    extension_layers: Option<Vec<ContributedMcpLayerV1>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HarnessViewV1 {
    /// `_tool_call_configuration` of the harness config.
    config: Map<String, Value>,
    /// The fields `build_tool_call_identity` binds into the approval token.
    hash_config: Map<String, Value>,
}

/// One harness's view, ready for a call.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct HarnessView {
    pub(super) config: Map<String, Value>,
    pub(super) hash_config: Map<String, Value>,
    pub(super) mode: String,
    pub(super) layers: Vec<ContributedMcpLayerV1>,
}

pub(super) fn harness_view(
    view: Option<&Value>,
    harness: &str,
) -> Result<HarnessView, &'static str> {
    let view = view.ok_or(VIEW_MISSING)?;
    let mut parsed = RelayViewV1::deserialize(view).map_err(|_| VIEW_INVALID)?;
    if parsed.schema != VIEW_SCHEMA {
        return Err(VIEW_INVALID);
    }
    let entry = parsed.harnesses.remove(harness).ok_or(HARNESS_UNBOUND)?;
    let mode = entry
        .config
        .get("mode")
        .and_then(Value::as_str)
        .ok_or(VIEW_INVALID)?
        .to_owned();
    Ok(HarnessView {
        config: entry.config,
        hash_config: entry.hash_config,
        mode,
        layers: parsed.extension_layers.ok_or(LAYERS_UNAVAILABLE)?,
    })
}
