//! The MCP relay view the publisher binds with the direct lane.
//!
//! The proxy evaluates a call under `config_for_harness` of the config it
//! loaded, and binds the approval hash to that config plus the managed-policy
//! and sandbox fields. The publisher binds a harness only when every config
//! the lane settles agrees on those fields, and binds the extension-control
//! layers the store verified. Without either the call defers. The receipt
//! redaction level a queued call's inbox row is written with is bound with
//! the harness when every config agrees on it; without it a queued call
//! defers.
//!
//! A published binding never changes, so the view a call reads is parsed once
//! for the binding in force and each call only selects its harness from it.

use crate::policy_store::policy_store_direct_lane::DirectLaneBinding;
use guard_contracts::ContributedMcpLayerV1;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};

const VIEW_SCHEMA: &str = "guard-mcp-relay-view.v2";
const VIEW_MISSING: &str = "mcp_relay_view_missing";
const VIEW_INVALID: &str = "mcp_relay_view_invalid";
const HARNESS_UNBOUND: &str = "mcp_relay_harness_unbound";
const LAYERS_UNAVAILABLE: &str = "mcp_relay_layers_unavailable";
/// `VALID_RECEIPT_REDACTION_LEVELS`.
const REDACTION_LEVELS: [&str; 3] = ["full", "partial", "none"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayViewV2 {
    schema: String,
    harnesses: BTreeMap<String, HarnessViewV2>,
    #[serde(default)]
    extension_layers: Option<Vec<ContributedMcpLayerV1>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HarnessViewV2 {
    /// `_tool_call_configuration` of the harness config.
    config: Map<String, Value>,
    /// The fields `build_tool_call_identity` binds into the approval token.
    hash_config: Map<String, Value>,
    /// `receipt_redaction_level`, bound only when every config agrees on it.
    #[serde(default)]
    receipt_redaction_level: Option<String>,
}

/// One harness's view, ready for a call.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct HarnessView {
    pub(super) config: Map<String, Value>,
    pub(super) hash_config: Map<String, Value>,
    pub(super) mode: String,
    pub(super) layers: Vec<ContributedMcpLayerV1>,
    /// One of `full`, `partial` or `none`; any other value reads as unbound.
    pub(super) receipt_redaction_level: Option<String>,
}

/// A parsed view, or why it defers every call.
type Parsed = Arc<Result<RelayViewV2, &'static str>>;

/// The view parsed for the last binding a call read. The weak reference keeps
/// that binding's allocation, so no later binding can share its address, and
/// keeps the binding itself immutable while it lives.
static BOUND: Mutex<Option<(Weak<DirectLaneBinding>, Parsed)>> = Mutex::new(None);

/// `harness_view` of the binding's view, parsed once for the binding.
pub(super) fn bound_harness_view(
    binding: &Arc<DirectLaneBinding>,
    harness: &str,
) -> Result<HarnessView, &'static str> {
    let parsed = parsed_for(binding);
    match parsed.as_ref() {
        Ok(parsed) => select(parsed, harness),
        Err(reason) => Err(*reason),
    }
}

fn parsed_for(binding: &Arc<DirectLaneBinding>) -> Parsed {
    if let Ok(slot) = BOUND.lock() {
        if let Some((held, parsed)) = slot.as_ref() {
            if std::ptr::eq(held.as_ptr(), Arc::as_ptr(binding)) {
                return Arc::clone(parsed);
            }
        }
    }
    let parsed = Arc::new(parse(binding.mcp_relay.as_ref()));
    if let Ok(mut slot) = BOUND.lock() {
        *slot = Some((Arc::downgrade(binding), Arc::clone(&parsed)));
    }
    parsed
}

pub(super) fn harness_view(
    view: Option<&Value>,
    harness: &str,
) -> Result<HarnessView, &'static str> {
    select(&parse(view)?, harness)
}

fn parse(view: Option<&Value>) -> Result<RelayViewV2, &'static str> {
    let view = view.ok_or(VIEW_MISSING)?;
    let parsed = RelayViewV2::deserialize(view).map_err(|_| VIEW_INVALID)?;
    if parsed.schema != VIEW_SCHEMA {
        return Err(VIEW_INVALID);
    }
    Ok(parsed)
}

fn select(parsed: &RelayViewV2, harness: &str) -> Result<HarnessView, &'static str> {
    let entry = parsed.harnesses.get(harness).ok_or(HARNESS_UNBOUND)?;
    let mode = entry
        .config
        .get("mode")
        .and_then(Value::as_str)
        .ok_or(VIEW_INVALID)?
        .to_owned();
    Ok(HarnessView {
        config: entry.config.clone(),
        hash_config: entry.hash_config.clone(),
        mode,
        layers: parsed.extension_layers.clone().ok_or(LAYERS_UNAVAILABLE)?,
        receipt_redaction_level: entry
            .receipt_redaction_level
            .clone()
            .filter(|level| REDACTION_LEVELS.contains(&level.as_str())),
    })
}

#[cfg(test)]
#[path = "mcp_relay_decide_view_tests.rs"]
mod tests;
