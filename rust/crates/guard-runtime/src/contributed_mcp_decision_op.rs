//! `ContributedMcpDecide` — the native decision for catalog MCP contributions.
//!
//! Production dispatch retains the authenticated active collection and its
//! mutation lease. Identity fields and legacy request layers cannot activate
//! optional code. Per-tool states, reviewed package-launcher allows, direct
//! commands and remote endpoints are decided against that captured collection;
//! the request is pinned to the guard home and the reply is request-bound.

use guard_command::contributed_mcp_decision::{
    contributions, decide_contributed_mcp, ContributedMcpInput,
};
use guard_command::extension_control::{
    ControlLayerKind, ControlState, ControlTarget, ControlTargetKind, ExtensionControl,
    ExtensionControlLayer, CONTROL_SCHEMA_VERSION,
};
use guard_command::native_command_program::packaged_command_program;
use guard_contracts::{
    ContributedMcpDecisionRequestV1, ContributedMcpDecisionResultV1, ContributedMcpLayerV1,
    CONTRIBUTED_MCP_DECISION_REQUEST_SCHEMA, CONTRIBUTED_MCP_DECISION_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use crate::local_store_read::{self, StoreReadError};

const MAX_TEXT_BYTES: usize = 4096;
const MAX_LAYERS: usize = 2;
const MAX_CONTROLS_PER_LAYER: usize = 512;
const MAX_ENV_KEYS: usize = 1024;
const REQUEST_INVALID: &str = "native_contributed_mcp_request_invalid";
const PLACEHOLDER_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Borrowed only while the captured snapshot's mutation lease is held.
pub(crate) struct Catalog<'a> {
    pub(crate) guard_home: &'a str,
    pub(crate) controls:
        Option<&'a guard_command::native_command_controls::CompiledNativeCommandControls>,
}

pub(crate) fn with_catalog<T>(
    store: Option<&crate::policy_store::PolicySnapshotStore>,
    guard_home: &str,
    evaluate: impl FnOnce(&Catalog<'_>) -> Result<T, String>,
) -> Result<T, String> {
    let store = store.ok_or("native_contributed_mcp_authority_unavailable")?;
    store.require_guard_home(guard_home)?;
    let snapshot = store.current_admitted_snapshot()?;
    let _lease = store.command_authority_lease(&snapshot)?;
    evaluate(&Catalog {
        guard_home,
        controls: snapshot.command_extensions.as_ref(),
    })
}

pub(crate) fn evaluate_with_store(
    request: &ContributedMcpDecisionRequestV1,
    store: Option<&crate::policy_store::PolicySnapshotStore>,
) -> Result<Vec<u8>, String> {
    with_catalog(store, &request.guard_home, |catalog| {
        evaluate_with_catalog(request, Some(catalog))
    })
}

#[cfg(test)]
pub(crate) fn evaluate_contributed_mcp_decision_request(
    request: &ContributedMcpDecisionRequestV1,
) -> Result<Vec<u8>, String> {
    evaluate_with_catalog(request, None)
}

fn evaluate_with_catalog(
    request: &ContributedMcpDecisionRequestV1,
    catalog: Option<&Catalog<'_>>,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != CONTRIBUTED_MCP_DECISION_REQUEST_SCHEMA {
        return Err("native_contributed_mcp_schema_mismatch".to_owned());
    }
    let (status, code, payload) = match decide_with_catalog(request, catalog) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code.to_owned(), None),
    };
    crate::resident_protocol::encode_response(&ContributedMcpDecisionResultV1 {
        schema: CONTRIBUTED_MCP_DECISION_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

fn request_digest(request: &ContributedMcpDecisionRequestV1) -> Result<String, String> {
    let material = serde_json::to_value(request).map_err(|_| REQUEST_INVALID.to_owned())?;
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| REQUEST_INVALID.to_owned())?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

fn store_error(error: StoreReadError) -> &'static str {
    match error {
        StoreReadError::PathInvalid => "native_contributed_mcp_path_invalid",
        StoreReadError::StoreUnavailable => "native_contributed_mcp_store_unavailable",
        StoreReadError::SchemaInvalid => "native_contributed_mcp_schema_invalid",
    }
}

fn outcome(decided: Option<(&str, &str, &str)>) -> Value {
    match decided {
        Some((action, source, reason)) => json!({
            "state": "decided", "action": action, "source": source, "reason": reason,
        }),
        None => json!({"state": "none", "action": null, "source": null, "reason": null}),
    }
}

fn text_within_bounds(value: Option<&Value>) -> bool {
    match value {
        Some(Value::String(text)) => text.len() <= MAX_TEXT_BYTES,
        Some(Value::Array(items)) => {
            items.len() <= MAX_ENV_KEYS
                && items.iter().all(|item| match item {
                    Value::String(text) => text.len() <= MAX_TEXT_BYTES,
                    _ => true,
                })
        }
        _ => true,
    }
}

fn validate(request: &ContributedMcpDecisionRequestV1) -> Result<(), &'static str> {
    let identity_ok = request.server_identity.as_ref().is_none_or(|identity| {
        identity.len() <= 6
            && identity.iter().all(|(key, value)| {
                matches!(
                    key.as_str(),
                    "package_name"
                        | "command"
                        | "transport"
                        | "package_source"
                        | "package_version"
                        | "env_keys"
                ) && text_within_bounds(Some(value))
            })
    });
    let valid = identity_ok
        && request.current_action.len() <= MAX_TEXT_BYTES
        && text_within_bounds(request.artifact_transport.as_ref())
        && text_within_bounds(request.server_name.as_ref())
        && text_within_bounds(request.tool_name.as_ref())
        && request.layers.len() <= MAX_LAYERS
        && request
            .layers
            .iter()
            .all(|layer| layer.controls.len() <= MAX_CONTROLS_PER_LAYER);
    if valid {
        Ok(())
    } else {
        Err(REQUEST_INVALID)
    }
}

fn layer(source: &ContributedMcpLayerV1) -> Result<ExtensionControlLayer, &'static str> {
    let kind = match source.kind.as_str() {
        "local-admin" => ControlLayerKind::LocalAdmin,
        "signed-cloud" => ControlLayerKind::SignedCloud,
        _ => return Err(REQUEST_INVALID),
    };
    let controls = source
        .controls
        .iter()
        .map(|control| {
            let state = match control.state.as_str() {
                "enabled" => ControlState::Enabled,
                "disabled" => ControlState::Disabled,
                _ => return Err(REQUEST_INVALID),
            };
            let target =
                ControlTarget::new(ControlTargetKind::Extension, control.target_id.clone())
                    .map_err(|_| REQUEST_INVALID)?;
            Ok(ExtensionControl { target, state })
        })
        .collect::<Result<Vec<_>, &'static str>>()?;
    Ok(ExtensionControlLayer {
        schema_version: CONTROL_SCHEMA_VERSION.to_owned(),
        kind,
        catalog_digest: PLACEHOLDER_DIGEST.to_owned(),
        global_lockdown: source.global_lockdown,
        controls,
    })
}

pub(crate) fn decide_with_catalog(
    request: &ContributedMcpDecisionRequestV1,
    catalog: Option<&Catalog<'_>>,
) -> Result<Value, &'static str> {
    local_store_read::require_store_path(&request.store_path, &request.guard_home)
        .map_err(store_error)?;
    validate(request)?;
    let layers = request
        .layers
        .iter()
        .map(layer)
        .collect::<Result<Vec<_>, _>>()?;
    let input = ContributedMcpInput {
        current_action: &request.current_action,
        server_identity: request.server_identity.as_ref(),
        artifact_transport: request.artifact_transport.as_ref(),
        server_name: request.server_name.as_ref(),
        tool_name: request.tool_name.as_ref(),
        layers: &layers,
    };
    let decided = if let Some(catalog) = catalog {
        if catalog.guard_home != request.guard_home {
            return Err("native_contributed_mcp_guard_home_mismatch");
        }
        catalog
            .controls
            .and_then(|controls| controls.decide_contributed_mcp(&input))
    } else {
        let program =
            packaged_command_program().map_err(|_| "native_contributed_mcp_catalog_unavailable")?;
        decide_contributed_mcp(&contributions(&program), &input)
    };
    Ok(outcome(
        decided
            .as_ref()
            .map(|found| (found.action, found.source, found.reason)),
    ))
}

#[cfg(test)]
#[path = "contributed_mcp_decision_op_tests.rs"]
mod tests;
