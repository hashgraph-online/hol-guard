//! Optional cloud action bindings for existing contributions.
//!
//! A binding contribution is a sibling document to one command source or MCP
//! server contribution. It names hosted actions and ties each one to a
//! permission or tool the extension already declares, so cloud evaluation
//! reuses the reviewed permission instead of inventing a new one. Contributions
//! without a sibling stay local-only and are parsed exactly as before; v1
//! command and MCP documents still reject any cloud field.
//!
//! The document carries no defaults, decisions, code, includes or endpoints:
//! an action's effect and required restrictions are the only semantics it adds,
//! and those can only make hosted execution stricter.

use super::{contract::SourceDocument, json, mcp, validation};
use crate::cloud_action_binding::{valid_action_id, valid_label, ActionEffect, TargetCapability};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;

pub(super) const BINDING_CONTRIBUTION_SCHEMA: &str = "guard.cloud-action-binding-contribution.v1";
const MAX_BINDINGS_PER_EXTENSION: usize = 256;
/// Every hosted executor must pin egress and bound output; mirrors binding admission.
const EXECUTABLE_FLOOR: [TargetCapability; 2] = [
    TargetCapability::EgressPinned,
    TargetCapability::BoundedOutput,
];

/// How far a binding reaches into hosted execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CloudSupport {
    /// Native rules can evaluate authenticated cloud action facts; nothing runs.
    PortablePolicy,
    /// A reviewed adapter or remote transport may run the action under hosted authority.
    CloudExecutable,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindingResourceInput {
    pub kind: String,
    pub argument: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudBindingInput {
    pub action_id: String,
    /// Command sources: the declared `permission_id` this action exercises.
    pub permission_id: Option<String>,
    /// MCP servers: the declared tool name this action calls.
    pub tool: Option<String>,
    pub effect: ActionEffect,
    pub resource: Option<BindingResourceInput>,
    pub required_capabilities: BTreeSet<TargetCapability>,
    pub cloud_support: CloudSupport,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudBindingContribution {
    pub schema_version: String,
    pub extension_id: String,
    pub bindings: Vec<CloudBindingInput>,
}

/// What a binding may reference in the contribution it extends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BindingTarget {
    pub extension_id: String,
    kind: TargetKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TargetKind {
    Command {
        permissions: BTreeSet<String>,
    },
    Mcp {
        remote: bool,
        tools: BTreeSet<String>,
    },
}

impl BindingTarget {
    /// Read the referenceable identity of an already canonical contribution.
    pub(super) fn from_source(bytes: &[u8], server: bool) -> Result<Self, &'static str> {
        if server {
            let lowered = mcp::lower(bytes)?;
            validation::validate(&lowered.document, true)?;
            let id = lowered.canonical["id"]
                .as_str()
                .ok_or("command_source_mcp_contract_invalid")?;
            let tools = lowered.canonical["tools"]
                .as_array()
                .ok_or("command_source_mcp_contract_invalid")?
                .iter()
                .filter_map(|tool| tool["name"].as_str())
                // The catch-all entry covers undeclared tools; it is not a reviewed action.
                .filter(|name| *name != "other")
                .map(str::to_owned)
                .collect();
            return Ok(Self {
                extension_id: id.to_owned(),
                kind: TargetKind::Mcp {
                    remote: lowered.canonical["launch"]["kind"] == "remote-http",
                    tools,
                },
            });
        }
        let document: SourceDocument = serde_json::from_value(json::decode(bytes)?)
            .map_err(|_| "command_source_contract_invalid")?;
        validation::validate(&document, false)?;
        let permissions = document
            .extension
            .permissions
            .iter()
            .map(|permission| permission.permission_id.clone())
            .collect();
        Ok(Self {
            extension_id: document.extension.extension_id,
            kind: TargetKind::Command { permissions },
        })
    }
}

/// Strictly parse a binding contribution without resolving its references.
pub fn parse_binding_contribution(bytes: &[u8]) -> Result<CloudBindingContribution, &'static str> {
    let value: Value = json::decode(bytes).map_err(|_| "cloud_binding_json_invalid")?;
    if value["schemaVersion"].as_str() != Some(BINDING_CONTRIBUTION_SCHEMA) {
        return Err(if value["schemaVersion"].is_string() {
            "cloud_binding_unsupported_version"
        } else {
            "cloud_binding_contract_invalid"
        });
    }
    let contribution: CloudBindingContribution =
        serde_json::from_value(value).map_err(|_| "cloud_binding_contract_invalid")?;
    if contribution.extension_id.is_empty()
        || contribution.extension_id.len() > 256
        || !valid_label(&contribution.extension_id)
        || contribution.bindings.is_empty()
        || contribution.bindings.len() > MAX_BINDINGS_PER_EXTENSION
    {
        return Err("cloud_binding_contract_invalid");
    }
    let mut actions = BTreeSet::new();
    for binding in &contribution.bindings {
        if !valid_action_id(&binding.action_id) {
            return Err("cloud_binding_action_invalid");
        }
        if !actions.insert(binding.action_id.as_str()) {
            return Err("cloud_binding_duplicate_action");
        }
        if let Some(resource) = &binding.resource {
            if !valid_label(&resource.kind) || !valid_label(&resource.argument) {
                return Err("cloud_binding_resource_invalid");
            }
        }
        if binding.cloud_support == CloudSupport::CloudExecutable
            && !EXECUTABLE_FLOOR
                .iter()
                .all(|floor| binding.required_capabilities.contains(floor))
        {
            return Err("cloud_binding_missing_required_capability");
        }
    }
    Ok(contribution)
}

/// Check every binding against the contribution it extends.
pub(super) fn resolve(
    contribution: &CloudBindingContribution,
    target: &BindingTarget,
) -> Result<(), &'static str> {
    if contribution.extension_id != target.extension_id {
        return Err("cloud_binding_extension_mismatch");
    }
    for binding in &contribution.bindings {
        match (&target.kind, &binding.permission_id, &binding.tool) {
            (TargetKind::Command { permissions }, Some(permission), None) => {
                if !permissions.contains(permission) {
                    return Err("cloud_binding_permission_unknown");
                }
                // A command line is never a hosted action; only policy can carry over.
                if binding.cloud_support == CloudSupport::CloudExecutable {
                    return Err("cloud_binding_local_only_target");
                }
            }
            (TargetKind::Mcp { remote, tools }, None, Some(tool)) => {
                if !tools.contains(tool) {
                    return Err("cloud_binding_tool_unknown");
                }
                // A locally launched server needs a local process the cloud does not have.
                if !remote && binding.cloud_support == CloudSupport::CloudExecutable {
                    return Err("cloud_binding_local_only_target");
                }
            }
            _ => return Err("cloud_binding_reference_invalid"),
        }
    }
    Ok(())
}

/// Parse a binding contribution and resolve it against its extension source.
pub fn admit_binding_contribution(
    binding_bytes: &[u8],
    source_bytes: &[u8],
    server: bool,
) -> Result<CloudBindingContribution, &'static str> {
    let contribution = parse_binding_contribution(binding_bytes)?;
    resolve(
        &contribution,
        &BindingTarget::from_source(source_bytes, server)?,
    )?;
    Ok(contribution)
}

#[cfg(test)]
#[path = "native_command_source_cloud_binding_tests.rs"]
mod tests;
