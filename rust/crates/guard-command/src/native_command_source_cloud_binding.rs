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
//!
//! The offline source compiler turns resolved contributions into one binding
//! artifact beside the compiled program. Hosted evaluation loads that artifact;
//! it never parses or resolves contributions while serving a request.

use super::{catalog, contract::SourceDocument, json, mcp, validation};
use crate::cloud_action_binding::{
    valid_action_id, valid_label, ActionEffect, TargetCapability, MAX_BINDINGS,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub(super) const BINDING_CONTRIBUTION_SCHEMA: &str = "guard.cloud-action-binding-contribution.v1";
pub const BINDING_ARTIFACT_SCHEMA: &str = "guard.cloud-action-binding-artifact.v1";
pub(super) const BINDING_ARTIFACT_COMPILER_VERSION: u64 = 1;
pub(super) const BINDING_ARTIFACT_DOMAIN: &[u8] = b"hol-guard.cloud-action-binding-artifact.v1\0";
pub(super) const BINDING_MEANING_DOMAIN: &[u8] = b"hol-guard.cloud-action-binding-meaning.v1\0";
const MAX_BINDINGS_PER_EXTENSION: usize = 256;
/// Every hosted executor must pin egress and bound output; mirrors binding admission.
pub(super) const EXECUTABLE_FLOOR: [TargetCapability; 2] = [
    TargetCapability::EgressPinned,
    TargetCapability::BoundedOutput,
];

/// How far a binding reaches into hosted execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
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
        /// The canonical remote endpoint; `None` for a locally launched server.
        endpoint: Option<String>,
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
            let endpoint = if lowered.canonical["launch"]["kind"] == "remote-http" {
                Some(mcp::canonical_endpoint(
                    lowered.canonical["launch"]["url"]
                        .as_str()
                        .ok_or("command_source_mcp_contract_invalid")?,
                )?)
            } else {
                None
            };
            return Ok(Self {
                extension_id: id.to_owned(),
                kind: TargetKind::Mcp { endpoint, tools },
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
            (TargetKind::Mcp { endpoint, tools }, None, Some(tool)) => {
                if !tools.contains(tool) {
                    return Err("cloud_binding_tool_unknown");
                }
                // A locally launched server needs a local process the cloud does not have.
                if endpoint.is_none() && binding.cloud_support == CloudSupport::CloudExecutable {
                    return Err("cloud_binding_local_only_target");
                }
            }
            _ => return Err("cloud_binding_reference_invalid"),
        }
    }
    Ok(())
}

/// Compile resolved contributions into the binding artifact for one build.
///
/// Actions are ordered by action ID, so the artifact does not depend on the
/// order contributions arrived in. Each action carries a `binding_digest` over
/// what it means when run: its extension, the permission or tool and endpoint
/// it exercises, its effect, resource and required restrictions. A rule or
/// tool-state change leaves that digest alone; a change of meaning does not.
/// The artifact digest also covers the program it was compiled with.
pub(super) fn compile_artifact(
    resolved: &[(&CloudBindingContribution, BindingTarget)],
    program_digest: &str,
) -> Result<Value, &'static str> {
    let mut actions = Vec::new();
    for (contribution, target) in resolved {
        if contribution.extension_id != target.extension_id {
            return Err("cloud_binding_extension_mismatch");
        }
        for binding in &contribution.bindings {
            let exercised = match (&target.kind, &binding.permission_id, &binding.tool) {
                (TargetKind::Command { .. }, Some(permission), None) => {
                    json!({"kind": "command-permission", "permission_id": permission})
                }
                (TargetKind::Mcp { endpoint, .. }, None, Some(tool)) => {
                    json!({"kind": "mcp-tool", "tool": tool, "endpoint": endpoint})
                }
                _ => return Err("cloud_binding_reference_invalid"),
            };
            let mut action = json!({
                "action_id": binding.action_id,
                "extension_id": contribution.extension_id,
                "target": exercised,
                "effect": binding.effect,
                "resource": binding.resource.as_ref().map(|resource| json!({
                    "kind": resource.kind,
                    "argument": resource.argument,
                })),
                "required_capabilities": binding.required_capabilities,
                "cloud_support": binding.cloud_support,
            });
            action["binding_digest"] = json!(catalog::digest(BINDING_MEANING_DOMAIN, &action)?);
            actions.push(action);
        }
    }
    if actions.len() > MAX_BINDINGS {
        return Err("cloud_binding_artifact_limit");
    }
    actions.sort_by(|left, right| left["action_id"].as_str().cmp(&right["action_id"].as_str()));
    if actions
        .windows(2)
        .any(|pair| pair[0]["action_id"] == pair[1]["action_id"])
    {
        return Err("cloud_binding_duplicate_action");
    }
    let mut artifact = json!({
        "schema": BINDING_ARTIFACT_SCHEMA,
        "compiler_version": BINDING_ARTIFACT_COMPILER_VERSION,
        "program_digest": program_digest,
        "actions": actions,
    });
    artifact["artifact_digest"] = json!(catalog::digest(BINDING_ARTIFACT_DOMAIN, &artifact)?);
    artifact.sort_all_objects();
    Ok(artifact)
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
