//! The tool-policy subject `native_mcp_tool_policy._subject` builds, with the
//! extension input of `native_mcp_extension_input.build_extension_input`.

use super::view::HarnessView;
use super::McpRelayDecideRequestV1;
use crate::context_digest::python_strip;
use crate::local_store_read::STORE_FILE_NAME;
use guard_contracts::{
    BrowserMcpArtifactV1, LocalMcpServerMaterialV1, McpExtensionInputV1, McpToolCallArtifactV1,
    McpToolCallIdentityPayloadV1, McpToolPolicySubjectV1,
};
use serde_json::{json, Map, Value};
use std::path::Path;

const SUBJECT_INVALID: &str = "mcp_relay_subject_invalid";
/// The server identity fields a catalog contribution matches on.
const CONTRIBUTED_KEYS: [&str; 6] = [
    "package_name",
    "command",
    "transport",
    "package_source",
    "package_version",
    "env_keys",
];

pub(super) fn subject(
    request: &McpRelayDecideRequestV1,
    identity: &McpToolCallIdentityPayloadV1,
    view: &HarnessView,
) -> Result<McpToolPolicySubjectV1, &'static str> {
    let artifact = &identity.artifact;
    Ok(McpToolPolicySubjectV1 {
        config: view.config.clone(),
        workspace: request.workspace.clone(),
        artifact: BrowserMcpArtifactV1 {
            name: artifact.name.clone(),
            command: artifact.command.clone(),
            metadata: artifact.metadata.clone(),
        },
        artifact_type: "tool_call".to_owned(),
        artifact_id: artifact.artifact_id.clone(),
        harness: artifact.harness.clone(),
        publisher: artifact.publisher.clone(),
        artifact_hash: identity.artifact_hash.clone().ok_or(SUBJECT_INVALID)?,
        arguments: request.arguments.clone(),
        extension: Some(extension(request, identity, view)?),
    })
}

fn extension(
    request: &McpRelayDecideRequestV1,
    identity: &McpToolCallIdentityPayloadV1,
    view: &HarnessView,
) -> Result<McpExtensionInputV1, &'static str> {
    let artifact = &identity.artifact;
    let metadata = &artifact.metadata;
    let empty = Map::new();
    let server = object(metadata.get("mcp_server_identity")).unwrap_or(&empty);
    let store_path = Path::new(&request.guard_home).join(STORE_FILE_NAME);
    let connection_identity_hash = match server_identity_hash(server) {
        Some(server_hash) => Some(connection_hash(artifact, &server_hash)?),
        None => None,
    };
    let tool_identity = object(metadata.get("mcp_tool_identity"));
    Ok(McpExtensionInputV1 {
        store_path: store_path
            .into_os_string()
            .into_string()
            .map_err(|_| SUBJECT_INVALID)?,
        guard_home: request.guard_home.clone(),
        harness: artifact.harness.clone(),
        tool_name: tool_name(artifact),
        server: LocalMcpServerMaterialV1 {
            identity_hash: raw_text(server.get("identity_hash")),
            transport: raw_text(server.get("transport")),
            command: stripped(server.get("command")),
            args_hash: stripped(server.get("args_hash")),
            package_name: stripped(server.get("package_name")),
            package_version: stripped(server.get("package_version")),
            package_source: stripped(server.get("package_source")),
            env_values_hash: stripped(server.get("env_values_hash")),
        },
        connection_identity_hash,
        tool_authority_hash: tool_authority_hash(identity),
        launcher_path: request.launcher_path.clone(),
        launcher_home: Some(request.launcher_home.clone()),
        local_unavailable: false,
        server_identity: (!server.is_empty()).then(|| {
            CONTRIBUTED_KEYS
                .iter()
                .filter_map(|key| {
                    server
                        .get(*key)
                        .map(|value| ((*key).to_owned(), value.clone()))
                })
                .collect()
        }),
        artifact_transport: artifact.transport.clone().map(Value::String),
        server_name: present(metadata.get("server_name")),
        contributed_tool_name: present(tool_identity.and_then(|tool| tool.get("tool_name"))),
        layers: view.layers.clone(),
        layers_unavailable: false,
    })
}

/// A JSON value Python would send as other than `null`.
fn present(value: Option<&Value>) -> Option<Value> {
    value.filter(|value| !value.is_null()).cloned()
}

fn raw_text(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_owned)
}

fn stripped(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(python_strip)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// `_tool_name`: the identity's tool name, else the command, else the name.
pub(super) fn tool_name(artifact: &McpToolCallArtifactV1) -> String {
    let identity_name = object(artifact.metadata.get("mcp_tool_identity"))
        .and_then(|tool| tool.get("tool_name"))
        .and_then(Value::as_str)
        .map(python_strip);
    if let Some(name) = identity_name.filter(|name| !name.is_empty()) {
        return name.to_owned();
    }
    if let Some(command) = artifact
        .command
        .as_deref()
        .map(python_strip)
        .filter(|command| !command.is_empty())
    {
        return command.to_owned();
    }
    match artifact.name.rsplit_once(':') {
        Some((_, tail)) => python_strip(tail).to_owned(),
        None => python_strip(&artifact.name).to_owned(),
    }
}

/// `_tool_authority_hash`: the public hash unless it is `null`, then the
/// private one; anything but a string is no hash.
fn tool_authority_hash(identity: &McpToolCallIdentityPayloadV1) -> Option<String> {
    let public = identity
        .artifact
        .metadata
        .get("mcp_tool_authority_hash")
        .filter(|value| !value.is_null());
    let value = public.or_else(|| {
        identity
            .runtime_private_metadata
            .get("mcp_tool_authority_hash")
    });
    raw_text(value)
}

/// `_server_identity_hash`: a 64-digit hex identity hash, lowercased.
pub(super) fn server_identity_hash(server: &Map<String, Value>) -> Option<String> {
    let value = server.get("identity_hash")?.as_str()?;
    if value.chars().count() != 64 {
        return None;
    }
    let lowered = value.to_lowercase();
    lowered
        .chars()
        .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
        .then_some(lowered)
}

/// `build_mcp_connection_identity(...).identity_hash`.
pub(super) fn connection_hash(
    artifact: &McpToolCallArtifactV1,
    server_hash: &str,
) -> Result<String, &'static str> {
    let server_name = artifact
        .metadata
        .get("server_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let payload = json!({
        "version": 1,
        "host": artifact.harness,
        "source_scope": artifact.source_scope,
        "configuration_hash": guard_policy_snapshot::digest_bytes(artifact.config_path.as_bytes()),
        "server_name": server_name,
        "server_identity_hash": server_hash,
    });
    let mut bytes = Vec::with_capacity(256);
    guard_contracts::write_canonical_json_with_limit(
        &payload,
        &mut bytes,
        usize::MAX,
        SUBJECT_INVALID,
    )?;
    Ok(guard_policy_snapshot::digest_bytes(&bytes))
}

/// A metadata entry that is a mapping.
fn object(value: Option<&Value>) -> Option<&Map<String, Value>> {
    value.and_then(Value::as_object)
}
