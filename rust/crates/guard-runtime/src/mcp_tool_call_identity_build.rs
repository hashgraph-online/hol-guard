//! Artifact composition for `mcp_tool_call_identity`: server and tool
//! identity, tool-definition authority, firewall evidence and metadata layout.

use guard_command::mcp_decision::{
    build_mcp_tool_identity, mcp_server_identity_metadata, mcp_tool_identity_metadata,
    McpServerIdentity,
};
use guard_command::mcp_skill_firewall::evaluate_firewall_evidence;
use guard_contracts::{
    McpFirewallInputV1, McpToolCallArtifactV1, McpToolCallBuildV1, McpToolCallServerIdentityV1,
    McpToolCallSourceV1,
};
use serde_json::{json, Map, Value};

use crate::context_digest::python_strip;

pub(crate) const ERR_PROVIDER_HASH: &str = "native_mcp_tool_call_identity_provider_hash_invalid";
const ERR_FIREWALL: &str = "native_mcp_tool_call_identity_firewall_invalid";

/// Builds the artifact plus the `runtime_private_metadata` the local-grant
/// decision binds without changing the hashed metadata.
pub(crate) fn build_artifact(
    build: &McpToolCallBuildV1,
) -> Result<(McpToolCallArtifactV1, Map<String, Value>), &'static str> {
    let (schema, description, entry) = match &build.tool {
        McpToolCallSourceV1::Catalog { entry } => {
            let source = entry.as_ref();
            let schema = source
                .and_then(|map| map.get("inputSchema").or_else(|| map.get("input_schema")))
                .filter(|value| !value.is_null())
                .cloned();
            let description = source
                .and_then(|map| map.get("description"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            (schema, description, Some(entry))
        }
        McpToolCallSourceV1::Explicit {
            schema,
            description,
        } => (schema.clone(), description.clone(), None),
    };
    let mut metadata = Map::new();
    metadata.insert("server_name".to_owned(), json!(build.server_name));
    // A hash the caller supplies is checked wherever it came from: a malformed
    // one is a caller bug on any tool name, and admitting it would leave the
    // artifact quietly unbound. Only the binding itself is routed, because
    // only a wrapper call that can carry a provider action is bound to the
    // operator's provider authority. Which calls those are follows from the
    // Composio routing contract, so the runtime reads it here: a caller that
    // decided for itself would be recomputing a contract it does not own.
    if let Some(hash) = &build.provider_catalog_hash {
        if hash.len() != 64 || !hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(ERR_PROVIDER_HASH);
        }
        if crate::mcp_tool_policy_composio::requires_action_review(&build.tool_name) {
            metadata.insert("mcp_provider_catalog_hash".to_owned(), json!(hash));
        }
    }
    if let Some(server_id) = &build.server_id {
        metadata.insert("server_id".to_owned(), json!(server_id));
    }
    if let Some(fingerprint) = &build.server_fingerprint {
        metadata.insert("server_fingerprint".to_owned(), fingerprint.clone());
    }
    let server_metadata = build.server_identity.as_ref().map(server_identity_metadata);
    if let Some(identity) = &server_metadata {
        metadata.insert(
            "mcp_server_identity".to_owned(),
            Value::Object(identity.clone()),
        );
    }
    let server_hash = match (&build.server_id, &build.server_identity) {
        (Some(server_id), _) => server_id.clone(),
        (None, Some(identity)) => identity.identity_hash.clone(),
        (None, None) => guard_policy_snapshot::digest_bytes(
            format!(
                "{}:{}:{}",
                build.harness, build.source_scope, build.server_name
            )
            .as_bytes(),
        ),
    };
    let tool_identity = mcp_tool_identity_metadata(&build_mcp_tool_identity(
        &server_hash,
        &build.tool_name,
        schema.as_ref(),
        description.as_deref(),
    ));
    metadata.insert(
        "mcp_tool_identity".to_owned(),
        Value::Object(tool_identity.clone()),
    );
    if let Some(schema) = &schema {
        metadata.insert("tool_schema".to_owned(), schema.clone());
    }
    if let Some(entry) = entry {
        // Only a definition that names this tool binds its authority hash into
        // the public metadata. The runtime strips the name, so it stays null
        // there and the full-definition hash is private.
        let named = entry
            .as_ref()
            .filter(|map| map.get("name").and_then(Value::as_str) == Some(build.tool_name.as_str()))
            .and_then(tool_definition_authority_hash);
        metadata.insert(
            "mcp_tool_authority_hash".to_owned(),
            named.map_or(Value::Null, Value::String),
        );
    }
    let stripped = description
        .as_deref()
        .map(python_strip)
        .filter(|text| !text.is_empty());
    if let Some(text) = stripped {
        metadata.insert("tool_description".to_owned(), json!(text));
    }
    let name = format!("{}:{}", build.server_name, build.tool_name);
    let firewall = McpFirewallInputV1 {
        artifact_type: "tool_call".to_owned(),
        name: name.clone(),
        command: Some(build.tool_name.clone()),
        config_path: build.config_path.clone(),
        transport: Some(build.transport.clone()),
        has_url: false,
        args: Vec::new(),
        publisher: None,
        server_name: Some(build.server_name.clone()),
        env: Vec::new(),
        mcp_server_identity: server_metadata,
        mcp_tool_identity: Some(tool_identity),
        tool_schema: schema,
        tool_description: stripped.map(|text| json!(text)),
        tool_names: None,
        tool_names_camel: None,
        skill_content: None,
    };
    let evidence = evaluate_firewall_evidence(&firewall)?;
    match evidence.get("metadata_patch") {
        Some(Value::Object(patch)) => metadata.extend(patch.clone()),
        Some(Value::Null) => {}
        _ => return Err(ERR_FIREWALL),
    }
    let mut private = Map::new();
    if let Some(Some(entry)) = entry {
        private.insert(
            "mcp_tool_authority_hash".to_owned(),
            tool_definition_authority_hash(entry).map_or(Value::Null, Value::String),
        );
    }
    Ok((
        McpToolCallArtifactV1 {
            artifact_id: format!(
                "{}:runtime:{}:{}:{}",
                build.harness, build.source_scope, build.server_name, build.tool_name
            ),
            name,
            harness: build.harness.clone(),
            source_scope: build.source_scope.clone(),
            config_path: build.config_path.clone(),
            command: Some(build.tool_name.clone()),
            transport: Some(build.transport.clone()),
            publisher: None,
            metadata,
        },
        private,
    ))
}

fn server_identity_metadata(identity: &McpToolCallServerIdentityV1) -> Map<String, Value> {
    mcp_server_identity_metadata(&McpServerIdentity {
        config_path: identity.config_path.clone(),
        command: identity.command.clone(),
        args_hash: identity.args_hash.clone(),
        package_name: identity.package_name.clone(),
        package_version: identity.package_version.clone(),
        package_source: identity.package_source.clone(),
        transport: identity.transport.clone(),
        env_keys: identity.env_keys.clone(),
        env_values_hash: identity.env_values_hash.clone(),
        identity_hash: identity.identity_hash.clone(),
    })
}

/// SHA-256 over the tool's authority-bearing fields (`inputSchema`,
/// `outputSchema`, `annotations`); absent unless `inputSchema` is an object.
pub(crate) fn tool_definition_authority_hash(definition: &Map<String, Value>) -> Option<String> {
    if !definition.get("inputSchema").is_some_and(Value::is_object) {
        return None;
    }
    let shape = json!({
        "inputSchema": definition.get("inputSchema"),
        "outputSchema": definition.get("outputSchema"),
        "annotations": definition.get("annotations"),
    });
    let mut bytes = Vec::with_capacity(256);
    guard_contracts::write_canonical_json(&shape, &mut bytes).ok()?;
    Some(guard_policy_snapshot::digest_bytes(&bytes))
}
