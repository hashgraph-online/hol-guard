//! Portal-aligned MCP firewall projection for `mcp_server` and `tool_call`
//! artifacts.
//!
//! Port of `runtime/mcp_skill_firewall.py` (`_firewall_for_mcp_server`,
//! `_firewall_for_tool_call`, the legacy/portal identity conversions and
//! `attach_mcp_skill_firewall_metadata`). Identity and descriptor material
//! comes from `mcp_decision`; this module only composes it. The result is a
//! metadata patch the caller merges verbatim.

use guard_contracts::{
    McpFirewallInputV1, McpServerDescriptorRequestV1, McpServerIdentityV1,
    McpToolDescriptorRequestV1, McpToolIdentityV1,
};
use serde_json::{json, Map, Value};

use crate::mcp_decision::{
    build_configured_environment_hash, build_mcp_server_identity, build_mcp_tool_identity,
    portal_mcp_server_descriptor, portal_mcp_tool_descriptor, python_strip, McpServerIdentity,
    McpToolIdentity,
};
use crate::target_identities::{py_str, py_truthy};

const ERR_TYPE: &str = "native_mcp_tool_evidence_unsupported_artifact_type";

type Record = Map<String, Value>;

/// Python `a or b or ...`: the first truthy candidate, else the last one.
fn py_or(record: &Record, keys: &[&str]) -> Value {
    let mut last = Value::Null;
    for key in keys {
        last = record.get(*key).cloned().unwrap_or(Value::Null);
        if py_truthy(&last) {
            return last;
        }
    }
    last
}

/// `str(a or b or ... or fallback)` with record keys ahead of plain fallbacks.
fn py_or_text(record: &Record, keys: &[&str], fallbacks: &[&str]) -> String {
    let mut candidates: Vec<Value> = keys
        .iter()
        .map(|key| record.get(*key).cloned().unwrap_or(Value::Null))
        .collect();
    candidates.extend(
        fallbacks
            .iter()
            .map(|text| Value::String((*text).to_owned())),
    );
    let chosen = candidates
        .iter()
        .find(|candidate| py_truthy(candidate))
        .or(candidates.last())
        .cloned()
        .unwrap_or(Value::Null);
    py_str(&chosen)
}

fn string_items(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

fn identity_v1(identity: &McpServerIdentity) -> McpServerIdentityV1 {
    McpServerIdentityV1 {
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
    }
}

fn tool_identity_v1(identity: McpToolIdentity) -> McpToolIdentityV1 {
    McpToolIdentityV1 {
        server_hash: identity.server_hash,
        tool_name: identity.tool_name,
        schema_hash: identity.schema_hash,
        description_hash: identity.description_hash,
        identity_hash: identity.identity_hash,
    }
}

fn tool_descriptor(
    server_hash: &str,
    tool_name: &str,
    schema: Option<&Value>,
    description: Option<&str>,
) -> Record {
    let identity = build_mcp_tool_identity(server_hash, tool_name, schema, description);
    portal_mcp_tool_descriptor(&McpToolDescriptorRequestV1 {
        identity: tool_identity_v1(identity),
        schema: schema.cloned(),
        description: description.map(str::to_owned),
    })
}

fn server_descriptor(
    input: &McpFirewallInputV1,
    command: &str,
    transport: &str,
    env: &Record,
) -> (String, Record) {
    let identity = build_mcp_server_identity(
        &input.config_path,
        command,
        &input.args,
        transport,
        Some(env),
        &[],
    );
    let descriptor = portal_mcp_server_descriptor(&McpServerDescriptorRequestV1 {
        identity: identity_v1(&identity),
        config_path: input.config_path.clone(),
        args: input.args.clone(),
        publisher: input.publisher.clone(),
        install_source: None,
    });
    (identity.identity_hash, descriptor)
}

fn env_map(input: &McpFirewallInputV1) -> Record {
    input
        .env
        .iter()
        .map(|(key, value)| (key.clone(), Value::String(value.clone())))
        .collect()
}

fn fingerprints(server: Record, tools: Vec<Record>) -> Record {
    let mut payload = Record::new();
    payload.insert(
        "mcpTools".to_owned(),
        Value::Array(tools.into_iter().map(Value::Object).collect()),
    );
    payload.insert("mcpServer".to_owned(), Value::Object(server));
    payload
}

fn tool_names(input: &McpFirewallInputV1) -> Vec<String> {
    let raw = match input.tool_names.as_ref().filter(|value| py_truthy(value)) {
        Some(value) => Some(value),
        None => input.tool_names_camel.as_ref(),
    };
    string_items(raw)
        .into_iter()
        .filter(|name| !python_strip(name).is_empty())
        .collect()
}

fn firewall_for_mcp_server(input: &McpFirewallInputV1) -> Option<Record> {
    let command = input
        .command
        .as_deref()
        .filter(|c| !python_strip(c).is_empty())?;
    let transport = match input.transport.as_deref().filter(|t| !t.is_empty()) {
        Some(transport) => transport,
        None if input.has_url => "http",
        None => "stdio",
    };
    let (server_hash, server) = server_descriptor(input, command, transport, &env_map(input));
    let tools = tool_names(input)
        .iter()
        .map(|name| tool_descriptor(&server_hash, name, None, None))
        .collect();
    Some(fingerprints(server, tools))
}

fn legacy_environment_values_hash(record: &Record, env_keys: &[String]) -> String {
    let raw = py_or(record, &["env_values_hash", "envValuesHash"]);
    if let Value::String(text) = &raw {
        let stripped = python_strip(text);
        if !stripped.is_empty() {
            return stripped.to_owned();
        }
    }
    build_configured_environment_hash(None, Some(env_keys))
}

fn portal_server_from_legacy(record: &Record, input: &McpFirewallInputV1) -> Record {
    let artifact_command = input.command.as_deref().unwrap_or("");
    let artifact_transport = input.transport.as_deref().unwrap_or("");
    let identity_hash = py_or_text(record, &["identity_hash", "identityHash"], &[""]);
    let args_hash = py_or_text(record, &["args_hash", "argsHash"], &[&identity_hash]);
    let raw_env_keys = py_or(record, &["env_keys", "envKeys"]);
    let env_keys = string_items(Some(&raw_env_keys));
    let env_values_hash = legacy_environment_values_hash(record, &env_keys);
    let mut out = Record::new();
    out.insert("argsHash".to_owned(), json!(args_hash));
    out.insert(
        "command".to_owned(),
        json!(py_or_text(
            record,
            &["command"],
            &[artifact_command, "unknown"]
        )),
    );
    out.insert(
        "commandHash".to_owned(),
        json!(py_or_text(
            record,
            &["command_hash", "commandHash"],
            &[&args_hash]
        )),
    );
    out.insert(
        "configPath".to_owned(),
        json!(py_or_text(
            record,
            &["config_path", "configPath"],
            &[&input.config_path]
        )),
    );
    out.insert(
        "dependencyHash".to_owned(),
        py_or(record, &["dependency_hash", "dependencyHash"]),
    );
    out.insert("envKeys".to_owned(), json!(env_keys));
    out.insert("envValuesHash".to_owned(), json!(env_values_hash));
    out.insert("identityHash".to_owned(), json!(identity_hash));
    out.insert(
        "packageName".to_owned(),
        py_or(record, &["package_name", "packageName"]),
    );
    out.insert(
        "packageSource".to_owned(),
        py_or(record, &["package_source", "packageSource"]),
    );
    out.insert(
        "packageVersion".to_owned(),
        py_or(record, &["package_version", "packageVersion"]),
    );
    out.insert(
        "publisherStableId".to_owned(),
        py_or(record, &["publisher_stable_id", "publisherStableId"]),
    );
    out.insert(
        "transport".to_owned(),
        json!(py_or_text(
            record,
            &["transport"],
            &[artifact_transport, "unknown"]
        )),
    );
    out.insert(
        "transportHash".to_owned(),
        json!(py_or_text(
            record,
            &["transport_hash", "transportHash"],
            &[&identity_hash]
        )),
    );
    out
}

fn portal_tool_from_legacy(record: &Record, input: &McpFirewallInputV1) -> Record {
    let schema_present = input
        .tool_schema
        .as_ref()
        .is_some_and(|value| !value.is_null());
    let description_truthy = input.tool_description.as_ref().is_some_and(py_truthy);
    let mut out = Record::new();
    out.insert(
        "descriptionHash".to_owned(),
        py_or(record, &["description_hash", "descriptionHash"]),
    );
    out.insert(
        "descriptorHash".to_owned(),
        py_or(
            record,
            &[
                "descriptor_hash",
                "descriptorHash",
                "description_hash",
                "descriptionHash",
            ],
        ),
    );
    out.insert(
        "hashScope".to_owned(),
        json!(if schema_present || description_truthy {
            "full"
        } else {
            "manifest"
        }),
    );
    out.insert(
        "identityHash".to_owned(),
        py_or(record, &["identity_hash", "identityHash"]),
    );
    out.insert(
        "schemaHash".to_owned(),
        py_or(record, &["schema_hash", "schemaHash"]),
    );
    out.insert(
        "serverHash".to_owned(),
        py_or(record, &["server_hash", "serverHash"]),
    );
    out.insert(
        "toolName".to_owned(),
        py_or(record, &["tool_name", "toolName"]),
    );
    out
}

fn firewall_for_tool_call(input: &McpFirewallInputV1) -> Option<Record> {
    if let (Some(server_record), Some(tool_record)) =
        (&input.mcp_server_identity, &input.mcp_tool_identity)
    {
        let server = portal_server_from_legacy(server_record, input);
        let tool = portal_tool_from_legacy(tool_record, input);
        return Some(fingerprints(server, vec![tool]));
    }
    let tool_name = input.command.as_deref()?;
    let transport = input
        .transport
        .as_deref()
        .filter(|t| !t.is_empty())
        .unwrap_or("stdio");
    let command = input.server_name.as_deref().unwrap_or(&input.name);
    let (server_hash, server) = server_descriptor(input, command, transport, &env_map(input));
    let description = input.tool_description.as_ref().and_then(Value::as_str);
    let schema = input.tool_schema.as_ref().filter(|value| !value.is_null());
    let tool = tool_descriptor(&server_hash, tool_name, schema, description);
    Some(fingerprints(server, vec![tool]))
}

fn legacy_server_identity(server: &Record) -> Record {
    let env_keys = string_items(server.get("envKeys"));
    let get = |key: &str| server.get(key).cloned().unwrap_or(Value::Null);
    let mut out = Record::new();
    out.insert("args_hash".to_owned(), get("argsHash"));
    out.insert("command".to_owned(), get("command"));
    out.insert("command_hash".to_owned(), get("commandHash"));
    out.insert("config_path".to_owned(), get("configPath"));
    out.insert("dependency_hash".to_owned(), get("dependencyHash"));
    out.insert(
        "env_values_hash".to_owned(),
        json!(legacy_environment_values_hash(server, &env_keys)),
    );
    out.insert("env_keys".to_owned(), json!(env_keys));
    out.insert("identity_hash".to_owned(), get("identityHash"));
    out.insert("package_name".to_owned(), get("packageName"));
    out.insert("package_source".to_owned(), get("packageSource"));
    out.insert("package_version".to_owned(), get("packageVersion"));
    out.insert("publisher_stable_id".to_owned(), get("publisherStableId"));
    out.insert("transport".to_owned(), get("transport"));
    out.insert("transport_hash".to_owned(), get("transportHash"));
    out
}

fn legacy_tool_identity(tool: &Record) -> Value {
    let get = |key: &str| tool.get(key).cloned().unwrap_or(Value::Null);
    json!({
        "description_hash": get("descriptionHash"),
        "descriptor_hash": get("descriptorHash"),
        "identity_hash": get("identityHash"),
        "schema_hash": get("schemaHash"),
        "server_hash": get("serverHash"),
        "tool_name": get("toolName"),
    })
}

/// `attach_mcp_skill_firewall_metadata`, expressed as the keys it sets.
fn metadata_patch(firewall: Record) -> Record {
    let mut patch = Record::new();
    if let Some(Value::Object(server)) = firewall.get("mcpServer") {
        patch.insert(
            "mcp_server_identity".to_owned(),
            Value::Object(legacy_server_identity(server)),
        );
    }
    if let Some(Value::Array(tools)) = firewall.get("mcpTools") {
        let objects: Vec<&Record> = tools.iter().filter_map(Value::as_object).collect();
        if tools.len() == 1 && objects.len() == 1 {
            patch.insert(
                "mcp_tool_identity".to_owned(),
                legacy_tool_identity(objects[0]),
            );
        } else if !tools.is_empty() {
            patch.insert(
                "mcp_tool_identities".to_owned(),
                Value::Array(objects.into_iter().map(legacy_tool_identity).collect()),
            );
        }
    }
    patch.insert("mcpSkillFirewall".to_owned(), Value::Object(firewall));
    patch
}

/// `{metadata_patch}`; `null` leaves the artifact unchanged.
pub fn evaluate_firewall_evidence(input: &McpFirewallInputV1) -> Result<Value, &'static str> {
    let firewall = match input.artifact_type.as_str() {
        "mcp_server" => firewall_for_mcp_server(input),
        "tool_call" => firewall_for_tool_call(input),
        _ => return Err(ERR_TYPE),
    };
    Ok(json!({ "metadata_patch": firewall.map(metadata_patch) }))
}
