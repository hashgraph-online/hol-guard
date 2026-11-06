//! The effective OpenClaw MCP inventory: every supported server map visited in
//! precedence order, the first enabled definition of each name in effect and
//! the rest kept as shadowed provenance, plus the MCP server artifacts built
//! from it.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::adapter_inventory::{carried, ERR_VALUE};
use super::context_digest::python_strip;
use super::openclaw_detect::{string_list, SCOPE};
use super::pyjson::{PyVal, LONE_SURROGATE_MARK};
use super::zcode_artifacts::Fields;

/// OpenClaw's canonical map wins over the compatibility maps for duplicate
/// active names. Disabled entries are source-local, so they never mask an
/// enabled definition from another map.
const SOURCES: [(&str, &[&str]); 3] = [
    ("mcp.servers", &["mcp", "servers"]),
    ("mcp.mcpServers", &["mcp", "mcpServers"]),
    ("mcpServers", &["mcpServers"]),
];
const ERR_IDENTITY: &str = "native_runner_authority_openclaw_identity_unrepresentable";

pub(crate) struct Definition<'a> {
    pub(crate) name: String,
    config: &'a PyVal,
    pub(crate) source_scope: &'static str,
    enabled: bool,
    config_identity: String,
    identity: String,
}

pub(crate) struct Server<'a> {
    pub(crate) effective: usize,
    pub(crate) definitions: Vec<Definition<'a>>,
    conflicting: bool,
}

impl Server<'_> {
    pub(crate) fn effective(&self) -> &Definition<'_> {
        &self.definitions[self.effective]
    }
}

pub(crate) struct McpInventory<'a> {
    pub(crate) servers: Vec<Server<'a>>,
    pub(crate) warnings: Vec<Value>,
}

/// `_optional_string`: a string with something besides whitespace, stripped.
fn optional_string(value: Option<&PyVal>) -> Option<&str> {
    value
        .and_then(PyVal::as_str)
        .map(python_strip)
        .filter(|text| !text.is_empty())
}

fn alias(transport: &str) -> Option<&'static str> {
    match transport {
        "http" | "streamable-http" | "streamable_http" => Some("http"),
        "sse" => Some("sse"),
        "stdio" => Some("stdio"),
        _ => None,
    }
}

/// `effective_mcp_transport`.
fn transport(config: &PyVal) -> &'static str {
    if let Some(normalized) =
        optional_string(config.get("transport")).and_then(|value| alias(&value.to_lowercase()))
    {
        return normalized;
    }
    if optional_string(config.get("url")).is_some() {
        "http"
    } else {
        "stdio"
    }
}

/// `_mapping_keys`: the sorted keys of an object, else nothing.
fn mapping_keys(value: Option<&PyVal>) -> Vec<String> {
    let mut keys: Vec<String> = value
        .and_then(PyVal::as_dict)
        .unwrap_or_default()
        .iter()
        .map(|(key, _)| key.clone())
        .collect();
    keys.sort();
    keys
}

/// `_server_identity`: SHA-256 of the sorted, compact, ASCII-escaped JSON
/// CPython's `json.dumps` writes. A lone surrogate would hash differently on
/// this side, so it is refused.
fn server_identity(
    name: &str,
    config: &PyVal,
    source_scope: Option<&str>,
) -> Result<String, &'static str> {
    let identity = json!({
        "args": string_list(config.get("args")),
        "command": optional_string(config.get("command")),
        "configuredTransport": optional_string(config.get("transport")).map(str::to_lowercase),
        "envKeys": mapping_keys(config.get("env")),
        "headerKeys": mapping_keys(config.get("headers")),
        "name": name,
        "sourceScope": source_scope,
        "transport": transport(config),
        "url": optional_string(config.get("url")),
    });
    if identity.to_string().contains(LONE_SURROGATE_MARK) {
        return Err(ERR_VALUE);
    }
    let mut encoded = Vec::new();
    guard_contracts::write_canonical_json_with_limit(
        &identity,
        &mut encoded,
        usize::MAX,
        ERR_IDENTITY,
    )?;
    Ok(hex::encode(Sha256::digest(&encoded)))
}

/// `payload[path[0]][path[1]]...`, `None` when a step is missing, not an
/// object, or `null`.
fn path_value<'a>(payload: &'a PyVal, path: &[&str]) -> Option<&'a PyVal> {
    let mut value = payload;
    for key in path {
        value.as_dict()?;
        value = value.get(key)?;
    }
    (!matches!(value, PyVal::Null)).then_some(value)
}

/// `effective_mcp_inventory`.
pub(crate) fn inventory(payload: &PyVal) -> Result<McpInventory<'_>, &'static str> {
    let mut by_name: BTreeMap<String, Vec<Definition<'_>>> = BTreeMap::new();
    let mut warnings = Vec::new();
    for (source_scope, path) in SOURCES {
        let Some(raw_map) = path_value(payload, path) else {
            continue;
        };
        let Some(entries) = raw_map.as_dict() else {
            warnings
                .push(json!({"reason": "invalid_mcp_server_map", "source_scope": source_scope}));
            continue;
        };
        for (raw_name, config) in entries {
            let name = python_strip(raw_name);
            if name.is_empty() || config.as_dict().is_none() {
                warnings.push(json!({
                    "reason": "invalid_mcp_server_definition",
                    "source_scope": source_scope,
                }));
                continue;
            }
            let configured = optional_string(config.get("transport"));
            if configured.is_some_and(|value| alias(&value.to_lowercase()).is_none()) {
                warnings.push(json!({
                    "reason": "unsupported_mcp_transport",
                    "server_name": name,
                    "source_scope": source_scope,
                }));
            }
            let definition = Definition {
                name: name.to_owned(),
                config,
                source_scope,
                enabled: !matches!(config.get("enabled"), Some(PyVal::Bool(false))),
                config_identity: server_identity(name, config, None)?,
                identity: server_identity(name, config, Some(source_scope))?,
            };
            by_name.entry(name.to_owned()).or_default().push(definition);
        }
    }
    let mut servers = Vec::new();
    for (name, definitions) in by_name {
        let active: Vec<usize> = (0..definitions.len())
            .filter(|index| definitions[*index].enabled)
            .collect();
        let Some(&effective) = active.first() else {
            continue;
        };
        let conflicting = active[1..].iter().any(|index| {
            definitions[*index].config_identity != definitions[effective].config_identity
        });
        if active.len() > 1 {
            let reason = if conflicting {
                "conflicting_mcp_server_definitions"
            } else {
                "shadowed_mcp_server_definition"
            };
            let shadowed: Vec<&str> = active[1..]
                .iter()
                .map(|index| definitions[*index].source_scope)
                .collect();
            warnings.push(json!({
                "reason": reason,
                "server_name": name,
                "effective_source": definitions[effective].source_scope,
                "shadowed_sources": shadowed,
            }));
        }
        servers.push(Server {
            effective,
            definitions,
            conflicting,
        });
    }
    Ok(McpInventory { servers, warnings })
}

fn shadowed_definitions(server: &Server<'_>) -> Vec<Value> {
    let effective = server.effective();
    server
        .definitions
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != server.effective)
        .map(|(_, definition)| {
            json!({
                "source_key": format!("{}.{}", definition.source_scope, definition.name),
                "source_scope": definition.source_scope,
                "enabled": definition.enabled,
                "identity_sha256": definition.identity,
                "config_identity_sha256": definition.config_identity,
                "same_config_as_effective": definition.config_identity == effective.config_identity,
            })
        })
        .collect()
}

/// An object field carried as it is, else an empty object.
fn carried_dict(value: Option<&PyVal>) -> Result<Value, &'static str> {
    match value {
        Some(dict @ PyVal::Dict(_)) => carried(dict),
        _ => Ok(Value::Object(Map::new())),
    }
}

/// `_mcp_artifacts`.
pub(crate) fn artifacts(
    path: &Path,
    inventory: &McpInventory<'_>,
) -> Result<Vec<Value>, &'static str> {
    let mut artifacts = Vec::new();
    for server in &inventory.servers {
        let definition = server.effective();
        let config = definition.config;
        let mut metadata = Map::new();
        metadata.insert(
            "source_key".to_owned(),
            json!(format!("{}.{}", definition.source_scope, definition.name)),
        );
        metadata.insert("source_scope".to_owned(), json!(definition.source_scope));
        metadata.insert(
            "server_identity_sha256".to_owned(),
            json!(definition.identity),
        );
        metadata.insert(
            "config_identity_sha256".to_owned(),
            json!(definition.config_identity),
        );
        metadata.insert(
            "definition_count".to_owned(),
            json!(server.definitions.len()),
        );
        metadata.insert(
            "active_definition_count".to_owned(),
            json!(server
                .definitions
                .iter()
                .filter(|item| item.enabled)
                .count()),
        );
        metadata.insert(
            "conflicting_active_definitions".to_owned(),
            json!(server.conflicting),
        );
        metadata.insert(
            "shadowed_definitions".to_owned(),
            json!(shadowed_definitions(server)),
        );
        metadata.insert(
            "env_keys".to_owned(),
            json!(mapping_keys(config.get("env"))),
        );
        metadata.insert(
            "header_keys".to_owned(),
            json!(mapping_keys(config.get("headers"))),
        );
        metadata.insert("env".to_owned(), carried_dict(config.get("env"))?);
        metadata.insert("headers".to_owned(), carried_dict(config.get("headers"))?);
        artifacts.push(SCOPE.wire(
            format!(
                "openclaw:mcp:{}:{}",
                definition.name,
                &definition.identity[..16]
            ),
            &definition.name,
            "mcp_server",
            path,
            Fields {
                command: config.get("command").and_then(PyVal::as_str),
                args: string_list(config.get("args")),
                url: config.get("url").and_then(PyVal::as_str),
                transport: Some(transport(config)),
                publisher: None,
            },
            metadata,
        ));
    }
    Ok(artifacts)
}
