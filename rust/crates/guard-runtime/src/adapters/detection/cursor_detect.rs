//! `runner_authority` kind `cursor_detect`: the MCP server artifacts of
//! `CursorHarnessAdapter.detect`. Python keeps reading the editor configs
//! (from disk or from the bytes an install captured) and sends each non-empty
//! payload as JSON text, so object order survives the wire. It also keeps the
//! managed-origin lookup, the MCP firewall, the managed hook artifact, the CLI
//! lookup and the workspace AIBOM extension. Every refusal is a stable code
//! and never a partial inventory.

use std::path::PathBuf;

use serde_json::{json, Map, Value};

use super::adapter_inventory::{Inventory, Request, ERR_VALUE};
use super::aibom_mcp_metadata::{enrich, McpMetadataInput, ERR_METADATA};
use super::aibom_paths::py_path;
use super::codex_detect::is_guard_proxy;
use super::pyjson::{parse_marking_lone_surrogates, PyVal};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use super::zcode_artifacts::{mcp_environment, pair_value, string_pairs, Fields, Scope};

const HARNESS: &str = "cursor";

/// `str(value) for value in server_config.get("args", []) if isinstance(value, str)`:
/// a string iterates its characters and an object its keys; any other value
/// raised `TypeError` and is refused.
fn cursor_args(config: &PyVal) -> Result<Vec<String>, &'static str> {
    Ok(match config.get("args") {
        None => Vec::new(),
        Some(PyVal::List(items)) => items
            .iter()
            .filter_map(PyVal::as_str)
            .map(str::to_owned)
            .collect(),
        Some(PyVal::Str(text)) => text.chars().map(String::from).collect(),
        Some(PyVal::Dict(entries)) => entries.iter().map(|(key, _)| key.clone()).collect(),
        Some(_) => return Err(ERR_VALUE),
    })
}

fn configs(args: &Value) -> Result<Vec<(PathBuf, PyVal)>, &'static str> {
    args_object(args)?
        .get("configs")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|item| {
            let path = item["path"].as_str().filter(|path| !path.contains('\0'));
            let (Some(path), Some(text)) = (path, item["payload"].as_str()) else {
                return Err(ERR_INVALID);
            };
            let payload = parse_marking_lone_surrogates(text).map_err(|_| ERR_INVALID)?;
            Ok((py_path(path), payload))
        })
        .collect()
}

/// The `mcpServers` of one editor config.
fn mcp_servers(
    inventory: &mut Inventory,
    path: &std::path::Path,
    payload: &PyVal,
) -> Result<(), &'static str> {
    let Some(servers) = payload.get("mcpServers").and_then(PyVal::as_dict) else {
        return Ok(());
    };
    let scope = Scope {
        harness: HARNESS,
        scope: inventory.scope_for(path),
    };
    for (name, server) in servers {
        if server.as_dict().is_none() {
            continue;
        }
        let args = cursor_args(server)?;
        let command = server.get("command").and_then(PyVal::as_str);
        let url = server.get("url").and_then(PyVal::as_str);
        let transport = if url.is_some() { "http" } else { "stdio" };
        let environment = mcp_environment(server);
        let headers = server.get("headers").map(string_pairs).unwrap_or_default();
        let env_keys: Vec<String> = environment.keys().cloned().collect();
        let headers_keys: Vec<String> = headers.keys().cloned().collect();
        let enriched = enrich(&McpMetadataInput {
            command: command.map(str::to_owned),
            args: args.clone(),
            url: url.map(str::to_owned),
            transport: Some(transport.to_owned()),
            env_keys: env_keys.clone(),
            headers_keys: headers_keys.clone(),
            env: pair_value(&environment),
            headers: pair_value(&headers),
            env_values_hash: None,
            header_values_hash: None,
            label: name.clone(),
        })?;
        let mut metadata = Map::new();
        metadata.insert("name".to_owned(), json!(name));
        metadata.insert("env".to_owned(), json!(environment));
        metadata.insert("env_keys".to_owned(), json!(env_keys));
        metadata.insert("headers_keys".to_owned(), json!(headers_keys));
        metadata.insert(
            "guard_managed_proxy".to_owned(),
            json!(is_guard_proxy(command, &args)),
        );
        for (key, value) in enriched.as_object().ok_or(ERR_METADATA)? {
            metadata.insert(key.clone(), value.clone());
        }
        inventory.artifacts.push(scope.wire(
            format!("{HARNESS}:{}:{name}", scope.scope),
            name,
            "mcp_server",
            path,
            Fields {
                command,
                args,
                url,
                transport: Some(transport),
                publisher: None,
            },
            metadata,
        ));
    }
    Ok(())
}

pub(crate) fn detect(args: &Value) -> KindResult {
    let request = Request::parse(args, HARNESS)?;
    let configs = configs(args)?;
    let mut inventory = Inventory::new(&request);
    for (path, payload) in &configs {
        inventory.push_found(path);
        mcp_servers(&mut inventory, path, payload)?;
    }
    inventory.finish()
}
