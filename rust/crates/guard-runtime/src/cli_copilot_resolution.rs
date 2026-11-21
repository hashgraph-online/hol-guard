//! Copilot server discovery and fused launch/server identity construction.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use guard_command::ordered_json::Ordered;
use serde_json::{json, Map, Value};

use crate::cli_runtime_support_op::{
    config_digest, evaluate, server_fields, strip, text, tool_metadata,
};

const INVALID: &str = "native_runner_authority_cli_support_invalid";
const MAX_CONFIG_BYTES: u64 = 8 * 1024 * 1024;
type RankedServer = (usize, i64, String, Value, String);

#[cfg(test)]
#[path = "cli_copilot_resolution_tests.rs"]
mod tests;

fn entries(path: &Path, scope: &str, caller_cwd: &Path) -> Result<Vec<Value>, &'static str> {
    let source = if path.is_absolute() {
        path.to_owned()
    } else {
        caller_cwd.join(path)
    };
    let mut file = match File::open(source) {
        Ok(file) => file,
        Err(_) => return Ok(Vec::new()),
    };
    if file.metadata().map(|metadata| metadata.len()).unwrap_or(0) > MAX_CONFIG_BYTES {
        return Err("native_runner_authority_cli_support_config_too_large");
    }
    let mut raw = String::new();
    if file
        .by_ref()
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut raw)
        .is_err()
    {
        return Ok(Vec::new());
    }
    if raw.len() as u64 > MAX_CONFIG_BYTES {
        return Err("native_runner_authority_cli_support_config_too_large");
    }
    let (Ok(ordered), Ok(payload)) = (
        serde_json::from_str::<Ordered>(&raw),
        serde_json::from_str::<Value>(&raw),
    ) else {
        return Ok(Vec::new());
    };
    let Some(object) = ordered.as_object() else {
        return Ok(Vec::new());
    };
    let key = if object.get("servers").and_then(Ordered::as_object).is_some() {
        "servers"
    } else {
        "mcpServers"
    };
    let Some(servers) = object.get(key).and_then(Ordered::as_object) else {
        return Ok(Vec::new());
    };
    Ok(servers
        .iter()
        .filter(|(name, _)| !strip(name).is_empty())
        .map(|(name, ordered)| {
            let mut server = json!({"server_name": strip(name), "source_scope": scope,
            "config_path": path.to_string_lossy(), "server_config": payload[key][name].clone()});
            if let Some(environment) = ordered
                .as_object()
                .and_then(|value| value.get("env"))
                .and_then(Ordered::as_object)
            {
                server["environment_keys"] =
                    json!(environment.iter().map(|(key, _)| key).collect::<Vec<_>>());
            }
            server
        })
        .collect())
}

pub(crate) fn workspace_root(params: &Value) -> Result<Value, &'static str> {
    let Some(value) = params.get("workspace").and_then(Value::as_str) else {
        return Ok(Value::Null);
    };
    let path = Path::new(value);
    let caller_cwd = Path::new(text(params, "caller_cwd")?);
    for candidate in path.ancestors() {
        let source = if candidate.is_absolute() {
            candidate.to_owned()
        } else {
            caller_cwd.join(candidate)
        };
        if source.join(".mcp.json").is_file() || source.join(".vscode/mcp.json").is_file() {
            return Ok(json!(candidate.to_string_lossy()));
        }
    }
    Ok(json!(value))
}

fn priority(server: &Value, preferred: &Value) -> Result<i64, &'static str> {
    let result = evaluate(
        "match_priority",
        &json!({"config_path": server["config_path"], "preferred": preferred}),
    )?;
    result["result"].as_i64().ok_or(INVALID)
}

pub(super) fn select_server(params: &Value) -> Result<Option<(Value, String)>, &'static str> {
    let payload = params
        .get("payload")
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    let Some(tool) = payload
        .get("tool_name")
        .and_then(Value::as_str)
        .filter(|v| !strip(v).is_empty())
    else {
        return Ok(None);
    };
    let home = Path::new(text(params, "home_dir")?);
    let workspace = params
        .get("workspace")
        .and_then(Value::as_str)
        .map(Path::new);
    let preferred = params.get("preferred").unwrap_or(&Value::Null);
    let caller_cwd = Path::new(text(params, "caller_cwd")?);
    let mut servers = Vec::new();
    if let Some(workspace) = workspace {
        for path in [
            workspace.join(".vscode/mcp.json"),
            workspace.join(".mcp.json"),
        ] {
            servers.extend(entries(&path, "project", caller_cwd)?);
        }
    }
    servers.extend(entries(
        &home.join(".copilot/mcp-config.json"),
        "global",
        caller_cwd,
    )?);
    let mut selected: Option<RankedServer> = None;
    for server in servers {
        let name = text(&server, "server_name")?;
        let runtime = if let Some((requested, runtime)) = tool.split_once('/') {
            (strip(requested) == name && !strip(runtime).is_empty())
                .then(|| strip(runtime).to_owned())
        } else if let Some(suffix) = tool.strip_prefix("mcp_") {
            let token = evaluate("tool_token", &json!({"value": name}))?;
            suffix
                .strip_prefix(&format!("{}_", text(&token, "result")?))
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
        } else {
            None
        };
        let Some(runtime) = runtime else { continue };
        let length = if tool.contains('/') {
            0
        } else {
            evaluate("tool_token", &json!({"value": name}))?["result"]
                .as_str()
                .ok_or(INVALID)?
                .len()
        };
        let rank = priority(&server, preferred)?;
        let path = text(&server, "config_path")?.to_owned();
        if selected
            .as_ref()
            .is_none_or(|old| (length, rank, &path) > (old.0, old.1, &old.2))
        {
            selected = Some((length, rank, path, server, runtime));
        }
    }
    Ok(selected.map(|(_, _, _, server, runtime)| (server, runtime)))
}

pub(crate) fn resolve_tool(params: &Value) -> Result<Value, &'static str> {
    let payload = params
        .get("payload")
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    let Some(tool) = payload
        .get("tool_name")
        .and_then(Value::as_str)
        .filter(|v| !strip(v).is_empty())
    else {
        return Ok(Value::Null);
    };
    let home = Path::new(text(params, "home_dir")?);
    let workspace = params
        .get("workspace")
        .and_then(Value::as_str)
        .map(Path::new);
    let (server, runtime) = if let Some((server, runtime)) = select_server(params)? {
        (server, runtime)
    } else if let Some((name, runtime)) = tool.split_once('/') {
        if strip(name).is_empty() || strip(runtime).is_empty() {
            return Ok(Value::Null);
        }
        let scope = payload
            .get("source_scope")
            .and_then(Value::as_str)
            .filter(|v| !strip(v).is_empty())
            .map(strip)
            .unwrap_or(if workspace.is_some() {
                "project"
            } else {
                "global"
            });
        let path = workspace.map_or_else(
            || home.join(".copilot/config.json"),
            |path| path.join(".github/hooks/hol-guard-copilot.json"),
        );
        (
            json!({"server_name": strip(name), "source_scope": scope, "config_path": path.to_string_lossy(), "server_config": null}),
            strip(runtime).to_owned(),
        )
    } else {
        return Ok(Value::Null);
    };
    let identity = server_identity(
        &json!({"server": server, "launch_cwd": params["launch_cwd"], "environment": params["environment"]}),
    )?;
    let metadata = tool_metadata(
        &json!({"config": server["server_config"], "payload": payload,
        "requested_tool_name": tool, "runtime_tool_name": runtime}),
    )?;
    Ok(
        json!({"server": {"server_name": server["server_name"], "source_scope": server["source_scope"], "config_path": server["config_path"]},
        "tool_name": runtime, "identity": identity, "metadata": metadata}),
    )
}

pub(crate) fn server_identity(params: &Value) -> Result<Value, &'static str> {
    let server = params.get("server").ok_or(INVALID)?;
    let config = server.get("server_config").ok_or(INVALID)?;
    let fields = server_fields(config)?;
    let configured = fields["environment"].as_object().ok_or(INVALID)?;
    let mut environment = params
        .get("environment")
        .and_then(Value::as_object)
        .ok_or(INVALID)?
        .clone();
    if environment.values().any(|v| !v.is_string()) {
        return Err(INVALID);
    }
    environment.extend(configured.clone());
    let command = fields["command"].clone();
    let args = fields["args"].as_array().ok_or(INVALID)?;
    let cwd = PathBuf::from(text(params, "launch_cwd")?);
    let mut launch = guard_command::launch_identity::build_runtime_launch_identity(
        &command,
        args,
        true,
        false,
        environment.get("PATH").and_then(Value::as_str),
        Some(&cwd),
        None,
        Some(&Value::Object(environment.clone())),
    );
    launch["launch_args_sha256"] = json!(config_digest(&fields["args"])?);
    launch["server_config_sha256"] = fields["config_sha256"].clone();
    launch["transport"] = fields["transport"].clone();
    let remote = config
        .get("url")
        .and_then(Value::as_str)
        .and_then(guard_command::normalized_remote_mcp_url);
    if !config.is_object() || (command.is_null() && remote.is_none()) {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| "native_runner_authority_cli_support_entropy_unavailable")?;
        launch["reuse_nonce"] = json!(hex::encode(random));
        launch["status"] = json!(if !config.is_object() {
            "server_config_unresolved"
        } else {
            "server_command_unresolved"
        });
    } else if command.is_null() {
        launch["status"] = json!("remote_transport");
    }
    let args: Vec<String> = args
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let keys: Vec<String> = fields["env_keys"]
        .as_array()
        .ok_or(INVALID)?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let mut bound_environment = Map::new();
    if let Some(order) = server
        .get("environment_keys")
        .and_then(Value::as_array)
        .filter(|order| !order.is_empty())
    {
        for key in order.iter().filter_map(Value::as_str) {
            if let Some(value) = configured.get(key) {
                bound_environment.insert(strip(key).to_owned(), value.clone());
            }
        }
    } else {
        bound_environment.extend(
            configured
                .iter()
                .map(|(key, value)| (strip(key).to_owned(), value.clone())),
        );
    }
    let identity = guard_command::mcp_decision::build_mcp_server_identity(
        text(server, "config_path")?,
        remote
            .as_deref()
            .or_else(|| command.as_str())
            .unwrap_or("<unresolved>"),
        &args,
        text(&fields, "transport")?,
        Some(&bound_environment),
        &keys,
    );
    Ok(
        json!({"server_identity": {"config_path": identity.config_path, "command": identity.command,
        "args_hash": identity.args_hash, "package_name": identity.package_name, "package_version": identity.package_version,
        "package_source": identity.package_source, "transport": identity.transport, "env_keys": identity.env_keys,
        "env_values_hash": identity.env_values_hash, "identity_hash": identity.identity_hash},
        "fingerprint": {"config_sha256": fields["config_sha256"], "launch_args_sha256": launch["launch_args_sha256"],
            "resolved_executable": launch, "transport": fields["transport"]}, "transport": fields["transport"]}),
    )
}
