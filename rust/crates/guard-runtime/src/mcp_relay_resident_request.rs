//! The session facts and the per-call `mcp_relay_decide` request.

use std::ffi::OsString;
use std::path::PathBuf;

use guard_command::mcp_decision::{build_configured_environment_hash, build_mcp_server_identity};
use guard_contracts::{McpToolArgumentsV1, McpToolCallServerIdentityV1};
use serde_json::{json, Map, Value};

use super::{ProcessFacts, RelayFacts};
use crate::context_digest::python_strip;
use crate::mcp_relay_args::RelayArgs;
use crate::mcp_relay_catalog::{CatalogSnapshot, RelayCatalog};
use crate::mcp_relay_launch::Launch;

/// `_SHELL_TOOL_NAMES`: tools whose arguments the proxy parses as a command.
const SHELL_TOOL_NAMES: [&str; 12] = [
    "ash",
    "bash",
    "cmd",
    "dash",
    "powershell",
    "pwsh",
    "run_command",
    "run_terminal_command",
    "sh",
    "shell",
    "terminal",
    "zsh",
];
/// `_command_argument`: argument keys the proxy reads as a package command.
const COMMAND_KEYS: [&str; 4] = ["command", "cmd", "shell_command", "shellCommand"];

/// The session facts, or `None` when the proxy could not have built them as
/// the relay sees them.
pub(super) fn relay_facts(
    args: &RelayArgs,
    launch: &Launch,
    process: &ProcessFacts,
) -> Option<RelayFacts> {
    let guard_home = utf8(std::fs::canonicalize(&args.guard_home).ok()?)?;
    let workspace = match &args.workspace {
        Some(workspace) => Some(workspace.to_str()?.to_owned()),
        None => None,
    };
    // `_normalized_tool_call_workspace(workspace_dir or Path.cwd())`.
    let anchor = args.workspace.clone().or_else(|| process.cwd.clone())?;
    let hash_workspace = utf8(std::fs::canonicalize(anchor).ok()?)?;
    let launch_env: Map<String, Value> = launch
        .launch_env
        .iter()
        .map(|(key, value)| (key.clone(), Value::String(value.clone())))
        .collect();
    let keys = &args.server_env_keys;
    let configured: Map<String, Value> = keys
        .iter()
        .filter_map(|key| Some((key.clone(), launch_env.get(key)?.clone())))
        .collect();
    let mut command = vec![Value::String(args.command.clone())];
    command.extend(args.args.iter().cloned().map(Value::String));
    let mut fingerprint = Map::new();
    fingerprint.insert("command".to_owned(), Value::Array(command));
    fingerprint.insert(
        "configured_env_values_hash".to_owned(),
        Value::String(build_configured_environment_hash(
            Some(&launch_env),
            Some(keys.as_slice()),
        )),
    );
    fingerprint.insert(
        "transport".to_owned(),
        Value::String(args.transport.clone()),
    );
    fingerprint.insert(
        "resolved_executable".to_owned(),
        resolved_executable(args, &launch.identity)?,
    );
    let identity = build_mcp_server_identity(
        &args.config_path,
        &args.command,
        &args.args,
        &args.transport,
        Some(&configured),
        keys,
    );
    let server_identity = serde_json::to_value(McpToolCallServerIdentityV1 {
        config_path: identity.config_path,
        command: identity.command,
        args_hash: identity.args_hash,
        package_name: identity.package_name,
        package_version: identity.package_version,
        package_source: identity.package_source,
        transport: identity.transport,
        env_keys: identity.env_keys,
        env_values_hash: identity.env_values_hash,
        identity_hash: identity.identity_hash,
    })
    .ok()?;
    Some(RelayFacts {
        guard_home,
        workspace,
        hash_workspace,
        harness: args.harness.to_owned(),
        server_name: args.server_name.clone(),
        source_scope: args.source_scope.clone(),
        config_path: args.config_path.clone(),
        transport: args.transport.clone(),
        server_id: args.server_id.clone(),
        fingerprint,
        server_identity,
        launcher_path: launcher_path(process)?,
        launcher_home: launcher_home(process.home.as_ref()?)?,
    })
}

fn utf8(path: PathBuf) -> Option<String> {
    path.into_os_string().into_string().ok()
}

/// `_resolved_executable_identity`: the executable binding plus the command,
/// the launch directory and the entrypoint.
fn resolved_executable(args: &RelayArgs, identity: &Value) -> Option<Value> {
    let mut resolved = identity
        .get("executable")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    resolved.insert("command".to_owned(), Value::String(args.command.clone()));
    resolved.insert("launch_cwd".to_owned(), identity.get("launch_cwd")?.clone());
    resolved.insert("entrypoint".to_owned(), identity.get("entrypoint")?.clone());
    Some(Value::Object(resolved))
}

/// `_caller_launcher_path(os.environ.get("PATH"))`: relative entries are
/// anchored to the working directory. `Some(None)` is an unset `PATH`.
pub(super) fn launcher_path(process: &ProcessFacts) -> Option<Option<String>> {
    let Some(path) = process.path.as_ref() else {
        return Some(None);
    };
    let path = path.to_str()?;
    let parts: Vec<&str> = path.split(':').collect();
    if parts
        .iter()
        .all(|part| part.is_empty() || part.starts_with('/'))
    {
        return Some(Some(path.to_owned()));
    }
    let cwd = process.cwd.as_ref()?.to_str()?;
    let anchored: Vec<String> = parts
        .iter()
        .map(|part| {
            if part.is_empty() || part.starts_with('/') {
                (*part).to_owned()
            } else if cwd.ends_with('/') {
                format!("{cwd}{part}")
            } else {
                format!("{cwd}/{part}")
            }
        })
        .collect();
    Some(Some(anchored.join(":")))
}

/// `os.path.expanduser("~")` with `HOME` set.
pub(super) fn launcher_home(home: &OsString) -> Option<String> {
    let trimmed = home.to_str()?.trim_end_matches('/');
    Some(if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    })
}

/// The resident request for one call and the catalog it is decided against,
/// or `None` when the call is not sent.
pub(super) fn decide_request(
    facts: &RelayFacts,
    params: &Map<String, Value>,
    order: Option<&[String]>,
    catalog: &RelayCatalog,
) -> Option<(Vec<u8>, CatalogSnapshot)> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty() && name.is_ascii())?;
    if delegated_tool(name) {
        return None;
    }
    let arguments = arguments(params.get("arguments"), order)?;
    let expected = catalog.snapshot();
    let catalog_fingerprint = expected.fingerprint.clone()?;
    let entry = match catalog.definition(name) {
        None => None,
        Some(Value::Object(definition)) => {
            let mut entry = definition.clone();
            entry.remove("name");
            if !python_stable(&Value::Object(entry.clone())) {
                return None;
            }
            (!entry.is_empty()).then_some(entry)
        }
        Some(_) => return None,
    };
    let mut fingerprint = facts.fingerprint.clone();
    fingerprint.insert(
        "tool_catalog_state".to_owned(),
        Value::String(expected.state.clone()),
    );
    fingerprint.insert(
        "tool_catalog_fingerprint".to_owned(),
        Value::String(catalog_fingerprint),
    );
    let request = json!({
        "guard_home": facts.guard_home,
        "workspace": facts.workspace,
        "hash_workspace": facts.hash_workspace,
        "build": {
            "harness": facts.harness,
            "server_name": facts.server_name,
            "tool_name": name,
            "source_scope": facts.source_scope,
            "config_path": facts.config_path,
            "transport": facts.transport,
            "server_id": facts.server_id,
            "server_fingerprint": fingerprint,
            "server_identity": facts.server_identity,
            "provider_catalog_hash": null,
            "tool": {"kind": "catalog", "entry": entry},
        },
        "arguments": serde_json::to_value(arguments).ok()?,
        "launcher_path": facts.launcher_path,
        "launcher_home": facts.launcher_home,
        "catalog_state": expected.state,
        "params": params,
    });
    let payload = json!({"operation": "mcp_relay_decide", "request": request});
    Some((serde_json::to_vec(&payload).ok()?, expected))
}

/// Tools the proxy routes through a package check or a Composio provider
/// lookup, which the resident does not answer.
pub(super) fn delegated_tool(name: &str) -> bool {
    let normalized = python_strip(name).to_ascii_lowercase();
    if SHELL_TOOL_NAMES.contains(&normalized.as_str()) {
        return true;
    }
    let tail = name.rsplit("__").next().unwrap_or(name);
    tail.to_ascii_lowercase().starts_with("composio_")
}

/// The call arguments as the proxy received them, in host key order.
pub(super) fn arguments(
    value: Option<&Value>,
    order: Option<&[String]>,
) -> Option<McpToolArgumentsV1> {
    let arguments = match value {
        None => McpToolArgumentsV1::Other { value: Value::Null },
        Some(Value::String(text)) => McpToolArgumentsV1::Json { text: text.clone() },
        Some(Value::Object(map)) => {
            if COMMAND_KEYS.iter().any(|key| map.contains_key(*key)) {
                return None;
            }
            let entries = if map.len() < 2 {
                map.iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect()
            } else {
                let order = order.filter(|order| order.len() == map.len())?;
                order
                    .iter()
                    .map(|key| Some((key.clone(), map.get(key)?.clone())))
                    .collect::<Option<Vec<_>>>()?
            };
            McpToolArgumentsV1::Mapping { entries }
        }
        Some(other) => McpToolArgumentsV1::Other {
            value: other.clone(),
        },
    };
    let stable = match &arguments {
        McpToolArgumentsV1::Mapping { entries } => {
            entries.iter().all(|(_, value)| python_stable(value))
        }
        McpToolArgumentsV1::Json { .. } => true,
        McpToolArgumentsV1::Other { value } => python_stable(value),
    };
    stable.then_some(arguments)
}

/// Whether every number keeps its text through `json.loads` and
/// `json.dumps`: only integers in their shortest form do.
pub(super) fn python_stable(value: &Value) -> bool {
    match value {
        Value::Number(number) => {
            let text = number.to_string();
            let digits = text.strip_prefix('-').unwrap_or(&text);
            text != "-0"
                && !digits.is_empty()
                && digits.bytes().all(|byte| byte.is_ascii_digit())
                && (digits == "0" || !digits.starts_with('0'))
        }
        Value::Array(items) => items.iter().all(python_stable),
        Value::Object(map) => map.values().all(python_stable),
        Value::Null | Value::Bool(_) | Value::String(_) => true,
    }
}
