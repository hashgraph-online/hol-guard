//! `runner_authority` kind `codex_detect`: the filesystem half of
//! `CodexHarnessAdapter.detect`. Python resolves the source paths and scopes
//! and computes everything that needs the hook manifest, its HMAC and the
//! Windows-aware command splitter (the authenticated and legacy ownership
//! bindings); this reads the `config.toml` and `hooks.json` sources, walks
//! the MCP servers and the hook inventory, and returns the artifacts, the
//! config paths that were found, and the warnings. Text CPython would raise on
//! instead of returning is a stable refusal, never a partial inventory.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::aibom_mcp_metadata::{enrich, McpMetadataInput, ERR_METADATA};
use super::aibom_op::absolute;
use super::codex_hook_artifacts::hook_artifacts;
use super::codex_hooks::{enumerate, Source};
use super::codex_proxy::{parse_proxy_args, ProxyArgs};
use super::codex_sources::{
    hooks_feature_enabled, is_empty, json_payload, read_source, toml_payload, ERR_VALUE,
};
use super::codex_value::HookVal;
use super::context_digest::python_strip;
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use super::zcode_artifacts::{pair_value, Fields, Scope};

const HARNESS: &str = "codex";

struct SourcePair<'a> {
    config_path: &'a str,
    hooks_path: &'a str,
    config_scope: &'a str,
    hooks_scope: &'a str,
    authenticated: bool,
    config_legacy: &'a [Value],
    hooks_legacy: &'a [Value],
}

fn string_args(server: &HookVal) -> Option<Vec<String>> {
    match server.get("args") {
        None => Some(Vec::new()),
        Some(HookVal::List(items)) => Some(
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect(),
        ),
        Some(_) => None,
    }
}

const PROXY_COMMANDS: [&str; 5] = [
    "codex-mcp-proxy",
    "opencode-mcp-proxy",
    "copilot-mcp-proxy",
    "cursor-mcp-proxy",
    "mcp-proxy",
];

/// `_hol_guard_command_name`: the final path component, lowered, without one
/// launcher suffix.
fn is_guard_launcher(command: &str) -> bool {
    let normalized = command.replace('\\', "/");
    let name = normalized
        .split('/')
        .rfind(|part| !part.is_empty() && *part != ".")
        .unwrap_or("")
        .to_lowercase();
    let name = [".exe", ".cmd", ".bat"]
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix))
        .unwrap_or(&name);
    matches!(name, "hol-guard" | "current-hol-guard")
}

/// `proxy_argument_tail(...) is not None`.
fn has_proxy_tail(args: &[String]) -> bool {
    let command = |index: usize| {
        args.get(index)
            .is_some_and(|arg| PROXY_COMMANDS.contains(&arg.as_str()))
    };
    command(0)
        || (args.len() >= 2 && args[0] == "guard" && command(1))
        || (args.len() >= 4
            && args[0] == "-m"
            && args[1] == "codex_plugin_scanner.cli"
            && args[2] == "guard"
            && command(3))
}

/// `is_guard_proxy_command`.
pub(crate) fn is_guard_proxy(command: Option<&str>, args: &[String]) -> bool {
    let Some(command) = command else {
        return false;
    };
    if is_guard_launcher(command) {
        return has_proxy_tail(args);
    }
    args.iter().any(|arg| arg == "codex_plugin_scanner.cli")
        && args.iter().any(|arg| arg == "guard")
        && args
            .iter()
            .any(|arg| PROXY_COMMANDS.contains(&arg.as_str()))
}

fn enriched_metadata(
    mut metadata: Map<String, Value>,
    input: &McpMetadataInput,
) -> Result<Map<String, Value>, &'static str> {
    let enriched = enrich(input).map_err(|_| ERR_METADATA)?;
    for (key, value) in enriched.as_object().ok_or(ERR_METADATA)? {
        metadata.insert(key.clone(), value.clone());
    }
    Ok(metadata)
}

fn string_map(pairs: &BTreeMap<String, String>) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(key, value)| (key.clone(), json!(value)))
        .collect()
}

/// `_artifact_from_guard_proxy_args`: the wrapped server, without re-wrapping.
fn proxy_artifact(
    args: &[String],
    fallback_name: &str,
    fallback_scope: &str,
    fallback_config_path: &str,
    environment: Option<&HookVal>,
) -> Result<Option<Value>, &'static str> {
    let parsed: ProxyArgs = parse_proxy_args(args);
    let Some(command) = parsed
        .value("command")
        .filter(|command| !command.is_empty())
    else {
        return Ok(None);
    };
    let name = parsed
        .value("server-name")
        .filter(|name| !name.is_empty())
        .unwrap_or(fallback_name);
    let scope = parsed
        .value("source-scope")
        .filter(|scope| !scope.is_empty())
        .unwrap_or(fallback_scope);
    let config_path = parsed
        .value("config-path")
        .filter(|path| !path.is_empty())
        .unwrap_or(fallback_config_path);
    let transport = parsed
        .value("transport")
        .filter(|transport| !transport.is_empty())
        .unwrap_or("stdio");
    let mut env_keys = parsed.env_keys.clone();
    env_keys.sort();
    let mut configured = BTreeMap::new();
    if let Some(raw) = environment.and_then(HookVal::as_dict) {
        for key in &env_keys {
            if let Some((_, HookVal::Str(value))) = raw.iter().find(|(name, _)| name == key) {
                configured.insert(key.clone(), value.clone());
            }
        }
    }
    let mut metadata = Map::new();
    metadata.insert("env".to_owned(), Value::Object(string_map(&configured)));
    metadata.insert("env_keys".to_owned(), json!(env_keys));
    metadata.insert("guard_managed_proxy".to_owned(), json!(true));
    metadata.insert("name".to_owned(), json!(name));
    let metadata = enriched_metadata(
        metadata,
        &McpMetadataInput {
            command: Some(command.to_owned()),
            args: parsed.args.clone(),
            url: None,
            transport: Some(transport.to_owned()),
            env_keys: env_keys.clone(),
            headers_keys: Vec::new(),
            env: pair_value(&configured),
            headers: Value::Null,
            env_values_hash: None,
            header_values_hash: None,
            label: name.to_owned(),
        },
    )?;
    let scope_wire = Scope {
        harness: HARNESS,
        scope,
    };
    Ok(Some(scope_wire.wire(
        format!("{HARNESS}:{scope}:{name}"),
        name,
        "mcp_server",
        Path::new(config_path),
        Fields {
            command: Some(command),
            args: parsed.args.clone(),
            url: None,
            transport: Some(transport),
            publisher: None,
        },
        metadata,
    )))
}

/// One `mcp_servers` entry that is not a Guard proxy.
fn server_artifact(
    scope: &Scope<'_>,
    name: &str,
    server: &HookVal,
    args: Vec<String>,
    config_path: &str,
) -> Result<Value, &'static str> {
    let command = server.get("command").and_then(HookVal::as_str);
    let url = server.get("url").and_then(HookVal::as_str);
    let transport = if url.is_some() { "http" } else { "stdio" };
    let mut environment = BTreeMap::new();
    if let Some(entries) = server.get("env").and_then(HookVal::as_dict) {
        for (key, value) in entries {
            let key = python_strip(key);
            if let (false, HookVal::Str(value)) = (key.is_empty(), value) {
                environment.insert(key.to_owned(), value.clone());
            }
        }
    }
    let enabled = server.get("enabled") != Some(&HookVal::Bool(false));
    let mut metadata = Map::new();
    metadata.insert("name".to_owned(), json!(name));
    metadata.insert("enabled".to_owned(), json!(enabled));
    metadata.insert("env".to_owned(), Value::Object(string_map(&environment)));
    metadata.insert(
        "env_keys".to_owned(),
        json!(environment.keys().collect::<Vec<_>>()),
    );
    let metadata = enriched_metadata(
        metadata,
        &McpMetadataInput {
            command: command.map(str::to_owned),
            args: args.clone(),
            url: url.map(str::to_owned),
            transport: Some(transport.to_owned()),
            env_keys: environment.keys().cloned().collect(),
            headers_keys: Vec::new(),
            env: pair_value(&environment),
            headers: Value::Null,
            env_values_hash: None,
            header_values_hash: None,
            label: name.to_owned(),
        },
    )?;
    Ok(scope.wire(
        format!("{HARNESS}:{}:{name}", scope.scope),
        name,
        "mcp_server",
        Path::new(config_path),
        Fields {
            command,
            args,
            url,
            transport: Some(transport),
            publisher: None,
        },
        metadata,
    ))
}

fn mcp_artifacts(
    payload: &HookVal,
    scope_name: &str,
    config_path: &str,
    artifacts: &mut Vec<Value>,
) -> Result<(), &'static str> {
    let Some(HookVal::Dict(servers)) = payload.get("mcp_servers") else {
        return Ok(());
    };
    let scope = Scope {
        harness: HARNESS,
        scope: scope_name,
    };
    for (name, server) in servers {
        if !matches!(server, HookVal::Dict(_)) {
            continue;
        }
        let Some(args) = string_args(server) else {
            continue;
        };
        let command = server.get("command").and_then(HookVal::as_str);
        if is_guard_proxy(command, &args) {
            if let Some(artifact) =
                proxy_artifact(&args, name, scope_name, config_path, server.get("env"))?
            {
                artifacts.push(artifact);
            }
            continue;
        }
        artifacts.push(server_artifact(&scope, name, server, args, config_path)?);
    }
    Ok(())
}

fn text_field<'a>(entry: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    entry.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

fn path_field<'a>(entry: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    absolute(entry.get(key)).map_err(|_| ERR_INVALID)?;
    text_field(entry, key)
}

fn bindings_field<'a>(
    entry: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a [Value], &'static str> {
    let items = entry
        .get(key)
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    if items.iter().all(Value::is_object) {
        Ok(items)
    } else {
        Err(ERR_INVALID)
    }
}

fn source_pairs(args: &Map<String, Value>) -> Result<Vec<SourcePair<'_>>, &'static str> {
    args.get("sources")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|entry| {
            let entry = entry.as_object().ok_or(ERR_INVALID)?;
            Ok(SourcePair {
                config_path: path_field(entry, "config_path")?,
                hooks_path: path_field(entry, "hooks_path")?,
                config_scope: text_field(entry, "config_scope")?,
                hooks_scope: text_field(entry, "hooks_scope")?,
                authenticated: entry
                    .get("authenticated")
                    .and_then(Value::as_bool)
                    .ok_or(ERR_INVALID)?,
                config_legacy: bindings_field(entry, "config_legacy")?,
                hooks_legacy: bindings_field(entry, "hooks_legacy")?,
            })
        })
        .collect()
}

pub(crate) fn detect(args: &Value) -> KindResult {
    let args = args_object(args)?;
    if args.get("harness").and_then(Value::as_str) != Some(HARNESS) {
        return Err(ERR_INVALID);
    }
    let sources = source_pairs(args)?;
    let authenticated: &[Value] = bindings_field(args, "authenticated_bindings")?;
    let contents = match args.get("contents") {
        None | Some(Value::Null) => None,
        Some(Value::Object(captured)) => Some(captured),
        Some(_) => return Err(ERR_INVALID),
    };

    let mut artifacts = Vec::new();
    let mut found = Vec::new();
    let mut warnings = Vec::new();
    let mut records = Vec::new();
    let mut configs = Vec::new();
    for source in &sources {
        let raw = read_source(source.config_path, contents)?;
        let payload = toml_payload(raw.bytes.as_deref())?;
        if !is_empty(&payload) {
            found.push(source.config_path.to_owned());
            let inventory = enumerate(
                &payload,
                Source {
                    path: source.config_path,
                    scope: source.config_scope,
                    format: "toml",
                    hooks_enabled: hooks_feature_enabled(&payload),
                },
                if source.authenticated {
                    authenticated
                } else {
                    &[]
                },
                source.config_legacy,
            );
            records.extend(inventory.records);
            warnings.extend(inventory.warnings);
            mcp_artifacts(
                &payload,
                source.config_scope,
                source.config_path,
                &mut artifacts,
            )?;
        }
        configs.push(payload);
    }
    for (source, config) in sources.iter().zip(&configs) {
        let raw = read_source(source.hooks_path, contents)?;
        let payload = json_payload(raw.bytes.as_deref())?;
        if !raw.present {
            continue;
        }
        found.push(source.hooks_path.to_owned());
        let inventory = enumerate(
            &payload,
            Source {
                path: source.hooks_path,
                scope: source.hooks_scope,
                format: "json",
                hooks_enabled: hooks_feature_enabled(config),
            },
            &[],
            source.hooks_legacy,
        );
        records.extend(inventory.records);
        warnings.extend(inventory.warnings);
    }
    if records.iter().any(|record| record.unencodable) {
        return Err(ERR_VALUE);
    }
    artifacts.extend(hook_artifacts(&records)?);
    Ok(json!({
        "artifacts": artifacts,
        "found_paths": found,
        "warnings": warnings,
    }))
}
