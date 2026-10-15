//! The MCP server and hook artifacts `ClaudeCodeHarnessAdapter.detect` reads
//! from one parsed settings payload, with the Python scalar rules the
//! discovery was written against. Every string the inventory carries must be
//! encodable: a lone surrogate CPython would keep is refused, never dropped.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::aibom_mcp_metadata::{enrich, McpMetadataInput, ERR_METADATA};
use super::context_digest::python_strip;
use super::pyjson::{PyVal, LONE_SURROGATE_MARK};
use super::zcode_artifacts::{Fields, Scope};

pub(crate) const ERR_VALUE: &str = "native_runner_authority_claude_code_value_unrepresentable";

pub(crate) fn kept(text: &str) -> Result<&str, &'static str> {
    if text.contains(LONE_SURROGATE_MARK) {
        Err(ERR_VALUE)
    } else {
        Ok(text)
    }
}

/// `tuple(str(v) for v in config.get("args", []) if isinstance(v, str))`:
/// a list keeps its strings, a string its characters and an object its keys;
/// iterating any other present value raises `TypeError`.
fn server_args(config: &PyVal) -> Result<Vec<String>, &'static str> {
    let args = match config.get("args") {
        None => Vec::new(),
        Some(PyVal::List(items)) => items
            .iter()
            .filter_map(PyVal::as_str)
            .map(str::to_owned)
            .collect(),
        Some(PyVal::Str(text)) => text.chars().map(String::from).collect(),
        Some(PyVal::Dict(entries)) => entries.iter().map(|(key, _)| key.clone()).collect(),
        Some(_) => return Err(ERR_VALUE),
    };
    for arg in &args {
        kept(arg)?;
    }
    Ok(args)
}

/// `{key.strip(): value ...}` over string keys that stay non-blank and string
/// values: a later key that strips onto an earlier one takes its value and
/// keeps the earlier position.
fn stripped_pairs(value: Option<&PyVal>) -> Result<Vec<(String, String)>, &'static str> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for (key, value) in value.and_then(PyVal::as_dict).unwrap_or_default() {
        let key = python_strip(key);
        let Some(value) = value.as_str() else {
            continue;
        };
        if key.is_empty() {
            continue;
        }
        let (key, value) = (kept(key)?.to_owned(), kept(value)?.to_owned());
        match pairs.iter_mut().find(|(existing, _)| *existing == key) {
            Some(slot) => slot.1 = value,
            None => pairs.push((key, value)),
        }
    }
    Ok(pairs)
}

fn pair_list(pairs: &[(String, String)]) -> Value {
    Value::Array(
        pairs
            .iter()
            .map(|(key, value)| json!([key, value]))
            .collect(),
    )
}

fn sorted_keys<'a>(keys: impl Iterator<Item = &'a String>) -> Result<Vec<String>, &'static str> {
    let mut keys = keys
        .map(|key| kept(key).map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    keys.sort();
    Ok(keys)
}

/// The `mcpServers` entries of one settings payload.
pub(crate) fn mcp_artifacts(
    scope: &Scope<'_>,
    path: &Path,
    payload: &PyVal,
) -> Result<Vec<Value>, &'static str> {
    let Some(servers) = payload.get("mcpServers").and_then(PyVal::as_dict) else {
        return Ok(Vec::new());
    };
    let mut artifacts = Vec::new();
    for (name, config) in servers {
        if config.as_dict().is_none() {
            continue;
        }
        let name = kept(name)?;
        let command = config
            .get("command")
            .and_then(PyVal::as_str)
            .map(kept)
            .transpose()?;
        let url = config
            .get("url")
            .and_then(PyVal::as_str)
            .map(kept)
            .transpose()?;
        let transport = if url.is_some() { "http" } else { "stdio" };
        let args = server_args(config)?;
        let env = stripped_pairs(config.get("env"))?;
        let headers = config.get("headers");
        let configured_headers = stripped_pairs(headers)?;
        let env_keys = sorted_keys(env.iter().map(|(key, _)| key))?;
        let headers_keys = match headers.and_then(PyVal::as_dict) {
            Some(entries) => sorted_keys(entries.iter().map(|(key, _)| key))?,
            None => Vec::new(),
        };
        let digests = enrich(&McpMetadataInput {
            command: command.map(str::to_owned),
            args: args.clone(),
            url: url.map(str::to_owned),
            transport: Some(transport.to_owned()),
            env_keys: env_keys.clone(),
            headers_keys,
            env: pair_list(&env),
            headers: pair_list(&configured_headers),
            env_values_hash: None,
            header_values_hash: None,
            label: name.to_owned(),
        })
        .map_err(|_| ERR_METADATA)?;
        let mut metadata = Map::new();
        metadata.insert("name".to_owned(), json!(name));
        let env_object: Map<String, Value> = env
            .iter()
            .map(|(key, value)| (key.clone(), json!(value)))
            .collect();
        metadata.insert("env".to_owned(), Value::Object(env_object));
        for (key, value) in digests.as_object().ok_or(ERR_METADATA)? {
            metadata.insert(key.clone(), value.clone());
        }
        artifacts.push(scope.wire(
            format!("claude-code:{}:mcp:{name}", scope.scope),
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
    Ok(artifacts)
}

/// `command_handler_argv(handler)[1:]`: the `args` list when the handler has a
/// string command and every arg is a string, else nothing.
fn handler_args(handler: &PyVal) -> Result<Vec<String>, &'static str> {
    if handler.get("command").and_then(PyVal::as_str).is_none() {
        return Ok(Vec::new());
    }
    let Some(items) = handler.get("args").and_then(PyVal::as_list) else {
        return Ok(Vec::new());
    };
    let mut args = Vec::with_capacity(items.len());
    for item in items {
        let Some(text) = item.as_str() else {
            return Ok(Vec::new());
        };
        args.push(kept(text)?.to_owned());
    }
    Ok(args)
}

/// The metadata of one grouped handler; `timeout` keeps any `int`, which in
/// Python includes `bool`.
fn handler_metadata(
    matcher: Option<&str>,
    handler: &PyVal,
) -> Result<Map<String, Value>, &'static str> {
    let mut metadata = Map::new();
    if let Some(matcher) = matcher {
        metadata.insert("matcher".to_owned(), json!(kept(matcher)?));
    }
    for key in ["type", "url"] {
        if let Some(text) = handler.get(key).and_then(PyVal::as_str) {
            metadata.insert(key.to_owned(), json!(kept(text)?));
        }
    }
    if let Some(timeout @ (PyVal::Int(_) | PyVal::Bool(_))) = handler.get("timeout") {
        metadata.insert("timeout".to_owned(), timeout.to_json().ok_or(ERR_VALUE)?);
    }
    if let Some(condition) = handler.get("if").and_then(PyVal::as_str) {
        metadata.insert("if".to_owned(), json!(kept(condition)?));
    }
    Ok(metadata)
}

/// The `hooks` entries of one settings payload: a flat entry with a string
/// command is one hook, a grouped entry one hook per handler.
pub(crate) fn hook_artifacts(
    scope: &Scope<'_>,
    path: &Path,
    payload: &PyVal,
) -> Result<Vec<Value>, &'static str> {
    let Some(hooks) = payload.get("hooks").and_then(PyVal::as_dict) else {
        return Ok(Vec::new());
    };
    let mut artifacts = Vec::new();
    for (hook_name, entries) in hooks {
        let Some(entries) = entries.as_list() else {
            continue;
        };
        let hook_name = kept(hook_name)?;
        let event = python_strip(hook_name).to_lowercase();
        for (group_index, entry) in entries.iter().enumerate() {
            if entry.as_dict().is_none() {
                continue;
            }
            if let Some(command) = entry.get("command").and_then(PyVal::as_str) {
                artifacts.push(scope.wire(
                    format!("claude-code:{}:{event}:{group_index}", scope.scope),
                    hook_name,
                    "hook",
                    path,
                    Fields {
                        command: Some(kept(command)?),
                        args: handler_args(entry)?,
                        ..Fields::default()
                    },
                    Map::new(),
                ));
                continue;
            }
            let matcher = entry.get("matcher").and_then(PyVal::as_str);
            let Some(handlers) = entry.get("hooks").and_then(PyVal::as_list) else {
                continue;
            };
            for (handler_index, handler) in handlers.iter().enumerate() {
                if handler.as_dict().is_none() {
                    continue;
                }
                let command = handler.get("command").and_then(PyVal::as_str);
                let url = handler.get("url").and_then(PyVal::as_str);
                artifacts.push(scope.wire(
                    format!(
                        "claude-code:{}:{event}:{group_index}:{handler_index}",
                        scope.scope
                    ),
                    hook_name,
                    "hook",
                    path,
                    Fields {
                        command: command.map(kept).transpose()?,
                        args: handler_args(handler)?,
                        url: url.map(kept).transpose()?,
                        ..Fields::default()
                    },
                    handler_metadata(matcher, handler)?,
                ));
            }
        }
    }
    Ok(artifacts)
}
