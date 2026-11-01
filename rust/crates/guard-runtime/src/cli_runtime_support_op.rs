//! Native Copilot configuration fields and tool metadata selection.

use serde_json::{json, Map, Value};
use std::path::Path;

const INVALID: &str = "native_runner_authority_cli_support_invalid";

pub(super) fn strip(value: &str) -> &str {
    value.trim_matches(|character: char| {
        character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
    })
}

pub(super) fn text<'a>(params: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    params.get(key).and_then(Value::as_str).ok_or(INVALID)
}

fn command(config: Option<&Map<String, Value>>) -> (Option<String>, Vec<String>) {
    let mut result = None;
    let mut args = Vec::new();
    if let Some(value) = config.and_then(|value| value.get("command")) {
        if let Some(value) = value.as_str() {
            if !strip(value).is_empty() {
                result = Some(strip(value).to_owned());
            }
        } else if let Some(values) = value.as_array() {
            let mut parts = values
                .iter()
                .filter_map(Value::as_str)
                .filter(|v| !v.is_empty());
            result = parts.next().map(str::to_owned);
            args.extend(parts.map(str::to_owned));
        }
    }
    if let Some(values) = config
        .and_then(|value| value.get("args"))
        .and_then(Value::as_array)
    {
        args.extend(values.iter().filter_map(Value::as_str).map(str::to_owned));
    }
    (result, args)
}

fn transport(config: Option<&Map<String, Value>>) -> String {
    let Some(config) = config else {
        return "stdio".to_owned();
    };
    if let Some(value) = config
        .get("transport")
        .or_else(|| config.get("type"))
        .and_then(Value::as_str)
    {
        if !strip(value).is_empty() {
            let value = strip(value).to_lowercase().replace('_', "-");
            return match value.as_str() {
                "local" | "stdio" => "stdio".to_owned(),
                "http" | "https" | "remote" | "streamable-http" => "http".to_owned(),
                _ => value,
            };
        }
    }
    if config
        .get("url")
        .and_then(Value::as_str)
        .is_some_and(|v| !strip(v).is_empty())
    {
        "http".to_owned()
    } else {
        "stdio".to_owned()
    }
}

pub(super) fn config_digest(config: &Value) -> Result<String, &'static str> {
    let mut encoded = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(config, &mut encoded, usize::MAX)
        .map_err(|_| INVALID)?;
    Ok(guard_policy_snapshot::digest_bytes(&encoded))
}

pub(super) fn server_fields(config: &Value) -> Result<Value, &'static str> {
    let mapping = config.as_object();
    let (command, args) = command(mapping);
    let mut environment = Map::new();
    let mut keys = Vec::new();
    if let Some(env) = mapping
        .and_then(|v| v.get("env"))
        .and_then(Value::as_object)
    {
        for (key, value) in env {
            if !strip(key).is_empty() {
                keys.push(key.clone());
                if value.is_string() {
                    environment.insert(key.clone(), value.clone());
                }
            }
        }
    }
    keys.sort();
    Ok(
        json!({"command": command, "args": args, "environment": environment,
        "env_keys": keys, "transport": transport(mapping), "config_sha256": config_digest(config)?}),
    )
}

fn tool_definition<'a>(config: &'a Value, name: &str) -> Option<&'a Map<String, Value>> {
    let tools = config.get("tools")?;
    if let Some(tools) = tools.as_object() {
        return tools.get(name).and_then(Value::as_object);
    }
    tools.as_array()?.iter().find_map(|item| {
        let item = item.as_object()?;
        (item.get("name").and_then(Value::as_str) == Some(name)).then_some(item)
    })
}

pub(super) fn tool_metadata(params: &Value) -> Result<Value, &'static str> {
    let payload = params
        .get("payload")
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    let config = params.get("config").ok_or(INVALID)?;
    let requested = text(params, "requested_tool_name")?;
    let runtime = text(params, "runtime_tool_name")?;
    let mut candidates = vec![payload];
    for key in ["tool", "tool_definition", "toolDefinition"] {
        if let Some(value) = payload.get(key).and_then(Value::as_object) {
            candidates.push(value);
        }
    }
    if let Some(calls) = payload.get("toolCalls").and_then(Value::as_array) {
        for item in calls {
            if let Some(item) = item.as_object() {
                if item
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name == requested || name == runtime)
                {
                    candidates.push(item);
                }
            }
        }
    }
    if let Some(value) = tool_definition(config, runtime) {
        candidates.push(value);
    }
    let mut schema = None;
    let mut description = None;
    for candidate in candidates {
        if schema.is_none() {
            schema = [
                "tool_schema",
                "toolSchema",
                "input_schema",
                "inputSchema",
                "schema",
            ]
            .iter()
            .find_map(|key| candidate.get(*key));
        }
        if description.is_none() {
            description = ["tool_description", "toolDescription", "description"]
                .iter()
                .filter_map(|key| candidate.get(*key).and_then(Value::as_str))
                .find(|value| !strip(value).is_empty())
                .map(strip);
        }
        if schema.is_some() && description.is_some() {
            break;
        }
    }
    Ok(json!({"schema": schema.unwrap_or(&Value::Null), "description": description}))
}

pub(crate) fn dispatch(args: &Value) -> Result<Value, &'static str> {
    if args.as_object().is_none_or(|args| args.len() != 2) {
        return Err(INVALID);
    }
    evaluate(text(args, "operation")?, args.get("params").ok_or(INVALID)?)
}

pub(super) fn evaluate(operation: &str, params: &Value) -> Result<Value, &'static str> {
    let result = match operation {
        "resolve_tool" => crate::cli_copilot_resolution::resolve_tool(params)?,
        "server_identity" => crate::cli_copilot_resolution::server_identity(params)?,
        "workspace_root" => crate::cli_copilot_resolution::workspace_root(params)?,
        "remote_url" => params
            .get("value")
            .and_then(Value::as_str)
            .and_then(guard_command::normalized_remote_mcp_url)
            .map_or(Value::Null, Value::String),
        "remote_endpoint_identity" => params
            .get("value")
            .and_then(Value::as_str)
            .and_then(guard_command::normalized_remote_mcp_url)
            .map(|url| match url.split_once('?') {
                Some((endpoint, _)) => endpoint.to_owned(),
                None => url,
            })
            .map_or(Value::Null, Value::String),
        "remote_server_name" => params
            .get("value")
            .and_then(Value::as_str)
            .and_then(guard_command::contributed_mcp_decision::normalized_remote_server_name)
            .map_or(Value::Null, Value::String),
        "direct_command_name" => params
            .get("value")
            .and_then(Value::as_str)
            .and_then(guard_command::contributed_mcp_decision::direct_mcp_command_name)
            .map_or(Value::Null, Value::String),
        "fd_exec_request" => Value::Bool(
            guard_command::false_positive_rules::fd_arg_requests_exec(text(params, "value")?),
        ),
        "skill_doc_path" => {
            let home = params.get("home_dir").and_then(Value::as_str);
            Value::Bool(
                guard_command::false_positive_rules::target_is_known_skill_doc_path(
                    text(params, "value")?,
                    home.map(Path::new),
                ),
            )
        }
        "server_fields" => server_fields(params.get("config").ok_or(INVALID)?)?,
        "tool_metadata" => tool_metadata(params)?,
        "tool_token" => {
            let value = strip(text(params, "value")?).to_lowercase();
            let mut token = String::new();
            let mut separator = false;
            for character in value.chars() {
                if character.is_ascii_lowercase() || character.is_ascii_digit() {
                    if separator && !token.is_empty() {
                        token.push('_');
                    }
                    token.push(character);
                    separator = false;
                } else {
                    separator = true;
                }
            }
            Value::String(token)
        }
        "match_priority" => {
            let path = Path::new(text(params, "config_path")?);
            let cli = path.file_name().is_some_and(|v| v == ".mcp.json");
            let ide = path.file_name().is_some_and(|v| v == "mcp.json")
                && path
                    .parent()
                    .and_then(Path::file_name)
                    .is_some_and(|v| v == ".vscode");
            let priority = match params.get("preferred").and_then(Value::as_str) {
                Some("cli") if cli => 2,
                Some("cli") if ide => 1,
                Some("ide") if ide => 2,
                Some("ide") if cli => 1,
                _ => 0,
            };
            json!(priority)
        }
        _ => return Err(INVALID),
    };
    Ok(json!({"result": result}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_support_vectors() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/cli_runtime_support_vectors.json"
        ))
        .unwrap();
        for (index, case) in vectors["cases"].as_array().unwrap().iter().enumerate() {
            if case["operation"] == "selection_fixture" {
                continue;
            }
            let result = evaluate(case["operation"].as_str().unwrap(), &case["params"]).unwrap();
            assert_eq!(result["result"], case["expected"], "vector {index}");
        }
    }
}
