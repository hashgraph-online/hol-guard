//! §7.2 and §9.2: the MCP servers a client loads from `mcp.json`.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{Map, Value};

use super::paths::{lexically_inside, package_path_inside, read_inside, Read};
use super::url::url_problem;
use super::{declared_version, Effect, Report, MCP_SCHEMA};

/// The MCP servers a client would load from `mcp.json`, by name.
pub(super) fn mcp_servers(root: &Path, report: &mut Report) -> Vec<String> {
    const PATH: &str = "mcp.json";
    let disable = |report: &mut Report, code, section, message: &str| {
        report.error(code, PATH, section, Effect::DisableMcp, message);
    };
    let text = match read_inside(root, Path::new(PATH)) {
        Read::Missing => return Vec::new(),
        Read::Outside => {
            report.error(
                "mcp_outside_root",
                PATH,
                "4.1",
                Effect::InvalidComponent,
                "mcp.json resolves outside the plugin folder; clients load no MCP servers.",
            );
            return Vec::new();
        }
        Read::NotFile => {
            report.error(
                "mcp_not_file",
                PATH,
                "6.2",
                Effect::InvalidComponent,
                "mcp.json must be a file; clients load no MCP servers.",
            );
            return Vec::new();
        }
        Read::Unreadable => {
            disable(
                report,
                "mcp_unreadable",
                "7.2.2",
                "mcp.json must be readable UTF-8 of at most 1 MiB.",
            );
            return Vec::new();
        }
        Read::Text(text) => text,
    };
    let Ok(Value::Object(document)) = serde_json::from_str::<Value>(&text) else {
        disable(
            report,
            "mcp_invalid_json",
            "7.2.2",
            "mcp.json must hold one JSON object.",
        );
        return Vec::new();
    };
    let mut disabled = false;
    for key in document.keys() {
        if key != "$schema" && key != "mcpServers" {
            disabled = true;
            disable(
                report,
                "mcp_unknown_field",
                "7.2.1",
                &format!("mcp.json allows only `$schema` and `mcpServers`, not `{key}`."),
            );
        }
    }
    match document.get("$schema") {
        Some(Value::String(schema)) if schema == MCP_SCHEMA => {}
        Some(Value::String(schema)) if declared_version(schema, "mcp.schema.json").is_some() => {
            disabled = true;
            disable(
                report,
                "mcp_version_mismatch",
                "10.1",
                &format!("mcp.json must target the same Agent Plugins version as plugin.json: {MCP_SCHEMA}."),
            );
        }
        _ => {
            disabled = true;
            disable(
                report,
                "mcp_schema_invalid",
                "7.2.1",
                &format!("mcp.json needs `\"$schema\": \"{MCP_SCHEMA}\"`."),
            );
        }
    }
    let Some(Value::Object(entries)) = document.get("mcpServers") else {
        disable(
            report,
            "mcp_servers_invalid",
            "7.2.1",
            "mcp.json needs an `mcpServers` object.",
        );
        return Vec::new();
    };
    if disabled {
        return Vec::new();
    }
    let mut loaded = Vec::new();
    for (name, entry) in entries {
        let path = format!("{PATH}#/mcpServers/{name}");
        if server_valid(root, &path, entry, report) {
            loaded.push(name.clone());
        }
    }
    loaded
}

fn server_valid(root: &Path, path: &str, entry: &Value, report: &mut Report) -> bool {
    let skip = |report: &mut Report, code, section, message: String| {
        report.error(code, path, section, Effect::SkipServer, message);
        false
    };
    let Some(entry) = entry.as_object() else {
        return skip(
            report,
            "mcp_server_invalid",
            "7.2.1",
            "A server entry must be an object.".into(),
        );
    };
    let kind = entry.get("type").and_then(Value::as_str).unwrap_or("");
    let allowed: &[&str] = match kind {
        "stdio" => &["type", "command", "args", "env", "cwd"],
        "streamable-http" | "sse" => &["type", "url", "headers"],
        _ => {
            return skip(
                report,
                "mcp_server_type_invalid",
                "7.2.1",
                "`type` must be `stdio`, `streamable-http` or `sse`.".into(),
            )
        }
    };
    if let Some(key) = entry.keys().find(|key| !allowed.contains(&key.as_str())) {
        return skip(
            report,
            "mcp_server_field_invalid",
            "7.2.1",
            format!("`{key}` is not a field of a `{kind}` server."),
        );
    }
    if kind == "stdio" {
        stdio_valid(root, entry, report, path)
    } else {
        if kind == "sse" {
            report.warning(
                "mcp_sse_deprecated",
                path,
                "7.2.1",
                "`sse` is the deprecated HTTP+SSE transport and optional for clients; prefer `streamable-http`.",
            );
        }
        remote_valid(entry, report, path)
    }
}

fn stdio_valid(root: &Path, entry: &Map<String, Value>, report: &mut Report, path: &str) -> bool {
    let skip = |report: &mut Report, code, message: &str| {
        report.error(code, path, "7.2.1", Effect::SkipServer, message);
        false
    };
    let command = match entry.get("command") {
        Some(Value::String(command)) if !command.is_empty() => command,
        _ => {
            return skip(
                report,
                "mcp_command_missing",
                "A stdio server needs a `command` string.",
            )
        }
    };
    if command.chars().any(char::is_whitespace) {
        return skip(
            report,
            "mcp_command_not_single_token",
            "`command` must be one executable, not a shell command line; put arguments in `args`.",
        );
    }
    if let Some(relative) = command.strip_prefix("./") {
        if !package_path_inside(root, relative) {
            return skip(
                report,
                "mcp_command_outside_root",
                "`command` resolves outside the plugin folder.",
            );
        }
        if !root.join(relative).is_file() {
            return skip(
                report,
                "mcp_command_not_found",
                "`command` names a file the plugin folder does not contain.",
            );
        }
    } else if command.contains(['/', '\\']) {
        return skip(
            report,
            "mcp_command_path_invalid",
            "`command` must be a bare executable name or a path starting with `./`.",
        );
    }
    if let Some(args) = entry.get("args") {
        if !args
            .as_array()
            .is_some_and(|args| args.iter().all(Value::is_string))
        {
            return skip(
                report,
                "mcp_args_invalid",
                "`args` must be a list of strings.",
            );
        }
    }
    if let Some(env) = entry.get("env") {
        let Some(env) = env.as_object() else {
            return skip(
                report,
                "mcp_env_invalid",
                "`env` must be an object of strings.",
            );
        };
        if env.values().any(|value| !value.is_string()) {
            return skip(
                report,
                "mcp_env_invalid",
                "`env` must be an object of strings.",
            );
        }
        if env
            .keys()
            .any(|key| key == "PLUGIN_ROOT" || key == "PLUGIN_DATA")
        {
            report.error(
                "mcp_env_reserved",
                path,
                "9.2",
                Effect::SkipServer,
                "`env` must not set PLUGIN_ROOT or PLUGIN_DATA; the client sets them.",
            );
            return false;
        }
        for (key, value) in env {
            if secret_name(key) && !value.as_str().unwrap_or("").contains("${PLUGIN_") {
                report.warning(
                    "mcp_env_may_hold_secret",
                    path,
                    "9.2",
                    format!("`env.{key}` looks like a credential. Values in env are package data that anyone can read; leave credentials to the client."),
                );
            }
        }
    }
    if let Some(cwd) = entry.get("cwd") {
        let Some(cwd) = cwd.as_str() else {
            return skip(report, "mcp_cwd_invalid", "`cwd` must be a string.");
        };
        let inside = if let Some(relative) = cwd.strip_prefix("./") {
            package_path_inside(root, relative)
        } else if let Some(rest) = placeholder_rest(cwd, "${PLUGIN_ROOT}") {
            package_path_inside(root, rest)
        } else if let Some(rest) = placeholder_rest(cwd, "${PLUGIN_DATA}") {
            lexically_inside(rest)
        } else {
            return skip(
                report,
                "mcp_cwd_invalid",
                "`cwd` must start with `./`, `${PLUGIN_ROOT}` or `${PLUGIN_DATA}`.",
            );
        };
        if !inside {
            return skip(
                report,
                "mcp_cwd_outside_root",
                "`cwd` resolves outside the folder it starts from.",
            );
        }
    }
    true
}

fn remote_valid(entry: &Map<String, Value>, report: &mut Report, path: &str) -> bool {
    let skip = |report: &mut Report, code, message: &str| {
        report.error(code, path, "7.2.1", Effect::SkipServer, message);
        false
    };
    let url = match entry.get("url") {
        Some(Value::String(url)) if !url.is_empty() => url,
        _ => {
            return skip(
                report,
                "mcp_url_missing",
                "A remote server needs a `url` string.",
            )
        }
    };
    if let Some(problem) = url_problem(url) {
        return skip(report, "mcp_url_invalid", problem);
    }
    if let Some(headers) = entry.get("headers") {
        let Some(headers) = headers.as_object() else {
            return skip(
                report,
                "mcp_headers_invalid",
                "`headers` must be an object of strings.",
            );
        };
        let mut seen = BTreeSet::new();
        for (name, value) in headers {
            let Some(value) = value.as_str() else {
                return skip(
                    report,
                    "mcp_headers_invalid",
                    "`headers` must be an object of strings.",
                );
            };
            if !header_name_valid(name) || !header_value_valid(value) {
                return skip(
                    report,
                    "mcp_header_invalid",
                    "Each header needs a valid HTTP field name and a value without control characters.",
                );
            }
            if !seen.insert(name.to_ascii_lowercase()) {
                return skip(
                    report,
                    "mcp_header_duplicate",
                    "The same header name appears twice with different casing.",
                );
            }
            let lower = name.to_ascii_lowercase();
            if matches!(
                lower.as_str(),
                "authorization" | "proxy-authorization" | "cookie"
            ) {
                report.error(
                    "mcp_header_holds_credential",
                    path,
                    "7.2.1",
                    Effect::None,
                    format!("`{name}` carries a credential. Header values are package data anyone can read; the client handles authorization."),
                );
            } else if secret_name(name) {
                report.warning(
                    "mcp_header_may_hold_secret",
                    path,
                    "7.2.1",
                    format!("`{name}` looks like a credential. Header values are package data anyone can read; leave credentials to the client."),
                );
            } else if value.contains("${") {
                report.warning(
                    "mcp_header_placeholder",
                    path,
                    "7.2.1",
                    format!("`{name}` is sent as written: Agent Plugins does not expand variables in headers."),
                );
            }
        }
    }
    true
}

fn header_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

fn header_value_valid(value: &str) -> bool {
    value
        .chars()
        .all(|character| character == '\t' || !character.is_control())
        && value.trim_matches([' ', '\t']).len() == value.len()
}

fn secret_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == "authorization"
        || name == "proxy-authorization"
        || [
            "token", "secret", "password", "api_key", "api-key", "apikey",
        ]
        .iter()
        .any(|marker| name.contains(marker))
}

/// The path after an exact placeholder, or `None` when `value` does not
/// start with it as a whole path segment.
fn placeholder_rest<'a>(value: &'a str, placeholder: &str) -> Option<&'a str> {
    let rest = value.strip_prefix(placeholder)?;
    if rest.is_empty() {
        Some("")
    } else {
        rest.strip_prefix('/')
    }
}
