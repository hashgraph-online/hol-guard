//! MCP server entries from `mcpServers` maps and MCP Registry `server.json`
//! documents. Entries read `command`, `args`, `env`, `headers`, `type` and
//! the remote aliases `url`, `httpUrl` and `serverUrl`, as the host adapter
//! detection does.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::text;
use crate::model::{McpServer, Plugin, ROOT_PLACEHOLDERS};
use crate::reference::{normalize_template, single_reference};
use crate::walk;

/// Adds each server in an `mcpServers` map that is not already known.
/// `gemini` reads a bare `url` as SSE, as Gemini CLI does.
pub(super) fn collect_servers(
    servers: &mut BTreeMap<String, McpServer>,
    raw_env: &mut Vec<(String, String, bool)>,
    value: Option<&Value>,
    gemini: bool,
    agent_plugins: bool,
) {
    let Some(Value::Object(entries)) = value else {
        return;
    };
    for (name, config) in entries {
        let Value::Object(config) = config else {
            continue;
        };
        if let Some(Value::Object(env)) = config.get("env") {
            for (key, value) in env {
                let literal = value.as_str().map(str::trim).is_some_and(|value| {
                    !value.is_empty()
                        && single_reference(value).is_none()
                        && !value.starts_with('<')
                });
                raw_env.push((name.clone(), key.clone(), literal));
            }
        }
        servers.entry(name.clone()).or_insert_with(|| {
            let mut server = server_entry(config, gemini);
            if agent_plugins {
                // Agent Plugins resolves a `./` command against the
                // plugin root; other runtimes need the placeholder.
                if let Some(rest) = server.command.as_deref().and_then(|c| c.strip_prefix("./")) {
                    server.command = Some(format!("${{PLUGIN_ROOT}}/{rest}"));
                }
                server.cwd = config
                    .get("cwd")
                    .and_then(Value::as_str)
                    .filter(|cwd| !cwd.is_empty())
                    .map(str::to_owned);
            }
            server
        });
    }
}

fn server_entry(config: &Map<String, Value>, gemini: bool) -> McpServer {
    let string = |key: &str| {
        config
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    let env = match config.get("env") {
        Some(Value::Object(env)) => env
            .iter()
            .map(|(key, value)| {
                let source = value
                    .as_str()
                    .and_then(single_reference)
                    .unwrap_or_else(|| key.clone());
                (key.clone(), source)
            })
            .collect(),
        _ => BTreeMap::new(),
    };
    let command = string("command");
    let url = string("url")
        .or_else(|| string("httpUrl"))
        .or_else(|| string("serverUrl"));
    let transport = (command.is_none() && url.is_some()).then(|| {
        match string("type").as_deref() {
            Some("sse") => "sse",
            Some(_) => "http",
            None if gemini && string("httpUrl").is_none() => "sse",
            None => "http",
        }
        .to_owned()
    });
    let mut headers = BTreeMap::new();
    let mut literal_headers = Vec::new();
    if let Some(Value::Object(entries)) = config.get("headers") {
        for (name, value) in entries {
            match value.as_str().and_then(normalize_template) {
                Some(template) => {
                    headers.insert(name.clone(), template);
                }
                None => literal_headers.push(name.clone()),
            }
        }
    }
    McpServer {
        command,
        args: match config.get("args") {
            Some(Value::Array(args)) => args
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            _ => Vec::new(),
        },
        url,
        transport,
        env,
        headers,
        literal_headers,
        ..McpServer::default()
    }
}

/// Records, for each server, the paths below `plugin_dir` its command, args
/// and `cwd` name, and whether any of them is missing there. `files` is the
/// repository walk and `base` the plugin folder within it: a file counts only
/// when the walk found it, and a folder only when the walk found a file in
/// it, since packaging copies the walked files and an excluded file or an
/// empty or fully excluded folder would not exist in the package.
pub(super) fn resolve_bundles(
    plugin_dir: &Path,
    base: &str,
    files: &[PathBuf],
    servers: &mut BTreeMap<String, McpServer>,
) {
    let Ok(canonical_root) = plugin_dir.canonicalize() else {
        return;
    };
    let repository_path = |relative: &str| {
        if base.is_empty() {
            relative.to_owned()
        } else {
            format!("{base}/{relative}")
        }
    };
    let carries_files = |relative: &str| {
        let folder = format!("{}/", repository_path(relative));
        files
            .iter()
            .any(|file| walk::display(file).starts_with(&folder))
    };
    let carries_file = |relative: &str| {
        let path = repository_path(relative);
        files.iter().any(|file| walk::display(file) == path)
    };
    for server in servers.values_mut() {
        for relative in root_references(server) {
            // The canonical path must be the written one, so no part of it
            // is a symlink, which the package walk would not follow.
            let resolved = plugin_dir.join(&relative);
            let present = resolved
                .canonicalize()
                .is_ok_and(|resolved| resolved == canonical_root.join(&relative))
                && if resolved.is_dir() {
                    carries_files(&relative)
                } else {
                    carries_file(&relative)
                };
            if present {
                if !server.bundled.contains(&relative) {
                    server.bundled.push(relative);
                }
            } else {
                server.bundle_missing = true;
            }
        }
        server.bundled.sort();
    }
}

/// Paths below the plugin root named by a placeholder at the start of the
/// command or anywhere in an argument, such as `dist/index.js` in
/// `--entry=${CLAUDE_PLUGIN_ROOT}/dist/index.js`, and an Agent Plugins `cwd`
/// inside the plugin. A reference the package cannot carry as one path (the
/// bare root, or a path with `.` or `..` parts) is returned as `..`, so it
/// never resolves inside the root and the server is reported, not shipped
/// without its files.
pub(crate) fn root_references(server: &McpServer) -> Vec<String> {
    let mut found = Vec::new();
    let values = server.command.iter().chain(&server.args);
    for value in values {
        let value = value.replace("${/}", "/");
        for placeholder in ROOT_PLACEHOLDERS {
            let mut rest = value.as_str();
            while let Some(index) = rest.find(placeholder) {
                rest = &rest[index + placeholder.len()..];
                let path = rest.strip_prefix('/').unwrap_or("");
                let end = path
                    .find(|c: char| {
                        c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | ':' | '$')
                    })
                    .unwrap_or(path.len());
                found.push(carried_path(&path[..end]));
            }
        }
    }
    if let Some(cwd) = server.cwd.as_deref().and_then(cwd_reference) {
        found.push(cwd);
    }
    found
}

/// The folder an Agent Plugins `cwd` names inside the plugin: `./work`,
/// `work` or `${PLUGIN_ROOT}/work`. The plugin root itself is always in the
/// package, and an absolute or variable path is not a plugin file, so
/// neither is returned.
fn cwd_reference(cwd: &str) -> Option<String> {
    let cwd = cwd.replace("${/}", "/");
    let rooted = ROOT_PLACEHOLDERS
        .iter()
        .find_map(|placeholder| cwd.strip_prefix(placeholder));
    let path = match rooted {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => rest.trim_start_matches('/'),
        Some(_) => return Some("..".to_owned()),
        None if cwd.starts_with('/') || cwd.contains(['$', ':', '\\']) => return None,
        None => cwd.strip_prefix("./").unwrap_or(&cwd),
    };
    let path = path.trim_end_matches('/');
    (!path.is_empty() && path != ".").then(|| carried_path(path))
}

/// `path` without a trailing slash, or `..` when it is empty or has an
/// empty, `.` or `..` part.
fn carried_path(path: &str) -> String {
    let path = path.trim_end_matches('/');
    if path.is_empty()
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        "..".to_owned()
    } else {
        path.to_owned()
    }
}

/// An MCP Registry `server.json` becomes one server: its first package as a
/// local command, else its first remote.
pub(super) fn registry_server(plugin: &mut Plugin, document: &Value) {
    plugin.registry_server = Some(document.clone());
    let Some(name) = plugin.name.clone().or_else(|| text(document, "name")) else {
        return;
    };
    let package = document
        .get("packages")
        .and_then(Value::as_array)
        .and_then(|packages| packages.first());
    let remote = document
        .get("remotes")
        .and_then(Value::as_array)
        .and_then(|remotes| remotes.first());
    let server = if let Some(package) = package {
        let identifier = text(package, "identifier").unwrap_or_default();
        let version = text(package, "version");
        let (command, args) = match text(package, "registryType").as_deref() {
            Some("npm") => (
                "npx",
                vec![
                    "-y".to_owned(),
                    version.map_or(identifier.clone(), |version| {
                        format!("{identifier}@{version}")
                    }),
                ],
            ),
            Some("pypi") => (
                "uvx",
                vec![version.map_or(identifier.clone(), |version| {
                    format!("{identifier}=={version}")
                })],
            ),
            Some("oci") => (
                "docker",
                vec![
                    "run".to_owned(),
                    "-i".to_owned(),
                    "--rm".to_owned(),
                    identifier.clone(),
                ],
            ),
            _ => return,
        };
        let env = package
            .get("environmentVariables")
            .and_then(Value::as_array)
            .map(|variables| {
                variables
                    .iter()
                    .filter_map(|variable| text(variable, "name"))
                    .map(|name| (name.clone(), name))
                    .collect()
            })
            .unwrap_or_default();
        McpServer {
            command: Some(command.to_owned()),
            args,
            env,
            ..McpServer::default()
        }
    } else if let Some(url) = remote.and_then(|remote| text(remote, "url")) {
        let sse = remote.and_then(|remote| text(remote, "type")).as_deref() == Some("sse");
        McpServer {
            url: Some(url),
            transport: Some(if sse { "sse" } else { "http" }.to_owned()),
            ..McpServer::default()
        }
    } else {
        return;
    };
    plugin.mcp_servers.entry(name).or_insert(server);
}
