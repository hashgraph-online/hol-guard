//! MCP server entries in each runtime's config syntax, the MCP Registry
//! `server.json`, and the Gemini CLI settings that pass variables through.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::agent_plugins;
use crate::check::is_kebab;
use crate::config::Excludes;
use crate::model::{McpServer, Plugin, ROOT_PLACEHOLDERS};
use crate::reference;
use crate::walk;

const MCP_REGISTRY_SCHEMA: &str =
    "https://static.modelcontextprotocol.io/schemas/2025-09-29/server.schema.json";

#[derive(Clone, Copy)]
pub(super) enum Syntax {
    Claude,
    Gemini,
    Cursor,
    Vscode,
    Opencode,
}

fn env_reference(syntax: Syntax, name: &str) -> String {
    match syntax {
        Syntax::Claude => format!("${{{name}}}"),
        Syntax::Gemini => format!("${name}"),
        Syntax::Cursor | Syntax::Vscode => format!("${{env:{name}}}"),
        Syntax::Opencode => format!("{{env:{name}}}"),
    }
}

pub(super) fn servers(plugin: &Plugin, syntax: Syntax) -> Value {
    let mut entries = Map::new();
    for (name, server) in &plugin.mcp_servers {
        if let Some(entry) = server_value(server, syntax) {
            entries.insert(name.clone(), entry);
        }
    }
    Value::Object(entries)
}

fn server_value(server: &McpServer, syntax: Syntax) -> Option<Value> {
    let env: Map<String, Value> = server
        .env
        .iter()
        .map(|(name, source)| (name.clone(), json!(env_reference(syntax, source))))
        .collect();
    let headers: Map<String, Value> = server
        .headers
        .iter()
        .map(|(name, template)| {
            let value = reference::render(template, |variable| env_reference(syntax, variable));
            (name.clone(), json!(value))
        })
        .collect();
    let mut entry = Map::new();
    if server.command.is_some() {
        let (command, args) = rooted_command(server, syntax)?;
        match syntax {
            Syntax::Opencode => {
                let mut command_line = vec![command];
                command_line.extend(args);
                entry.insert("type".into(), json!("local"));
                entry.insert("command".into(), json!(command_line));
                if !env.is_empty() {
                    entry.insert("environment".into(), Value::Object(env));
                }
                return Some(Value::Object(entry));
            }
            Syntax::Vscode => {
                entry.insert("type".into(), json!("stdio"));
            }
            _ => {}
        }
        entry.insert("command".into(), json!(command));
        if !args.is_empty() {
            entry.insert("args".into(), json!(args));
        }
        if !env.is_empty() {
            entry.insert("env".into(), Value::Object(env));
        }
    } else {
        let url = server.url.as_ref()?;
        let sse = server.transport.as_deref() == Some("sse");
        match syntax {
            Syntax::Claude | Syntax::Vscode => {
                entry.insert("type".into(), json!(if sse { "sse" } else { "http" }));
                entry.insert("url".into(), json!(url));
            }
            // Gemini CLI reads `url` as SSE and `httpUrl` as streamable HTTP.
            Syntax::Gemini => {
                entry.insert(if sse { "url" } else { "httpUrl" }.into(), json!(url));
            }
            Syntax::Cursor => {
                entry.insert("url".into(), json!(url));
            }
            Syntax::Opencode => {
                entry.insert("type".into(), json!("remote"));
                entry.insert("url".into(), json!(url));
            }
        }
        if !headers.is_empty() {
            entry.insert("headers".into(), Value::Object(headers));
        }
    }
    Some(Value::Object(entry))
}

/// An MCP Registry `server.json`: the repository's own when it has one, or
/// one generated for a single remote server on GitHub. Anything else would
/// need a package identity the Kit cannot infer, so it is not emitted.
pub(super) fn registry_document(plugin: &Plugin) -> Option<Value> {
    if let Some(document) = &plugin.registry_server {
        // The schema allows a default `value` for each package variable; a
        // package never carries one, so a literal secret cannot ship.
        let mut document = document.clone();
        if let Some(packages) = document.get_mut("packages").and_then(Value::as_array_mut) {
            for package in packages {
                if let Some(variables) = package
                    .get_mut("environmentVariables")
                    .and_then(Value::as_array_mut)
                {
                    for variable in variables.iter_mut().filter_map(Value::as_object_mut) {
                        variable.remove("value");
                    }
                }
            }
        }
        return Some(document);
    }
    let (_, server) = plugin
        .mcp_servers
        .iter()
        .next()
        .filter(|_| plugin.mcp_servers.len() == 1)?;
    let url = server.url.as_ref().filter(|_| server.command.is_none())?;
    let repository = plugin.github_repository()?;
    let name = plugin.name.as_deref().filter(|name| is_kebab(name))?;
    let (owner, _) = repository.split_once('/')?;
    Some(json!({
        "$schema": MCP_REGISTRY_SCHEMA,
        "name": format!("io.github.{owner}/{name}"),
        "description": plugin.description.as_deref()?,
        "version": plugin.version.as_deref()?,
        "repository": {"url": format!("https://github.com/{repository}"), "source": "github"},
        "remotes": [{
            "type": if server.transport.as_deref() == Some("sse") { "sse" } else { "streamable-http" },
            "url": url,
        }],
    }))
}

/// Gemini CLI passes an extension's MCP servers only the variables it
/// declares, so each variable a server references becomes a sensitive
/// setting the user is asked for at install.
pub(super) fn gemini_settings(plugin: &Plugin) -> Vec<Value> {
    let mut variables = BTreeMap::new();
    for (name, server) in &plugin.mcp_servers {
        for variable in server.referenced_variables() {
            variables.entry(variable).or_insert_with(|| name.clone());
        }
    }
    variables
        .into_iter()
        .map(|(variable, server)| {
            json!({
                "name": variable,
                "description": format!("{variable} for the {server} MCP server."),
                "envVar": variable,
                "sensitive": true,
            })
        })
        .collect()
}

/// What an Agent Plugins `mcp.json` could not carry.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct AgentPluginsLoss {
    /// A server left out: its command or URL has no Agent Plugins form.
    pub servers: bool,
    /// Environment variables left out. Agent Plugins has no user-variable
    /// references, and literal values are never carried.
    pub env: bool,
    /// Remote headers left out, for the same reason.
    pub headers: bool,
}

/// Files an Agent Plugins package generates at its root.
pub(super) const AGENT_PLUGINS_GENERATED: [&str; 2] = ["plugin.json", "mcp.json"];

/// The files the kept Agent Plugins servers name, as (source, package path).
/// A server's command and args resolve against the package root, so the
/// files travel at the same paths.
pub(super) fn agent_plugins_bundled(
    root: &Path,
    plugin: &Plugin,
    excludes: &Excludes,
) -> Result<Vec<(PathBuf, String)>, String> {
    let (entries, _) = agent_plugins_servers(plugin);
    let plugin_dir = root.join(&plugin.base);
    let mut bundled = BTreeSet::new();
    for name in entries.keys() {
        bundled.extend(plugin.mcp_servers[name].bundled.iter().cloned());
    }
    let mut found = Vec::new();
    for relative in bundled {
        let path = plugin_dir.join(&relative);
        if !path.is_dir() {
            found.push((path, relative));
            continue;
        }
        let repository_path = if plugin.base.is_empty() {
            relative.clone()
        } else {
            format!("{}/{relative}", plugin.base)
        };
        for file in walk::files(&path, &repository_path, excludes)? {
            found.push((
                path.join(&file),
                format!("{relative}/{}", walk::display(&file)),
            ));
        }
    }
    Ok(found)
}

/// Servers in Agent Plugins `mcp.json` syntax, and what was left out.
pub(super) fn agent_plugins_servers(plugin: &Plugin) -> (Map<String, Value>, AgentPluginsLoss) {
    let mut entries = Map::new();
    let mut loss = AgentPluginsLoss::default();
    for (name, server) in &plugin.mcp_servers {
        let mut entry = Map::new();
        if let Some(command) = &server.command {
            // A server whose files the package cannot carry would not start,
            // and a bundled file may not replace the generated metadata.
            let carried = !server.bundle_missing
                && !server
                    .bundled
                    .iter()
                    .any(|path| AGENT_PLUGINS_GENERATED.contains(&path.as_str()));
            let Some(command) = portable_command(command).filter(|_| carried) else {
                loss.servers = true;
                continue;
            };
            let args: Vec<String> = server.args.iter().map(|arg| portable_arg(arg)).collect();
            // Agent Plugins expands only its own placeholders, so an argument
            // that reads a user variable would arrive as written.
            if args.iter().any(|arg| user_variable(arg)) {
                loss.servers = true;
                continue;
            }
            entry.insert("type".into(), json!("stdio"));
            entry.insert("command".into(), json!(command));
            if !args.is_empty() {
                entry.insert("args".into(), json!(args));
            }
            if let Some(cwd) = &server.cwd {
                entry.insert("cwd".into(), json!(cwd));
            }
        } else {
            let Some(url) = server
                .url
                .as_deref()
                .filter(|url| !user_variable(url) && agent_plugins::url_problem(url).is_none())
            else {
                loss.servers = true;
                continue;
            };
            let sse = server.transport.as_deref() == Some("sse");
            entry.insert(
                "type".into(),
                json!(if sse { "sse" } else { "streamable-http" }),
            );
            entry.insert("url".into(), json!(url));
        }
        loss.env |= !server.env.is_empty();
        loss.headers |= !server.headers.is_empty() || !server.literal_headers.is_empty();
        entries.insert(name.clone(), Value::Object(entry));
    }
    (entries, loss)
}

/// A stdio command as one token: a bare executable name, or a `./` path
/// inside the plugin, translated from a plugin-root placeholder.
fn portable_command(command: &str) -> Option<String> {
    let command = match ROOT_PLACEHOLDERS
        .iter()
        .find_map(|placeholder| command.strip_prefix(placeholder))
    {
        Some(rest) => {
            let rest = rest
                .strip_prefix("${/}")
                .or_else(|| rest.strip_prefix('/'))?;
            format!("./{}", rest.replace("${/}", "/"))
        }
        None => command.to_owned(),
    };
    if command.is_empty()
        || command.chars().any(char::is_whitespace)
        || command.contains(['$', '\\', ':'])
    {
        return None;
    }
    match command.strip_prefix("./") {
        Some(relative) => relative
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
            .then_some(command),
        None => (!command.contains('/')).then_some(command),
    }
}

/// Whether `value` references a variable other than the Agent Plugins
/// placeholders: `${NAME}` or `$NAME`. A `$` before a digit or at the end,
/// as in `price=$5`, is literal.
fn user_variable(value: &str) -> bool {
    let value = value
        .replace("${PLUGIN_ROOT}", "")
        .replace("${PLUGIN_DATA}", "");
    value.match_indices('$').any(|(index, _)| {
        value[index + 1..]
            .chars()
            .next()
            .is_some_and(|next| next == '{' || next == '_' || next.is_ascii_alphabetic())
    })
}

/// A server's command and args with `${PLUGIN_ROOT}`, which only Agent
/// Plugins sources use, written in the runtime's placeholder. `None` when
/// the runtime has no plugin-root placeholder, or the server needs a working
/// folder or `${PLUGIN_DATA}`, which no other runtime config can express.
fn rooted_command(server: &McpServer, syntax: Syntax) -> Option<(String, Vec<String>)> {
    let command = server.command.clone()?;
    let values = || std::iter::once(&command).chain(&server.args);
    if server.cwd.is_some() || values().any(|value| value.contains("${PLUGIN_DATA}")) {
        return None;
    }
    if !values().any(|value| value.contains("${PLUGIN_ROOT}")) {
        return Some((command.clone(), server.args.clone()));
    }
    let root = match syntax {
        Syntax::Claude => "${CLAUDE_PLUGIN_ROOT}",
        Syntax::Gemini => "${extensionPath}",
        Syntax::Cursor | Syntax::Vscode | Syntax::Opencode => return None,
    };
    let render = |value: &String| value.replace("${PLUGIN_ROOT}", root);
    Some((render(&command), server.args.iter().map(render).collect()))
}

/// Whether some complete server has no entry in this syntax. A server with
/// neither a command nor a url is already reported as incomplete.
pub(super) fn servers_left_out(plugin: &Plugin, syntax: Syntax) -> bool {
    plugin
        .mcp_servers
        .values()
        .filter(|server| server.command.is_some() || server.url.is_some())
        .any(|server| server_value(server, syntax).is_none())
}

/// An argument with each plugin-root placeholder written as `${PLUGIN_ROOT}`.
fn portable_arg(arg: &str) -> String {
    let mut arg = arg.replace("${/}", "/");
    for placeholder in ROOT_PLACEHOLDERS {
        arg = arg.replace(placeholder, "${PLUGIN_ROOT}");
    }
    arg
}

#[cfg(test)]
mod tests {
    use super::{env_reference, portable_arg, portable_command, Syntax};

    #[test]
    fn env_references_use_each_runtime_syntax() {
        assert_eq!(env_reference(Syntax::Claude, "API_KEY"), "${API_KEY}");
        assert_eq!(env_reference(Syntax::Gemini, "API_KEY"), "$API_KEY");
        assert_eq!(env_reference(Syntax::Vscode, "API_KEY"), "${env:API_KEY}");
        assert_eq!(env_reference(Syntax::Opencode, "API_KEY"), "{env:API_KEY}");
    }

    #[test]
    fn agent_plugins_commands_are_one_token_inside_the_plugin() {
        assert_eq!(portable_command("node").as_deref(), Some("node"));
        assert_eq!(
            portable_command("${CLAUDE_PLUGIN_ROOT}/bin/server").as_deref(),
            Some("./bin/server")
        );
        assert_eq!(
            portable_command("${extensionPath}${/}dist${/}server.js").as_deref(),
            Some("./dist/server.js")
        );
        assert_eq!(portable_command("./run.sh").as_deref(), Some("./run.sh"));
        for rejected in [
            "/usr/bin/node",
            "bin/server",
            "./../server",
            "${CLAUDE_PLUGIN_ROOT}/../server",
            "npx -y server",
            "${HOME}/server",
            "C:\\server.exe",
        ] {
            assert_eq!(portable_command(rejected), None, "{rejected}");
        }
        assert_eq!(
            portable_arg("${CLAUDE_PLUGIN_ROOT}/dist/index.js"),
            "${PLUGIN_ROOT}/dist/index.js"
        );
        assert_eq!(
            portable_arg("${extensionPath}${/}index.js"),
            "${PLUGIN_ROOT}/index.js"
        );
    }
}
