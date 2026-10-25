//! MCP server entries in each runtime's config syntax, the MCP Registry
//! `server.json`, and the Gemini CLI settings that pass variables through.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::check::is_kebab;
use crate::model::{McpServer, Plugin};
use crate::reference;

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
    if let Some(command) = &server.command {
        match syntax {
            Syntax::Opencode => {
                let mut command_line = vec![command.clone()];
                command_line.extend(server.args.iter().cloned());
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
        if !server.args.is_empty() {
            entry.insert("args".into(), json!(server.args));
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

#[cfg(test)]
mod tests {
    use super::{env_reference, Syntax};

    #[test]
    fn env_references_use_each_runtime_syntax() {
        assert_eq!(env_reference(Syntax::Claude, "API_KEY"), "${API_KEY}");
        assert_eq!(env_reference(Syntax::Gemini, "API_KEY"), "$API_KEY");
        assert_eq!(env_reference(Syntax::Vscode, "API_KEY"), "${env:API_KEY}");
        assert_eq!(env_reference(Syntax::Opencode, "API_KEY"), "{env:API_KEY}");
    }
}
