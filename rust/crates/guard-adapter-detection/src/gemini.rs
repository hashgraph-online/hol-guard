//! `runner_authority` kind `gemini_detect`: the config parsing and artifact
//! discovery of `GeminiHarnessAdapter.detect`. For the home directory and then
//! the workspace this lists the `.gemini/extensions` manifests, the
//! `.gemini/settings.json` MCP servers and hooks, and the `.gemini/skills`
//! documents with their directory identity. Python keeps the command lookup
//! and the workspace AIBOM extension. Every refusal is a stable code and never
//! a partial inventory.

use std::fs;
use std::path::Path;

use serde_json::{Map, Value};

use guard_runtime_pyjson::PyVal;

use crate::artifacts::{Fields, Scope};
use crate::host::{DetectionHost, DetectionRequest, SkillNaming};
use crate::payload::{carried, json_payload, mcp_fields, ERR_NAME};

const HARNESS: &str = "gemini";

/// `sorted(extension_root.glob("*/gemini-extension.json"))`: every child,
/// hidden ones included, that is a directory once links are followed. A child
/// whose name cannot be carried is refused only when its manifest would be
/// listed.
fn extension_names(root: &Path) -> Result<Vec<String>, &'static str> {
    let Ok(entries) = fs::read_dir(root) else {
        return Ok(Vec::new());
    };
    let mut names = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        match entry.file_name().into_string() {
            Ok(name) => names.push(name),
            Err(_) if json_payload(&path.join("gemini-extension.json"))?.truthy() => {
                return Err(ERR_NAME)
            }
            Err(_) => {}
        }
    }
    names.sort();
    Ok(names)
}

/// `_entry_hook_command`: the entry's own command and its nested handlers'
/// commands, one per line.
fn entry_hook_command(entry: &PyVal) -> Option<String> {
    let mut commands: Vec<&str> = Vec::new();
    if let Some(command) = entry.get("command").and_then(PyVal::as_str) {
        commands.push(command);
    }
    for nested in entry
        .get("hooks")
        .and_then(PyVal::as_list)
        .unwrap_or_default()
    {
        if let Some(command) = nested.get("command").and_then(PyVal::as_str) {
            commands.push(command);
        }
    }
    (!commands.is_empty()).then(|| commands.join("\n"))
}

/// The `mcpServers` entries of one payload; `prefix` is the id segment
/// between the scope and the server name.
fn mcp_servers(
    host: &mut dyn DetectionHost,
    scope: &Scope<'_>,
    prefix: &str,
    path: &Path,
    payload: &PyVal,
) {
    let Some(servers) = payload.get("mcpServers").and_then(PyVal::as_dict) else {
        return;
    };
    for (name, config) in servers {
        if config.as_dict().is_none() {
            continue;
        }
        host.record(scope.wire(
            format!("{HARNESS}:{}:{prefix}:{name}", scope.scope),
            name,
            "mcp_server",
            path,
            mcp_fields(config),
            Map::new(),
        ));
    }
}

fn extensions(
    host: &mut dyn DetectionHost,
    scope: &Scope<'_>,
    extension_root: &Path,
) -> Result<(), &'static str> {
    if !host.is_dir(extension_root)? {
        return Ok(());
    }
    for child in extension_names(&host.resolve(extension_root))? {
        let manifest = extension_root.join(&child).join("gemini-extension.json");
        let payload = json_payload(&host.resolve(&manifest))?;
        if !payload.truthy() {
            continue;
        }
        host.mark_found(&manifest);
        let name = payload
            .get("name")
            .and_then(PyVal::as_str)
            .unwrap_or(child.as_str());
        let mut metadata = Map::new();
        let context_file = payload.get("contextFileName");
        metadata.insert(
            "context_file".to_owned(),
            context_file
                .map(carried)
                .transpose()?
                .unwrap_or(Value::Null),
        );
        host.record(scope.wire(
            format!("{HARNESS}:{}:{name}", scope.scope),
            name,
            "extension",
            &manifest,
            Fields {
                publisher: payload.get("publisher").and_then(PyVal::as_str),
                ..Fields::default()
            },
            metadata,
        ));
        mcp_servers(host, scope, name, &manifest, &payload);
    }
    Ok(())
}

fn settings(
    host: &mut dyn DetectionHost,
    scope: &Scope<'_>,
    path: &Path,
) -> Result<(), &'static str> {
    let payload = json_payload(&host.resolve(path))?;
    if !payload.truthy() {
        return Ok(());
    }
    host.mark_found(path);
    mcp_servers(host, scope, "mcp", path, &payload);
    let Some(hooks) = payload.get("hooks").and_then(PyVal::as_dict) else {
        return Ok(());
    };
    for (hook_name, entries) in hooks {
        let Some(entries) = entries.as_list() else {
            continue;
        };
        let event = hook_name.to_lowercase();
        for (index, entry) in entries.iter().enumerate() {
            if entry.as_dict().is_none() {
                continue;
            }
            let command = entry_hook_command(entry);
            let mut metadata = Map::new();
            metadata.insert("hook_config".to_owned(), carried(entry)?);
            host.record(scope.wire(
                format!("{HARNESS}:{}:hook:{event}:{index}", scope.scope),
                hook_name,
                "hook",
                path,
                Fields {
                    command: command.as_deref(),
                    ..Fields::default()
                },
                metadata,
            ));
        }
    }
    Ok(())
}

pub fn detect(
    host: &mut dyn DetectionHost,
    request: &DetectionRequest,
) -> Result<(), &'static str> {
    let mut roots = vec![request.home.clone()];
    roots.extend(request.workspace.clone());
    for root in &roots {
        let gemini = root.join(".gemini");
        let settings_path = gemini.join("settings.json");
        let scope = Scope {
            harness: HARNESS,
            scope: host.scope_of(&settings_path),
        };
        extensions(host, &scope, &gemini.join("extensions"))?;
        settings(host, &scope, &settings_path)?;
        host.discover_skills(
            &scope,
            "Gemini",
            &SkillNaming::Prefixed,
            &gemini.join("skills"),
            root,
        )?;
    }
    Ok(())
}
