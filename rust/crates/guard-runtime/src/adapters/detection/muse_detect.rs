//! `runner_authority` kind `muse_detect`: the config parsing and artifact
//! discovery of `MuseHarnessAdapter.detect`. For the Muse config directory
//! (which Python resolves from `XDG_CONFIG_HOME` and sends as `config_dir`)
//! and the workspace this lists the `settings.json` hook entries and
//! `mcpServers`, the project `.muse-plugin/plugin.json` hook and MCP
//! capabilities, and the skill roots Muse loads. Python keeps the config
//! directory choice, the command lookup and the workspace AIBOM extension.
//! Every refusal is a stable code and never a partial inventory.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::adapter_inventory::{carried, json_document, Inventory, Request, SkillNaming};
use super::claude_guard_question::python_lower;
use super::context_digest::python_strip;
use super::pyjson::PyVal;
use super::runner_authority_op::KindResult;
use super::zcode_artifacts::{Fields, Scope};

const HARNESS: &str = "muse";
const GLOBAL: Scope<'static> = Scope {
    harness: HARNESS,
    scope: "global",
};
const PROJECT: Scope<'static> = Scope {
    harness: HARNESS,
    scope: "project",
};

fn under(base: &Path, parts: &[&str]) -> PathBuf {
    parts
        .iter()
        .fold(base.to_path_buf(), |path, part| path.join(part))
}

/// `is_guard_managed_hook_command` for Muse.
fn guard_managed(command: &str) -> bool {
    let normalized = command.replace("\\\"", "\"");
    command.contains("HOL_GUARD_MANAGED_MUSE")
        || (command.contains("codex_plugin_scanner.cli")
            && command.contains("'guard', 'hook'")
            && command.contains("--harness', 'muse'"))
        || (command.contains("bounded_cli_hook_bridge")
            && normalized.contains("\"harness\":\"muse\""))
        || (command.contains("__guard-bounded-hook") && normalized.contains("\"harness\":\"muse\""))
        || normalized
            .replace('\\', "/")
            .contains("managed/bounded-hooks/muse.py")
}

fn file_name(path: &Path) -> &str {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
}

/// The `hooks` groups of one Claude-Code-shaped settings payload: every
/// handler with a command Guard does not own.
fn hooks(
    inventory: &mut Inventory,
    scope: &Scope<'_>,
    path: &Path,
    hooks: Option<&PyVal>,
) -> Result<(), &'static str> {
    let Some(hooks) = hooks.and_then(PyVal::as_dict) else {
        return Ok(());
    };
    for (event, groups) in hooks {
        let Some(groups) = groups.as_list() else {
            continue;
        };
        let lowered = python_lower(event);
        let mut index = 0;
        for group in groups.iter().filter(|group| group.as_dict().is_some()) {
            let matcher = group
                .get("matcher")
                .and_then(PyVal::as_str)
                .filter(|matcher| !matcher.is_empty());
            let Some(handlers) = group.get("hooks").and_then(PyVal::as_list) else {
                continue;
            };
            for handler in handlers {
                let Some(command) = handler.get("command").and_then(PyVal::as_str) else {
                    continue;
                };
                if python_strip(command).is_empty() || guard_managed(command) {
                    continue;
                }
                let mut metadata = Map::new();
                metadata.insert("event".to_owned(), json!(event));
                if let Some(matcher) = matcher {
                    metadata.insert("matcher".to_owned(), json!(matcher));
                }
                if let Some(timeout) = handler
                    .get("timeout")
                    .filter(|timeout| matches!(timeout, PyVal::Int(_) | PyVal::Float(_)))
                {
                    metadata.insert("timeout".to_owned(), carried(timeout)?);
                }
                if let Some(kind) = handler
                    .get("type")
                    .and_then(PyVal::as_str)
                    .filter(|kind| !kind.is_empty())
                {
                    metadata.insert("type".to_owned(), json!(kind));
                }
                let name =
                    matcher.map_or_else(|| event.clone(), |matcher| format!("{event}:{matcher}"));
                inventory.artifacts.push(scope.wire(
                    format!(
                        "{HARNESS}:{}:hook:{}:{lowered}:{index}",
                        scope.scope,
                        file_name(path)
                    ),
                    &name,
                    "hook",
                    path,
                    Fields {
                        command: Some(command),
                        ..Fields::default()
                    },
                    metadata,
                ));
                index += 1;
            }
        }
    }
    Ok(())
}

/// One `mcpServers` entry. Muse stdio servers name an argv `command`
/// list; HTTP servers name a `url`. A string `command` is one program.
fn mcp_server(
    inventory: &mut Inventory,
    scope: &Scope<'_>,
    path: &Path,
    name: &str,
    config: &PyVal,
) {
    if config.as_dict().is_none() {
        return;
    }
    let url = config.get("url").and_then(PyVal::as_str);
    let (command, mut args): (Option<String>, Vec<String>) = match config.get("command") {
        Some(PyVal::Str(program)) => (Some(program.clone()), Vec::new()),
        Some(PyVal::List(items)) => {
            let argv: Vec<String> = items
                .iter()
                .filter_map(PyVal::as_str)
                .map(str::to_owned)
                .collect();
            let mut argv = argv.into_iter();
            (argv.next(), argv.collect())
        }
        _ => (None, Vec::new()),
    };
    if let Some(extra) = config.get("args").and_then(PyVal::as_list) {
        args.extend(extra.iter().filter_map(PyVal::as_str).map(str::to_owned));
    }
    if command.is_none() && url.is_none() {
        return;
    }
    inventory.artifacts.push(scope.wire(
        format!("{HARNESS}:{}:mcp:{}:{name}", scope.scope, file_name(path)),
        name,
        "mcp_server",
        path,
        Fields {
            command: command.as_deref(),
            args,
            url,
            transport: Some(if url.is_some() { "http" } else { "stdio" }),
            publisher: None,
        },
        Map::new(),
    ));
}

fn mcp_servers(inventory: &mut Inventory, scope: &Scope<'_>, path: &Path, servers: Option<&PyVal>) {
    let Some(servers) = servers.and_then(PyVal::as_dict) else {
        return;
    };
    for (name, config) in servers {
        mcp_server(inventory, scope, path, name, config);
    }
}

/// Hook and MCP capabilities of one `.muse-plugin/plugin.json` manifest.
fn plugin_manifest(
    inventory: &mut Inventory,
    scope: &Scope<'_>,
    path: &Path,
    payload: &PyVal,
) -> Result<(), &'static str> {
    let Some(capabilities) = payload.get("capabilities").and_then(PyVal::as_dict) else {
        return Ok(());
    };
    if let Some(entries) = capabilities
        .iter()
        .find(|(name, _)| name == "hooks")
        .and_then(|(_, value)| value.as_list())
    {
        for (index, entry) in entries.iter().enumerate() {
            if entry.as_dict().is_none() {
                continue;
            }
            let event = entry.get("event").and_then(PyVal::as_str).unwrap_or("");
            let argv: Vec<String> = entry
                .get("command")
                .and_then(PyVal::as_list)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(PyVal::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            if event.is_empty() || argv.is_empty() {
                continue;
            }
            let id = entry
                .get("id")
                .and_then(PyVal::as_str)
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| format!("hook-{index}"));
            let mut metadata = Map::new();
            metadata.insert("event".to_owned(), json!(event));
            metadata.insert("plugin_hook_id".to_owned(), json!(id));
            inventory.artifacts.push(scope.wire(
                format!("{HARNESS}:{}:hook:plugin:{id}", scope.scope),
                event,
                "hook",
                path,
                Fields {
                    command: Some(argv[0].as_str()),
                    args: argv[1..].to_vec(),
                    ..Fields::default()
                },
                metadata,
            ));
        }
    }
    if let Some(entries) = capabilities
        .iter()
        .find(|(name, _)| name == "mcpServers")
        .and_then(|(_, value)| value.as_list())
    {
        for entry in entries {
            if entry.as_dict().is_none() {
                continue;
            }
            let Some(id) = entry.get("id").and_then(PyVal::as_str) else {
                continue;
            };
            mcp_server(inventory, scope, path, id, entry);
        }
    }
    Ok(())
}

/// A settings or manifest file that exists: its object, or `None` with a
/// warning when it could not be parsed as a JSON object.
fn config(
    inventory: &mut Inventory,
    path: &Path,
    label: &str,
) -> Result<Option<PyVal>, &'static str> {
    let on_disk = inventory.fs(path);
    if !on_disk.is_file() {
        return Ok(None);
    }
    inventory.found(path);
    let parsed = json_document(&on_disk)?;
    match &parsed {
        Some(PyVal::Dict(_)) => Ok(parsed),
        _ => {
            inventory.warn(format!(
                "Muse {label} at {} could not be parsed; hooks and MCP servers in it were not inventoried.",
                path.to_string_lossy()
            ));
            Ok(None)
        }
    }
}

pub(crate) fn detect(args: &Value) -> KindResult {
    let request = Request::parse(args, HARNESS)?;
    let config_dir = request.path(args, "config_dir")?;
    let mut inventory = Inventory::new(&request);

    let settings_path = config_dir.join("settings.json");
    if let Some(payload) = config(&mut inventory, &settings_path, "settings")? {
        hooks(
            &mut inventory,
            &GLOBAL,
            &settings_path,
            payload.get("hooks"),
        )?;
        mcp_servers(
            &mut inventory,
            &GLOBAL,
            &settings_path,
            payload.get("mcpServers"),
        );
    }

    let mut skill_roots: Vec<(PathBuf, PathBuf, &Scope<'_>)> = vec![
        (
            config_dir.join("skills"),
            config_dir.parent().unwrap_or(&config_dir).to_path_buf(),
            &GLOBAL,
        ),
        (
            under(&request.home, &[".agents", "skills"]),
            request.home.clone(),
            &GLOBAL,
        ),
        (
            under(&request.home, &[".claude", "skills"]),
            request.home.clone(),
            &GLOBAL,
        ),
    ];
    if let Some(workspace) = &request.workspace {
        let project_settings = under(workspace, &[".muse", "settings.json"]);
        if let Some(payload) = config(&mut inventory, &project_settings, "project settings")? {
            hooks(
                &mut inventory,
                &PROJECT,
                &project_settings,
                payload.get("hooks"),
            )?;
            mcp_servers(
                &mut inventory,
                &PROJECT,
                &project_settings,
                payload.get("mcpServers"),
            );
        }
        let manifest_path = under(workspace, &[".muse-plugin", "plugin.json"]);
        if let Some(payload) = config(&mut inventory, &manifest_path, "plugin manifest")? {
            plugin_manifest(&mut inventory, &PROJECT, &manifest_path, &payload)?;
        }
        // The workspace `.agents/skills` root belongs to shared discovery, which
        // already walks it for Muse; walking it again here would publish the same
        // skill under a second artifact id.
        skill_roots.push((
            under(workspace, &[".muse", "skills"]),
            workspace.clone(),
            &PROJECT,
        ));
    }
    for (skill_root, identity_root, scope) in skill_roots {
        inventory.skills(
            scope,
            "Muse",
            &SkillNaming::Bare {
                root_label: &skill_root.to_string_lossy(),
            },
            &skill_root,
            &identity_root,
        )?;
    }
    inventory.finish()
}
