//! `runner_authority` kind `devin_detect`: the config parsing and artifact
//! discovery of `DevinHarnessAdapter.detect`. This reads Devin's JSONC config
//! files (`config.json`, `config.local.json`, `hooks.v1.json` and the
//! `mcp_config` files) for hooks and MCP servers, walks the four skill roots,
//! and warns when Guard-managed Claude Code hooks would also run inside Devin.
//! Python keeps the config directory choice, the command lookup and the
//! workspace AIBOM extension. Every refusal is a stable code and never a
//! partial inventory.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::adapter_inventory::{carried, json_payload, Inventory, Request, SkillNaming, ERR_VALUE};
use super::aibom_mcp_metadata::{enrich, McpMetadataInput, ERR_METADATA};
use super::claude_guard_question::python_lower;
use super::context_digest::python_strip;
use super::pyjson::{parse_marking_lone_surrogates, JsonFailure, PyVal, LONE_SURROGATE_MARK};
use super::runner_authority_op::KindResult;
use super::zcode_artifacts::{pair_value, scalar_args, string_pairs, transport, Fields, Scope};

const HARNESS: &str = "devin";
const GLOBAL: Scope<'static> = Scope {
    harness: HARNESS,
    scope: "global",
};
const PROJECT: Scope<'static> = Scope {
    harness: HARNESS,
    scope: "project",
};

const CLAUDE_HOOK_MARKERS: [&str; 4] = [
    "--harness', 'claude-code'",
    "--harness claude-code",
    "HOL_GUARD_CLAUDE_DAEMON_HOOK",
    "HOL_GUARD_CLAUDE_SESSION_START_HOOK",
];
const OVERLAP_WARNING: &str = "Devin also loads Claude Code hooks by default, so Guard's Claude Code \
hooks will run inside Devin sessions and attribute them to Claude Code. Set read_config_from.claude to \
false in Devin's user config if you want Devin events attributed only to the Devin adapter.";

fn under(base: &Path, parts: &[&str]) -> PathBuf {
    parts
        .iter()
        .fold(base.to_path_buf(), |path, part| path.join(part))
}

fn empty() -> PyVal {
    PyVal::Dict(Vec::new())
}

/// The end of the `//` or `/* */` comment that starts at `index`, if one does.
fn comment_end(chars: &[char], index: usize) -> Option<usize> {
    if chars[index] != '/' || index + 1 >= chars.len() {
        return None;
    }
    let mut end = index + 2;
    match chars[index + 1] {
        '/' => {
            while end < chars.len() && !matches!(chars[end], '\r' | '\n') {
                end += 1;
            }
            Some(end)
        }
        '*' => {
            while end + 1 < chars.len() && !(chars[end] == '*' && chars[end + 1] == '/') {
                end += 1;
            }
            Some(end + 2)
        }
        _ => None,
    }
}

/// `_strip_jsonc_syntax`: comments and trailing commas outside strings go.
fn strip_jsonc_syntax(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    let mut in_string = false;
    while index < chars.len() {
        let character = chars[index];
        if in_string {
            output.push(character);
            if character == '\\' && index + 1 < chars.len() {
                output.push(chars[index + 1]);
                index += 2;
                continue;
            }
            in_string = character != '"';
            index += 1;
            continue;
        }
        if character == '"' {
            in_string = true;
            output.push(character);
            index += 1;
            continue;
        }
        if let Some(end) = comment_end(&chars, index) {
            index = end;
            continue;
        }
        if character == ',' {
            let mut lookahead = index + 1;
            while lookahead < chars.len() {
                if matches!(chars[lookahead], ' ' | '\t' | '\r' | '\n') {
                    lookahead += 1;
                } else if let Some(end) = comment_end(&chars, lookahead) {
                    lookahead = end;
                } else {
                    break;
                }
            }
            if lookahead < chars.len() && matches!(chars[lookahead], ']' | '}') {
                index += 1;
                continue;
            }
        }
        output.push(character);
        index += 1;
    }
    output
}

/// One `json.loads` attempt: `Ok(None)` on a syntax error, the object or an
/// unparsed marker otherwise. Integer-limit and depth failures raise in
/// Python, so they are refused.
fn loads(text: &str) -> Result<Option<Option<PyVal>>, &'static str> {
    match parse_marking_lone_surrogates(text) {
        Ok(value @ PyVal::Dict(_)) => Ok(Some(Some(value))),
        Ok(_) => Ok(Some(None)),
        Err(JsonFailure::Syntax) => Ok(None),
        Err(_) => Err(ERR_VALUE),
    }
}

/// `parse_devin_jsonc`: the object a config holds, or `None` when it could
/// not be parsed.
fn parse_jsonc(text: &str) -> Result<Option<PyVal>, &'static str> {
    if python_strip(text).is_empty() {
        return Ok(Some(empty()));
    }
    if let Some(parsed) = loads(text)? {
        return Ok(parsed);
    }
    let stripped = strip_jsonc_syntax(text);
    if python_strip(&stripped).is_empty() {
        return Ok(Some(empty()));
    }
    Ok(loads(&stripped)?.flatten())
}

/// `load_devin_jsonc`: a file that vanished is empty; one that cannot be read
/// or decoded is unparsed.
fn load_jsonc(path: &Path) -> Result<Option<PyVal>, &'static str> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Some(empty())),
        Err(_) => return Ok((!path.exists()).then(empty)),
    };
    match String::from_utf8(bytes) {
        Ok(text) => parse_jsonc(&text),
        Err(_) => Ok(None),
    }
}

/// `_mcp_environment`: stripped string keys with string values. A lone
/// surrogate in a value would only reach the configured-value digest, so it
/// is refused rather than bound to an unbound placeholder.
fn environment(config: &PyVal) -> Result<BTreeMap<String, String>, &'static str> {
    let env = config
        .get("env")
        .filter(|value| value.as_dict().is_some())
        .map(string_pairs)
        .unwrap_or_default();
    if env
        .values()
        .any(|value| value.contains(LONE_SURROGATE_MARK))
    {
        return Err(ERR_VALUE);
    }
    Ok(env)
}

fn file_name(path: &Path) -> &str {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
}

/// `is_guard_managed_hook_command`.
fn guard_managed(command: &str) -> bool {
    let normalized = command.replace("\\\"", "\"");
    command.contains("HOL_GUARD_MANAGED_DEVIN")
        || (command.contains("codex_plugin_scanner.cli")
            && command.contains("'guard', 'hook'")
            && command.contains("--harness', 'devin'"))
        || (command.contains("bounded_cli_hook_bridge")
            && normalized.contains("\"harness\":\"devin\""))
        || (command.contains("__guard-bounded-hook")
            && normalized.contains("\"harness\":\"devin\""))
        || normalized
            .replace('\\', "/")
            .contains("managed/bounded-hooks/devin.py")
}

/// `append_mcp_server_artifacts`.
fn mcp_servers(
    inventory: &mut Inventory,
    scope: &Scope<'_>,
    path: &Path,
    servers: Option<&PyVal>,
) -> Result<(), &'static str> {
    let Some(servers) = servers.and_then(PyVal::as_dict) else {
        return Ok(());
    };
    for (name, config) in servers {
        if config.as_dict().is_none() {
            continue;
        }
        let command = config.get("command").and_then(PyVal::as_str);
        let url = config.get("url").and_then(PyVal::as_str);
        if command.is_none() && url.is_none() {
            continue;
        }
        let args = scalar_args(config);
        let transport = transport(config);
        let env = environment(config)?;
        let env_keys: Vec<String> = env.keys().cloned().collect();
        let enriched = enrich(&McpMetadataInput {
            command: command.map(str::to_owned),
            args: args.clone(),
            url: url.map(str::to_owned),
            transport: Some(transport.clone()),
            env_keys: env_keys.clone(),
            headers_keys: Vec::new(),
            env: pair_value(&env),
            headers: pair_value(&BTreeMap::new()),
            env_values_hash: None,
            header_values_hash: None,
            label: name.clone(),
        })
        .map_err(|_| ERR_METADATA)?;
        let mut metadata = Map::new();
        metadata.insert("name".to_owned(), json!(name));
        metadata.insert("env_keys".to_owned(), json!(env_keys));
        for (key, value) in enriched.as_object().ok_or(ERR_METADATA)? {
            metadata.insert(key.clone(), value.clone());
        }
        inventory.artifacts.push(scope.wire(
            format!("{HARNESS}:{}:mcp:{}:{name}", scope.scope, file_name(path)),
            name,
            "mcp_server",
            path,
            Fields {
                command,
                args,
                url,
                transport: Some(transport.as_str()),
                publisher: None,
            },
            metadata,
        ));
    }
    Ok(())
}

/// `append_devin_hook_artifacts`: every handler with a command Guard does not
/// own; the index counts the handlers listed for each event.
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

/// A config file that exists: its object, or `None` with a warning when it
/// could not be parsed.
fn config(inventory: &mut Inventory, path: &Path) -> Result<Option<PyVal>, &'static str> {
    let on_disk = inventory.fs(path);
    if !on_disk.is_file() {
        return Ok(None);
    }
    inventory.found(path);
    let parsed = load_jsonc(&on_disk)?;
    if parsed.is_none() {
        inventory.warn(format!(
            "Devin config at {} could not be parsed; hooks and MCP servers in it were not inventoried.",
            path.to_string_lossy()
        ));
    }
    Ok(parsed)
}

/// `has_guard_managed_claude_hooks`.
fn guard_managed_claude_hooks(payload: &PyVal) -> bool {
    let Some(hooks) = payload.get("hooks").and_then(PyVal::as_dict) else {
        return false;
    };
    let mut commands = Vec::new();
    for (_, groups) in hooks {
        for group in groups.as_list().unwrap_or_default() {
            if group.as_dict().is_none() {
                continue;
            }
            commands.extend(group.get("command").and_then(PyVal::as_str));
            for handler in group
                .get("hooks")
                .and_then(PyVal::as_list)
                .unwrap_or_default()
            {
                commands.extend(handler.get("command").and_then(PyVal::as_str));
            }
        }
    }
    commands.iter().any(|command| {
        CLAUDE_HOOK_MARKERS
            .iter()
            .any(|marker| command.contains(marker))
    })
}

/// `_claude_hooks_overlap`: Guard-managed Claude Code hooks Devin would also
/// load, unless its user config turns Claude config reading off.
fn claude_hooks_overlap(
    inventory: &Inventory,
    request: &Request,
    user_config: &PyVal,
) -> Result<bool, &'static str> {
    let reads_claude = user_config
        .get("read_config_from")
        .filter(|value| value.as_dict().is_some())
        .and_then(|value| value.get("claude"));
    if matches!(reads_claude, Some(PyVal::Bool(false))) {
        return Ok(false);
    }
    let mut candidates = vec![
        under(&request.home, &[".claude", "settings.json"]),
        under(&request.home, &[".claude", "settings.local.json"]),
        request.home.join(".claude.json"),
    ];
    if let Some(workspace) = &request.workspace {
        candidates.push(under(workspace, &[".claude", "settings.json"]));
        candidates.push(under(workspace, &[".claude", "settings.local.json"]));
    }
    for path in candidates {
        let on_disk = inventory.fs(&path);
        if !on_disk.is_file() {
            continue;
        }
        let payload = json_payload(&on_disk)?;
        if payload.truthy() && guard_managed_claude_hooks(&payload) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `skill_root.relative_to(identity_root).as_posix()`, else the root itself.
fn root_label(skill_root: &Path, identity_root: &Path) -> String {
    let label = skill_root
        .strip_prefix(identity_root)
        .unwrap_or(skill_root)
        .to_string_lossy()
        .into_owned();
    if cfg!(windows) {
        label.replace('\\', "/")
    } else {
        label
    }
}

pub(crate) fn detect(args: &Value) -> KindResult {
    let request = Request::parse(args, HARNESS)?;
    let config_dir = request.path(args, "config_dir")?;
    let mut inventory = Inventory::new(&request);
    let project = request.workspace.as_ref().map(|work| work.join(".devin"));

    let user_config = config_dir.join("config.json");
    let mut user_payload = empty();
    let mut configs = vec![(user_config.clone(), &GLOBAL)];
    if let Some(project) = &project {
        configs.push((project.join("config.json"), &PROJECT));
        configs.push((project.join("config.local.json"), &PROJECT));
    }
    for (path, scope) in configs {
        let Some(payload) = config(&mut inventory, &path)? else {
            continue;
        };
        if path == user_config {
            user_payload = payload.clone();
        }
        if !payload.truthy() {
            continue;
        }
        hooks(&mut inventory, scope, &path, payload.get("hooks"))?;
        // Legacy Devin versions kept mcpServers inside config.json.
        mcp_servers(&mut inventory, scope, &path, payload.get("mcpServers"))?;
    }
    if let Some(project) = &project {
        let path = project.join("hooks.v1.json");
        if let Some(payload) = config(&mut inventory, &path)? {
            // hooks.v1.json is the hooks object itself, not wrapped.
            hooks(&mut inventory, &PROJECT, &path, Some(&payload))?;
        }
    }

    let mut mcp_configs = vec![(config_dir.join("mcp_config.json"), &GLOBAL)];
    if let Some(project) = &project {
        mcp_configs.push((project.join("mcp_config.json"), &PROJECT));
        mcp_configs.push((project.join("mcp_config.local.json"), &PROJECT));
    }
    for (path, scope) in mcp_configs {
        if let Some(payload) = config(&mut inventory, &path)? {
            mcp_servers(&mut inventory, scope, &path, payload.get("mcpServers"))?;
        }
    }

    let config_parent = config_dir.parent().unwrap_or(&config_dir).to_path_buf();
    let mut skill_roots = vec![
        (config_dir.join("skills"), config_parent, &GLOBAL),
        (
            under(&request.home, &[".agents", "skills"]),
            request.home.clone(),
            &GLOBAL,
        ),
    ];
    if let (Some(workspace), Some(project)) = (&request.workspace, &project) {
        skill_roots.push((project.join("skills"), workspace.clone(), &PROJECT));
        skill_roots.push((
            under(workspace, &[".agents", "skills"]),
            workspace.clone(),
            &PROJECT,
        ));
    }
    for (skill_root, identity_root, scope) in skill_roots {
        let label = root_label(&skill_root, &identity_root);
        inventory.skills(
            scope,
            "Devin",
            &SkillNaming::Bare { root_label: &label },
            &skill_root,
            &identity_root,
            "skills",
        )?;
    }

    if claude_hooks_overlap(&inventory, &request, &user_payload)? {
        inventory.warn(OVERLAP_WARNING.to_owned());
    }
    inventory.finish()
}
