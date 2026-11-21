//! `runner_authority` kind `grok_detect`: the config parsing and artifact
//! discovery of `GrokHarnessAdapter.detect`. Under the Grok home (which Python
//! resolves from `GROK_HOME` and sends as `grok_home`) this reads the three
//! `.grok` TOML configs (permission lists, MCP servers, degraded-mode
//! markers), the `hooks/*.json` files there and in the workspace, the plugin
//! marketplace list and the known surfaces, then the `~/.agents` roots and the
//! workspace instruction files. Python keeps the executable resolution, the
//! version probe, the stale-entry check, the workspace AIBOM extension and the
//! readability check of the system policy files, which it sends as
//! `system_policy_paths`. Every refusal is a stable code and never a partial
//! inventory.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::adapter_inventory::{
    carried, json_payload, required_path, Inventory, Request, ERR_NAME, ERR_VALUE,
};
use super::aibom_mcp_metadata::{enrich, McpMetadataInput, ERR_METADATA};
use super::aibom_paths::py_path;
use super::codex_sources::{is_empty, toml_payload};
use super::codex_value::HookVal;
use super::context_digest::python_strip;
use super::pyjson::{float_repr, PyVal};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use super::zcode_artifacts::{pair_value, Fields, Scope};

const HARNESS: &str = "grok";
const GROK_DIR: &str = ".grok";
const CONFIG_FILES: [&str; 3] = ["config.toml", "managed_config.toml", "requirements.toml"];
const SURFACES: [&str; 10] = [
    "skills",
    "plugins",
    "plugins/marketplaces",
    "plugins/known_marketplaces.json",
    "sessions",
    "agents",
    "personas",
    "workflows",
    "sandbox.toml",
    "trusted_folders.toml",
];
const PROJECT_SURFACES: [&str; 7] = [
    "skills",
    "plugins",
    "hooks",
    "agents",
    "personas",
    "workflows",
    "sandbox.toml",
];
const DEGRADED_MODE_MARKERS: [&str; 7] = [
    "always-approve",
    "bypasspermissions",
    "bypass_permissions",
    "defaultmode = \"bypasspermissions\"",
    "defaultMode\": \"bypassPermissions\"",
    "sandbox = \"off\"",
    "sandbox=\"off\"",
];

/// The system policy files Python found readable, as absolute paths.
fn system_policy_paths(args: &Value) -> Result<Vec<PathBuf>, &'static str> {
    let Some(Value::Array(items)) = args_object(args)?.get("system_policy_paths") else {
        return Err(ERR_INVALID);
    };
    items
        .iter()
        .map(|item| match item.as_str() {
            Some(path) if !path.contains('\0') && Path::new(path).is_absolute() => {
                Ok(py_path(path))
            }
            _ => Err(ERR_INVALID),
        })
        .collect()
}

fn file_name(path: &Path) -> &str {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
}

/// `json.dumps` string escaping with `ensure_ascii`.
fn write_ascii_string(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(character),
            _ => {
                let mut units = [0u16; 2];
                for unit in character.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
}

/// `json.dumps(payload, sort_keys=True)`; a date or time is the `TypeError`
/// Python raises.
fn write_dumps(value: &HookVal, out: &mut String) -> Result<(), &'static str> {
    match value {
        HookVal::Null => out.push_str("null"),
        HookVal::Bool(true) => out.push_str("true"),
        HookVal::Bool(false) => out.push_str("false"),
        HookVal::Int(digits) => out.push_str(digits),
        HookVal::Float(number) if number.is_nan() => out.push_str("NaN"),
        HookVal::Float(number) if number.is_infinite() => out.push_str(if *number > 0.0 {
            "Infinity"
        } else {
            "-Infinity"
        }),
        HookVal::Float(number) => out.push_str(&float_repr(*number)),
        HookVal::Str(text) => write_ascii_string(text, out),
        HookVal::List(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_dumps(item, out)?;
            }
            out.push(']');
        }
        HookVal::Dict(entries) => {
            let mut sorted: Vec<&(String, HookVal)> = entries.iter().collect();
            sorted.sort_by(|left, right| left.0.cmp(&right.0));
            out.push('{');
            for (index, (key, item)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_ascii_string(key, out);
                out.push_str(": ");
                write_dumps(item, out)?;
            }
            out.push('}');
        }
        HookVal::Temporal(..) => return Err(ERR_VALUE),
    }
    Ok(())
}

fn degraded_message(name: &str, signal: &str) -> String {
    format!(
        "Degraded Grok protection signal in {name}: {signal}. Guard hooks still run, but Grok may auto-approve some actions."
    )
}

/// `degraded_mode_warnings`: `text` is the file the payload was parsed from.
fn degraded_mode_warnings(
    inventory: &mut Inventory,
    name: &str,
    payload: &HookVal,
    text: &str,
) -> Result<(), &'static str> {
    let mut serialized = String::new();
    write_dumps(payload, &mut serialized)?;
    let serialized = serialized.to_ascii_lowercase();
    let raw_text = text.to_lowercase();
    for marker in DEGRADED_MODE_MARKERS {
        let lowered = marker.to_lowercase();
        if serialized.contains(&lowered) || raw_text.contains(&lowered) {
            inventory.warn(degraded_message(name, marker));
        }
    }
    if let Some(sandbox) = payload.get("sandbox").and_then(HookVal::as_str) {
        if python_strip(sandbox).to_lowercase() == "off" {
            inventory.warn(degraded_message(name, "sandbox off"));
        }
    }
    Ok(())
}

/// `append_permission_artifacts`.
fn permissions(inventory: &mut Inventory, scope: &Scope<'_>, path: &Path, payload: &HookVal) {
    let Some(permission) = payload
        .get("permission")
        .filter(|value| value.as_dict().is_some())
    else {
        return;
    };
    for key in ["allow", "deny", "ask", "rules"] {
        let Some(entries) = permission.get(key).and_then(HookVal::as_list) else {
            continue;
        };
        if entries.is_empty() {
            continue;
        }
        let mut metadata = Map::new();
        metadata.insert("entries".to_owned(), json!(entries.len()));
        inventory.artifacts.push(scope.wire(
            format!("{HARNESS}:{}:permission:{key}", scope.scope),
            &format!("permission:{key}"),
            "policy",
            path,
            Fields::default(),
            metadata,
        ));
    }
}

/// `str(item)` for a TOML value; a list, table, date or time is refused
/// (a date or time already fails `json.dumps` in the same detection).
fn python_str(value: &HookVal) -> Result<String, &'static str> {
    match value {
        HookVal::Null => Ok("None".to_owned()),
        HookVal::Bool(true) => Ok("True".to_owned()),
        HookVal::Bool(false) => Ok("False".to_owned()),
        HookVal::Int(digits) => Ok(digits.clone()),
        HookVal::Float(number) => Ok(float_repr(*number)),
        HookVal::Str(text) => Ok(text.clone()),
        _ => Err(ERR_VALUE),
    }
}

/// Stripped, non-empty string keys with string values; a later key wins.
fn string_pairs(pairs: &mut BTreeMap<String, String>, value: Option<&HookVal>) {
    for (key, item) in value.and_then(HookVal::as_dict).unwrap_or_default() {
        let key = python_strip(key);
        if let (false, Some(text)) = (key.is_empty(), item.as_str()) {
            pairs.insert(key.to_owned(), text.to_owned());
        }
    }
}

/// The `mcp_servers` table, updated by top-level `"mcp_servers.<name>"`
/// tables; an updated name keeps its first position.
fn server_entries(payload: &HookVal) -> Vec<(&str, &HookVal)> {
    let mut servers: Vec<(&str, &HookVal)> = Vec::new();
    let nested = payload
        .get("mcp_servers")
        .and_then(HookVal::as_dict)
        .unwrap_or_default();
    let dotted = payload
        .as_dict()
        .unwrap_or_default()
        .iter()
        .filter(|(_, value)| value.as_dict().is_some())
        .filter_map(|(key, value)| Some((key.strip_prefix("mcp_servers.")?, value)));
    for (name, value) in nested
        .iter()
        .map(|(key, value)| (key.as_str(), value))
        .chain(dotted)
    {
        match servers.iter_mut().find(|(known, _)| *known == name) {
            Some(slot) => slot.1 = value,
            None => servers.push((name, value)),
        }
    }
    servers
}

/// `append_mcp_artifacts`.
fn mcp_servers(
    inventory: &mut Inventory,
    scope: &Scope<'_>,
    path: &Path,
    payload: &HookVal,
) -> Result<(), &'static str> {
    for (name, config) in server_entries(payload) {
        if config.as_dict().is_none() {
            continue;
        }
        let command = config.get("command").and_then(HookVal::as_str);
        let url = config.get("url").and_then(HookVal::as_str);
        if command.is_none() && url.is_none() {
            continue;
        }
        let args: Vec<String> = match config.get("args").and_then(HookVal::as_list) {
            Some(items) => items.iter().map(python_str).collect::<Result<_, _>>()?,
            None => Vec::new(),
        };
        let transport = if url.is_some() { "http" } else { "stdio" };
        let mut environment = BTreeMap::new();
        string_pairs(&mut environment, config.get("environment"));
        string_pairs(&mut environment, config.get("env"));
        let mut headers = BTreeMap::new();
        string_pairs(&mut headers, config.get("headers"));
        let env_keys: Vec<String> = environment.keys().cloned().collect();
        let headers_keys: Vec<String> = headers.keys().cloned().collect();
        let enriched = enrich(&McpMetadataInput {
            command: command.map(str::to_owned),
            args: args.clone(),
            url: url.map(str::to_owned),
            transport: Some(transport.to_owned()),
            env_keys: env_keys.clone(),
            headers_keys: headers_keys.clone(),
            env: pair_value(&environment),
            headers: pair_value(&headers),
            env_values_hash: None,
            header_values_hash: None,
            label: name.to_owned(),
        })
        .map_err(|_| ERR_METADATA)?;
        let mut metadata = Map::new();
        metadata.insert("name".to_owned(), json!(name));
        metadata.insert("env_keys".to_owned(), json!(env_keys));
        metadata.insert("headers_keys".to_owned(), json!(headers_keys));
        for (key, value) in enriched.as_object().ok_or(ERR_METADATA)? {
            metadata.insert(key.clone(), value.clone());
        }
        inventory.artifacts.push(scope.wire(
            format!("{HARNESS}:{}:mcp:{name}", scope.scope),
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
    Ok(())
}

/// One of the three `.grok` TOML configs.
fn config_file(inventory: &mut Inventory, path: &Path) -> Result<(), &'static str> {
    if !inventory.is_file(path)? {
        return Ok(());
    }
    inventory.found(path);
    let bytes = fs::read(inventory.fs(path)).ok();
    let payload = toml_payload(bytes.as_deref())?;
    if is_empty(&payload) {
        return Ok(());
    }
    let scope = Scope {
        harness: HARNESS,
        scope: "global",
    };
    permissions(inventory, &scope, path, &payload);
    mcp_servers(inventory, &scope, path, &payload)?;
    // A non-empty payload was parsed from these bytes, so they are UTF-8.
    let text = bytes
        .as_deref()
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .unwrap_or("");
    degraded_mode_warnings(inventory, file_name(path), &payload, text)
}

/// `sorted(hooks_dir.glob("*.json"))` (case-sensitive, hidden names and
/// directories included): a name that cannot be carried is refused only when
/// its file would be listed.
fn hook_file_names(inventory: &Inventory, hooks_dir: &Path) -> Result<Vec<String>, &'static str> {
    let Ok(entries) = fs::read_dir(inventory.fs(hooks_dir)) else {
        return Ok(Vec::new());
    };
    let mut names = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        match entry.file_name().into_string() {
            Ok(name) if name.ends_with(".json") => names.push(name),
            Ok(_) => {}
            Err(raw) if raw.to_string_lossy().ends_with(".json") => {
                if json_payload(&entry.path())?.truthy() {
                    return Err(ERR_NAME);
                }
            }
            Err(_) => {}
        }
    }
    names.sort();
    Ok(names)
}

/// `append_hooks_dir_artifacts`.
fn hooks_dir(inventory: &mut Inventory, dir: &Path, scope: &str) -> Result<(), &'static str> {
    if !inventory.is_dir(dir)? {
        return Ok(());
    }
    let scope = Scope {
        harness: HARNESS,
        scope,
    };
    for name in hook_file_names(inventory, dir)? {
        let hook_file = dir.join(&name);
        let payload = json_payload(&inventory.fs(&hook_file))?;
        if !payload.truthy() {
            continue;
        }
        inventory.found(&hook_file);
        let Some(hooks) = payload.get("hooks").and_then(PyVal::as_dict) else {
            continue;
        };
        for (event, entries) in hooks {
            let Some(entries) = entries.as_list() else {
                continue;
            };
            let lowered = event.to_lowercase();
            for (index, entry) in entries.iter().enumerate() {
                if entry.as_dict().is_none() {
                    continue;
                }
                let Some(nested) = entry.get("hooks").and_then(PyVal::as_list) else {
                    continue;
                };
                let matcher = entry.get("matcher");
                let label = match matcher.and_then(PyVal::as_str) {
                    Some(matcher) => format!("{event}:{matcher}"),
                    None => event.clone(),
                };
                for (nested_index, hook_entry) in nested.iter().enumerate() {
                    if hook_entry.as_dict().is_none() {
                        continue;
                    }
                    let Some(command) = hook_entry.get("command").and_then(PyVal::as_str) else {
                        continue;
                    };
                    if python_strip(command).is_empty() {
                        continue;
                    }
                    let mut metadata = Map::new();
                    metadata.insert("event".to_owned(), json!(event));
                    metadata.insert(
                        "matcher".to_owned(),
                        matcher.map(carried).transpose()?.unwrap_or(Value::Null),
                    );
                    inventory.artifacts.push(scope.wire(
                        format!(
                            "{HARNESS}:{}:hook:{lowered}:{index}:{nested_index}",
                            scope.scope
                        ),
                        &label,
                        "hook",
                        &hook_file,
                        Fields {
                            command: Some(command),
                            ..Fields::default()
                        },
                        metadata,
                    ));
                }
            }
        }
    }
    Ok(())
}

/// `plugins/known_marketplaces.json`.
fn marketplaces(inventory: &mut Inventory, grok_root: &Path) -> Result<(), &'static str> {
    let path = grok_root.join("plugins").join("known_marketplaces.json");
    if !inventory.is_file(&path)? {
        return Ok(());
    }
    inventory.found(&path);
    let payload = json_payload(&inventory.fs(&path))?;
    if !payload.truthy() {
        return Ok(());
    }
    let mut metadata = Map::new();
    metadata.insert(
        "entries".to_owned(),
        json!(payload.as_dict().map_or(0, <[_]>::len)),
    );
    let scope = Scope {
        harness: HARNESS,
        scope: "global",
    };
    inventory.artifacts.push(scope.wire(
        format!("{HARNESS}:global:marketplace-metadata"),
        "known_marketplaces",
        "marketplace",
        &path,
        Fields::default(),
        metadata,
    ));
    Ok(())
}

fn found_if_exists(inventory: &mut Inventory, path: &Path) -> Result<(), &'static str> {
    if inventory.exists(path)? {
        inventory.found(path);
    }
    Ok(())
}

pub(crate) fn detect(args: &Value) -> KindResult {
    let request = Request::parse(args, HARNESS)?;
    let grok_home = required_path(args, "grok_home")?;
    let system_paths = system_policy_paths(args)?;
    let mut inventory = Inventory::new(&request);
    if !grok_home.is_absolute() && !inventory.has_cwd() {
        return Err(ERR_INVALID);
    }
    let grok_root = grok_home.join(GROK_DIR);
    for file in CONFIG_FILES {
        config_file(&mut inventory, &grok_root.join(file))?;
    }
    for path in &system_paths {
        inventory.found(path);
        inventory.warn(format!(
            "Enterprise Grok policy detected at {}.",
            file_name(path)
        ));
    }
    hooks_dir(&mut inventory, &grok_root.join("hooks"), "global")?;
    let project_root = request.workspace.as_ref().map(|path| path.join(GROK_DIR));
    if let Some(project_root) = &project_root {
        let config = project_root.join("config.toml");
        if inventory.is_file(&config)? {
            inventory.found(&config);
        }
        hooks_dir(&mut inventory, &project_root.join("hooks"), "project")?;
    }
    let hooks_paths = grok_root.join("hooks-paths");
    if inventory.is_file(&hooks_paths)? {
        inventory.found(&hooks_paths);
    }
    marketplaces(&mut inventory, &grok_root)?;
    for relative in SURFACES {
        found_if_exists(&mut inventory, &grok_root.join(relative))?;
    }
    if let Some(project_root) = &project_root {
        for relative in PROJECT_SURFACES {
            found_if_exists(&mut inventory, &project_root.join(relative))?;
        }
    }
    let agents = request.home.join(".agents");
    for child in ["skills", "commands"] {
        found_if_exists(&mut inventory, &agents.join(child))?;
    }
    if let Some(workspace) = &request.workspace {
        for name in ["AGENTS.md", "CLAUDE.md"] {
            let path = workspace.join(name);
            if !inventory.is_file(&path)? {
                continue;
            }
            inventory.found(&path);
            let scope = Scope {
                harness: HARNESS,
                scope: "project",
            };
            inventory.artifacts.push(scope.wire(
                format!("{HARNESS}:project:instruction:{}", name.to_lowercase()),
                name,
                "instruction_surface",
                &path,
                Fields::default(),
                Map::new(),
            ));
        }
    }
    inventory.finish()
}
