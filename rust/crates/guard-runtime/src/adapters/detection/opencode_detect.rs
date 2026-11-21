//! `runner_authority` kind `opencode_detect`: the artifact discovery of
//! `OpenCodeHarnessAdapter.detect` and the install snapshot. Python keeps the
//! config path list, the JSONC parsing (it sends each config's payload as JSON
//! text, so object order survives the wire), the command lookup, the
//! MCP/skill firewall and the workspace AIBOM extension. From the payloads
//! this lists the MCP servers, config plugins and config commands; it then
//! walks the command and plugin directories (including `OPENCODE_CONFIG_DIR`,
//! which Python resolves and sends as `config_dir`) and the skill roots the
//! way `os.walk` does. An artifact id seen again replaces the earlier
//! artifact in place. Every refusal is a stable code and never a partial
//! inventory.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::adapter_inventory::{carried, Inventory, Request, ERR_NAME};
use super::aibom_paths::py_path;
use super::codex_detect::is_guard_proxy;
use super::context_digest::python_strip;
use super::pyjson::{parse_marking_lone_surrogates, PyVal};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use super::zcode_artifacts::{Fields, Scope};

const HARNESS: &str = "opencode";
const COMPANION_PREFIX: &str = "hol-guard::";
const PRETOOL_PLUGIN: &str = "hol-guard-pretool.ts";
const PLUGIN_SUFFIXES: [&str; 4] = [".js", ".ts", ".mjs", ".cjs"];
const GLOBAL_SKILLS: [(&str, &str); 4] = [
    (".config/opencode/skills", "opencode"),
    (".config/opencode/skill", "opencode"),
    (".claude/skills", "claude"),
    (".agents/skills", "agents"),
];
const PROJECT_SKILLS: [(&str, &str); 4] = [
    (".opencode/skills", "opencode"),
    (".opencode/skill", "opencode"),
    (".claude/skills", "claude"),
    (".agents/skills", "agents"),
];

/// One parsed config Python sends: its path, scope and payload.
struct Config {
    path: PathBuf,
    scope: String,
    payload: PyVal,
}

#[derive(Clone, Copy, PartialEq)]
enum DirKind {
    Command,
    PluginFile,
}

fn configs(args: &Map<String, Value>) -> Result<Vec<Config>, &'static str> {
    let items = args
        .get("configs")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    items
        .iter()
        .map(|item| {
            let path = item["path"].as_str().filter(|path| !path.contains('\0'));
            let scope = item["scope"].as_str();
            let text = item["payload"].as_str();
            let (Some(path), Some(scope), Some(text)) = (path, scope, text) else {
                return Err(ERR_INVALID);
            };
            let payload = parse_marking_lone_surrogates(text).map_err(|_| ERR_INVALID)?;
            Ok(Config {
                path: py_path(path),
                scope: scope.to_owned(),
                payload,
            })
        })
        .collect()
}

/// `append_artifact`: an id seen again replaces the earlier artifact in place.
fn append(inventory: &mut Inventory, artifact: Value) {
    let id = artifact["artifact_id"].clone();
    match inventory
        .artifacts
        .iter_mut()
        .find(|existing| existing["artifact_id"] == id)
    {
        Some(existing) => *existing = artifact,
        None => inventory.artifacts.push(artifact),
    }
}

/// `_command_parts`.
fn command_parts(config: &PyVal) -> (Option<&str>, Vec<String>) {
    match config.get("command") {
        Some(PyVal::List(items)) => {
            let mut parts = items.iter().filter_map(PyVal::as_str);
            match parts.next() {
                Some(command) => (Some(command), parts.map(str::to_owned).collect()),
                None => (None, Vec::new()),
            }
        }
        Some(PyVal::Str(command)) => {
            let args = config
                .get("args")
                .and_then(PyVal::as_list)
                .unwrap_or_default()
                .iter()
                .filter_map(PyVal::as_str)
                .map(str::to_owned)
                .collect();
            (Some(command), args)
        }
        _ => (None, Vec::new()),
    }
}

/// `_append_mcp_artifacts`.
fn mcp_servers(
    inventory: &mut Inventory,
    config: &Config,
    skip_companions: bool,
) -> Result<(), &'static str> {
    let Some(servers) = config.payload.get("mcp").and_then(PyVal::as_dict) else {
        return Ok(());
    };
    let scope = Scope {
        harness: HARNESS,
        scope: &config.scope,
    };
    for (name, server) in servers {
        if server.as_dict().is_none() {
            continue;
        }
        let (command, args) = command_parts(server);
        let guard_proxy = is_guard_proxy(command, &args);
        if skip_companions && name.starts_with(COMPANION_PREFIX) && guard_proxy {
            continue;
        }
        let url = server.get("url").and_then(PyVal::as_str);
        let transport = match server.get("type").and_then(PyVal::as_str) {
            Some(kind) if !kind.is_empty() => kind,
            _ if url.is_some() => "remote",
            _ => "stdio",
        };
        let mut env = Map::new();
        for (key, value) in server
            .get("environment")
            .and_then(PyVal::as_dict)
            .unwrap_or_default()
        {
            if let Some(value) = value.as_str() {
                env.insert(key.clone(), json!(value));
            }
        }
        let enabled = server.get("enabled").is_none_or(PyVal::truthy);
        let mut metadata = Map::new();
        metadata.insert("enabled".to_owned(), json!(enabled));
        metadata.insert("guard_managed_proxy".to_owned(), json!(guard_proxy));
        metadata.insert("env".to_owned(), Value::Object(env));
        let artifact = scope.wire(
            format!("{HARNESS}:{}:{name}", config.scope),
            name,
            "mcp_server",
            &config.path,
            Fields {
                command,
                args,
                url,
                transport: Some(transport),
                publisher: None,
            },
            metadata,
        );
        append(inventory, artifact);
    }
    Ok(())
}

/// `_publisher_from_package`.
fn publisher(package: &str) -> Option<&str> {
    package
        .strip_prefix('@')
        .and_then(|rest| rest.split_once('/'))
        .map(|(scope, _)| scope)
}

/// `_append_plugin_artifacts`: the `plugins` and then the `plugin` list.
fn plugins(inventory: &mut Inventory, config: &Config) -> Result<(), &'static str> {
    let scope = Scope {
        harness: HARNESS,
        scope: &config.scope,
    };
    for key in ["plugins", "plugin"] {
        let Some(items) = config.payload.get(key).and_then(PyVal::as_list) else {
            continue;
        };
        for item in items {
            let (name, options) = match item {
                PyVal::Str(name) => (name.as_str(), Map::new()),
                PyVal::List(pair) => match pair.as_slice() {
                    [PyVal::Str(name), options @ PyVal::Dict(_)] => {
                        let Value::Object(options) = carried(options)? else {
                            return Err(ERR_INVALID);
                        };
                        (name.as_str(), options)
                    }
                    _ => continue,
                },
                _ => continue,
            };
            let artifact = scope.wire(
                format!("{HARNESS}:{}:plugin:{name}", config.scope),
                name,
                "plugin",
                &config.path,
                Fields {
                    publisher: publisher(name),
                    ..Fields::default()
                },
                options,
            );
            append(inventory, artifact);
        }
    }
    Ok(())
}

/// `_append_config_command_artifacts`.
fn config_commands(inventory: &mut Inventory, config: &Config) -> Result<(), &'static str> {
    let Some(commands) = config.payload.get("command").and_then(PyVal::as_dict) else {
        return Ok(());
    };
    let scope = Scope {
        harness: HARNESS,
        scope: &config.scope,
    };
    for (name, command) in commands {
        if command.as_dict().is_none() {
            continue;
        }
        let Some(template) = command.get("template").and_then(PyVal::as_str) else {
            continue;
        };
        if python_strip(template).is_empty() {
            continue;
        }
        let mut metadata = Map::new();
        for key in ["description", "agent", "model", "subtask"] {
            match command.get(key) {
                None | Some(PyVal::Null) => {}
                Some(value) => {
                    metadata.insert(key.to_owned(), carried(value)?);
                }
            }
        }
        metadata.insert("template".to_owned(), json!(template));
        let artifact = scope.wire(
            format!("{HARNESS}:{}:config-command:{name}", config.scope),
            name,
            "command",
            &config.path,
            Fields::default(),
            metadata,
        );
        append(inventory, artifact);
    }
    Ok(())
}

/// `Path.suffix`: the last dotted part of the final component, unless the
/// name starts or ends with that dot.
fn py_suffix(name: &str) -> &str {
    match name.rfind('.') {
        Some(index) if index > 0 && index < name.len() - 1 => &name[index..],
        _ => "",
    }
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}

/// One file `os.walk` lists: the directories below the top, then its name.
type Walked = (Vec<OsString>, OsString);

/// `os.walk(top)` with sorted names: every non-directory entry below `top`,
/// top-down. A directory it cannot list is skipped, and a symlinked directory
/// is listed but not entered. Names stay undecoded until a caller matches one.
fn walk(top: &Path, relative: &[OsString], out: &mut Vec<Walked>) {
    let Ok(entries) = fs::read_dir(top) else {
        return;
    };
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            return;
        };
        if fs::metadata(entry.path()).is_ok_and(|metadata| metadata.is_dir()) {
            dirs.push(entry.file_name());
        } else {
            files.push(entry.file_name());
        }
    }
    dirs.sort();
    files.sort();
    for name in files {
        out.push((relative.to_vec(), name));
    }
    for name in dirs {
        let path = top.join(&name);
        if is_symlink(&path) {
            continue;
        }
        let mut nested = relative.to_vec();
        nested.push(name);
        walk(&path, &nested, out);
    }
}

/// A matched entry's names as text: one CPython would carry with a lone
/// surrogate cannot cross the wire and is refused.
fn decoded(parts: &[OsString], name: &OsString) -> Result<(Vec<String>, String), &'static str> {
    let text = |part: &OsString| part.to_str().map(str::to_owned).ok_or(ERR_NAME);
    Ok((
        parts.iter().map(text).collect::<Result<_, _>>()?,
        text(name)?,
    ))
}

/// `_file_metadata`.
fn file_metadata(path: &Path) -> Map<String, Value> {
    let mut metadata = Map::new();
    match fs::read(path) {
        Ok(bytes) => metadata.insert(
            "content_digest".to_owned(),
            json!(hex::encode(Sha256::digest(bytes))),
        ),
        Err(_) => metadata.insert("content_digest_unavailable".to_owned(), json!(true)),
    };
    metadata
}

fn joined(base: &Path, parts: &[String], name: &str) -> PathBuf {
    let mut path = base.to_path_buf();
    for part in parts {
        path.push(part);
    }
    path.push(name);
    path
}

fn dir_name(path: &Path) -> Result<&str, &'static str> {
    path.file_name()
        .unwrap_or_default()
        .to_str()
        .ok_or(ERR_NAME)
}

/// One command or plugin directory of `append_directory_artifacts`.
fn directory(
    inventory: &mut Inventory,
    directory: &Path,
    scope: &str,
    kind: DirKind,
) -> Result<(), &'static str> {
    if !inventory.is_dir(directory)? {
        return Ok(());
    }
    let mut files = Vec::new();
    walk(&inventory.fs(directory), &[], &mut files);
    let label = match kind {
        DirKind::Command => "command",
        DirKind::PluginFile => "plugin-file",
    };
    let wire_scope = Scope {
        harness: HARNESS,
        scope,
    };
    for (parts, name) in &files {
        let lossy = name.to_string_lossy();
        let wanted = match kind {
            DirKind::Command => py_suffix(&lossy) == ".md",
            DirKind::PluginFile => PLUGIN_SUFFIXES.contains(&py_suffix(&lossy)),
        };
        if !wanted {
            continue;
        }
        let (parts, name) = decoded(parts, name)?;
        let suffix = py_suffix(&name);
        let path = joined(directory, &parts, &name);
        inventory.found(&path);
        let mut relative = parts;
        relative.push(match kind {
            DirKind::Command => name[..name.len() - suffix.len()].to_owned(),
            DirKind::PluginFile => name.clone(),
        });
        let relative = relative.join("/");
        let artifact_name = match kind {
            DirKind::Command => relative,
            DirKind::PluginFile => format!("{}/{relative}", dir_name(directory)?),
        };
        let artifact_type = match kind {
            DirKind::Command => "command",
            DirKind::PluginFile if name == PRETOOL_PLUGIN => "daemon_plugin",
            DirKind::PluginFile => "plugin",
        };
        let artifact = wire_scope.wire(
            format!("{HARNESS}:{scope}:{label}:{artifact_name}"),
            &artifact_name,
            artifact_type,
            &path,
            Fields::default(),
            file_metadata(&inventory.fs(&path)),
        );
        append(inventory, artifact);
    }
    Ok(())
}

/// The `SKILL.md` documents below one skill root.
fn skill_root(inventory: &mut Inventory, root: &Path, source: &str) -> Result<(), &'static str> {
    if !inventory.is_dir(root)? {
        return Ok(());
    }
    let scope = inventory.scope_for(root);
    let mut files = Vec::new();
    walk(&inventory.fs(root), &[], &mut files);
    let wire_scope = Scope {
        harness: HARNESS,
        scope,
    };
    for (parts, name) in &files {
        if name.to_str() != Some("SKILL.md") {
            continue;
        }
        let (parts, name) = decoded(parts, name)?;
        let path = joined(root, &parts, &name);
        inventory.found(&path);
        let parent = if parts.is_empty() {
            ".".to_owned()
        } else {
            parts.join("/")
        };
        let relative_id = format!("{}/{parent}", dir_name(root)?);
        let mut metadata = Map::new();
        metadata.insert("skill_source".to_owned(), json!(source));
        metadata.extend(file_metadata(&inventory.fs(&path)));
        let artifact = wire_scope.wire(
            format!("{HARNESS}:{scope}:skill:{source}:{relative_id}"),
            &relative_id,
            "skill",
            &path,
            Fields::default(),
            metadata,
        );
        append(inventory, artifact);
    }
    Ok(())
}

pub(crate) fn detect(args: &Value) -> KindResult {
    let request = Request::parse(args, HARNESS)?;
    let object = args_object(args)?;
    let configs = configs(object)?;
    let skip_companions = object
        .get("skip_verified_mcp_companions")
        .and_then(Value::as_bool)
        .ok_or(ERR_INVALID)?;
    let config_dir = match object.get("config_dir") {
        None | Some(Value::Null) => None,
        Some(Value::String(path)) if !path.contains('\0') => Some(py_path(path)),
        Some(_) => return Err(ERR_INVALID),
    };
    let mut inventory = Inventory::new(&request);
    for config in &configs {
        inventory.found(&config.path);
        mcp_servers(&mut inventory, config, skip_companions)?;
        plugins(&mut inventory, config)?;
        config_commands(&mut inventory, config)?;
    }
    let mut specs: Vec<(PathBuf, &str, DirKind)> = Vec::new();
    let opencode_home = request.home.join(".config").join("opencode");
    specs.push((opencode_home.join("commands"), "global", DirKind::Command));
    specs.push((opencode_home.join("plugins"), "global", DirKind::PluginFile));
    specs.push((opencode_home.join("plugin"), "global", DirKind::PluginFile));
    if let Some(workspace) = &request.workspace {
        let project = workspace.join(".opencode");
        specs.push((project.join("commands"), "project", DirKind::Command));
        specs.push((project.join("plugins"), "project", DirKind::PluginFile));
        specs.push((project.join("plugin"), "project", DirKind::PluginFile));
    }
    if let Some(config_dir) = &config_dir {
        let scope = inventory.scope_for(config_dir);
        specs.push((config_dir.join("commands"), scope, DirKind::Command));
        specs.push((config_dir.join("plugins"), scope, DirKind::PluginFile));
        specs.push((config_dir.join("plugin"), scope, DirKind::PluginFile));
    }
    for (path, scope, kind) in &specs {
        directory(&mut inventory, path, scope, *kind)?;
    }
    let mut roots: Vec<(PathBuf, &str)> = GLOBAL_SKILLS
        .iter()
        .map(|(relative, source)| (request.home.join(relative), *source))
        .collect();
    if let Some(workspace) = &request.workspace {
        roots.extend(
            PROJECT_SKILLS
                .iter()
                .map(|(relative, source)| (workspace.join(relative), *source)),
        );
    }
    for (root, source) in &roots {
        skill_root(&mut inventory, root, source)?;
    }
    inventory.finish()
}
