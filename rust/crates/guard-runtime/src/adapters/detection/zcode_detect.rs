//! `runner_authority` kind `zcode_detect`: the filesystem discovery of
//! `ZCodeHarnessAdapter.detect`. Python anchors the candidate roots and scopes;
//! this walks them in the same order, parses the config, plugin and
//! marketplace JSON the way `json.loads` does, and returns the artifacts and
//! the config paths that were found. Every refusal is a stable code and never
//! a partial inventory.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::aibom_op::absolute;
use super::aibom_paths::{file_name_string, is_dir, is_file, py_join, stem};
use super::pyjson::{parse, JsonFailure, PyVal};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use super::zcode_artifacts::{
    cli_config_artifacts, command_artifact, hook_artifacts, marketplace_artifact, mcp_server,
    plugin_artifact, raw_hook_groups, skill_artifact, Scope, ERR_UNREPRESENTABLE,
};

const ERR_TEXT: &str = "native_runner_authority_zcode_text_invalid";
const ERR_DIRECTORY: &str = "native_runner_authority_zcode_directory_unreadable";
const ERR_NAME: &str = "native_runner_authority_zcode_non_utf8_path";

const HARNESS: &str = "zcode";
const MANIFEST_DIR: &str = ".zcode-plugin";
const MANIFEST_FILE: &str = "plugin.json";
const SEED_FILE: &str = ".zcode-plugin-seed.json";
const MCP_FILE: &str = ".mcp.json";
const HOOK_FILES: [&str; 2] = ["hooks/hooks.json", "hooks/hooks-cursor.json"];
const MARKETPLACE_FILE: &str = "marketplace.json";

#[derive(Default)]
struct Found {
    artifacts: Vec<Value>,
    paths: Vec<String>,
}

impl Found {
    fn path(&mut self, path: &Path) {
        let text = path.to_string_lossy().into_owned();
        if !self.paths.contains(&text) {
            self.paths.push(text);
        }
    }
}

/// `_json_payload`: the object a file holds, or an empty object when it is
/// missing, unreadable, not JSON or not an object. Text CPython would raise on
/// instead of returning (invalid UTF-8, nesting past the recursion limit) is
/// refused.
pub(crate) fn json_payload(path: &Path) -> Result<PyVal, &'static str> {
    let empty = PyVal::Dict(Vec::new());
    let Ok(bytes) = fs::read(path) else {
        return Ok(empty);
    };
    let text = String::from_utf8(bytes).map_err(|_| ERR_TEXT)?;
    match parse(&text) {
        Ok(value @ PyVal::Dict(_)) => Ok(value),
        Ok(_) | Err(JsonFailure::Syntax) => Ok(empty),
        // A top-level array is discarded whatever it holds, so only an
        // object the walkers would have to read can be unrepresentable.
        Err(JsonFailure::Unrepresentable | JsonFailure::IntegerLimit | JsonFailure::Duplicate)
            if text.trim_start().starts_with('[') =>
        {
            Ok(empty)
        }
        Err(JsonFailure::Unrepresentable | JsonFailure::IntegerLimit | JsonFailure::Duplicate) => {
            Err(ERR_UNREPRESENTABLE)
        }
    }
}

fn has_content(payload: &PyVal) -> bool {
    payload.truthy()
}

pub(crate) fn sort_key(name: &str) -> String {
    if cfg!(windows) {
        name.to_lowercase()
    } else {
        name.to_owned()
    }
}

/// `sorted(entry for entry in path.iterdir() if entry.is_dir())`.
fn child_directories(path: &Path) -> Result<Vec<PathBuf>, &'static str> {
    let entries = fs::read_dir(path).map_err(|_| ERR_DIRECTORY)?;
    let mut named: Vec<(String, PathBuf)> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| ERR_DIRECTORY)?;
        let child = entry.path();
        if !is_dir(&child) {
            continue;
        }
        let name = entry.file_name().into_string().map_err(|_| ERR_NAME)?;
        named.push((sort_key(&name), child));
    }
    named.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(named.into_iter().map(|(_, child)| child).collect())
}

/// `sorted(root.rglob("SKILL.md"))`: any entry so named at any depth, never
/// descending through a directory link, unreadable directories skipped.
fn skill_documents(root: &Path) -> Result<Vec<(Vec<String>, PathBuf)>, &'static str> {
    let mut found: Vec<(Vec<String>, PathBuf)> = Vec::new();
    let mut pending = vec![(root.to_path_buf(), Vec::<String>::new())];
    while let Some((directory, relative)) = pending.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let is_real_dir = entry.file_type().is_ok_and(|kind| kind.is_dir());
            let Ok(name) = entry.file_name().into_string() else {
                if is_real_dir {
                    return Err(ERR_NAME);
                }
                continue;
            };
            let mut parts = relative.clone();
            parts.push(name.clone());
            if is_real_dir {
                pending.push((entry.path(), parts.clone()));
            }
            if name == "SKILL.md" {
                found.push((relative.clone(), entry.path()));
            }
        }
    }
    found.sort_by(|left, right| {
        let key = |item: &(Vec<String>, PathBuf)| {
            let mut parts = item.0.clone();
            parts.push("SKILL.md".to_owned());
            parts
        };
        key(left).cmp(&key(right))
    });
    Ok(found)
}

/// `sorted(root.glob("*.md"))`: direct children only, of any kind.
fn command_documents(root: &Path) -> Result<Vec<(String, PathBuf)>, &'static str> {
    let entries = fs::read_dir(root).map_err(|_| ERR_DIRECTORY)?;
    let mut found: Vec<(String, PathBuf)> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| ERR_DIRECTORY)?;
        let Ok(name) = entry.file_name().into_string() else {
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStrExt;
                if entry.file_name().as_bytes().ends_with(b".md") {
                    return Err(ERR_NAME);
                }
            }
            continue;
        };
        let matches = if cfg!(windows) {
            name.to_lowercase().ends_with(".md")
        } else {
            name.ends_with(".md")
        };
        if matches {
            found.push((name, entry.path()));
        }
    }
    found.sort_by(|left, right| sort_key(&left.0).cmp(&sort_key(&right.0)));
    Ok(found)
}

fn text_field<'a>(payload: &'a PyVal, key: &str) -> Option<&'a str> {
    payload.get(key).and_then(PyVal::as_str)
}

fn plugin_manifest(
    scope: &Scope<'_>,
    plugin_root: &Path,
    found: &mut Found,
) -> Result<(), &'static str> {
    let manifest_path = plugin_root.join(MANIFEST_DIR).join(MANIFEST_FILE);
    let payload = json_payload(&manifest_path)?;
    if !has_content(&payload) {
        return Ok(());
    }
    found.path(&manifest_path);
    let plugin_name = text_field(&payload, "name")
        .map(str::to_owned)
        .unwrap_or_else(|| file_name_string(plugin_root));
    let version = text_field(&payload, "version");
    let publisher = match payload.get("author") {
        Some(author @ PyVal::Dict(_)) => text_field(author, "name"),
        Some(PyVal::Str(text)) => Some(text.as_str()),
        _ => None,
    };
    let mut metadata = Map::new();
    if let Some(version) = version {
        metadata.insert("version".to_owned(), json!(version));
    }
    let seed_path = plugin_root.join(SEED_FILE);
    let seed = json_payload(&seed_path)?;
    let mut marketplace: Option<String> = None;
    if has_content(&seed) {
        found.path(&seed_path);
        if let Some(text) = text_field(&seed, "marketplace") {
            marketplace = Some(text.to_owned());
            metadata.insert("marketplace".to_owned(), json!(text));
        }
        for (field, key) in [
            ("source", "source"),
            ("pluginVersion", "plugin_version"),
            ("hash", "provenance_hash"),
        ] {
            if let Some(text) = text_field(&seed, field) {
                metadata.insert(key.to_owned(), json!(text));
            }
        }
    }
    let prefix = format!("{}:{}:plugin", scope.harness, scope.scope);
    let artifact_id = match marketplace.as_deref().filter(|text| !text.is_empty()) {
        Some(market) => format!("{prefix}:{market}:{plugin_name}"),
        None => format!("{prefix}:{plugin_name}"),
    };
    found.artifacts.push(plugin_artifact(
        scope,
        artifact_id,
        &plugin_name,
        &manifest_path,
        publisher,
        metadata,
    ));

    let mcp_path = plugin_root.join(MCP_FILE);
    let mcp = json_payload(&mcp_path)?;
    if let Some(servers) = mcp.get("mcpServers").and_then(PyVal::as_dict) {
        found.path(&mcp_path);
        for (name, config) in servers {
            if config.as_dict().is_none() {
                continue;
            }
            found.artifacts.extend(mcp_server(
                scope,
                name,
                config,
                &mcp_path,
                Some(&plugin_name),
            )?);
        }
    }

    for relative in HOOK_FILES {
        hooks_file(scope, &plugin_root.join(relative), found)?;
    }

    let skill_root = plugin_root.join("skills");
    if is_dir(&skill_root) {
        for (relative, path) in skill_documents(&skill_root)? {
            found.path(&path);
            let name = if relative.is_empty() {
                ".".to_owned()
            } else {
                relative.join("/")
            };
            found.artifacts.push(skill_artifact(scope, &name, &path));
        }
    }
    let command_root = plugin_root.join("commands");
    if is_dir(&command_root) {
        for (name, path) in command_documents(&command_root)? {
            found.path(&path);
            found
                .artifacts
                .push(command_artifact(scope, stem(&name), &path));
        }
    }
    Ok(())
}

fn hooks_file(scope: &Scope<'_>, hooks_file: &Path, found: &mut Found) -> Result<(), &'static str> {
    let payload = json_payload(hooks_file)?;
    if !has_content(&payload) {
        return Ok(());
    }
    found.path(hooks_file);
    if let Some(hooks) = payload
        .get("hooks")
        .filter(|hooks| hooks.as_dict().is_some())
    {
        found
            .artifacts
            .extend(hook_artifacts(scope, &raw_hook_groups(hooks), hooks_file)?);
    }
    Ok(())
}

fn marketplace(scope: &Scope<'_>, file: &Path, found: &mut Found) -> Result<(), &'static str> {
    let payload = json_payload(file)?;
    if !has_content(&payload) {
        return Ok(());
    }
    found.path(file);
    let name = text_field(&payload, "name")
        .map(str::to_owned)
        .unwrap_or_else(|| file.parent().map(file_name_string).unwrap_or_default());
    let entries = payload
        .get("plugins")
        .and_then(PyVal::as_list)
        .map_or(0, <[PyVal]>::len);
    found
        .artifacts
        .push(marketplace_artifact(scope, &name, file, entries));
    Ok(())
}

struct Root {
    path: PathBuf,
    scope: String,
}

fn roots(value: Option<&Value>) -> Result<Vec<Root>, &'static str> {
    value
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|entry| {
            let entry = args_object(entry)?;
            Ok(Root {
                path: absolute(entry.get("path")).map_err(|_| ERR_INVALID)?,
                scope: entry
                    .get("scope")
                    .and_then(Value::as_str)
                    .ok_or(ERR_INVALID)?
                    .to_owned(),
            })
        })
        .collect()
}

pub(crate) fn detect(args: &Value) -> KindResult {
    let args = args_object(args)?;
    if args.get("harness").and_then(Value::as_str) != Some(HARNESS) {
        return Err(ERR_INVALID);
    }
    let configs = roots(args.get("configs"))?;
    let plugin_roots = roots(args.get("plugin_roots"))?;
    let marketplace_roots = roots(args.get("marketplace_roots"))?;
    let v2_config = match args.get("v2_config") {
        None | Some(Value::Null) => None,
        other => Some(absolute(other).map_err(|_| ERR_INVALID)?),
    };
    let mut found = Found::default();

    for config in &configs {
        if !is_file(&config.path) {
            continue;
        }
        found.path(&config.path);
        let payload = json_payload(&config.path)?;
        if has_content(&payload) {
            let scope = Scope {
                harness: HARNESS,
                scope: &config.scope,
            };
            found
                .artifacts
                .extend(cli_config_artifacts(&scope, &payload, &config.path)?);
        }
    }
    if let Some(v2) = v2_config.filter(|path| is_file(path)) {
        found.path(&v2);
    }
    for root in &plugin_roots {
        if !is_dir(&root.path) {
            continue;
        }
        let scope = Scope {
            harness: HARNESS,
            scope: &root.scope,
        };
        for marketplace_dir in child_directories(&root.path)? {
            for plugin_dir in child_directories(&marketplace_dir)? {
                for version_dir in child_directories(&plugin_dir)? {
                    let manifest = version_dir.join(MANIFEST_DIR).join(MANIFEST_FILE);
                    if is_file(&manifest) {
                        plugin_manifest(&scope, &version_dir, &mut found)?;
                    }
                }
            }
        }
    }
    for root in &marketplace_roots {
        if !is_dir(&root.path) {
            continue;
        }
        let scope = Scope {
            harness: HARNESS,
            scope: &root.scope,
        };
        for directory in child_directories(&root.path)? {
            let file = py_join(&directory, MARKETPLACE_FILE);
            if is_file(&file) {
                marketplace(&scope, &file, &mut found)?;
            }
        }
    }
    Ok(json!({ "artifacts": found.artifacts, "found_paths": found.paths }))
}
