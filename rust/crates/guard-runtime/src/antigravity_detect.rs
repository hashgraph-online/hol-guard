//! `runner_authority` kind `antigravity_detect`: the config parsing and
//! artifact discovery of `AntigravityHarnessAdapter.detect`. This lists the
//! extensions in `~/.antigravity/extensions/extensions.json`, the MCP servers
//! in `.gemini/antigravity/mcp_config.json`, the Antigravity skill documents,
//! and the MCP servers of the editor settings files Antigravity owns. Python
//! keeps the command lookup. Every refusal is a stable code and never a
//! partial inventory.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::adapter_inventory::{
    json_document, json_payload, mcp_fields, Inventory, Request, SkillNaming,
};
use super::aibom_paths::{py_join, py_path};
use super::pyjson::PyVal;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use super::zcode_artifacts::{Fields, Scope};

const HARNESS: &str = "antigravity";

/// The editor settings Antigravity owns outright, with the source each one
/// names its MCP servers by.
const OWNED_SETTINGS: [(&[&str], &str); 3] = [
    (
        &[
            "Library",
            "Application Support",
            "Antigravity",
            "User",
            "settings.json",
        ],
        "settings:macos-user",
    ),
    (
        &[".config", "Antigravity", "User", "settings.json"],
        "settings:xdg-user",
    ),
    (
        &["AppData", "Roaming", "Antigravity", "User", "settings.json"],
        "settings:windows-user",
    ),
];

fn under(base: &Path, parts: &[&str]) -> PathBuf {
    parts
        .iter()
        .fold(base.to_path_buf(), |path, part| path.join(part))
}

/// `_mcp_source` for a settings file: the fixed source when a directory
/// precedes the matched suffix, else the token of its last four parts, which
/// for these fixed names is their lowercased alphanumeric runs.
fn settings_source(path: &Path, source: &str, parts: &[&str]) -> String {
    if path.components().count() > parts.len() {
        return source.to_owned();
    }
    let tokens: Vec<String> = parts[parts.len().saturating_sub(4)..]
        .iter()
        .map(|part| {
            part.to_ascii_lowercase()
                .chars()
                .map(|character| {
                    if character.is_ascii_alphanumeric() {
                        character
                    } else {
                        '-'
                    }
                })
                .collect::<String>()
                .trim_matches('-')
                .to_owned()
        })
        .filter(|token| !token.is_empty())
        .collect();
    format!("settings:{}", tokens.join("-"))
}

fn mcp_servers(
    inventory: &mut Inventory,
    path: &Path,
    source: &str,
    payload: &PyVal,
) -> Result<(), &'static str> {
    let scope = Scope {
        harness: HARNESS,
        scope: inventory.scope_for(path),
    };
    let Some(servers) = payload.get("mcpServers").and_then(PyVal::as_dict) else {
        return Ok(());
    };
    for (name, config) in servers {
        if config.as_dict().is_none() {
            continue;
        }
        inventory.artifacts.push(scope.wire(
            format!("{HARNESS}:{}:mcp:{source}:{name}", scope.scope),
            name,
            "mcp_server",
            path,
            mcp_fields(config),
            Map::new(),
        ));
    }
    Ok(())
}

/// `_extension_artifacts` over a non-empty extension index.
fn extensions(inventory: &mut Inventory, items: &[PyVal]) -> Result<(), &'static str> {
    let scope = Scope {
        harness: HARNESS,
        scope: "global",
    };
    for item in items {
        let (Some(identifier), Some(location)) = (
            item.get("identifier")
                .filter(|value| value.as_dict().is_some()),
            item.get("location")
                .filter(|value| value.as_dict().is_some()),
        ) else {
            continue;
        };
        let (Some(extension_id), Some(location)) = (
            identifier.get("id").and_then(PyVal::as_str),
            location.get("path").and_then(PyVal::as_str),
        ) else {
            continue;
        };
        // `read_text` raises `ValueError` on an embedded NUL.
        if location.contains('\0') {
            return Err(ERR_INVALID);
        }
        let manifest = py_join(&py_path(location), "package.json");
        // A relative location is read from Python's cwd; without one it has
        // no anchor and is never read from the resident's own directory.
        let payload = if manifest.is_absolute() || inventory.has_cwd() {
            json_payload(&inventory.fs(&manifest))?
        } else {
            PyVal::Dict(Vec::new())
        };
        if payload.truthy() {
            inventory.found(&manifest);
        }
        let text = |key: &str| payload.get(key).and_then(PyVal::as_str);
        let publisher = text("publisher").or_else(|| {
            item.get("metadata")
                .and_then(|metadata| metadata.get("publisherDisplayName"))
                .and_then(PyVal::as_str)
        });
        let display_name = text("displayName");
        let name = display_name
            .filter(|name| !name.is_empty())
            .unwrap_or(extension_id);
        let mut metadata = Map::new();
        metadata.insert("display_name".to_owned(), json!(display_name));
        metadata.insert("description".to_owned(), json!(text("description")));
        metadata.insert("extension_id".to_owned(), json!(extension_id));
        inventory.artifacts.push(scope.wire(
            format!("{HARNESS}:global:{extension_id}"),
            name,
            "extension",
            &manifest,
            Fields {
                publisher,
                ..Fields::default()
            },
            metadata,
        ));
    }
    Ok(())
}

pub(crate) fn detect(args: &Value) -> KindResult {
    let request = Request::parse(args, HARNESS)?;
    let mut inventory = Inventory::new(&request);
    let home = &request.home;
    let mut roots = vec![home.clone()];
    roots.extend(request.workspace.clone());

    let index = under(home, &[".antigravity", "extensions", "extensions.json"]);
    if let Some(PyVal::List(items)) = json_document(&inventory.fs(&index))? {
        if !items.is_empty() {
            inventory.found(&index);
            extensions(&mut inventory, &items)?;
        }
    }
    for root in &roots {
        let path = under(root, &[".gemini", "antigravity", "mcp_config.json"]);
        let payload = json_payload(&inventory.fs(&path))?;
        if payload.truthy() {
            inventory.found(&path);
            mcp_servers(&mut inventory, &path, "bridge", &payload)?;
        }
    }
    for root in &roots {
        let skill_root = under(root, &[".gemini", "antigravity", "skills"]);
        let scope = Scope {
            harness: HARNESS,
            scope: inventory.scope_for(&skill_root),
        };
        inventory.skills(
            &scope,
            "Antigravity",
            &SkillNaming::Prefixed,
            &skill_root,
            root,
        )?;
    }

    let mut candidates: Vec<(PathBuf, String, bool)> = OWNED_SETTINGS
        .iter()
        .map(|(parts, source)| {
            let path = under(home, parts);
            let source = settings_source(&path, source, parts);
            (path, source, true)
        })
        .collect();
    if let Some(workspace) = &request.workspace {
        let parts: &[&str] = &[".vscode", "settings.json"];
        let path = under(workspace, parts);
        let source = settings_source(&path, "settings:workspace-vscode", parts);
        candidates.push((path, source, false));
    }
    let mut signal = inventory.has_found();
    for (path, source, owned) in candidates {
        let payload = json_payload(&inventory.fs(&path))?;
        if !payload.truthy() {
            continue;
        }
        let names_antigravity = payload
            .as_dict()
            .unwrap_or_default()
            .iter()
            .any(|(key, _)| key.starts_with("antigravity."));
        if !(owned || names_antigravity || signal) {
            continue;
        }
        mcp_servers(&mut inventory, &path, &source, &payload)?;
        inventory.found(&path);
        signal = true;
    }
    inventory.finish()
}
