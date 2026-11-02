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
const OWNED_SETTINGS: [(&[&str], &str); 4] = [
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
        &[".config", "antigravity", "user", "settings.json"],
        XDG_LOWER_SOURCE,
    ),
    (
        &["AppData", "Roaming", "Antigravity", "User", "settings.json"],
        "settings:windows-user",
    ),
];

const XDG_LOWER_SOURCE: &str = "settings:xdg-user-lower";

/// Antigravity-owned skill roots. Home `.agents/skills` belongs to other
/// harnesses, so it is not in this list. Each prefix is one path segment.
/// Discovery walks a root recursively, so a prefix of `skills/<dir>` would
/// match a nested skill under the primary `skills` root.
const SKILL_CANDIDATES: [(&[&str], &str); 3] = [
    (&[".gemini", "antigravity", "skills"], "skills"),
    (
        &[".gemini", "antigravity", "builtin", "skills"],
        "builtin-skills",
    ),
    (&[".gemini", "config", "plugins"], "plugin-skills"),
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
    // A parent directory keeps the caller's source. The lowercase XDG file
    // keeps its source even when the path is only the suffix: folding those
    // parts to lowercase would give it the capitalized file's id.
    if path.components().count() > parts.len() || source == XDG_LOWER_SOURCE {
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
        for (parts, prefix) in SKILL_CANDIDATES {
            record_skills(&mut inventory, root, parts, prefix)?;
        }
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
    let mut seen_canonical: Vec<PathBuf> = Vec::new();
    for (path, source, owned) in candidates {
        let fs_path = inventory.fs(&path);
        let canonical = std::fs::canonicalize(&fs_path).unwrap_or_else(|_| fs_path.clone());
        if seen_canonical.contains(&canonical) {
            continue;
        }
        let payload = json_payload(&fs_path)?;
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
        seen_canonical.push(canonical);
        mcp_servers(&mut inventory, &path, &source, &payload)?;
        inventory.found(&path);
        signal = true;
    }
    // Workspace `.agents/skills` is scanned after settings so those shared
    // documents do not by themselves admit unrelated editor settings.
    if let Some(workspace) = &request.workspace {
        record_skills(
            &mut inventory,
            workspace,
            &[".agents", "skills"],
            "agents-skills",
        )?;
    }
    inventory.finish()
}

fn record_skills(
    inventory: &mut Inventory,
    root: &Path,
    parts: &[&str],
    prefix: &str,
) -> Result<(), &'static str> {
    let skill_root = under(root, parts);
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
        prefix,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn detect_at(home: &Path, workspace: Option<&Path>) -> Value {
        let mut args = json!({
            "harness": HARNESS,
            "home": home.to_string_lossy(),
        });
        if let Some(workspace) = workspace {
            args["workspace"] = json!(workspace.to_string_lossy());
        }
        detect(&args).expect("detect")
    }

    fn same_inode(left: &Path, right: &Path) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let Ok(left) = std::fs::metadata(left) else {
                return false;
            };
            let Ok(right) = std::fs::metadata(right) else {
                return false;
            };
            left.ino() == right.ino()
        }
        #[cfg(not(unix))]
        {
            let _ = (left, right);
            false
        }
    }

    fn ids(result: &Value) -> Vec<String> {
        result["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["artifact_id"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn lowercase_xdg_source_stays_distinct_when_the_path_is_only_the_suffix() {
        let parts = [".config", "antigravity", "user", "settings.json"];
        let path = Path::new(".config/antigravity/user/settings.json");
        assert_eq!(
            settings_source(path, XDG_LOWER_SOURCE, &parts),
            XDG_LOWER_SOURCE
        );
        let upper_parts = [".config", "Antigravity", "User", "settings.json"];
        let upper = Path::new(".config/Antigravity/User/settings.json");
        assert_ne!(
            settings_source(upper, "settings:xdg-user", &upper_parts),
            XDG_LOWER_SOURCE
        );
    }

    #[test]
    fn lowercase_xdg_settings_keep_a_distinct_mcp_id() {
        let root = std::env::temp_dir().join(format!("ag-xdg-lower-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("home");
        let upper = home.join(".config/Antigravity/User/settings.json");
        let lower = home.join(".config/antigravity/user/settings.json");
        write(
            &lower,
            r#"{"mcpServers":{"demo_server":{"command":"demo"}}}"#,
        );
        let found = ids(&detect_at(&home, None));
        let same_file = same_inode(&upper, &lower);
        if same_file {
            assert!(
                found.contains(&"antigravity:global:mcp:settings:xdg-user:demo_server".to_owned())
            );
            assert!(!found.contains(
                &"antigravity:global:mcp:settings:xdg-user-lower:demo_server".to_owned()
            ));
        } else {
            assert!(found.contains(
                &"antigravity:global:mcp:settings:xdg-user-lower:demo_server".to_owned()
            ));
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn xdg_case_variants_do_not_collapse_when_they_are_different_files() {
        let root = std::env::temp_dir().join(format!("ag-xdg-both-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("home");
        let upper = home.join(".config/Antigravity/User/settings.json");
        let lower = home.join(".config/antigravity/user/settings.json");
        write(
            upper.as_path(),
            r#"{"mcpServers":{"shared":{"command":"upper"}}}"#,
        );
        write(
            lower.as_path(),
            r#"{"mcpServers":{"shared":{"command":"lower"}}}"#,
        );
        let found = ids(&detect_at(&home, None));
        let shared: Vec<_> = found
            .into_iter()
            .filter(|id| id.ends_with(":shared"))
            .collect();
        let same_file = same_inode(&upper, &lower);
        if same_file {
            assert_eq!(
                shared,
                vec!["antigravity:global:mcp:settings:xdg-user:shared".to_owned()]
            );
        } else {
            assert!(shared.contains(&"antigravity:global:mcp:settings:xdg-user:shared".to_owned()));
            assert!(shared
                .contains(&"antigravity:global:mcp:settings:xdg-user-lower:shared".to_owned()));
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn home_agents_skills_are_not_antigravity_and_do_not_admit_editor_settings() {
        let root = std::env::temp_dir().join(format!("ag-agents-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("home");
        let workspace = root.join("workspace");
        write(
            &home.join(".agents/skills/other-tool/SKILL.md"),
            "---\nname: other-tool\n---\nShared.\n",
        );
        write(
            &workspace.join(".vscode/settings.json"),
            r#"{"mcpServers":{"editor":{"command":"code"}}}"#,
        );
        let found = ids(&detect_at(&home, Some(&workspace)));
        assert!(found
            .iter()
            .all(|id| !id.contains("other-tool") && !id.ends_with(":editor")));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn workspace_agents_skills_and_builtin_skills_keep_distinct_ids() {
        let root = std::env::temp_dir().join(format!("ag-skills-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("home");
        let workspace = root.join("workspace");
        write(
            &home.join(".gemini/antigravity/skills/custom/SKILL.md"),
            "---\nname: custom\n---\nOwned.\n",
        );
        write(
            &home.join(".gemini/antigravity/builtin/skills/custom/SKILL.md"),
            "---\nname: custom\n---\nBuiltin.\n",
        );
        write(
            &workspace.join(".agents/skills/team-helper/SKILL.md"),
            "---\nname: team-helper\n---\nTeam.\n",
        );
        let found = ids(&detect_at(&home, Some(&workspace)));
        assert!(found.contains(&"antigravity:global:skill:skills/custom".to_owned()));
        assert!(found.contains(&"antigravity:global:skill:builtin-skills/custom".to_owned()));
        assert!(found.contains(&"antigravity:project:skill:agents-skills/team-helper".to_owned()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn nested_primary_skills_do_not_reuse_other_root_ids() {
        let root = std::env::temp_dir().join(format!("ag-nested-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("home");
        let workspace = root.join("workspace");
        write(
            &home.join(".gemini/antigravity/skills/builtin/custom/SKILL.md"),
            "---\nname: custom\n---\nNested.\n",
        );
        write(
            &home.join(".gemini/antigravity/builtin/skills/custom/SKILL.md"),
            "---\nname: custom\n---\nBuiltin.\n",
        );
        write(
            &home.join(".gemini/antigravity/skills/plugins/my-plugin/skills/custom/SKILL.md"),
            "---\nname: custom\n---\nNested plugin.\n",
        );
        write(
            &home.join(".gemini/config/plugins/my-plugin/skills/custom/SKILL.md"),
            "---\nname: custom\n---\nPlugin.\n",
        );
        write(
            &workspace.join(".gemini/antigravity/skills/agents/team-helper/SKILL.md"),
            "---\nname: team-helper\n---\nNested agent.\n",
        );
        write(
            &workspace.join(".agents/skills/team-helper/SKILL.md"),
            "---\nname: team-helper\n---\nTeam.\n",
        );
        let found = ids(&detect_at(&home, Some(&workspace)));
        for (nested, owned) in [
            (
                "antigravity:global:skill:skills/builtin/custom",
                "antigravity:global:skill:builtin-skills/custom",
            ),
            (
                "antigravity:global:skill:skills/plugins/my-plugin/skills/custom",
                "antigravity:global:skill:plugin-skills/my-plugin/skills/custom",
            ),
            (
                "antigravity:project:skill:skills/agents/team-helper",
                "antigravity:project:skill:agents-skills/team-helper",
            ),
        ] {
            assert!(found.contains(&nested.to_owned()), "missing {nested}");
            assert!(found.contains(&owned.to_owned()), "missing {owned}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
