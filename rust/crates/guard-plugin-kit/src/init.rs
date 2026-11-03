//! `hol-guard plugin init`: a Kit config for an existing plugin, or a minimal
//! Claude Code plugin with one skill in a new folder. Never overwrites.

use std::path::Path;

use serde_json::{json, Value};

use crate::check::is_kebab;
use crate::detect::Detection;
use crate::emit::{self, Output, Runtime};

pub const CONFIG_FILE: &str = "hol.json";
pub const CONFIG_SCHEMA: &str = "hol.plugin-kit.config.v1";
pub const DEFAULT_OUT_DIR: &str = "dist/hol-plugin";

pub fn plan(root: &Path, detection: &Detection, name: Option<&str>) -> Result<Vec<Output>, String> {
    let mut outputs = Vec::new();
    let runtimes: Vec<&str> = if detection.sources.is_empty() {
        if !is_new_folder(root)? {
            return Err("plugin_kit_init_folder_not_empty".to_owned());
        }
        let name = name.ok_or("plugin_kit_init_needs_name")?;
        if !is_kebab(name) || name.len() > 64 {
            return Err("plugin_kit_init_name_invalid".to_owned());
        }
        scaffold(name, &mut outputs);
        vec!["claude-code", "codex", "agent-skills"]
    } else {
        Runtime::ALL
            .into_iter()
            .filter(|runtime| emit::supports(*runtime, &detection.plugin))
            .map(Runtime::id)
            .collect()
    };
    outputs.push(Output {
        path: CONFIG_FILE.to_owned(),
        content: emit::json_bytes(&json!({
            "schema": CONFIG_SCHEMA,
            "out": DEFAULT_OUT_DIR,
            "runtimes": runtimes,
        })),
    });
    for output in &outputs {
        if std::fs::symlink_metadata(root.join(&output.path)).is_ok() {
            return Err("plugin_kit_init_would_overwrite".to_owned());
        }
    }
    Ok(outputs)
}

/// A folder holds nothing but what a new repository starts with: dotfiles
/// such as `.git`, a README and a license.
fn is_new_folder(root: &Path) -> Result<bool, String> {
    let entries = std::fs::read_dir(root).map_err(|_| "plugin_kit_root_unreadable")?;
    for entry in entries {
        let entry = entry.map_err(|_| "plugin_kit_root_unreadable")?;
        let name = entry.file_name().to_string_lossy().to_ascii_uppercase();
        let starter = name.starts_with('.')
            || name.starts_with("README")
            || name.starts_with("LICENSE")
            || name.starts_with("LICENCE");
        if !starter {
            return Ok(false);
        }
    }
    Ok(true)
}

fn scaffold(name: &str, outputs: &mut Vec<Output>) {
    let description = format!("Describe what {name} does in one sentence.");
    let plugin: Value = json!({
        "name": name,
        "version": "0.1.0",
        "description": description,
        "license": "MIT",
    });
    outputs.push(Output {
        path: ".claude-plugin/plugin.json".to_owned(),
        content: emit::json_bytes(&plugin),
    });
    outputs.push(Output {
        path: ".claude-plugin/marketplace.json".to_owned(),
        content: emit::json_bytes(&json!({
            "name": name,
            "owner": {"name": name},
            "plugins": [{"name": name, "source": "./", "description": description}],
        })),
    });
    outputs.push(Output {
        path: format!("skills/{name}/SKILL.md"),
        content: format!(
            "---\nname: {name}\ndescription: Use when the user asks for {name}. Replace this with when the agent should load the skill.\n---\n\n# {name}\n\nWrite the instructions the agent follows here.\n"
        )
        .into_bytes(),
    });
}
