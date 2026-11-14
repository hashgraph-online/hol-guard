//! Where `hol-guard install claude-code` writes, what else Claude Code reads,
//! and how to undo it.
//!
//! Guard writes its hook entries to one file: the user settings under the
//! home. `--workspace` does not move them into the project; it only scopes the
//! hook URL and Guard's policy. Claude Code merges hooks from managed, user,
//! project and local settings and runs them all, so a project file cannot
//! remove Guard's entries, but `disableAllHooks` in any of those files, or
//! `allowManagedHooksOnly` in managed settings, turns them off. Those
//! overrides are read here, never written, so the install output can say so
//! before anything is published.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::{path_text, Ctx};

const CONFIG_DIR_ENV: &str = "CLAUDE_CONFIG_DIR";

/// Claude Code's managed settings file for this OS. Only the documented
/// locations; anything else is not guessed.
fn managed_settings(ctx: &Ctx) -> PathBuf {
    if ctx.windows {
        let program_files = ctx
            .env
            .get("ProgramFiles")
            .filter(|value| !value.is_empty())
            .cloned()
            .unwrap_or_else(|| "C:\\Program Files".to_owned());
        return PathBuf::from(program_files)
            .join("ClaudeCode")
            .join("managed-settings.json");
    }
    if cfg!(target_os = "macos") {
        return PathBuf::from("/Library/Application Support/ClaudeCode/managed-settings.json");
    }
    PathBuf::from("/etc/claude-code/managed-settings.json")
}

/// `true` when the file is a JSON object whose `key` is `true`. Unreadable or
/// malformed files are not overrides; Claude Code reports those itself.
fn flag_set(ctx: &Ctx, path: &Path, key: &str) -> bool {
    std::fs::read(ctx.absolute(path))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value.get(key).and_then(Value::as_bool))
        == Some(true)
}

struct Layer {
    scope: &'static str,
    path: PathBuf,
    guard_writes: bool,
}

/// Highest precedence first, as Claude Code documents it.
fn layers(ctx: &Ctx, settings: &Path) -> Vec<Layer> {
    let mut layers = vec![Layer {
        scope: "managed",
        path: managed_settings(ctx),
        guard_writes: false,
    }];
    if let Some(workspace) = &ctx.workspace {
        let project = workspace.join(".claude");
        layers.push(Layer {
            scope: "project_local",
            path: project.join("settings.local.json"),
            guard_writes: false,
        });
        layers.push(Layer {
            scope: "project",
            path: project.join("settings.json"),
            guard_writes: false,
        });
    }
    layers.push(Layer {
        scope: "user",
        path: settings.to_path_buf(),
        guard_writes: true,
    });
    layers
}

/// A `CLAUDE_CONFIG_DIR` that points somewhere other than the settings Guard
/// writes: Claude Code then reads a different user file.
fn config_dir_override(ctx: &Ctx, settings: &Path) -> Option<String> {
    let value = ctx.env.get(CONFIG_DIR_ENV)?.trim();
    if value.is_empty() {
        return None;
    }
    let dir = ctx.absolute(Path::new(value));
    let written = ctx.absolute(settings.parent()?);
    if dir == written {
        return None;
    }
    Some(path_text(&dir))
}

fn overrides(ctx: &Ctx, layers: &[Layer], settings: &Path) -> Vec<Value> {
    let mut found = Vec::new();
    for layer in layers {
        if flag_set(ctx, &layer.path, "disableAllHooks") {
            found.push(json!({
                "code": "disable_all_hooks",
                "scope": layer.scope,
                "path": path_text(&layer.path),
                "message": format!(
                    "{} sets disableAllHooks, so Claude Code runs none of Guard's hooks.",
                    path_text(&layer.path)
                ),
            }));
        }
    }
    let managed = &layers[0];
    if flag_set(ctx, &managed.path, "allowManagedHooksOnly") {
        found.push(json!({
            "code": "managed_hooks_only",
            "scope": managed.scope,
            "path": path_text(&managed.path),
            "message": format!(
                "{} sets allowManagedHooksOnly, so Claude Code ignores the hooks Guard writes \
                 to user settings.",
                path_text(&managed.path)
            ),
        }));
    }
    if let Some(dir) = config_dir_override(ctx, settings) {
        found.push(json!({
            "code": "config_dir_elsewhere",
            "scope": "user",
            "path": dir,
            "message": format!(
                "CLAUDE_CONFIG_DIR is {dir}, so Claude Code reads user settings there, not the \
                 file Guard writes."
            ),
        }));
    }
    found
}

/// The install target answer: the one file Guard writes, the precedence it
/// sits in, the overrides that would silence it, and the rollback.
pub(super) fn target(ctx: &Ctx, settings: &Path) -> Value {
    let layers = layers(ctx, settings);
    let overrides = overrides(ctx, &layers, settings);
    let precedence: Vec<Value> = layers
        .iter()
        .map(|layer| {
            json!({
                "scope": layer.scope,
                "path": path_text(&layer.path),
                "guard_writes": layer.guard_writes,
            })
        })
        .collect();
    let workspace_note = ctx.workspace.as_ref().map(|workspace| {
        format!(
            "--workspace does not install into {}; it only scopes the hook URL and Guard \
             policy. Guard writes no project settings file.",
            path_text(&workspace.join(".claude"))
        )
    });
    json!({
        "scope": "user",
        "settings_path": path_text(settings),
        "workspace": ctx.workspace.as_deref().map(path_text),
        "workspace_note": workspace_note,
        "precedence": precedence,
        "hooks_merge": "Claude Code runs the hooks from every settings file together; a project \
            file cannot remove Guard's user entries, but the overrides below can turn them off.",
        "hook_overrides": overrides,
        "background": "Headless `claude -p` runs on this machine read the same user settings. \
            Remote and cloud Claude Code sessions do not, and Guard does not cover them.",
        "rollback": {
            "command": ["hol-guard", "uninstall", "claude-code"],
            "path": path_text(settings),
            "effect": "Removes only Guard's hook entries from this file and leaves every other \
                setting. It makes no backup; `hol-guard hooks remove --all` backs the file up \
                first.",
        },
    })
}

/// Install notes for the manifest: the file written, the rollback, and one
/// line per override that would silence the hooks.
pub(super) fn notes(target: &Value) -> Vec<String> {
    let text = |key: &str| target.get(key).and_then(Value::as_str).unwrap_or_default();
    let mut notes = vec![
        format!(
            "Guard writes its hook entries to user settings at {}.",
            text("settings_path")
        ),
        format!(
            "To undo, run `hol-guard uninstall claude-code`; it removes only Guard's entries \
             from {}.",
            text("settings_path")
        ),
    ];
    if let Some(overrides) = target.get("hook_overrides").and_then(Value::as_array) {
        notes.extend(
            overrides
                .iter()
                .filter_map(|item| item.get("message").and_then(Value::as_str))
                .map(|message| format!("Warning: {message}")),
        );
    }
    notes
}
