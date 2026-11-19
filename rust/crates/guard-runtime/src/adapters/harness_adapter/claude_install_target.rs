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
//! before anything is published. Only the files listed in [`layers`] and the
//! install's own environment are read; a value passed later at launch (for
//! example `--settings`) cannot be seen here.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::claude_install_target_text as text;
use super::{path_text, Ctx};

const CONFIG_DIR_ENV: &str = "CLAUDE_CONFIG_DIR";
/// Settings files are small. A project can point `.claude/settings.json` at a
/// device or a huge file, so reads stop here instead of running to EOF.
const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;
#[cfg(test)]
const TEST_MANAGED_SETTINGS_ENV: &str = "HOL_GUARD_TEST_CLAUDE_MANAGED_SETTINGS";

/// Claude Code's managed settings file for this OS. Only the documented
/// locations; anything else is not guessed.
fn managed_settings(ctx: &Ctx) -> PathBuf {
    // Tests must not read the host's real managed policy.
    #[cfg(test)]
    if let Some(path) = ctx.env.get(TEST_MANAGED_SETTINGS_ENV) {
        return PathBuf::from(path);
    }
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

/// The bytes of a regular settings file no larger than
/// [`MAX_SETTINGS_BYTES`]. Devices, FIFOs, directories and oversized files are
/// not read.
fn read_settings(path: &Path) -> Option<Vec<u8>> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_SETTINGS_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_SETTINGS_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= MAX_SETTINGS_BYTES).then_some(bytes)
}

/// The boolean `key` in the file, when it is a JSON object that sets one.
/// Unreadable or malformed files set nothing; Claude Code reports those itself.
fn flag(ctx: &Ctx, path: &Path, key: &str) -> Option<bool> {
    read_settings(&ctx.absolute(path))
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value.get(key).and_then(Value::as_bool))
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
    let dir = ctx.resolved(Path::new(value));
    let written = ctx.resolved(settings.parent()?);
    if dir == written {
        return None;
    }
    Some(path_text(&dir))
}

fn overrides(ctx: &Ctx, layers: &[Layer], settings: &Path) -> Vec<Value> {
    let mut found = Vec::new();
    // Claude Code uses the highest-precedence file that sets the key, so a
    // project `false` re-enables hooks that user settings turned off.
    let effective = layers
        .iter()
        .find_map(|layer| flag(ctx, &layer.path, "disableAllHooks").map(|value| (layer, value)));
    if let Some((layer, true)) = effective {
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
    let managed = &layers[0];
    if flag(ctx, &managed.path, "allowManagedHooksOnly") == Some(true) {
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

/// The uninstall command for this install. It names the same home and Guard
/// home the install used, so the undo edits the file reported here and never
/// a different installation.
fn rollback_command(ctx: &Ctx) -> Vec<String> {
    let mut command = vec![
        "hol-guard".to_owned(),
        "uninstall".to_owned(),
        "claude-code".to_owned(),
    ];
    // The CLI takes the Guard home from `--home` when one is given, and from
    // the user's home otherwise, so name it whenever it differs from that.
    let implied_guard_home = if ctx.default_home() {
        ctx.user_home.join(".hol-guard")
    } else {
        command.push("--home".to_owned());
        command.push(path_text(&ctx.home));
        ctx.home.clone()
    };
    if ctx.resolved(&ctx.guard_home) != ctx.resolved(&implied_guard_home) {
        command.push("--guard-home".to_owned());
        command.push(path_text(&ctx.guard_home));
    }
    command
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
    let command = rollback_command(ctx);
    let command_text = command
        .iter()
        .map(|word| shell_word(word, ctx.windows))
        .collect::<Vec<_>>()
        .join(" ");
    let mut answer = json!({
        "scope": "user",
        "settings_path": path_text(settings),
        "workspace": ctx.workspace.as_deref().map(path_text),
        "workspace_note": workspace_note,
        "precedence": precedence,
        "hooks_merge": "Claude Code runs the hooks from every settings file together; a project \
            file cannot remove Guard's user entries, but the overrides below can turn them off.",
        "hook_overrides": overrides,
        "background": "Headless `claude -p` runs and Remote Control sessions continue on this \
            machine and read the same user settings. Cloud sessions (Claude Code on the web) run \
            elsewhere, do not read this file, and Guard does not cover them. Sessions started \
            with `--bare`, or with setting sources that leave out `user`, skip Guard's hooks. \
            Background sessions (`claude --bg`) run them but are not qualified with Guard.",
        "rollback": {
            "command": command,
            // The command for the shell that will run it, so the caller shows
            // it as is: PowerShell on Windows, POSIX sh elsewhere.
            "command_text": command_text,
            "shell": if ctx.windows { "powershell" } else { "sh" },
            "path": path_text(settings),
            "effect": "Removes only Guard's hook entries from this file and leaves every other \
                setting. It makes no backup; `hol-guard hooks remove --all` backs the file up \
                first.",
        },
    });
    answer["border"] = json!(text::border(&answer));
    answer["text"] = json!(text::lines(&answer));
    answer
}

/// Install notes for the manifest: the file written, the rollback, and one
/// line per override that would silence the hooks.
pub(super) fn notes(target: &Value) -> Vec<String> {
    let text = |key: &str| target.get(key).and_then(Value::as_str).unwrap_or_default();
    let undo = target
        .pointer("/rollback/command")
        .and_then(Value::as_array)
        .map(|words| {
            words
                .iter()
                .filter_map(Value::as_str)
                .map(|word| shell_word(word, cfg!(windows)))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_else(|| "hol-guard uninstall claude-code".to_owned());
    let shell = if cfg!(windows) { " in PowerShell" } else { "" };
    let mut notes = vec![
        format!(
            "Guard writes its hook entries to user settings at {}.",
            text("settings_path")
        ),
        format!(
            "To undo, run{shell} `{undo}`; it removes only Guard's entries from {}.",
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

/// Quote a word when it holds anything beyond plain path characters, so a
/// copied undo command keeps the path literal. On Windows the command is for
/// PowerShell, where only single quotes are literal (`$` and backtick expand
/// inside double quotes) and a single quote is escaped by doubling it.
pub(super) fn shell_word(word: &str, windows: bool) -> String {
    let plain_chars = if windows { "-_./:\\" } else { "-_./:@%+=," };
    let plain = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || plain_chars.contains(c));
    if plain {
        word.to_owned()
    } else if windows {
        // PowerShell ends a single-quoted string at the ASCII quote and at
        // the typographic quotes U+2018 to U+201B, so each one is doubled.
        let mut out = String::from("'");
        for c in word.chars() {
            if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
                out.push(c);
            }
            out.push(c);
        }
        out.push('\'');
        out
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}
