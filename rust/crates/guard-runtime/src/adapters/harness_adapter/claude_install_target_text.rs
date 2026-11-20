//! The panel the install and plan screens show for the Claude Code settings
//! target, ported from `render_settings_target`. The runtime words the lines
//! and picks the border; the CLI prints them as plain text.

use serde_json::Value;

/// The border of the panel: red when a project file would turn the hooks off.
pub(super) fn border(target: &Value) -> &'static str {
    let overridden = target
        .get("hook_overrides")
        .and_then(Value::as_array)
        .is_some_and(|overrides| !overrides.is_empty());
    if overridden {
        "red"
    } else {
        "cyan"
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn shown(value: &Value, key: &str) -> String {
    text(value, key).unwrap_or("None").to_owned()
}

/// The panel body, one line per fact.
pub(super) fn lines(target: &Value) -> String {
    let mut lines = vec![format!(
        "Writes: {} ({} settings)",
        shown(target, "settings_path"),
        shown(target, "scope")
    )];
    if let Some(note) = text(target, "workspace_note").filter(|note| !note.is_empty()) {
        lines.push(note.to_owned());
    }
    if let Some(precedence) = target.get("precedence").and_then(Value::as_array) {
        lines.push("Claude Code reads, highest precedence first:".to_owned());
        for layer in precedence.iter().filter(|layer| layer.is_object()) {
            let marker = if layer.get("guard_writes") == Some(&Value::Bool(true)) {
                "  * "
            } else {
                "  - "
            };
            lines.push(format!(
                "{marker}{}: {}",
                shown(layer, "scope"),
                shown(layer, "path")
            ));
        }
    }
    for key in ["hooks_merge", "background"] {
        if let Some(value) = text(target, key).filter(|value| !value.is_empty()) {
            lines.push(value.to_owned());
        }
    }
    if let Some(rollback) = target.get("rollback").filter(|value| value.is_object()) {
        if let Some(undo) = text(rollback, "command_text") {
            let label = if text(rollback, "shell") == Some("powershell") {
                "Undo (PowerShell)"
            } else {
                "Undo"
            };
            let effect = text(rollback, "effect").unwrap_or_default();
            lines.push(format!("{label}: {undo}. {effect}").trim_end().to_owned());
        }
    }
    if let Some(overrides) = target.get("hook_overrides").and_then(Value::as_array) {
        for item in overrides.iter().filter(|item| item.is_object()) {
            lines.push(format!("Warning: {}", shown(item, "message")));
        }
    }
    lines.join("\n")
}
