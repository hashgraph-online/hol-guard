//! The Cursor CLI surface's install manifest.

use serde_json::{Map, Value};

use super::{files, get, parse_object, path_text, Ctx, Doc, Failure, PyVal, Step};
use super::{HARNESS, SHIM_COMMANDS};

/// The CLI surface's manifest over the two shims and the shell profile.
pub(super) fn cli_manifest(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let parsed = |key: &str| -> Step<Vec<(String, PyVal)>> {
        let raw = fields
            .get(key)
            .and_then(Value::as_str)
            .ok_or(Failure::Invalid)?;
        parse_object(raw).ok_or(Failure::Invalid)
    };
    let (agent, cursor, profile) = (
        parsed("agent_shim")?,
        parsed("cursor_shim")?,
        parsed("profile")?,
    );
    let bin = path_text(&ctx.guard_home.join("bin"));
    let mut notes = files::shim_notes(&agent);
    notes.push(files::text(
        "Use guard-cursor-agent for the standalone cursor-agent binary.",
    ));
    notes.push(files::text(
        "Use guard-cursor agent ... when launching through the Cursor app CLI.",
    ));
    notes.push(files::text(format!("Guard launcher shims live in {bin}.")));
    let truthy = |key: &str| get(&profile, key).is_some_and(PyVal::truthy);
    if truthy("changed") {
        notes.push(files::text(
            "Prepended the Guard launcher shim directory to your shell profile.",
        ));
    } else if truthy("restart_shell_required") {
        notes.push(files::text(
            "Restart your shell or open a new terminal so guard-cursor shims are on PATH.",
        ));
    } else if truthy("manual_path_required") {
        notes.push(files::text(format!(
            "Put {bin} first on your PATH so guard-cursor shims run."
        )));
    }
    let field =
        |shim: &[(String, PyVal)], key: &str| get(shim, key).cloned().ok_or(Failure::Invalid);
    let mut doc = Doc::default();
    doc.set("harness", files::text(HARNESS))
        .set("active", PyVal::Bool(true))
        .set("surface", files::text("cli"))
        .set("shim_path", field(&agent, "shim_path")?)
        .set("shim_dir", field(&agent, "shim_dir")?)
        .set("shim_command", field(&agent, "shim_command")?)
        .set(
            "shim_paths",
            PyVal::List(vec![
                field(&agent, "shim_path")?,
                field(&cursor, "shim_path")?,
            ]),
        )
        .set(
            "shim_commands",
            PyVal::List(
                SHIM_COMMANDS
                    .iter()
                    .map(|name| files::text(*name))
                    .collect(),
            ),
        )
        .set(
            "windows_shim_path",
            get(&agent, "windows_shim_path")
                .cloned()
                .unwrap_or(PyVal::Null),
        )
        .set("shell_profile", PyVal::Dict(profile))
        .set("notes", PyVal::List(notes));
    files::manifest_answer(doc)
}
