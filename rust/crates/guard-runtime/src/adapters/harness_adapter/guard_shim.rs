//! `prepare_guard_shim`: both launchers an install writes for a harness,
//! rendered and snapshotted without changing a file.
//!
//! Python sends the installing interpreter's facts (`executable`, `frozen`,
//! `package_interpreter`, `python_flags`, `import_root` and the ordered
//! `launcher_env` pairs) and gets back the transition files and the shim
//! manifest it publishes with the rest of the install.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::files::{mode, path_value, render, snapshot, text, Change, Doc};
use super::guard_shim_text::{harness_shim, windows_script, Interpreter};
use super::{path_text, Ctx, Failure, Step};
use crate::pyjson::PyVal;

fn string(fields: &Map<String, Value>, key: &str) -> Step<String> {
    fields
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Failure::Invalid)
}

fn optional(fields: &Map<String, Value>, key: &str) -> Step<Option<String>> {
    match fields.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(Failure::Invalid),
    }
}

fn strings(value: Option<&Value>) -> Step<Vec<String>> {
    value
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|item| item.as_str().map(str::to_owned).ok_or(Failure::Invalid))
        .collect()
}

fn interpreter(fields: &Map<String, Value>) -> Step<Interpreter> {
    let facts = fields
        .get("interpreter")
        .and_then(Value::as_object)
        .ok_or(Failure::Invalid)?;
    let launcher_env = facts
        .get("launcher_env")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|pair| match strings(Some(pair))?.as_slice() {
            [key, value] => Ok((key.clone(), value.clone())),
            _ => Err(Failure::Invalid),
        })
        .collect::<Step<_>>()?;
    Ok(Interpreter {
        executable: string(facts, "executable")?,
        frozen: facts
            .get("frozen")
            .and_then(Value::as_bool)
            .ok_or(Failure::Invalid)?,
        package_interpreter: string(facts, "package_interpreter")?,
        python_flags: strings(facts.get("python_flags"))?,
        import_root: string(facts, "import_root")?,
        launcher_env,
    })
}

/// `_home_override_args` followed by the workspace flag.
fn context_args(ctx: &Ctx) -> Vec<String> {
    let mut args = Vec::new();
    if ctx.home_explicit || !ctx.default_home() {
        args.extend(["--home".to_owned(), path_text(&ctx.home)]);
    }
    if let Some(workspace) = &ctx.workspace {
        args.extend(["--workspace".to_owned(), path_text(workspace)]);
    }
    args
}

fn change(ctx: &Ctx, path: &Path, source: &str, executable: bool) -> Step<Value> {
    let before = snapshot(ctx, path)?;
    let before_mode = if before.is_some() {
        mode(ctx, path).unwrap_or(0o644)
    } else {
        0o644
    };
    let payload = if ctx.windows {
        source.replace('\n', "\r\n")
    } else {
        source.to_owned()
    };
    let mut planned = Change::at(ctx, path, before, Some(payload.into_bytes()), before_mode);
    if executable {
        planned.after_mode = before_mode | 0o755;
    }
    Ok(planned.wire())
}

pub(super) fn prepare(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let harness = string(fields, "harness")?;
    let interpreter = interpreter(fields)?;
    let shim_name = optional(fields, "launcher_name")?.unwrap_or_else(|| harness.clone());
    let label = optional(fields, "display_name")?.unwrap_or_else(|| harness.clone());
    let shim_dir = ctx.guard_home.join("bin");
    let posix_path = shim_dir.join(format!("guard-{shim_name}"));
    let windows_path = shim_dir.join(format!("guard-{shim_name}.cmd"));
    let source = harness_shim(ctx, &harness, &context_args(ctx), &interpreter);
    let windows = windows_script(ctx, &interpreter.package_interpreter, &posix_path, &source);
    let files = vec![
        change(ctx, &posix_path, &source, true)?,
        change(ctx, &windows_path, &windows, false)?,
    ];
    let command = format!("guard-{shim_name}");
    let mut doc = Doc::default();
    doc.set("shim_path", path_value(&posix_path))
        .set("shim_dir", text(path_text(&shim_dir)))
        .set("shim_command", text(command.clone()))
        .set("windows_shim_path", path_value(&windows_path))
        .set(
            "notes",
            PyVal::List(vec![
                text(format!(
                    "Launch {label} through {command} so Guard checks changes before the harness starts."
                )),
                text(format!(
                    "Add {} to PATH to use the wrapper command from any shell.",
                    path_text(&shim_dir)
                )),
            ]),
        );
    Ok(json!({ "files": files, "manifest": render(&doc.value())? }))
}
