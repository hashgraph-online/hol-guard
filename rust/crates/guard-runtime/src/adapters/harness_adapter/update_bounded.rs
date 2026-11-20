//! The bounded hook clients older releases installed under
//! `managed/bounded-hooks`, which `hol-guard update` moves onto the native
//! runtime.
//!
//! Python reads the managed-install store, reinstalls each active harness
//! this module names and then asks for its old client to be removed.
//! Grok is repaired by its own path.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::update_support::os_failure;
use super::{Ctx, Failure, Step};

/// Harnesses older releases installed with a stable client script, with the
/// name an update warning uses for each.
const HARNESSES: [(&str, &str); 7] = [
    ("zcode", "ZCode"),
    ("devin", "Devin"),
    ("kimi", "Kimi"),
    ("copilot", "Copilot"),
    ("openclaw", "OpenClaw"),
    ("hermes", "Hermes"),
    ("muse", "Muse"),
];
const SCRIPT_DIR: [&str; 2] = ["managed", "bounded-hooks"];

/// `bounded_hook_script_path`: the client path older installs wrote.
fn script_path(guard_home: &Path, harness: &str) -> PathBuf {
    guard_home
        .join(SCRIPT_DIR[0])
        .join(SCRIPT_DIR[1])
        .join(format!("{harness}.py"))
}

/// Whether any path component below the Guard home is a symlink.
fn crosses_symlink(guard_home: &Path, harness: &str) -> bool {
    let mut current = guard_home.to_path_buf();
    SCRIPT_DIR
        .iter()
        .map(|part| (*part).to_owned())
        .chain(std::iter::once(format!("{harness}.py")))
        .any(|part| {
            current.push(part);
            current.is_symlink()
        })
}

/// `bounded_hook_scripts`: the harnesses whose old client is still a regular
/// file the update may replace and remove, in the order it moves them.
pub(super) fn scripts(ctx: &Ctx) -> Step<Value> {
    let guard_home = ctx.absolute(&ctx.guard_home);
    let stale: Vec<Value> = HARNESSES
        .iter()
        .filter(|(harness, _)| {
            !crosses_symlink(&guard_home, harness) && script_path(&guard_home, harness).is_file()
        })
        .map(|(harness, display_name)| json!({"harness": harness, "display_name": display_name}))
        .collect();
    Ok(json!({ "scripts": stale }))
}

/// `remove_bounded_hook_script`: delete a moved harness's old client, with no
/// complaint when it is already gone.
pub(super) fn remove(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let harness = fields
        .get("harness")
        .and_then(Value::as_str)
        .filter(|harness| HARNESSES.iter().any(|(known, _)| known == harness))
        .ok_or(Failure::Invalid)?;
    let path = script_path(&ctx.absolute(&ctx.guard_home), harness);
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(os_failure(ctx, &error, &path)),
    }
    Ok(json!({ "removed": true }))
}
