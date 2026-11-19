//! `prepare_guard_shim_shell_profile`: the shell profile change that puts
//! the harness launcher directory first on PATH, captured without a write.
//! Ported from `prepare_guard_shim_shell_profile` in `guard/shims.py`.
//!
//! Request fields: `shell` (the name of the user's login shell, `SHELL`'s
//! last component) and `shim_dir_transient` (the Guard process's own
//! answer, shared with the shim status facts). Answer: `files` (the one profile change, or none) and
//! `manifest`. A Windows host, or a Guard home in a temporary directory,
//! gets no change and a manifest that asks the user to add the PATH entry.

use std::path::Path;

use guard_command::shims::guard_shim_profile_content;
use serde_json::{json, Map, Value};

use super::files::{mode, snapshot, within_root, Change};
use super::{path_text, Ctx, Failure, Step};

/// The profile under the home directory for each shell; any other shell
/// uses `.zshrc`.
fn profile_parts(shell: &str) -> &'static [&'static str] {
    match shell {
        "fish" => &[".config", "fish", "config.fish"],
        "bash" => &[".bashrc"],
        _ => &[".zshrc"],
    }
}

fn manual(shim_dir: &Path, reason: &str) -> Value {
    json!({
        "files": [],
        "manifest": {
            "changed": false,
            "profile_path": null,
            "shim_dir": path_text(shim_dir),
            "restart_shell_required": false,
            "manual_path_required": true,
            "manual_path_reason": reason,
        },
    })
}

/// `prepare_guard_shim_shell_profile`.
pub(super) fn prepare(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let shell = match fields.get("shell") {
        None | Some(Value::Null) => "",
        Some(Value::String(shell)) => shell.as_str(),
        Some(_) => return Err(Failure::Invalid),
    };
    let transient = match fields.get("shim_dir_transient") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => return Err(Failure::Invalid),
    };
    let shim_dir = ctx.guard_home.join("bin");
    if ctx.windows {
        return Ok(manual(&shim_dir, "unsupported_shell"));
    }
    if transient {
        return Ok(manual(&shim_dir, "transient_guard_home"));
    }
    let profile = profile_parts(shell)
        .iter()
        .fold(ctx.home.clone(), |path, part| path.join(part));
    within_root(ctx, &ctx.home, &profile, "Guard shell profile")?;
    let before = snapshot(ctx, &profile)?;
    let existing = match &before {
        Some(bytes) => std::str::from_utf8(bytes)
            .map_err(|_| Failure::Refusal("Guard shell profile is not UTF-8.".into()))?,
        None => "",
    };
    let after =
        guard_shim_profile_content(existing, &path_text(&shim_dir), shell == "fish").into_bytes();
    let file_mode = if before.is_some() {
        mode(ctx, &profile).unwrap_or(0o600)
    } else {
        0o600
    };
    let changed = before.as_deref() != Some(after.as_slice());
    let mut change = Change::at(ctx, &profile, before, Some(after), file_mode);
    change.no_follow = true;
    Ok(json!({
        "files": [change.wire()],
        "manifest": {
            "changed": changed,
            "profile_path": path_text(&profile),
            "shim_dir": path_text(&shim_dir),
            "restart_shell_required": true,
        },
    }))
}

#[cfg(all(test, unix))]
#[path = "shim_profile_tests.rs"]
mod tests;
