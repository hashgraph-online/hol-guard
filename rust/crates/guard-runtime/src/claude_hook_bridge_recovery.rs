//! The daemon recovery command for a Claude hook command written before the
//! native bridge.
//!
//! An installed native command carries its `recovery_command`. The legacy
//! Python launcher instead names the program that recovers the daemon (an
//! interpreter with its package root, or a frozen Guard) as
//! `recovery_launcher`, and the command is built here from the same state
//! path and query the bridge already reads.

use std::path::{Component, Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::claude_hook_bridge::home_directory;
use crate::claude_hook_bridge_url::{query_values, resolve_absolute};
use crate::guard_store_json::dumps_sorted;
use crate::hook_process_spawn::isolated_daemon_start_command;

/// `FROZEN_DAEMON_RECOVER_ARG`.
pub(crate) const FROZEN_RECOVER_ARG: &str = "--_hol-guard-codex-daemon-recover";

/// `Path(text)`: repeated and trailing separators and `.` parts dropped.
fn pure_path(text: &str) -> PathBuf {
    Path::new(text)
        .components()
        .filter(|part| !matches!(part, Component::CurDir))
        .collect()
}

/// `str(path.resolve(strict=False))`, a relative path taken from the cwd.
fn resolved(path: &Path) -> Option<String> {
    let absolute = std::path::absolute(path).ok()?;
    Some(resolve_absolute(absolute.to_str()?))
}

/// `frozen_daemon_recovery_command(guard_home, home_dir, executable=...)`
/// (`frozen_runtime_commands.py`).
pub(crate) fn frozen_recovery_command(
    executable: &str,
    guard_home: &Path,
    home_dir: &Path,
) -> Option<Vec<String>> {
    let payload = json!({
        "guard_home": resolved(guard_home)?,
        "home_dir": resolved(home_dir)?,
    });
    Some(vec![
        executable.to_owned(),
        FROZEN_RECOVER_ARG.to_owned(),
        dumps_sorted(&payload)?,
    ])
}

/// `_recovery_command(state_path, query)` for the launcher that named itself.
pub(crate) fn launcher_recovery(
    state_path: &str,
    query: &str,
    launcher: &Map<String, Value>,
) -> Option<Vec<String>> {
    let executable = launcher.get("executable")?.as_str()?;
    if executable.is_empty() || state_path.contains('\0') {
        return None;
    }
    let guard_home = pure_path(state_path).parent()?.to_path_buf();
    let home_dir = match query_values(query, "home").first() {
        Some(home) => pure_path(home),
        None => home_directory()?,
    };
    match (launcher.get("frozen"), launcher.get("package_root")) {
        (Some(Value::Bool(true)), None) => {
            frozen_recovery_command(executable, &guard_home, &home_dir)
        }
        (None | Some(Value::Bool(false)), Some(Value::String(root))) if !root.is_empty() => {
            Some(isolated_daemon_start_command(
                executable,
                Path::new(root),
                &guard_home,
                Some(&home_dir),
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "claude_hook_bridge_recovery_tests.rs"]
mod tests;
