//! `package_manager_launch_path`: the `PATH` a package manager that Guard
//! reviewed runs with, without Guard's own package shim directory.
//!
//! A package request reviews and launches the real package manager. While the
//! interception shims (`<guard_home>/package-shims/bin`) stay on `PATH`, the
//! reviewed launch would resolve a shim and re-enter Guard instead. Every
//! entry that resolves to the shim directory is dropped, as are empty entries;
//! every other entry is kept as it was spelled.
//!
//! The caller passes its own `PATH`, separator, working directory and home, so
//! a relative or `~` entry resolves the way the launching process sees it. An
//! entry that cannot be resolved refuses the launch rather than guessing
//! whether it names the shims; that includes a `~user` entry, whose account
//! this op does not look up.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::aibom_paths::resolve;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const MAX_PATH_BYTES: usize = 1024 * 1024;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let guard_home = absolute(text(args, "guard_home")?).ok_or(ERR_INVALID)?;
    let launch_cwd = absolute(text(args, "launch_cwd")?).ok_or(ERR_INVALID)?;
    let user_home = match args.get("user_home") {
        None | Some(Value::Null) => None,
        Some(Value::String(home)) => Some(absolute(home).ok_or(ERR_INVALID)?),
        Some(_) => return Err(ERR_INVALID),
    };
    let separator = text(args, "separator")?;
    if separator != ":" && separator != ";" {
        return Err(ERR_INVALID);
    }
    let path = text(args, "path")?;
    if path.len() > MAX_PATH_BYTES {
        return Err(ERR_INVALID);
    }
    let Ok(shim_dir) = resolve(&posix_root(guard_home.join("package-shims").join("bin"))) else {
        return Ok(json!({ "refused": "shim_unverified" }));
    };
    let shim_dir = long_names(shim_dir);
    let mut kept = Vec::new();
    for entry in path.split(separator).filter(|entry| !entry.is_empty()) {
        let resolved = expand_user(entry, user_home.as_deref())
            .map(|expanded| posix_root(launch_cwd.join(expanded)))
            .and_then(|joined| resolve(&joined).ok())
            .map(long_names);
        let Some(resolved) = resolved else {
            return Ok(json!({ "refused": "path_unverified" }));
        };
        if !same_path(&resolved, &shim_dir) {
            kept.push(entry);
        }
    }
    Ok(json!({ "path": kept.join(separator) }))
}

fn text<'a>(args: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    args.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

fn absolute(text: &str) -> Option<PathBuf> {
    let path = PathBuf::from(text);
    (!text.contains('\0') && path.is_absolute()).then_some(path)
}

/// `Path.expanduser()` for `~` and `~/rest` (and `~\rest` on Windows); `None`
/// for a NUL, for `~` without a home, and for a `~user` entry.
fn expand_user(entry: &str, home: Option<&Path>) -> Option<PathBuf> {
    if entry.contains('\0') {
        return None;
    }
    let Some(rest) = entry.strip_prefix('~') else {
        return Some(PathBuf::from(entry));
    };
    let separated = rest.starts_with('/') || (cfg!(windows) && rest.starts_with('\\'));
    if !rest.is_empty() && !separated {
        return None;
    }
    let rest = rest.trim_start_matches(|c: char| c == '/' || (cfg!(windows) && c == '\\'));
    let home = home?;
    Some(if rest.is_empty() {
        home.to_path_buf()
    } else {
        home.join(rest)
    })
}

/// Linux and macOS treat a leading `//` as `/`, so `//usr/bin` names
/// `/usr/bin`. The resolver refuses that spelling, so it is folded first;
/// three or more slashes already mean the root.
fn posix_root(path: PathBuf) -> PathBuf {
    let collapsed = path
        .to_str()
        .and_then(|text| text.strip_prefix('/'))
        .filter(|rest| cfg!(unix) && rest.starts_with('/') && !rest.starts_with("//"))
        .map(PathBuf::from);
    collapsed.unwrap_or(path)
}

/// Windows also names a directory by its 8.3 short name (`PROGRA~1`), which
/// Python's `Path.resolve` expands to the long one. The longest existing
/// prefix is canonicalized there so both spellings compare equal; a missing
/// tail is kept as it was resolved.
fn long_names(path: PathBuf) -> PathBuf {
    if cfg!(windows) {
        canonical_prefix(&path).unwrap_or(path)
    } else {
        path
    }
}

fn canonical_prefix(path: &Path) -> Option<PathBuf> {
    let mut missing = Vec::new();
    let mut existing = path;
    loop {
        if let Ok(mut canonical) = std::fs::canonicalize(existing) {
            canonical.extend(missing.iter().rev());
            return Some(canonical);
        }
        missing.push(existing.file_name()?);
        existing = existing.parent()?;
    }
}

/// Python compares Windows paths without regard to case, and a link whose
/// target is spelled `\\?\C:\...` still names `C:\...`.
fn same_path(left: &Path, right: &Path) -> bool {
    if cfg!(windows) {
        windows_spelling(left) == windows_spelling(right)
    } else {
        left == right
    }
}

fn windows_spelling(path: &Path) -> String {
    let text = path.to_string_lossy();
    let plain = if let Some(share) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{share}")
    } else if let Some(drive) = text.strip_prefix(r"\\?\") {
        drive.to_owned()
    } else {
        text.into_owned()
    };
    plain.to_lowercase()
}

#[cfg(test)]
#[path = "package_manager_launch_path_tests.rs"]
mod tests;
