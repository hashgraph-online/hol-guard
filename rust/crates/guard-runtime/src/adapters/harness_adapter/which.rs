//! Command lookup as the caller's process answers it: `shutil.which` over the
//! caller's `PATH`, then the user install directories `user_command_lookup`
//! searches. Relative `PATH` entries are checked against the caller's working
//! directory, but the answer keeps the form `shutil.which` would return.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::{path_text, Ctx};

/// `os.confstr("CS_PATH")`, or `os.defpath` where there is none.
const DEFAULT_PATH: &str = if cfg!(target_os = "macos") {
    "/usr/bin:/bin:/usr/sbin:/sbin"
} else if cfg!(windows) {
    ".;C:\\bin"
} else {
    "/bin:/usr/bin"
};

const WINDOWS_PATHEXT: &str = ".COM;.EXE;.BAT;.CMD;.VBS;.JS;.WS;.MSC";

/// `os.access(path, os.X_OK)` for the calling user.
#[cfg(unix)]
pub(crate) fn executable(path: &Path) -> bool {
    use nix::unistd::{access, AccessFlags};
    access(path, AccessFlags::X_OK).is_ok()
}

#[cfg(not(unix))]
pub(crate) fn executable(path: &Path) -> bool {
    path.exists()
}

/// `shutil._access_check`: exists, executable and not a directory.
fn access_check(ctx: &Ctx, name: &Path) -> bool {
    let path = ctx.absolute(name);
    path.exists() && executable(&path) && !path.is_dir()
}

fn has_dirname(command: &str, windows: bool) -> bool {
    command.contains('/') || (windows && command.contains('\\'))
}

fn normcase(directory: &str, windows: bool) -> String {
    if windows {
        directory.replace('/', "\\").to_lowercase()
    } else {
        directory.to_owned()
    }
}

/// `shutil.which(command)` in the caller's process.
pub(crate) fn which(ctx: &Ctx, command: &str) -> Option<String> {
    let windows = ctx.windows;
    if has_dirname(command, windows) {
        return access_check(ctx, Path::new(command)).then(|| command.to_owned());
    }
    let search = ctx.env("PATH").unwrap_or(DEFAULT_PATH);
    if search.is_empty() {
        return None;
    }
    let separator = if windows { ';' } else { ':' };
    let mut directories: Vec<&str> = search.split(separator).collect();
    let mut files = vec![command.to_owned()];
    if windows {
        if ctx.env("NoDefaultCurrentDirectoryInExePath").is_none() {
            directories.insert(0, ".");
        }
        let source = ctx
            .env("PATHEXT")
            .filter(|value| !value.is_empty())
            .unwrap_or(WINDOWS_PATHEXT);
        let extensions: Vec<&str> = source.split(';').filter(|ext| !ext.is_empty()).collect();
        files.extend(extensions.iter().map(|ext| format!("{command}{ext}")));
        let suffix = Path::new(command)
            .extension()
            .map(|ext| format!(".{}", ext.to_string_lossy()).to_uppercase())
            .unwrap_or_default();
        if !extensions.iter().any(|ext| ext.to_uppercase() == suffix) {
            files.rotate_left(1);
        }
    }
    let mut seen = BTreeSet::new();
    for directory in directories {
        if !seen.insert(normcase(directory, windows)) {
            continue;
        }
        for file in &files {
            let name = Path::new(directory).join(file);
            if access_check(ctx, &name) {
                return Some(path_text(&name));
            }
        }
    }
    None
}

/// `_which_from_user_directories`: a CLI installed outside the caller's PATH.
pub(crate) fn user_directory_command(
    ctx: &Ctx,
    command: &str,
    home: &Path,
    extra: &[PathBuf],
) -> Option<String> {
    if ctx.windows || command.contains('/') {
        return None;
    }
    let request = json!({
        "command": command,
        "home": path_text(home),
        "path": ctx.env("PATH"),
        "extra": extra.iter().map(|directory| path_text(directory)).collect::<Vec<_>>(),
    });
    match crate::user_command_lookup::dispatch(&request)
        .ok()?
        .get("path")
    {
        Some(Value::String(path)) => Some(path.clone()),
        _ => None,
    }
}

/// `_command_available`; `home` defaults to the caller's own home.
pub(crate) fn command_available(
    ctx: &Ctx,
    command: &str,
    home: Option<&Path>,
    extra: &[PathBuf],
) -> bool {
    which(ctx, command).is_some()
        || user_directory_command(ctx, command, home.unwrap_or(&ctx.user_home), extra).is_some()
}

/// `_resolve_command`: PATH first, then the first executable candidate.
pub(crate) fn resolve_command(ctx: &Ctx, command: &str, candidates: &[PathBuf]) -> Option<String> {
    which(ctx, command).or_else(|| {
        candidates
            .iter()
            .find(|candidate| {
                let path = ctx.absolute(candidate);
                path.is_file() && executable(&path)
            })
            .map(|candidate| path_text(candidate))
    })
}
