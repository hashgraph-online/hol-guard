//! Desktop Core layout facts a generated Pi-family extension depends on.
//!
//! Desktop installs each Core release under `versions/<release>/` (launcher at
//! `<release>/hol-guard` or `<release>/bundle/hol-guard`) or `bundled/<release>/`
//! and moves its `current.json` pointer on every update. A stable
//! `current-hol-guard` launcher beside those directories survives the update,
//! so an extension bakes that launcher and never a versioned one.

use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use super::{which, Ctx};

const CURRENT_HOL_GUARD_SHIM: &str = "current-hol-guard";
const POINTER: &str = "current.json";
const MAX_POINTER_BYTES: u64 = 64 * 1024;

fn launcher_name(path: &Path) -> bool {
    path.file_name()
        .map(|name| name.to_string_lossy().to_lowercase())
        .is_some_and(|name| name == "hol-guard" || name == "hol-guard.exe")
}

fn lower_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

/// `executable.relative_to(ancestor).parts` for every ancestor, nearest first.
fn ancestors(executable: &Path) -> impl Iterator<Item = (&Path, Vec<String>)> {
    executable.ancestors().skip(1).filter_map(move |ancestor| {
        let relative = executable.strip_prefix(ancestor).ok()?;
        let parts = relative
            .components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect();
        Some((ancestor, parts))
    })
}

/// Whether a path below `versions/` is a Core launcher: `<release>/hol-guard`
/// or Desktop's `<release>/bundle/hol-guard`.
fn versioned_launcher(parts: &[String]) -> bool {
    parts.len() == 2 || (parts.len() == 3 && parts[1] == "bundle")
}

fn core_root(executable: &Path) -> Option<PathBuf> {
    if !launcher_name(executable) {
        return None;
    }
    for (ancestor, parts) in ancestors(executable) {
        let name = lower_name(ancestor);
        if name == "versions" && versioned_launcher(&parts) {
            return ancestor.parent().map(Path::to_path_buf);
        }
        if name != "bundled" {
            continue;
        }
        let bin = parts.len() == 3 && parts[1] == "bin";
        let lib = parts.len() == 4 && parts[1] == "lib" && parts[2] == "hol-guard-core";
        if bin || lib {
            return ancestor.parent().map(Path::to_path_buf);
        }
    }
    None
}

/// The stable `current-hol-guard` launcher next to a versioned or bundled Core.
pub(super) fn shim_for_executable(ctx: &Ctx, executable: &Path) -> Option<PathBuf> {
    let root = core_root(executable)?;
    let unix = root.join(CURRENT_HOL_GUARD_SHIM);
    if !ctx.windows {
        return Some(unix);
    }
    let windows = root.join(format!("{CURRENT_HOL_GUARD_SHIM}.cmd"));
    if ctx.absolute(&windows).is_file() || !ctx.absolute(&unix).is_file() {
        return Some(windows);
    }
    Some(unix)
}

/// Whether a frozen launcher can run as argv0.
pub(super) fn runnable(ctx: &Ctx, path: &Path) -> bool {
    let path = ctx.absolute(path);
    path.is_file() && (ctx.windows || which::executable(&path))
}

/// Desktop's app-data `current-hol-guard`, which outranks a PATH install.
pub(super) fn durable_current(ctx: &Ctx, home: &Path) -> Option<PathBuf> {
    let home = super::kimi::expand_user(ctx, &home.to_string_lossy());
    let mut roots = Vec::new();
    if let Some(data) = ctx
        .env("XDG_DATA_HOME")
        .map(str::trim)
        .filter(|data| !data.is_empty())
    {
        roots.push(super::kimi::expand_user(ctx, data));
    }
    if cfg!(target_os = "macos") {
        roots.push(home.join("Library").join("Application Support"));
    } else if ctx.windows {
        match ctx
            .env("APPDATA")
            .map(str::trim)
            .filter(|data| !data.is_empty())
        {
            Some(appdata) => roots.push(super::kimi::expand_user(ctx, appdata)),
            None => roots.push(home.join("AppData").join("Roaming")),
        }
    }
    roots.push(home.join(".local").join("share"));
    let mut seen = Vec::new();
    for root in roots {
        let key = ctx.resolved(&root);
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        let shim = root
            .join("org.hol.guard.desktop")
            .join("core")
            .join(CURRENT_HOL_GUARD_SHIM);
        if runnable(ctx, &shim) {
            return Some(shim);
        }
    }
    None
}

/// The Core root and release of a launcher below `versions/<release>/`.
fn versioned_root(executable: &Path) -> Option<(PathBuf, String)> {
    if !launcher_name(executable) {
        return None;
    }
    ancestors(executable)
        .filter(|(ancestor, _)| lower_name(ancestor) == "versions")
        .find(|(_, parts)| versioned_launcher(parts))
        .and_then(|(ancestor, parts)| Some((ancestor.parent()?.to_path_buf(), parts[0].clone())))
}

/// The release whose launcher `current.json` selects, or `None` when the
/// pointer cannot be judged.
fn selected_release(ctx: &Ctx, root: &Path) -> Option<String> {
    let pointer = ctx.absolute(&root.join(POINTER));
    let meta = std::fs::symlink_metadata(&pointer).ok()?;
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > MAX_POINTER_BYTES {
        return None;
    }
    let text = std::fs::read_to_string(&pointer).ok()?;
    let document: Value = serde_json::from_str(&text).ok()?;
    let relative = document.get("relativePath")?.as_str()?;
    if relative.is_empty() || relative.contains('\\') || relative.starts_with('/') {
        return None;
    }
    // `PurePosixPath` drops empty and `.` segments before `parts` is read.
    let parts: Vec<String> = Path::new(relative)
        .components()
        .filter_map(|part| match part {
            Component::Normal(name) => Some(Ok(name.to_string_lossy().into_owned())),
            Component::CurDir => None,
            _ => Some(Err(())),
        })
        .collect::<Result<_, _>>()
        .ok()?;
    if parts.len() < 2 || parts[0] != "versions" {
        return None;
    }
    let launcher = &parts[1..];
    let last = launcher.last()?.to_lowercase();
    if (last == "hol-guard" || last == "hol-guard.exe") && versioned_launcher(launcher) {
        return Some(launcher[0].clone());
    }
    None
}

/// Whether `executable` is a Core release `current.json` no longer selects.
pub(super) fn superseded(ctx: &Ctx, executable: &Path) -> bool {
    let Some((root, running)) = versioned_root(executable) else {
        return false;
    };
    selected_release(ctx, &root).is_some_and(|selected| selected != running)
}
