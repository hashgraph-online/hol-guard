//! Shared helpers of the routine ports: `Path.resolve(strict=True)`, absolute
//! paths and the `tool_action_requests.py` git-status wrappers.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use crate::codex_output_env::{Ctx, GitCheck};
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::PyPath;
use crate::sfrs_pytest_config_safety::shell_args_without_trailing_redirections;
use crate::sfrs_static_safety::shell_token_has_command_substitution;

/// `Path.absolute()`: a relative path is joined to the process directory.
pub(crate) fn absolute(path: &PyPath, ctx: &Ctx) -> PyPath {
    if path.is_absolute() {
        path.clone()
    } else {
        ctx.process_cwd.join(&path.to_string())
    }
}

/// `Path.resolve(strict=False)`; a relative path starts at the process
/// directory. `None` is the `OSError`/`RuntimeError` Python raises.
pub(crate) fn resolve(path: &PyPath, ctx: &Ctx) -> Option<PyPath> {
    pyfs::resolve(&absolute(path, ctx))
}

/// `Path.resolve(strict=True)`: every component must exist. Each cumulative
/// prefix is probed with the operating system so `missing/..` still fails.
pub(crate) fn resolve_strict(path: &PyPath, ctx: &Ctx) -> Option<PyPath> {
    let full = absolute(path, ctx);
    let resolved = pyfs::resolve(&full)?;
    let mut stack: Vec<&str> = Vec::new();
    for part in full.components() {
        let prefix = format!("/{}", stack.join("/"));
        // `os.path.realpath` pops `..` lexically, so a plain file followed by
        // `..` still resolves; a symlink or directory keeps the OS answer.
        if part == ".." {
            let plain_file = std::fs::symlink_metadata(&prefix)
                .is_ok_and(|meta| !meta.is_dir() && !meta.file_type().is_symlink());
            if plain_file {
                stack.pop();
                continue;
            }
        }
        stack.push(part);
        let probe = format!("/{}", stack.join("/"));
        if std::fs::metadata(&probe).is_err() {
            return None;
        }
    }
    (pyfs::exists(&resolved) == Ok(true)).then_some(resolved)
}

pub(crate) fn to_path(path: &PyPath) -> PathBuf {
    PathBuf::from(path.to_string())
}

/// `Path.is_relative_to`.
pub(crate) fn is_relative_to(path: &PyPath, base: &PyPath) -> bool {
    path.relative_to(base).is_some()
}

/// `_safe_git_status_cd_target`.
pub(crate) fn safe_git_status_cd_target(
    command_name: &str,
    args: &[String],
    cwd: &Path,
    ctx: &Ctx,
) -> Option<PathBuf> {
    if command_name != "cd" {
        return None;
    }
    let path_args = shell_args_without_trailing_redirections(args);
    if path_args != args || path_args.len() != 1 || matches!(path_args[0].as_str(), "-" | "--") {
        return None;
    }
    let path_text = &path_args[0];
    if shell_token_has_command_substitution(path_text) || path_text.contains('\0') {
        return None;
    }
    let candidate = ctx.expanduser(path_text)?;
    let candidate = if candidate.is_absolute() {
        candidate
    } else {
        PyPath::new(&cwd.to_string_lossy()).join(&candidate.to_string())
    };
    let resolved = resolve(&candidate, ctx)?;
    (pyfs::is_dir(&resolved) == Ok(true)).then(|| to_path(&resolved))
}

/// `_git_status_has_execution_free_config`.
pub(crate) fn git_status_has_execution_free_config(cwd: Option<&Path>, ctx: &Ctx) -> bool {
    let base = cwd.map_or_else(
        || ctx.process_cwd.clone(),
        |path| PyPath::new(&path.to_string_lossy()),
    );
    let Some(execution_cwd) = resolve(&base, ctx) else {
        return false;
    };
    ctx.host.git_safety(
        GitCheck::StatusConfig,
        Some(&execution_cwd.to_string()),
        &[],
    )
}

/// `_git_status_args_are_read_only`.
pub(crate) fn git_status_args_are_read_only(args: &[String], ctx: &Ctx) -> bool {
    ctx.host.git_safety(GitCheck::StatusArguments, None, args)
}
