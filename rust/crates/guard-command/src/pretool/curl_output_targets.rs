//! Files a proven network read may save its body to without review: a file
//! under a plain dot-named scratch directory in the workspace, such as
//! `.tmp/repo.json`, or a private temporary file such as `/tmp/repo.json`.
//!
//! A response body is remote content. Saved anywhere else in the workspace it
//! could replace a manifest, a test helper or a script that a later allowed
//! command loads, so those targets keep their review. No tool loads code or
//! configuration from a scratch directory on its own.

use std::path::{Component, Path};

/// Dot-named directories that only hold scratch output.
const SCRATCH_DIRECTORIES: &[&str] = &[".scratch", ".temp", ".tmp"];

/// A literal scratch file the user may write: below a scratch directory of
/// the workspace and accepted by the file-edit write check, or a private
/// temporary file. An existing executable never qualifies.
pub(in crate::pretool) fn scratch_output_target(
    target: &str,
    context: crate::pretool::PathContext<'_>,
) -> bool {
    if target.is_empty()
        || target.len() > 4096
        || target.starts_with(['-', '~'])
        || !target
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || "._-/+@%,=".contains(value))
        || crate::pretool::sensitive_command(target)
        || existing_executable(target, context.cwd)
    {
        return false;
    }
    let path = Path::new(target);
    if path.is_absolute() {
        return crate::pretool::chain_temporary::temporary_file_target(
            target,
            context.home_dir,
            context.cwd,
        );
    }
    let mut names = Vec::new();
    for component in path.components() {
        let Component::Normal(name) = component else {
            return false;
        };
        let Some(name) = name.to_str() else {
            return false;
        };
        names.push(name.to_ascii_lowercase());
    }
    let Some((_, directories)) = names.split_last() else {
        return false;
    };
    directories
        .iter()
        .any(|name| SCRATCH_DIRECTORIES.contains(&name.as_str()))
        && crate::pretool::safe_writes::bounded_native_file_write_target(
            target,
            context.home_dir,
            context.cwd,
        )
}

/// An existing regular file with an execute bit. Truncating it replaces a
/// program that a later step may run.
pub(in crate::pretool) fn existing_executable(target: &str, cwd: Option<&str>) -> bool {
    let path = Path::new(target);
    let path = match cwd {
        Some(cwd) if !path.is_absolute() => Path::new(cwd).join(path),
        _ => path.to_path_buf(),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::metadata(&path)
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}
