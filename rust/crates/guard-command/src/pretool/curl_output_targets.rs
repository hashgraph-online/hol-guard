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

/// Makes curl create every missing directory above an `-o` or `-D` file
/// before writing it. Kept out of `PLAIN_FLAGS` so the bound delivery route,
/// which admits no file effects, still refuses it.
pub(super) const CREATE_DIRS: &str = "--create-dirs";

/// Whether the command asks curl to create missing output directories. A
/// stray copy that is really another option's value only makes the output
/// check stricter than curl needs, never looser.
pub(super) fn creates_dirs(arguments: &[String]) -> bool {
    arguments.iter().any(|argument| argument == CREATE_DIRS)
}

/// A file `-o` or `-D` may name: a scratch file, or with `--create-dirs` one
/// whose missing directories curl makes inside a private temporary root.
pub(super) fn output_target(
    value: &str,
    context: crate::pretool::PathContext<'_>,
    create_dirs: bool,
) -> bool {
    if create_dirs {
        scratch_output_target_creating_dirs(value, context)
    } else {
        scratch_output_target(value, context)
    }
}

/// A scratch file `curl --create-dirs` may write, making any missing
/// directory above it first.
///
/// A workspace target is already judged without its directories existing, so
/// it reads the same as without the option. An absolute target is judged at
/// the first directory curl would make: that name must pass as a fresh
/// private temporary file, so its parent is the user's own temporary root and
/// nothing sits at it yet. Every name below it is then a directory curl
/// creates itself, and each must be a plain name that is not hidden.
pub(in crate::pretool) fn scratch_output_target_creating_dirs(
    target: &str,
    context: crate::pretool::PathContext<'_>,
) -> bool {
    if scratch_output_target(target, context) {
        return true;
    }
    let path = Path::new(target);
    if !path.is_absolute()
        || target.len() > 4096
        || !target
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || "._-/+@%,=".contains(value))
        || crate::pretool::sensitive_command(target)
        || crate::pretool::sensitive_read_path_argument(target)
        || !path.components().all(|component| match component {
            Component::RootDir => true,
            Component::Normal(name) => !name.to_string_lossy().starts_with('.'),
            _ => false,
        })
    {
        return false;
    }
    let mut first_missing = None;
    for ancestor in path.ancestors().skip(1) {
        match std::fs::symlink_metadata(ancestor) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                first_missing = Some(ancestor);
            }
            Err(_) => return false,
        }
    }
    first_missing
        .and_then(Path::to_str)
        .is_some_and(|directory| scratch_output_target(directory, context))
}

/// Extensions Windows runs a file by. A fixed list, not the caller's PATHEXT,
/// which the agent's environment controls. `.js` and `.psm1` are left out:
/// in a workspace they are source a tool loads, like a `.py` file, not a
/// program run by name, and POSIX hosts treat them the same way.
///
/// Shared so every route that asks "would Windows run this file?" reads the
/// same answer. A route whose own risk is wider adds to this list rather than
/// keeping a second copy of it.
#[cfg(any(not(unix), test))]
pub(in crate::pretool) const WINDOWS_PROGRAM_EXTENSIONS: &[&str] = &[
    "bat", "cmd", "com", "cpl", "exe", "jse", "msc", "msi", "ps1", "scr", "vbe", "vbs", "wsf",
    "wsh",
];

/// The extension Windows opens a name by, lowercased.
///
/// Win32 drops trailing dots and spaces from each name component, so
/// `tool.exe.` and `tool.exe ` both open `tool.exe`. Reading `Path::extension`
/// off the spelling instead returns nothing for them, which is how a runnable
/// file slips past an extension check.
#[cfg(any(not(unix), test))]
pub(in crate::pretool) fn windows_spelled_extension(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.trim_end_matches(['.', ' ']))
        .and_then(|name| name.rsplit_once('.'))
        .map(|(_, extension)| extension.to_ascii_lowercase())
}

/// An existing regular file with an execute bit, or on Windows a program
/// extension. Truncating it replaces a program that a later step may run.
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
    #[cfg(windows)]
    {
        windows_spelled_extension(&path)
            .is_some_and(|extension| WINDOWS_PROGRAM_EXTENSIONS.contains(&extension.as_str()))
            && std::fs::metadata(&path).is_ok_and(|metadata| metadata.is_file())
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = path;
        false
    }
}
