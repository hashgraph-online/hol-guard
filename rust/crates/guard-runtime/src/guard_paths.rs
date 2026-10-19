//! The path rules Guard's Python runtime applies before it trusts a
//! directory, repeated here so the resident can answer for itself. Every
//! helper reproduces a specific CPython call, named in its documentation;
//! where a verdict would depend on something this process cannot observe,
//! the helper reports [`PathError::Unusable`] rather than guessing.

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// A path the caller's rules cannot settle: an implementation-defined prefix,
/// bytes CPython would reject, or a symlink chain too long to follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathError {
    /// The path names no root, so nothing here can say what it points at
    /// without reading the process's own working directory.
    Relative,
    Unusable,
}

/// Python's `str.strip()`, or a defer for the separators it strips and Rust
/// does not. `None` when nothing is left.
pub(crate) fn python_strip(value: &str) -> Result<Option<&str>, PathError> {
    if value
        .chars()
        .any(|character| ('\u{1c}'..='\u{1f}').contains(&character))
    {
        return Err(PathError::Unusable);
    }
    let stripped = value.trim();
    Ok((!stripped.is_empty()).then_some(stripped))
}
/// `os.path.expanduser` for the daemon's own home; another user's home defers.
/// `ntpath` accepts a backslash after `~` as well, so Windows is told both.
pub(crate) fn expanduser(value: &str, home_dir: &str) -> Result<String, PathError> {
    if value == "~" {
        return Ok(home_dir.to_owned());
    }
    let separators: &[&str] = if cfg!(windows) {
        &["~/", "~\\"]
    } else {
        &["~/"]
    };
    for prefix in separators {
        if let Some(rest) = value.strip_prefix(prefix) {
            let home = home_dir.trim_end_matches(is_separator);
            return Ok(format!("{home}{}{rest}", &prefix[1..]));
        }
    }
    if value.starts_with('~') {
        return Err(PathError::Unusable);
    }
    Ok(value.to_owned())
}

/// Whether this target treats `character` as a path separator.
fn is_windows_separator(character: char) -> bool {
    cfg!(windows) && character == '\\'
}

/// Whether `character` separates path components here, as `os.path` sees it.
pub(crate) fn is_separator(character: char) -> bool {
    character == '/' || is_windows_separator(character)
}

/// Lexical `os.path.normpath` for an absolute path. Relative paths and the
/// implementation-defined POSIX `//` prefix defer. On Windows the path keeps
/// the drive or UNC prefix it came with: a path with none is not one this
/// resolver can settle, and defers rather than being read against whatever
/// drive the process happens to be on.
#[cfg(windows)]
pub(crate) fn normpath(value: &str) -> Result<String, PathError> {
    windows_normpath(value)
}

#[cfg(not(windows))]
pub(crate) fn normpath(value: &str) -> Result<String, PathError> {
    if !value.starts_with('/') {
        return Err(PathError::Relative);
    }
    // The POSIX `//` prefix is implementation-defined, so it is not a path
    // this resolver may read lexically; `///` and longer are plain roots.
    if value.starts_with("//") && !value.starts_with("///") {
        return Err(PathError::Unusable);
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in value.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    Ok(format!("/{}", parts.join("/")))
}

/// `ntpath.normpath` for a path carrying its own prefix and root, which is
/// what `os.path.normpath` is on Windows. Both separators are read, `..` is
/// collapsed lexically as `ntpath` does, and the result is spelled with the
/// platform separator.
#[cfg(windows)]
fn windows_normpath(value: &str) -> Result<String, PathError> {
    let path = Path::new(value);
    let root = path_root(path)?;
    let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                let _ = parts.pop();
            }
            Component::Normal(part) => parts.push(part),
        }
    }
    let mut resolved = root;
    for part in parts {
        resolved.push(part);
    }
    resolved
        .to_str()
        .map(str::to_owned)
        .ok_or(PathError::Unusable)
}

/// The prefix and root `path` starts with — `/` on POSIX, the drive or UNC
/// share on Windows. A path with neither cannot be resolved against anything
/// this process can observe, so it defers.
fn path_root(path: &Path) -> Result<PathBuf, PathError> {
    let mut root = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => root.push(prefix.as_os_str()),
            Component::RootDir => root.push(std::path::MAIN_SEPARATOR_STR),
            _ => break,
        }
    }
    if root.as_os_str().is_empty() || !root.as_path().is_absolute() {
        // A drive-relative or rootless spelling: `ntpath` would read it
        // against the process's own current directory, which is not a root
        // this resolver may assume.
        return Err(PathError::Relative);
    }
    Ok(root)
}

/// Symlinks followed before a resolution defers: a cycle, which Python
/// reports as `OSError`, is not told apart from a long chain here.
const MAX_SYMLINKS: usize = 256;

/// Whether the daemon skips `candidate` as a temporary directory root:
/// `trusted_temporary_root_for_path` and the realpath comparison after it.
/// The daemon's own `tempfile.gettempdir()` is not visible here, so a verdict
/// that only this process's temporary directory decides defers.
pub(crate) fn is_temporary_root(candidate: &str) -> Result<bool, PathError> {
    // Python raises `ValueError` for an embedded NUL instead of skipping.
    if candidate.contains('\0') {
        return Err(PathError::Unusable);
    }
    let candidate = Path::new(candidate);
    let fixed = fixed_temporary_roots();
    let verdict = temporary_root_verdict(candidate, &fixed)?;
    let own = std::env::temp_dir();
    let own = normpath(own.to_str().ok_or(PathError::Unusable)?)?;
    let mut roots = vec![PathBuf::from(own)];
    roots.extend(fixed);
    if temporary_root_verdict(candidate, &roots)? != verdict {
        return Err(PathError::Unusable);
    }
    Ok(verdict)
}

/// The roots Python adds after `tempfile.gettempdir()`, in its order.
pub(crate) fn fixed_temporary_roots() -> Vec<PathBuf> {
    let mut roots = vec![PathBuf::from("/tmp"), PathBuf::from("/var/tmp")];
    if cfg!(target_os = "macos") {
        roots.extend([
            PathBuf::from("/private/tmp"),
            PathBuf::from("/private/var/tmp"),
        ]);
    }
    roots
}

pub(crate) fn temporary_root_verdict(
    candidate: &Path,
    roots: &[PathBuf],
) -> Result<bool, PathError> {
    if !lexically_temporary(candidate, roots)? {
        return Ok(false);
    }
    let Some(resolved) = python_realpath(candidate)? else {
        return Ok(false);
    };
    // The first root holding the candidate decides, as in Python.
    for root in roots {
        let Some(resolved_root) = python_realpath(root)? else {
            continue;
        };
        if resolved.starts_with(&resolved_root) {
            return Ok(resolved == resolved_root);
        }
    }
    let Some(root) = darwin_user_temporary_root(&resolved)? else {
        return Ok(false);
    };
    Ok(root == resolved && owned_by_current_user(&root))
}

/// `_is_lexically_temporary_path`. A normalized absolute path has no `..`.
pub(crate) fn lexically_temporary(candidate: &Path, roots: &[PathBuf]) -> Result<bool, PathError> {
    if !candidate.is_absolute() {
        return Ok(false);
    }
    if roots
        .iter()
        .any(|root| root.is_absolute() && candidate.starts_with(root))
    {
        return Ok(true);
    }
    Ok(darwin_user_temporary_root(candidate)?.is_some())
}

/// `os.path.realpath(path, strict=True)` for an absolute path, `None` where
/// Python raises `OSError`. Links are followed by their stored text, as
/// Python does, never by the platform `realpath`, which may also fold case.
pub(crate) fn python_realpath(path: &Path) -> Result<Option<PathBuf>, PathError> {
    if !path.is_absolute() {
        return Err(PathError::Unusable);
    }
    let root = path_root(path)?;
    let mut resolved = root.clone();
    let mut pending = Vec::new();
    push_components(&mut pending, path);
    let mut links = 0;
    while let Some(part) = pending.pop() {
        if part == ".." {
            resolved.pop();
            continue;
        }
        let next = resolved.join(part);
        let Ok(metadata) = std::fs::symlink_metadata(&next) else {
            return Ok(None);
        };
        if !metadata.file_type().is_symlink() {
            resolved = next;
            continue;
        }
        links += 1;
        if links > MAX_SYMLINKS {
            return Err(PathError::Unusable);
        }
        let Ok(target) = std::fs::read_link(next) else {
            return Ok(None);
        };
        if target.is_absolute() {
            resolved = path_root(&target)?;
        }
        push_components(&mut pending, &target);
    }
    Ok(Some(resolved))
}

/// Queues the components of `path` so that the first one pops first.
fn push_components(pending: &mut Vec<OsString>, path: &Path) {
    let parts: Vec<OsString> = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_owned()),
            Component::ParentDir => Some(OsString::from("..")),
            _ => None,
        })
        .collect();
    pending.extend(parts.into_iter().rev());
}

/// `_darwin_user_temporary_root`: `/var/folders/<xx>/<id>/T`, with or
/// without `/private`, when that root is a directory.
#[cfg(target_os = "macos")]
pub(crate) fn darwin_user_temporary_root(path: &Path) -> Result<Option<PathBuf>, PathError> {
    let parts: Vec<&std::ffi::OsStr> = path.components().map(|part| part.as_os_str()).collect();
    for prefix in [
        &["/", "var", "folders"][..],
        &["/", "private", "var", "folders"][..],
    ] {
        let length = prefix.len();
        if parts.len() < length + 3
            || !parts
                .iter()
                .zip(prefix)
                .all(|(part, expected)| *part == *expected)
        {
            continue;
        }
        // Python counts code points; other bytes defer.
        let bucket = parts[length].to_str().ok_or(PathError::Unusable)?;
        if bucket.chars().count() != 2 || parts[length + 2] != "T" {
            continue;
        }
        let root: PathBuf = parts[..length + 3].iter().collect();
        return Ok(root.is_dir().then_some(root));
    }
    Ok(None)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn darwin_user_temporary_root(_path: &Path) -> Result<Option<PathBuf>, PathError> {
    Ok(None)
}

#[cfg(unix)]
pub(crate) fn owned_by_current_user(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).is_ok_and(|metadata| metadata.uid() == nix::unistd::getuid().as_raw())
}

#[cfg(not(unix))]
pub(crate) fn owned_by_current_user(_path: &Path) -> bool {
    false
}

/// `os.path.realpath(path)` — the non-strict form, which keeps a component
/// that does not exist instead of failing. A relative path and an embedded
/// NUL are the two spellings CPython refuses outright.
///
/// CPython remembers each symlink it has already resolved and, on a cycle,
/// stops resolving and returns the rest of the path unresolved. A chain
/// longer than [`MAX_SYMLINKS`] stops the same way, so a cycle and a very
/// long chain are not told apart here.
pub(crate) fn python_realpath_lax(path: &Path) -> Result<PathBuf, PathError> {
    if !path.is_absolute() {
        return Err(PathError::Relative);
    }
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(PathError::Unusable);
    }
    let mut resolved = path_root(path)?;
    let mut pending = Vec::new();
    push_components(&mut pending, path);
    let mut links = 0;
    while let Some(part) = pending.pop() {
        if part == ".." {
            resolved.pop();
            continue;
        }
        let next = resolved.join(&part);
        let is_link = std::fs::symlink_metadata(&next)
            .is_ok_and(|metadata| metadata.file_type().is_symlink());
        if !is_link {
            resolved = next;
            continue;
        }
        links += 1;
        let target = std::fs::read_link(&next);
        if links > MAX_SYMLINKS || target.is_err() {
            // CPython returns `join(newpath, rest)` here: the link itself,
            // then everything it had not reached yet.
            pending.push(part);
            while let Some(remaining) = pending.pop() {
                resolved.push(remaining);
            }
            return Ok(resolved);
        }
        let target = target.expect("checked above");
        if target.is_absolute() {
            resolved = path_root(&target)?;
        }
        push_components(&mut pending, &target);
    }
    Ok(resolved)
}

/// `trusted_temporary_root_for_path`: the temporary root holding `candidate`,
/// or `None` when no root does. `temp_dir` is the caller's own
/// `tempfile.gettempdir()`, which this process cannot read for it.
pub(crate) fn trusted_temporary_root_for_path(
    candidate: &Path,
    temp_dir: &Path,
) -> Result<Option<PathBuf>, PathError> {
    let mut roots = vec![temp_dir.to_path_buf()];
    roots.extend(fixed_temporary_roots());
    if !lexically_temporary(candidate, &roots)? {
        return Ok(None);
    }
    // Python resolves strictly here and lets `OSError` reach its caller.
    let Some(resolved) = python_realpath(candidate)? else {
        return Err(PathError::Unusable);
    };
    for root in &roots {
        let Some(resolved_root) = python_realpath(root)? else {
            continue;
        };
        if resolved.starts_with(&resolved_root) {
            return Ok(Some(resolved_root));
        }
    }
    let Some(root) = darwin_user_temporary_root(&resolved)? else {
        return Ok(None);
    };
    Ok(owned_by_current_user(&root).then_some(root))
}

#[cfg(all(test, windows))]
#[path = "guard_paths_windows_tests.rs"]
mod guard_paths_windows_tests;
