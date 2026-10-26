//! Package paths and reads that stay inside the plugin root (§4.1).

use std::fs;
use std::path::{Path, PathBuf};

use crate::walk::MAX_TEXT_BYTES;

/// Whether a path below the plugin root stays inside it, both by its
/// components and, when it exists, after resolving symlinks.
pub(super) fn package_path_inside(root: &Path, relative: &str) -> bool {
    if !lexically_inside(relative) {
        return false;
    }
    let target = root.join(relative);
    match target.canonicalize() {
        Ok(resolved) => resolved.starts_with(root),
        Err(_) => true,
    }
}

pub(super) fn lexically_inside(relative: &str) -> bool {
    if relative.starts_with(['/', '\\']) || relative.contains(':') {
        return false;
    }
    let mut depth = 0usize;
    for part in relative.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => match depth.checked_sub(1) {
                Some(next) => depth = next,
                None => return false,
            },
            _ => depth += 1,
        }
    }
    true
}

pub(super) enum Read {
    Missing,
    Outside,
    NotFile,
    Unreadable,
    Text(String),
}

/// Reads a package file, following symlinks only while they stay inside the
/// plugin root, as the specification allows.
pub(super) fn read_inside(root: &Path, relative: &Path) -> Read {
    let path = root.join(relative);
    if fs::symlink_metadata(&path).is_err() {
        return Read::Missing;
    }
    let Some(resolved) = resolve_inside(root, &path) else {
        return Read::Outside;
    };
    let Ok(metadata) = fs::metadata(&resolved) else {
        return Read::Unreadable;
    };
    if !metadata.is_file() {
        return Read::NotFile;
    }
    if metadata.len() > MAX_TEXT_BYTES {
        return Read::Unreadable;
    }
    match fs::read(&resolved).map(String::from_utf8) {
        Ok(Ok(text)) => Read::Text(text),
        _ => Read::Unreadable,
    }
}

pub(super) fn resolve_inside(root: &Path, path: &Path) -> Option<PathBuf> {
    let resolved = path.canonicalize().ok()?;
    resolved.starts_with(root).then_some(resolved)
}

#[cfg(test)]
mod tests {
    use super::lexically_inside;

    #[test]
    fn relative_paths_stay_inside() {
        assert!(lexically_inside("bin/server"));
        assert!(lexically_inside("a/../b"));
        assert!(!lexically_inside("../bin/server"));
        assert!(!lexically_inside("a/../../b"));
        assert!(!lexically_inside("/etc"));
    }
}
