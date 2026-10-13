//! Sibling checkouts below the shared temporary directory. Anyone can write
//! there, so a checkout counts only when every directory down to it belongs
//! to the home owner and no one else can write it.

/// Whether canonical `path` is a non-hidden directory strictly below the
/// shared temporary directory whose every directory down from that root
/// belongs to the home owner and is writable by no one else.
pub(in crate::pretool) fn owned_temporary_directory(
    path: &std::path::Path,
    context: super::super::PathContext<'_>,
) -> bool {
    let Some(home) = context
        .home_dir
        .and_then(|home| std::fs::canonicalize(home).ok())
    else {
        return false;
    };
    owned_temporary_roots().iter().any(|root| {
        path.strip_prefix(root).is_ok_and(|relative| {
            !relative.as_os_str().is_empty()
                && relative.components().all(|part| {
                    matches!(part, std::path::Component::Normal(name) if !name.to_string_lossy().starts_with('.'))
                })
        }) && owned_below(root, path, &home)
    })
}

/// The canonical shared temporary roots (`/tmp`, which is `/private/tmp` on
/// macOS) that sibling checkouts may sit below; none off Unix.
pub(super) fn owned_temporary_roots() -> Vec<std::path::PathBuf> {
    if cfg!(not(unix)) {
        return Vec::new();
    }
    let mut roots: Vec<std::path::PathBuf> = ["/tmp", "/private/tmp"]
        .iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .collect();
    roots.dedup();
    roots
}

/// Whether every directory strictly below `root` down to `path` belongs to
/// the owner of `home` and grants no group or other write access.
#[cfg(unix)]
pub(super) fn owned_below(
    root: &std::path::Path,
    path: &std::path::Path,
    home: &std::path::Path,
) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(owner) = std::fs::metadata(home).map(|metadata| metadata.uid()) else {
        return false;
    };
    path.ancestors()
        .take_while(|directory| *directory != root)
        .all(|directory| {
            std::fs::symlink_metadata(directory).is_ok_and(|metadata| {
                metadata.is_dir() && metadata.uid() == owner && metadata.mode() & 0o022 == 0
            })
        })
}

#[cfg(not(unix))]
pub(super) fn owned_below(
    _root: &std::path::Path,
    _path: &std::path::Path,
    _home: &std::path::Path,
) -> bool {
    false
}
