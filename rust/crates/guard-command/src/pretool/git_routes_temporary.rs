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

/// Whether canonical `parent` may hold a fresh checkout `git worktree add`
/// creates: an owned directory below the shared temporary root, or the root
/// itself, or the home owner's private macOS or Windows temporary directory.
///
/// Directly in the sticky shared root, another user could pre-create the
/// leaf only by winning a race against the existence check, the same race
/// the native file-write proof already accepts there. A planted directory
/// still fails that check, and the hook, configuration and filter proofs
/// apply wherever the checkout lands.
pub(in crate::pretool) fn temporary_checkout_parent(
    parent: &std::path::Path,
    context: super::super::PathContext<'_>,
) -> bool {
    owned_temporary_directory(parent, context)
        || owned_temporary_roots()
            .iter()
            .any(|root| root == parent && sticky_shared_root(root, context))
        || private_temporary_root(parent, context)
}

/// Whether canonical `parent` is a temporary directory no other user can
/// create an entry in: an owned directory below the shared temporary root,
/// or the home owner's private macOS temporary directory or one below it.
pub(in crate::pretool) fn private_temporary_parent(
    parent: &std::path::Path,
    context: super::super::PathContext<'_>,
) -> bool {
    owned_temporary_directory(parent, context) || private_temporary_root(parent, context)
}

/// A sticky shared root owned by root or the home owner, so entries another
/// user creates there can never be renamed or removed out from under ours.
#[cfg(unix)]
fn sticky_shared_root(root: &std::path::Path, context: super::super::PathContext<'_>) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Some(owner) = home_owner(context) else {
        return false;
    };
    std::fs::symlink_metadata(root).is_ok_and(|metadata| {
        metadata.is_dir()
            && metadata.mode() & 0o1000 != 0
            && (metadata.uid() == 0 || metadata.uid() == owner)
    })
}

#[cfg(not(unix))]
fn sticky_shared_root(_root: &std::path::Path, _context: super::super::PathContext<'_>) -> bool {
    false
}

/// The home owner's own macOS temporary directory
/// (`/private/var/folders/<a>/<b>/T`), or an owned directory below it. No
/// other user can create an entry there.
#[cfg(target_os = "macos")]
fn private_temporary_root(
    parent: &std::path::Path,
    context: super::super::PathContext<'_>,
) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (Some(owner), Some(home)) = (
        home_owner(context),
        context
            .home_dir
            .and_then(|home| std::fs::canonicalize(home).ok()),
    ) else {
        return false;
    };
    let names: Vec<&std::ffi::OsStr> = parent
        .components()
        .skip(1)
        .map(|part| part.as_os_str())
        .collect();
    if names.len() < 6 || names[..3] != ["private", "var", "folders"] || names[5] != "T" {
        return false;
    }
    let root = std::path::Path::new("/").join(names[..6].iter().collect::<std::path::PathBuf>());
    std::fs::symlink_metadata(&root).is_ok_and(|metadata| {
        metadata.is_dir() && metadata.uid() == owner && metadata.mode() & 0o077 == 0
    }) && parent
        .strip_prefix(&root)
        .is_ok_and(|relative| {
            relative.components().all(|part| {
                matches!(part, std::path::Component::Normal(name) if !name.to_string_lossy().starts_with('.'))
            })
        })
        && owned_below(&root, parent, &home)
}

/// The profile's own Windows temporary directory (`<home>\AppData\Local\Temp`,
/// where Git Bash mounts `/tmp`), or a non-hidden directory below it. It is
/// located from the canonical home rather than the caller-controlled
/// `TEMP`/`TMP`, must be its own canonical path (no junction), and the
/// profile ACL keeps other non-administrator users out of it.
#[cfg(windows)]
fn private_temporary_root(
    parent: &std::path::Path,
    context: super::super::PathContext<'_>,
) -> bool {
    let Some(home) = context
        .home_dir
        .and_then(|home| std::fs::canonicalize(home).ok())
    else {
        return false;
    };
    let root = home.join("AppData").join("Local").join("Temp");
    std::fs::canonicalize(&root).ok().as_deref() == Some(root.as_path())
        && parent.strip_prefix(&root).is_ok_and(|relative| {
            relative.components().all(|part| {
                matches!(part, std::path::Component::Normal(name) if !name.to_string_lossy().starts_with('.'))
            })
        })
}

#[cfg(not(any(target_os = "macos", windows)))]
fn private_temporary_root(
    _parent: &std::path::Path,
    _context: super::super::PathContext<'_>,
) -> bool {
    false
}

#[cfg(unix)]
fn home_owner(context: super::super::PathContext<'_>) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    context
        .home_dir
        .and_then(|home| std::fs::metadata(home).ok())
        .map(|metadata| metadata.uid())
}

/// The canonical shared temporary roots (`/tmp`, which is `/private/tmp` on
/// macOS) that sibling checkouts may sit below; none off Unix.
pub(in crate::pretool) fn owned_temporary_roots() -> Vec<std::path::PathBuf> {
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
