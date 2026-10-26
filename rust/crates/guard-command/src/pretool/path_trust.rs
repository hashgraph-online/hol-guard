//! Whether a path spelling can be retargeted by anyone but this user or root.
//!
//! A `cd` target spelled through a symbolic link names the same directory as
//! its canonical path only while nobody else can swap that link. System
//! aliases such as macOS `/tmp -> private/tmp` and `/var -> private/var` are
//! root's links in root's directories, and a link the user keeps in a
//! directory only they can write is theirs alone. A link in a directory other
//! users can write, or one another user owns, can point somewhere else by the
//! time the shell follows it, so its spelling never counts as the target.

use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

/// Deepest chain of links followed before a spelling is refused.
const MAX_LINK_DEPTH: u8 = 8;

/// Whether `supplied` reaches `canonical` only through links that this user
/// or root owns, each kept in a directory no other user can write, and whose
/// targets are spelled the same way.
pub(in crate::pretool) fn trusted_link_spelling(supplied: &Path, canonical: &Path) -> bool {
    let uid = nix::unistd::getuid().as_raw();
    supplied.is_absolute()
        && plain_components(supplied)
        && std::fs::canonicalize(supplied).is_ok_and(|resolved| resolved == canonical)
        && links_trusted(supplied, uid, 0)
}

fn plain_components(path: &Path) -> bool {
    path.components()
        .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

/// Every entry of `path` belongs to this user or root inside a
/// [`steady_directory`]. A link must also sit in a [`private_directory`], and
/// its target must pass the same check.
fn links_trusted(path: &Path, uid: u32, depth: u8) -> bool {
    depth < MAX_LINK_DEPTH
        && path.ancestors().all(|entry| {
            let Some(parent) = entry.parent() else {
                return true;
            };
            let Ok(metadata) = std::fs::symlink_metadata(entry) else {
                return false;
            };
            let Ok(resolved_parent) = parent.canonicalize() else {
                return false;
            };
            (metadata.uid() == uid || metadata.uid() == 0)
                && steady_directory(&resolved_parent, uid)
                && (!metadata.file_type().is_symlink()
                    || (private_directory(&resolved_parent, uid)
                        && std::fs::read_link(entry).is_ok_and(|target| {
                            link_target(&resolved_parent, &target).is_some_and(|target| {
                                plain_components(&target) && links_trusted(&target, uid, depth + 1)
                            })
                        })))
        })
}

/// Where a link whose canonical parent is `resolved_parent` points, spelled
/// without `.` or `..`. The kernel resolves a relative target from the
/// directory holding the link, so its leading `..` steps climb that canonical
/// directory exactly: `../../private/tmp` names one real path. A `..` after a
/// named step could climb back out of another link, so it is refused.
fn link_target(resolved_parent: &Path, target: &Path) -> Option<PathBuf> {
    let mut joined = if target.is_absolute() {
        PathBuf::new()
    } else {
        resolved_parent.to_path_buf()
    };
    let mut named = false;
    for component in target.components() {
        match component {
            Component::RootDir => joined.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir if !named => {
                joined.pop();
            }
            Component::Normal(name) => {
                named = true;
                joined.push(name);
            }
            _ => return None,
        }
    }
    Some(joined)
}

/// A directory, read without following a link, that belongs to this user or
/// root and that no other user can write, sticky or not.
fn private_directory(path: &Path, uid: u32) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.is_dir()
            && (metadata.uid() == uid || metadata.uid() == 0)
            && metadata.mode() & 0o022 == 0
    })
}

/// Whether nobody else can retarget `path` once checked: each component is this
/// user's or root's in a resolved [`steady_directory`], and so is each link's target.
pub(in crate::pretool) fn unswappable(path: &Path, uid: u32, depth: u8) -> bool {
    depth < MAX_LINK_DEPTH
        && path.ancestors().all(|entry| {
            let Some(parent) = entry.parent() else {
                return true;
            };
            std::fs::symlink_metadata(entry).is_ok_and(|metadata| {
                (metadata.uid() == uid || metadata.uid() == 0)
                    && (!metadata.file_type().is_symlink()
                        || std::fs::read_link(entry)
                            .is_ok_and(|target| unswappable(&parent.join(target), uid, depth + 1)))
            }) && parent
                .canonicalize()
                .is_ok_and(|parent| steady_directory(&parent, uid))
        })
}

/// A directory entry, read without following a link, that belongs to this
/// user or root and that other users cannot rename entries in.
pub(in crate::pretool) fn steady_directory(path: &Path, uid: u32) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| {
        (metadata.uid() == uid || metadata.uid() == 0)
            && (metadata.mode() & 0o022 == 0 || metadata.mode() & 0o1000 != 0)
    })
}

#[cfg(test)]
#[path = "path_trust_tests.rs"]
mod tests;
