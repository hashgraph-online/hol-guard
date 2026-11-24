//! Files the system's package manager installed below `/usr`.
//!
//! A recursive search of `/usr/lib/python3` or `/usr/include` reaches names
//! the per-entry screen refuses: a test certificate shipped with a library
//! (`dummycert.pem`), Git's credential-helper sources, C++'s `stop_token`
//! header, a keyring plugin. Those files belong to the operating system. Root
//! wrote them, every local account can read them, and none of them is the
//! user's secret, so a search over them is not a credential read.
//!
//! The proof is ownership, never a name: the file must be a regular file
//! owned by root, readable by everyone and writable by no one but root, and
//! every directory from `/usr` down to it must be owned by root and writable
//! by no one else, so no other account could have moved a file there.
//! `/usr/local` is excluded: administrators keep their own configuration
//! there. A process running as root gets nothing from this rule, because
//! everything it writes is root's too.
use std::path::Path;

/// A name-refused descendant may still be printed when it is a root-owned,
/// world-readable regular file installed below `/usr`.
#[cfg(unix)]
pub(in crate::pretool) fn packaged_file(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    if nix::unistd::geteuid().is_root() {
        return false;
    }
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.is_file() || !root_owned_readable(metadata.uid(), metadata.mode()) {
        return false;
    }
    let Some(parent) = path.parent() else {
        return false;
    };
    let Ok(parent) = std::fs::canonicalize(parent) else {
        return false;
    };
    system_tree(&parent)
        && parent
            .ancestors()
            .take_while(|dir| *dir != Path::new("/"))
            .all(|dir| {
                std::fs::symlink_metadata(dir).is_ok_and(|metadata| {
                    metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0
                })
            })
}

#[cfg(not(unix))]
pub(in crate::pretool) fn packaged_file(_path: &Path) -> bool {
    false
}

/// Owned by root, readable by everyone, writable only by root.
#[cfg(unix)]
fn root_owned_readable(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o004 != 0 && mode & 0o022 == 0
}

/// A directory inside `/usr` that is not `/usr/local` or below it.
#[cfg(unix)]
fn system_tree(directory: &Path) -> bool {
    directory.starts_with("/usr")
        && directory != Path::new("/usr")
        && !directory.starts_with("/usr/local")
}

#[cfg(all(test, unix))]
#[path = "packaged_file_tests.rs"]
mod tests;
