//! Location trust shared by the Git binary lookup and loader search paths.
//!
//! A path is trusted when it sits outside the home directory, the working
//! directory and the temporary directories, and no ancestor can be written by
//! another user. The agent can write the excluded trees, so a binary or library
//! there could be planted by an earlier tool call.
//!
//! Loader search paths also accept a directory below home (see
//! [`trusted_library_search_path`]); the Git binary lookup does not.
use std::fs;
use std::path::Path;

pub(super) fn trusted_location(path: &Path, home: &Path, cwd: &Path) -> bool {
    if path.starts_with(home) || path.starts_with(cwd) || temporary_location(path) {
        return false;
    }
    #[cfg(unix)]
    if !owned_by_user_or_root(path, home) {
        return false;
    }
    #[cfg(windows)]
    {
        // The system's own folder locations, not the caller-controlled and
        // runtime-filtered ProgramFiles/SystemRoot environment variables.
        if !guard_runtime_windows_process::trusted_install_roots()
            .into_iter()
            .filter_map(|root| fs::canonicalize(root).ok())
            .any(|root| path.starts_with(root))
        {
            return false;
        }
    }
    true
}

pub(super) fn temporary_location(path: &Path) -> bool {
    let canonical_temp = fs::canonicalize(std::env::temp_dir()).ok();
    path.starts_with(std::env::temp_dir())
        || canonical_temp
            .as_deref()
            .is_some_and(|directory| path.starts_with(directory))
        || path.starts_with("/tmp")
        || path.starts_with("/private/tmp")
}

/// Every ancestor exists, is owned by root or the home owner, and is neither
/// world-writable nor group-writable by a group other than the home owner's.
#[cfg(unix)]
fn owned_by_user_or_root(path: &Path, home: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(home_metadata) = fs::metadata(home) else {
        return false;
    };
    let owner = home_metadata.uid();
    std::iter::once(path)
        .chain(path.ancestors().skip(1))
        .all(|ancestor| {
            fs::metadata(ancestor).is_ok_and(|metadata| {
                metadata.mode() & 0o002 == 0
                    && (metadata.mode() & 0o020 == 0
                        || metadata.uid() == owner
                        || metadata.gid() == home_metadata.gid())
                    && (metadata.uid() == 0 || metadata.uid() == owner)
            })
        })
}

/// A stamped loader search path keeps a Git read proven only when every entry
/// is a non-empty absolute path naming a trusted directory. An empty entry or
/// `.` means the working directory, and a relative entry follows it, so either
/// could load a library from the repository.
///
/// The dynamic loader searches the literal entry again when Git starts. A
/// symlink, a `.` or `..` component, or a `/proc` path can canonicalize to a
/// trusted directory for this process and still point somewhere else for the
/// Git process. The entry therefore has to already be canonical.
///
/// A trusted directory is either a system location no ancestor of which the
/// hook user can write, or a directory strictly below home (such as
/// `~/.local/lib` or a toolchain prefix) outside the working directory, with no
/// ancestor another user can write. The home
/// case is not weaker than what already runs: the same exported search path
/// reaches every other process the agent starts without review, so refusing
/// it only for Git reads adds an approval without blocking a planted library.
/// Writes that plant the library are the step to review.
pub(super) fn trusted_library_search_path(value: &str, home: &Path, cwd: &Path) -> bool {
    !value.is_empty()
        && value
            .split(':')
            .all(|entry| trusted_loader_entry(Path::new(entry), home, cwd))
}

/// The Windows loader resolves DLLs through its own search order and never
/// reads the Unix loader search paths, and only a Git from the system install
/// roots is trusted, so on Windows a search path cannot load a library into
/// Git. Injection variables such as `LD_PRELOAD` stay refused everywhere.
pub(super) fn inert_loader_search_path(name: &str, windows: bool) -> bool {
    windows
        && guard_contracts::LIBRARY_SEARCH_PATH_NAMES
            .iter()
            .any(|known| known.eq_ignore_ascii_case(name))
}

fn trusted_loader_entry(entry: &Path, home: &Path, cwd: &Path) -> bool {
    if !entry.is_absolute() || process_relative_loader_prefix(entry) {
        return false;
    }
    let Ok(directory) = fs::canonicalize(entry) else {
        return false;
    };
    directory == entry
        && directory.is_dir()
        && (home_loader_directory(&directory, home, cwd)
            || (trusted_location(&directory, home, cwd)
                && !agent_writable_loader_tree(&directory, home)))
}

/// A canonical directory strictly below home, outside the working directory,
/// that only the home owner (or root) can write from the directory up to home.
/// Group write at or below home is another user's write even when the home
/// owner owns the directory or shares its group. A temporary directory counts
/// only when home itself is one, as for sandboxed and CI homes. Above home, a
/// sticky world-writable ancestor such as `/tmp` is accepted because other
/// users cannot rename entries they do not own.
#[cfg(unix)]
fn home_loader_directory(directory: &Path, home: &Path, cwd: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(home) = fs::canonicalize(home) else {
        return false;
    };
    let Ok(home_metadata) = fs::metadata(&home) else {
        return false;
    };
    let canonical_cwd = fs::canonicalize(cwd).ok();
    if directory == home
        || !directory.starts_with(&home)
        || directory.starts_with(cwd)
        || canonical_cwd
            .as_deref()
            .is_some_and(|cwd| directory.starts_with(cwd))
        || (temporary_location(directory) && !temporary_location(&home))
    {
        return false;
    }
    let owner = home_metadata.uid();
    directory.ancestors().all(|ancestor| {
        fs::metadata(ancestor).is_ok_and(|metadata| {
            let mode = metadata.mode();
            let at_or_below_home = ancestor.starts_with(&home);
            let sticky_above_home = !at_or_below_home && mode & 0o1000 != 0;
            // Below home, the group-write bit is enough. Owning the directory
            // does not stop another member of its group from planting a library.
            let foreign_writable = mode & 0o002 != 0
                || (mode & 0o020 != 0
                    && (at_or_below_home
                        || (metadata.uid() != owner && metadata.gid() != home_metadata.gid())));
            (sticky_above_home || !foreign_writable)
                && (metadata.uid() == 0 || metadata.uid() == owner)
        })
    })
}

#[cfg(not(unix))]
fn home_loader_directory(_directory: &Path, _home: &Path, _cwd: &Path) -> bool {
    false
}

fn process_relative_loader_prefix(entry: &Path) -> bool {
    entry.starts_with("/proc") || entry.starts_with("/dev/fd")
}

/// The hook user can plant a library in any directory they own, and in a
/// group-writable directory of their group, even when that directory sits
/// outside home, the working directory and the temporary directories.
#[cfg(unix)]
fn agent_writable_loader_tree(path: &Path, home: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(home_metadata) = fs::metadata(home) else {
        return true;
    };
    let owner = home_metadata.uid();
    let group = home_metadata.gid();
    std::iter::once(path)
        .chain(path.ancestors().skip(1))
        .any(|ancestor| {
            fs::metadata(ancestor).map_or(true, |metadata| {
                metadata.uid() == owner
                    || (metadata.mode() & 0o020 != 0 && metadata.gid() == group)
                    || metadata.mode() & 0o002 != 0
            })
        })
}

#[cfg(not(unix))]
fn agent_writable_loader_tree(_path: &Path, _home: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn search_paths_are_inert_only_on_windows() {
        for name in guard_contracts::LIBRARY_SEARCH_PATH_NAMES {
            assert!(inert_loader_search_path(name, true));
            assert!(inert_loader_search_path(&name.to_ascii_lowercase(), true));
            assert!(!inert_loader_search_path(name, false));
        }
        for name in [
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "LD_AUDIT",
            "GIT_EXEC_PATH",
        ] {
            assert!(!inert_loader_search_path(name, true));
            assert!(!inert_loader_search_path(name, false));
        }
    }

    fn proof_root() -> PathBuf {
        std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("loader-proof-{}", std::process::id()))
    }

    #[test]
    fn system_directory_stays_a_proven_loader_entry() {
        let entry = Path::new("/usr/lib");
        if fs::canonicalize(entry).ok().as_deref() != Some(entry) {
            return;
        }
        let home = PathBuf::from(std::env::var("HOME").unwrap());
        let cwd = PathBuf::from("/guard-loader-cwd-sentinel");
        assert!(trusted_library_search_path(
            entry.to_str().unwrap(),
            &home,
            &cwd
        ));
    }

    #[test]
    fn symlink_and_dotdot_entries_are_not_proven() {
        let home = PathBuf::from(std::env::var("HOME").unwrap());
        let cwd = PathBuf::from("/guard-loader-cwd-sentinel");
        let root = proof_root();
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        #[cfg(unix)]
        {
            let link = root.join("lib");
            std::os::unix::fs::symlink("/usr/lib", &link).unwrap();
            assert!(!trusted_library_search_path(
                link.to_str().unwrap(),
                &home,
                &cwd
            ));
        }
        assert!(!trusted_library_search_path("/usr/lib/../lib", &home, &cwd));
        assert!(!trusted_library_search_path("/proc/self/cwd", &home, &cwd));
        assert!(!trusted_library_search_path(".", &home, &cwd));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn agent_owned_directory_outside_home_cwd_and_temp_is_not_proven() {
        let root = proof_root();
        let _ = fs::remove_dir_all(&root);
        let home = root.join("home");
        let cwd = root.join("cwd");
        let directory = root.join("lib");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&cwd).unwrap();
        fs::create_dir_all(&directory).unwrap();
        // A developer checkout can sit below a directory the binary lookup
        // already refuses; the loader check is what this test exercises.
        if !trusted_location(&directory, &home, &cwd) {
            let _ = fs::remove_dir_all(&root);
            return;
        }
        assert!(!trusted_library_search_path(
            directory.to_str().unwrap(),
            &home,
            &cwd
        ));
        let _ = fs::remove_dir_all(&root);
    }
    #[cfg(unix)]
    #[test]
    fn home_directory_outside_the_working_tree_is_proven() {
        use std::os::unix::fs::PermissionsExt;
        // Other tests remove the shared proof root, so this one owns a sibling.
        let root = proof_root().with_file_name(format!("loader-home-proof-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let home = root.join("home");
        let cwd = home.join("app");
        let toolchain = home.join(".local/lib");
        let repository = cwd.join("lib");
        let shared = home.join("shared");
        fs::create_dir_all(&toolchain).unwrap();
        fs::create_dir_all(&repository).unwrap();
        fs::create_dir_all(shared.join("lib")).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        let entry = |path: &Path| {
            let path = fs::canonicalize(path).unwrap();
            trusted_library_search_path(path.to_str().unwrap(), &home, &cwd)
        };
        // A checkout under a group-writable tree is not a clean fixture.
        if owned_by_user_or_root(&fs::canonicalize(&home).unwrap(), &home) {
            assert!(entry(&toolchain));
        }
        assert!(!entry(&repository));
        assert!(!entry(&cwd));
        assert!(!entry(&home));
        assert!(!entry(&shared.join("lib")));
        let group_leaf = home.join(".conda/lib");
        fs::create_dir_all(&group_leaf).unwrap();
        fs::set_permissions(&group_leaf, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(!entry(&group_leaf));
        let group_prefix = home.join("toolchains");
        let planted = group_prefix.join("lib");
        fs::create_dir_all(&planted).unwrap();
        fs::set_permissions(&group_prefix, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(!entry(&planted));
        let _ = fs::remove_dir_all(&root);
    }
}
