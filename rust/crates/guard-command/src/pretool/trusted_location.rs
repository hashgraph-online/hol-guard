//! Location trust shared by the Git binary lookup and loader search paths.
//!
//! A path is trusted when it sits outside the home directory, the working
//! directory and the temporary directories, and no ancestor can be written by
//! another user. The agent can write the excluded trees, so a binary or library
//! there could be planted by an earlier tool call.
use std::fs;
use std::path::Path;

pub(super) fn trusted_location(path: &Path, home: &Path, cwd: &Path) -> bool {
    let canonical_temp = fs::canonicalize(std::env::temp_dir()).ok();
    if path.starts_with(home)
        || path.starts_with(cwd)
        || path.starts_with(std::env::temp_dir())
        || canonical_temp
            .as_deref()
            .is_some_and(|directory| path.starts_with(directory))
        || path.starts_with("/tmp")
        || path.starts_with("/private/tmp")
    {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(home_metadata) = fs::metadata(home) else {
            return false;
        };
        let owner = home_metadata.uid();
        for ancestor in std::iter::once(path).chain(path.ancestors().skip(1)) {
            let Ok(metadata) = fs::metadata(ancestor) else {
                return false;
            };
            if metadata.mode() & 0o002 != 0
                || (metadata.mode() & 0o020 != 0
                    && metadata.uid() != owner
                    && metadata.gid() != home_metadata.gid())
                || !matches!(metadata.uid(), uid if uid == 0 || uid == owner)
            {
                return false;
            }
        }
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

/// A stamped loader search path keeps a Git read proven only when every entry
/// is a non-empty absolute path whose directory is a trusted location. An
/// empty entry or `.` means the working directory, and a relative entry
/// follows it, so either could load a library from the repository.
///
/// The dynamic loader searches the literal entry again when Git starts. A
/// symlink, a `.` or `..` component, or a `/proc` path can canonicalize to a
/// trusted directory for this process and still point somewhere the agent can
/// write for the Git process. The entry therefore has to already be canonical,
/// and no ancestor may be writable by the hook user.
pub(super) fn trusted_library_search_path(value: &str, home: &Path, cwd: &Path) -> bool {
    !value.is_empty()
        && value
            .split(':')
            .all(|entry| trusted_loader_entry(Path::new(entry), home, cwd))
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
        && trusted_location(&directory, home, cwd)
        && !agent_writable_loader_tree(&directory, home)
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
        let link = root.join("lib");
        #[cfg(unix)]
        {
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
}
