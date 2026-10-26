#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

/// File attributes that change whenever an update replaces an executable.
#[derive(Clone, PartialEq, Eq)]
struct ExecutableStamp {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

fn executable_stamp(executable: &Path) -> Option<ExecutableStamp> {
    let metadata = fs::symlink_metadata(executable).ok()?;
    if !metadata.is_file() {
        return None;
    }
    Some(ExecutableStamp {
        len: metadata.len(),
        modified: metadata.modified().ok(),
        #[cfg(unix)]
        device: std::os::unix::fs::MetadataExt::dev(&metadata),
        #[cfg(unix)]
        inode: std::os::unix::fs::MetadataExt::ino(&metadata),
    })
}

/// The last executable confirmed to still hold its loaded runtime. Hooks call
/// this on every request while an update marker from another install is in
/// place, so an unchanged file is not hashed again.
static CONFIRMED_CURRENT: Mutex<Option<(PathBuf, String, ExecutableStamp)>> = Mutex::new(None);

/// Report whether this process's executable no longer holds the runtime it
/// loaded, which is how an update that replaced or removed the binary shows up
/// to processes still running the old image. Unreadable paths count as
/// superseded so the caller fails closed.
pub(crate) fn runtime_superseded(loaded_digest: &str) -> bool {
    std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_or(true, |executable| {
            executable_superseded(&executable, loaded_digest)
        })
}

pub(super) fn executable_superseded(executable: &Path, loaded_digest: &str) -> bool {
    let Some(stamp) = executable_stamp(executable) else {
        return true;
    };
    let mut confirmed = CONFIRMED_CURRENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if confirmed.as_ref().is_some_and(|(path, digest, current)| {
        path == executable && digest == loaded_digest && *current == stamp
    }) {
        return false;
    }
    let current = super::executable_digest(executable).is_ok_and(|digest| digest == loaded_digest)
        && executable_stamp(executable).as_ref() == Some(&stamp);
    *confirmed = current.then(|| (executable.to_path_buf(), loaded_digest.to_owned(), stamp));
    !current
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_executable(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "hol-guard-supersession-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root.join("hol-guard-core")
    }

    #[test]
    fn replacing_or_removing_a_confirmed_executable_supersedes_it() {
        let executable = temp_executable("replace");
        fs::write(&executable, b"original runtime").unwrap();
        let loaded = super::super::executable_digest(&executable).unwrap();
        assert!(!executable_superseded(&executable, &loaded));
        // A cached confirmation must not hide an update that swapped the file.
        assert!(!executable_superseded(&executable, &loaded));
        let staged = executable.with_extension("new");
        fs::write(&staged, b"updated runtime binary").unwrap();
        fs::rename(&staged, &executable).unwrap();
        assert!(executable_superseded(&executable, &loaded));
        fs::remove_file(&executable).unwrap();
        assert!(executable_superseded(&executable, &loaded));
        fs::remove_dir_all(executable.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_different_loaded_digest_is_superseded() {
        let executable = temp_executable("digest");
        fs::write(&executable, b"runtime").unwrap();
        assert!(executable_superseded(&executable, &"0".repeat(64)));
        fs::remove_dir_all(executable.parent().unwrap()).unwrap();
    }
}
