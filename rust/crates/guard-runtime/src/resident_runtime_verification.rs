#![forbid(unsafe_code)]

use crate::resident_process_identity::{executable_digest, validate_process_start_marker};
use std::path::PathBuf;
use std::time::SystemTime;

#[cfg(test)]
#[path = "resident_runtime_verification_tests.rs"]
mod tests;

/// Prove the process runs `expected_digest` and started as recorded.
///
/// The image is hashed only the first time a process lifetime is seen with
/// that file. Long-lived client streams reach a onefile resident whose
/// extracted path never equals their own; without the cache they hash the
/// whole runtime on every request. The start marker rules out PID reuse.
/// Windows has no exec, so a running process keeps the image it started with.
/// Unix exec can swap the image under the same PID and start marker, so a Unix
/// entry also holds the file's identity: an exec of another file, a rename
/// over the path or a rewrite in place changes it and forces a fresh hash.
/// The change time cannot be set back without changing the clock, so a match
/// says as much about the bytes on disk as hashing them again would. A file
/// changed moments before the read is not remembered, because a second write
/// inside the same timestamp tick would leave its identity unchanged.
pub(crate) fn validate_process_runtime_digest(
    process_id: u32,
    expected_start_marker: &str,
    process_path: PathBuf,
    expected_digest: &str,
) -> Result<(), String> {
    let file = file_identity::read(&process_path)?;
    let candidate = verified_cache::VerifiedRuntime {
        process_id,
        start_marker: expected_start_marker.to_owned(),
        path: process_path,
        digest: expected_digest.to_owned(),
        file,
    };
    let cached = verified_cache::contains(&candidate);
    let read_started = SystemTime::now();
    if !cached && executable_digest(&candidate.path)? != expected_digest {
        return Err("native_resident_process_identity_mismatch".to_owned());
    }
    validate_process_start_marker(process_id, expected_start_marker)?;
    // The identity behind a cache hit was read before the lookup. A rename over
    // the path since then must not ride on that entry, so the file the path
    // names now is hashed.
    if cached
        && file_identity::read(&candidate.path).as_ref() != Ok(&candidate.file)
        && executable_digest(&candidate.path)? != expected_digest
    {
        return Err("native_resident_process_identity_mismatch".to_owned());
    }
    // A write during the read shows up as a changed identity, and a hash of a
    // file that was changing proves nothing about the next call.
    if !cached
        && candidate.file.settled_before(read_started)
        && file_identity::read(&candidate.path).as_ref() == Ok(&candidate.file)
    {
        verified_cache::remember(candidate);
    }
    Ok(())
}

mod file_identity {
    use std::path::Path;
    #[cfg(not(windows))]
    use std::time::Duration;
    use std::time::SystemTime;

    /// How long a file must have been left alone before its identity is
    /// trusted to reveal the next write. Coarse filesystem clocks tick in
    /// milliseconds; this leaves a wide margin.
    #[cfg(not(windows))]
    const SETTLE: Duration = Duration::from_secs(1);

    #[cfg(not(windows))]
    #[derive(Debug, PartialEq, Eq)]
    pub(super) struct FileIdentity {
        device: u64,
        inode: u64,
        size: u64,
        modified: (i64, i64),
        changed: (i64, i64),
    }

    #[cfg(not(windows))]
    pub(super) fn read(path: &Path) -> Result<FileIdentity, String> {
        use std::os::unix::fs::MetadataExt;

        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| "native_resident_process_identity_unavailable".to_owned())?;
        if !metadata.is_file() {
            return Err("native_resident_process_identity_unavailable".to_owned());
        }
        Ok(FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    #[cfg(not(windows))]
    impl FileIdentity {
        pub(super) fn settled_before(&self, moment: SystemTime) -> bool {
            let (Ok(seconds), Ok(nanos)) =
                (u64::try_from(self.changed.0), u32::try_from(self.changed.1))
            else {
                return false;
            };
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::new(seconds, nanos))
                .and_then(|changed| changed.checked_add(SETTLE))
                .is_some_and(|settled| settled <= moment)
        }
    }

    /// A Windows process cannot exec another image, so its lifetime alone
    /// identifies what it runs.
    #[cfg(windows)]
    #[derive(Debug, PartialEq, Eq)]
    pub(super) struct FileIdentity;

    #[cfg(windows)]
    pub(super) fn read(_path: &Path) -> Result<FileIdentity, String> {
        Ok(FileIdentity)
    }

    #[cfg(windows)]
    impl FileIdentity {
        pub(super) fn settled_before(&self, _moment: SystemTime) -> bool {
            true
        }
    }
}

mod verified_cache {
    use super::file_identity::FileIdentity;
    use std::path::PathBuf;
    use std::sync::Mutex;

    const CAPACITY: usize = 8;

    #[derive(PartialEq, Eq)]
    pub(super) struct VerifiedRuntime {
        pub(super) process_id: u32,
        pub(super) start_marker: String,
        pub(super) path: PathBuf,
        pub(super) digest: String,
        pub(super) file: FileIdentity,
    }

    static VERIFIED: Mutex<Vec<VerifiedRuntime>> = Mutex::new(Vec::new());

    pub(super) fn contains(candidate: &VerifiedRuntime) -> bool {
        VERIFIED
            .lock()
            .is_ok_and(|verified| verified.contains(candidate))
    }

    pub(super) fn remember(candidate: VerifiedRuntime) {
        if let Ok(mut verified) = VERIFIED.lock() {
            if verified.contains(&candidate) {
                return;
            }
            if verified.len() >= CAPACITY {
                verified.remove(0);
            }
            verified.push(candidate);
        }
    }
}
