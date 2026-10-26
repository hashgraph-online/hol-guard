#![forbid(unsafe_code)]

use crate::resident_process_identity::{executable_digest, validate_process_start_marker};
use std::path::PathBuf;

/// Prove the process runs `expected_digest` and started as recorded.
///
/// On Windows the image is hashed only the first time a process lifetime is
/// seen. Windows has no exec, so a running process keeps the image it started
/// with, and the start marker rules out PID reuse. Long-lived client streams
/// reach a onefile resident whose extracted path never equals their own;
/// without the cache they hash the whole runtime on every request. Unix exec
/// can swap the image under the same PID and start marker, so Unix hashes on
/// every call.
pub(crate) fn validate_process_runtime_digest(
    process_id: u32,
    expected_start_marker: &str,
    process_path: PathBuf,
    expected_digest: &str,
) -> Result<(), String> {
    #[cfg(windows)]
    {
        let candidate = verified_cache::VerifiedRuntime {
            process_id,
            start_marker: expected_start_marker.to_owned(),
            path: process_path,
            digest: expected_digest.to_owned(),
        };
        let cached = verified_cache::contains(&candidate);
        if !cached && executable_digest(&candidate.path)? != expected_digest {
            return Err("native_resident_process_identity_mismatch".to_owned());
        }
        validate_process_start_marker(process_id, expected_start_marker)?;
        if !cached {
            verified_cache::remember(candidate);
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        if executable_digest(&process_path)? != expected_digest {
            return Err("native_resident_process_identity_mismatch".to_owned());
        }
        validate_process_start_marker(process_id, expected_start_marker)
    }
}

#[cfg(windows)]
mod verified_cache {
    use std::path::PathBuf;
    use std::sync::Mutex;

    const CAPACITY: usize = 8;

    #[derive(PartialEq, Eq)]
    pub(super) struct VerifiedRuntime {
        pub(super) process_id: u32,
        pub(super) start_marker: String,
        pub(super) path: PathBuf,
        pub(super) digest: String,
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
