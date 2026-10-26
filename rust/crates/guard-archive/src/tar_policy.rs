//! Archive admission: open the immutable blob, bind it to the caller's digest,
//! then run the two policy passes (decompression preflight, member policy)
//! over digest-verified streams. Result codes and messages are part of the
//! caller contract and must not drift.

use std::path::Path;
use std::time::Instant;

use guard_secure_fs::{open_immutable_blob, SecureReadError};

use crate::member_policy::scan_tar_members;
use crate::stream::{hash_stream, preflight_expanded_stream, with_verified_stream};
use crate::stream::{Binding, HashFailure};
use crate::{ArchiveCaps, ArchiveOutcome};

pub(crate) struct InspectStats {
    pub sha256: String,
    pub members: u64,
    pub expanded_bytes: u64,
}

pub(crate) fn inspect(
    path: &Path,
    expected_sha256: &str,
    caps: &ArchiveCaps,
    deadline: Instant,
    halt: &dyn Fn() -> bool,
) -> Result<InspectStats, ArchiveOutcome> {
    let blob = open_immutable_blob(path).map_err(|error| match error {
        SecureReadError::SymlinkInPath
        | SecureReadError::NotRegularFile
        | SecureReadError::HardLinkedFile
        | SecureReadError::MutableLeaf => ArchiveOutcome::blocked(
            "external_archive_blob_rejected",
            "External archive blob is not a regular immutable file.",
            None,
        ),
        _ => ArchiveOutcome::incomplete(
            "external_archive_inspection_incomplete",
            "External archive could not be opened for offline inspection.",
            None,
        ),
    })?;
    if blob.identity.size > caps.max_archive_bytes {
        return Err(ArchiveOutcome::blocked(
            "external_archive_download_size_limit",
            "External archive exceeded Guard's inspection size limit.",
            None,
        ));
    }
    let mut file = blob.file;
    let (actual_sha256, actual_size) =
        match hash_stream(&mut file, caps.max_archive_bytes, deadline, halt) {
            Ok(pair) => pair,
            Err(HashFailure::Timeout) => return Err(ArchiveOutcome::timeout(None)),
            Err(HashFailure::Halted) => return Err(ArchiveOutcome::halted()),
            Err(_) => {
                return Err(ArchiveOutcome::incomplete(
                    "external_archive_inspection_incomplete",
                    "External archive could not be read completely for offline inspection.",
                    None,
                ))
            }
        };
    if actual_size != blob.identity.size || actual_sha256 != expected_sha256 {
        return Err(ArchiveOutcome::blocked(
            "external_archive_digest_mismatch",
            "External archive changed between download and offline inspection.",
            Some(actual_sha256),
        ));
    }
    let actual = Some(actual_sha256.clone());
    let binding = Binding {
        sha256: expected_sha256,
        size: actual_size,
        actual: &actual,
    };
    // Each policy pass reads the descriptor through its own digest and is
    // accepted only if the bytes it consumed are the bound bytes, so no pass
    // can be shown different content than the one that proved the digest.
    preflight_expanded_stream(&mut file, &binding, caps, deadline, halt)?;
    let mut stats = with_verified_stream(&mut file, &binding, caps, deadline, halt, |reader| {
        scan_tar_members(reader, actual_size, caps, deadline, halt, &actual)
    })?;
    stats.sha256 = actual_sha256;
    Ok(stats)
}
