#![forbid(unsafe_code)]

#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;
use std::time::SystemTime;

use super::identity::LeaseIdentity;
use super::{process_start_marker, LEASE_EXPIRY, LEASE_MAX_BYTES};

pub(super) struct LeaseFile {
    pub(super) identity: LeaseIdentity,
    pub(super) modified: SystemTime,
    pub(super) bytes: Vec<u8>,
}

impl LeaseFile {
    pub(super) fn remove_if_same(&self, path: &Path) -> bool {
        self.identity.remove_if_same(path)
    }
}

pub(super) enum LeaseFileOpenError {
    Missing,
    Unavailable,
}

pub(super) fn open_lease_file(
    path: &Path,
    private_root: &Path,
) -> Result<LeaseFile, LeaseFileOpenError> {
    #[cfg(not(windows))]
    let _ = private_root;
    #[cfg(windows)]
    let file = match crate::resident_state::open_private_read(path, u64::MAX, "lease", private_root)
    {
        Ok(Some(file)) => file,
        Ok(None) => return Err(LeaseFileOpenError::Missing),
        Err(_) => return Err(LeaseFileOpenError::Unavailable),
    };
    #[cfg(not(windows))]
    let file = {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(LeaseFileOpenError::Missing)
            }
            Err(_) => return Err(LeaseFileOpenError::Unavailable),
        }
    };
    let identity = LeaseIdentity::from_file(&file).map_err(|_| LeaseFileOpenError::Unavailable)?;
    #[cfg(unix)]
    if !identity.matches_path(path) {
        return Err(LeaseFileOpenError::Unavailable);
    }
    let modified = file
        .metadata()
        .map_err(|_| LeaseFileOpenError::Unavailable)?
        .modified()
        .map_err(|_| LeaseFileOpenError::Unavailable)?;
    let mut file = file;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(LEASE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LeaseFileOpenError::Unavailable)?;
    Ok(LeaseFile {
        identity,
        modified,
        bytes,
    })
}

pub(super) struct LeaseRecord {
    pub(super) identity: LeaseIdentity,
    pub(super) process_id: u32,
    pub(super) start_marker: String,
    pub(super) digest: String,
    pub(super) modified: SystemTime,
}

pub(super) struct LeaseContents {
    pub(super) process_id: u32,
    pub(super) start_marker: String,
    pub(super) digest: String,
}

pub(super) fn parse_lease_contents(bytes: &[u8]) -> Option<LeaseContents> {
    if bytes.len() as u64 > LEASE_MAX_BYTES {
        return None;
    }
    let contents = String::from_utf8(bytes.to_owned()).ok()?;
    let mut lines = contents.lines();
    let process_id = lines.next()?.parse::<u32>().ok()?;
    let start_marker = lines.next()?.to_owned();
    let digest = lines.next()?.to_owned();
    if process_id == 0
        || start_marker.is_empty()
        || start_marker.len() > 256
        || digest.len() != 64
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        || lines.next().is_some()
    {
        return None;
    }
    Some(LeaseContents {
        process_id,
        start_marker,
        digest,
    })
}

pub(super) fn lease_file_is_recent(modified: SystemTime, observed_at: SystemTime) -> bool {
    !observed_at
        .duration_since(modified)
        .is_ok_and(|age| age > LEASE_EXPIRY)
}

pub(super) enum LeaseReadError {
    Missing,
    Unavailable,
    Malformed(LeaseFile),
}

pub(super) fn read_lease(path: &Path, private_root: &Path) -> Result<LeaseRecord, LeaseReadError> {
    let file = open_lease_file(path, private_root).map_err(|error| match error {
        LeaseFileOpenError::Missing => LeaseReadError::Missing,
        LeaseFileOpenError::Unavailable => LeaseReadError::Unavailable,
    })?;
    let Some(LeaseContents {
        process_id,
        start_marker,
        digest,
    }) = parse_lease_contents(&file.bytes)
    else {
        return Err(LeaseReadError::Malformed(file));
    };
    Ok(LeaseRecord {
        identity: file.identity,
        process_id,
        start_marker,
        digest,
        modified: file.modified,
    })
}

pub(super) fn lease_is_live(
    path: &Path,
    expected_digest: Option<&str>,
    private_root: &Path,
    observed_at: SystemTime,
) -> bool {
    let record = match read_lease(path, private_root) {
        Ok(record) => record,
        Err(LeaseReadError::Missing) => return false,
        Err(LeaseReadError::Unavailable) => return true,
        Err(LeaseReadError::Malformed(file)) => {
            return lease_file_is_recent(file.modified, observed_at)
        }
    };
    let Ok(age) = observed_at.duration_since(record.modified) else {
        return false;
    };
    if age > LEASE_EXPIRY
        || expected_digest.is_some_and(|expected| !record.digest.eq_ignore_ascii_case(expected))
    {
        return false;
    }
    process_start_marker(record.process_id).is_ok_and(|actual| actual == record.start_marker)
}

pub(super) fn remove_stale_lease(
    path: &Path,
    private_root: &Path,
    observed_at: SystemTime,
) -> bool {
    let record = match read_lease(path, private_root) {
        Ok(record) => record,
        Err(LeaseReadError::Missing | LeaseReadError::Unavailable) => return false,
        Err(LeaseReadError::Malformed(file)) => {
            let Ok(age) = observed_at.duration_since(file.modified) else {
                return false;
            };
            if age <= LEASE_EXPIRY {
                return false;
            }
            return file.remove_if_same(path);
        }
    };
    let Ok(age) = observed_at.duration_since(record.modified) else {
        return false;
    };
    if age <= LEASE_EXPIRY {
        return false;
    }
    // A client whose heartbeat has stopped can still be the same process.
    // Re-read the file before unlinking so a refresh or replacement is kept.
    let confirmed = match read_lease(path, private_root) {
        Ok(record) => record,
        Err(
            LeaseReadError::Missing | LeaseReadError::Unavailable | LeaseReadError::Malformed(_),
        ) => {
            return false;
        }
    };
    if confirmed.process_id != record.process_id
        || confirmed.start_marker != record.start_marker
        || !confirmed.digest.eq_ignore_ascii_case(&record.digest)
    {
        return false;
    }
    let Ok(confirmed_age) = observed_at.duration_since(confirmed.modified) else {
        return false;
    };
    if confirmed_age <= LEASE_EXPIRY {
        return false;
    }
    confirmed.identity.remove_if_same(path)
}
