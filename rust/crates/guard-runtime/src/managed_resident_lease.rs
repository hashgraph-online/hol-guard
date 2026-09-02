#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::resident_state::{ensure_private_directory, process_start_marker};

const LEASE_DIRECTORY: &str = "resident-client-leases.v1";
const LEASE_PREFIX: &str = "client-";
const LEASE_SUFFIX: &str = ".lease";
const LEASE_LOCK_FILE: &str = ".leases.lock";
const LEASE_MAX_BYTES: u64 = 512;
const LEASE_MAX_FILES: usize = 64;
const LEASE_MAX_DIRECTORY_ENTRIES: usize = LEASE_MAX_FILES + 1;
const LEASE_HEARTBEAT: Duration = Duration::from_millis(250);
pub(super) const LEASE_EXPIRY: Duration = Duration::from_secs(1);
const LEASE_ACQUIRE_RETRY_BUDGET: Duration = Duration::from_millis(200);
const LEASE_CLEANUP_RETRY_BUDGET: Duration = Duration::from_millis(100);
const LEASE_ACQUIRE_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(1);
const LEASE_ACQUIRE_RETRY_MAX_DELAY: Duration = Duration::from_millis(16);

pub(super) struct ClientLease {
    directory: PathBuf,
    path: PathBuf,
    identity: LeaseIdentity,
    stopped: Arc<AtomicBool>,
    heartbeat: Option<thread::JoinHandle<()>>,
}

impl Drop for ClientLease {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(heartbeat) = self.heartbeat.take() {
            let _ = heartbeat.join();
        }
        if let Ok(_lock) =
            acquire_directory_lock_with_retry(&self.directory, LEASE_CLEANUP_RETRY_BUDGET)
        {
            let _ = self.identity.remove_if_same(&self.path);
        }
    }
}

struct LeaseDirectoryLock {
    file: File,
}

impl Drop for LeaseDirectoryLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

struct LeaseIdentity {
    #[cfg(windows)]
    file: File,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    nlink: u64,
}

impl LeaseIdentity {
    fn from_file(file: &File) -> Result<Self, String> {
        let metadata = file
            .metadata()
            .map_err(|_| "native_resident_lease_write_failed".to_owned())?;
        if !metadata.is_file() {
            return Err("native_resident_lease_write_failed".to_owned());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err("native_resident_lease_write_failed".to_owned());
            }
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                nlink: metadata.nlink(),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                file: file
                    .try_clone()
                    .map_err(|_| "native_resident_lease_write_failed".to_owned())?,
            })
        }
    }

    fn remove_if_same(&self, path: &Path) -> bool {
        #[cfg(windows)]
        return guard_runtime_windows_process::remove_file_if_same(path, &self.file)
            .unwrap_or(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let Ok(path_metadata) = fs::symlink_metadata(path) else {
                return false;
            };
            if path_metadata.file_type().is_symlink()
                || !path_metadata.is_file()
                || path_metadata.dev() != self.device
                || path_metadata.ino() != self.inode
                || path_metadata.nlink() != self.nlink
            {
                return false;
            }
        }
        fs::remove_file(path).is_ok()
    }

    #[cfg(unix)]
    fn matches_path(&self, path: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        let Ok(path_metadata) = fs::symlink_metadata(path) else {
            return false;
        };
        !path_metadata.file_type().is_symlink()
            && path_metadata.is_file()
            && path_metadata.dev() == self.device
            && path_metadata.ino() == self.inode
            && path_metadata.nlink() == self.nlink
    }
}

fn remove_open_file_if_same(path: &Path, file: &File) -> bool {
    #[cfg(windows)]
    return guard_runtime_windows_process::remove_file_if_same(path, file).unwrap_or(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(metadata) = file.metadata() else {
            return false;
        };
        let Ok(path_metadata) = fs::symlink_metadata(path) else {
            return false;
        };
        if !metadata.is_file()
            || metadata.nlink() != 1
            || path_metadata.file_type().is_symlink()
            || !path_metadata.is_file()
            || path_metadata.dev() != metadata.dev()
            || path_metadata.ino() != metadata.ino()
            || path_metadata.nlink() != metadata.nlink()
        {
            return false;
        }
    }
    fs::remove_file(path).is_ok()
}

fn lease_directory(state_base: &Path) -> Result<PathBuf, String> {
    let base = ensure_private_directory(state_base, false)?;
    ensure_private_directory(&base.join(LEASE_DIRECTORY), true)
}

fn acquire_directory_lock(directory: &Path) -> Result<Option<LeaseDirectoryLock>, String> {
    let path = directory.join(LEASE_LOCK_FILE);
    let file = crate::resident_state::private_lock_file(&path)?;
    match fs2::FileExt::try_lock_exclusive(&file) {
        Ok(()) => Ok(Some(LeaseDirectoryLock { file })),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(_) => Err("native_resident_lease_lock_failed".to_owned()),
    }
}

fn acquire_directory_lock_with_retry(
    directory: &Path,
    retry_budget: Duration,
) -> Result<LeaseDirectoryLock, String> {
    let deadline = Instant::now() + retry_budget;
    let mut delay = LEASE_ACQUIRE_RETRY_INITIAL_DELAY;
    loop {
        if let Some(lock) = acquire_directory_lock(directory)? {
            return Ok(lock);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("native_resident_lease_busy".to_owned());
        }
        thread::sleep(delay.min(remaining));
        delay = (delay * 2).min(LEASE_ACQUIRE_RETRY_MAX_DELAY);
    }
}

pub(super) fn acquire(state_base: &Path) -> Result<ClientLease, String> {
    let directory = lease_directory(state_base)?;
    let _lock = acquire_directory_lock_with_retry(&directory, LEASE_ACQUIRE_RETRY_BUDGET)?;
    let process_id = std::process::id();
    let start_marker = process_start_marker(process_id)?;
    let digest = crate::resident_state::runtime_digest()?;
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| "native_client_random_failed".to_owned())?;
    let nonce = crate::resident_state_encoding::hex_bytes(&nonce);
    let path = directory.join(format!("{LEASE_PREFIX}{process_id}-{nonce}{LEASE_SUFFIX}"));
    let contents = format!("{process_id}\n{start_marker}\n{digest}\n");
    let mut file = crate::resident_state::private_file(&path, true)?;
    let identity = match LeaseIdentity::from_file(&file) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = remove_open_file_if_same(&path, &file);
            return Err(error);
        }
    };
    if file
        .write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .is_err()
    {
        let _ = identity.remove_if_same(&path);
        return Err("native_resident_lease_write_failed".to_owned());
    }
    let stopped = Arc::new(AtomicBool::new(false));
    let heartbeat_stopped = Arc::clone(&stopped);
    let heartbeat_directory = directory.clone();
    let heartbeat_path = path.clone();
    let heartbeat_contents = contents.clone();
    let heartbeat = thread::spawn(move || {
        while !heartbeat_stopped.load(Ordering::Acquire) {
            thread::sleep(LEASE_HEARTBEAT);
            if heartbeat_stopped.load(Ordering::Acquire) {
                break;
            }
            if let Ok(Some(_lock)) = acquire_directory_lock(&heartbeat_directory) {
                let Ok(mut file) = crate::resident_state::private_file(&heartbeat_path, false)
                else {
                    break;
                };
                if file
                    .write_all(heartbeat_contents.as_bytes())
                    .and_then(|()| file.sync_all())
                    .is_err()
                {
                    break;
                }
            }
        }
    });
    Ok(ClientLease {
        directory,
        path,
        identity,
        stopped,
        heartbeat: Some(heartbeat),
    })
}

struct LeaseFile {
    identity: LeaseIdentity,
    modified: SystemTime,
    bytes: Vec<u8>,
}

impl LeaseFile {
    fn remove_if_same(&self, path: &Path) -> bool {
        self.identity.remove_if_same(path)
    }
}

enum LeaseFileOpenError {
    Missing,
    Unavailable,
}

fn open_lease_file(path: &Path) -> Result<LeaseFile, LeaseFileOpenError> {
    #[cfg(windows)]
    let file = match crate::resident_state::open_private_read(path, u64::MAX, "lease") {
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

struct LeaseRecord {
    identity: LeaseIdentity,
    process_id: u32,
    start_marker: String,
    digest: String,
    modified: SystemTime,
}

struct LeaseContents {
    process_id: u32,
    start_marker: String,
    digest: String,
}

fn parse_lease_contents(bytes: &[u8]) -> Option<LeaseContents> {
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

fn lease_file_is_recent(modified: SystemTime) -> bool {
    !SystemTime::now()
        .duration_since(modified)
        .is_ok_and(|age| age > LEASE_EXPIRY)
}

enum LeaseReadError {
    Missing,
    Unavailable,
    Malformed(LeaseFile),
}

fn read_lease(path: &Path) -> Result<LeaseRecord, LeaseReadError> {
    let file = open_lease_file(path).map_err(|error| match error {
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

fn lease_is_live(path: &Path, expected_digest: Option<&str>) -> bool {
    let record = match read_lease(path) {
        Ok(record) => record,
        Err(LeaseReadError::Missing) => return false,
        Err(LeaseReadError::Unavailable) => return true,
        Err(LeaseReadError::Malformed(file)) => return lease_file_is_recent(file.modified),
    };
    let Ok(age) = SystemTime::now().duration_since(record.modified) else {
        return false;
    };
    if age > LEASE_EXPIRY
        || expected_digest.is_some_and(|expected| !record.digest.eq_ignore_ascii_case(expected))
    {
        return false;
    }
    process_start_marker(record.process_id).is_ok_and(|actual| actual == record.start_marker)
}

fn remove_stale_lease(path: &Path) -> bool {
    let record = match read_lease(path) {
        Ok(record) => record,
        Err(LeaseReadError::Missing | LeaseReadError::Unavailable) => return false,
        Err(LeaseReadError::Malformed(file)) => {
            let Ok(age) = SystemTime::now().duration_since(file.modified) else {
                return false;
            };
            if age <= LEASE_EXPIRY {
                return false;
            }
            return file.remove_if_same(path);
        }
    };
    let Ok(age) = SystemTime::now().duration_since(record.modified) else {
        return false;
    };
    if age <= LEASE_EXPIRY
        || process_start_marker(record.process_id).is_ok_and(|actual| actual == record.start_marker)
    {
        return false;
    }
    record.identity.remove_if_same(path)
}

fn any_live_with_digest(state_base: &Path, expected_digest: Option<&str>) -> bool {
    let Ok(directory) = lease_directory(state_base) else {
        return true;
    };
    let _lock = match acquire_directory_lock(&directory) {
        Ok(Some(lock)) => lock,
        // A client may be updating its lease while this liveness probe runs.
        // Retain the resident until a later probe can inspect the directory.
        Ok(None) => return true,
        // Preserve the existing fail-closed behavior for lock/open errors.
        Err(_) => return false,
    };
    let Ok(entries) = fs::read_dir(directory) else {
        return true;
    };
    let mut paths = Vec::with_capacity(LEASE_MAX_FILES);
    for (entry_count, entry) in entries.enumerate() {
        if entry_count >= LEASE_MAX_DIRECTORY_ENTRIES {
            // Do not scan an attacker-controlled directory without a bound.
            // Any uninspected entry may be a live lease, so retain the resident.
            return true;
        }
        let Ok(entry) = entry else {
            return true;
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(LEASE_PREFIX) || !name.ends_with(LEASE_SUFFIX) {
            continue;
        }
        if paths.len() >= LEASE_MAX_FILES {
            // More matching lease records than the verifier can inspect must
            // retain the resident, even before the directory-entry bound.
            return true;
        }
        paths.push(entry.path());
    }
    paths.sort_unstable();
    paths.into_iter().fold(false, |found_live, path| {
        if lease_is_live(&path, expected_digest) {
            true
        } else {
            let _ = remove_stale_lease(&path);
            found_live
        }
    })
}

#[cfg(test)]
pub(super) fn any_live(state_base: &Path, expected_digest: &str) -> bool {
    any_live_with_digest(state_base, Some(expected_digest))
}

pub(super) fn any_live_for_home(state_base: &Path) -> bool {
    any_live_with_digest(state_base, None)
}

#[cfg(test)]
#[path = "managed_resident_lease_tests.rs"]
mod tests;
