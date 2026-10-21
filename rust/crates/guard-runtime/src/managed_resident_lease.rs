#![forbid(unsafe_code)]

#[cfg(test)]
use self::tests::{notify_lock_busy_for_test, notify_lock_retry_deadline_for_test};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::resident_state::{
    ensure_private_directory_under, private_root_for_state_base, process_is_definitively_gone,
    process_start_marker,
};

#[path = "managed_resident_lease_identity.rs"]
mod identity;
use identity::LeaseIdentity;

const LEASE_DIRECTORY: &str = "resident-client-leases.v1";
const LEASE_PREFIX: &str = "client-";
const LEASE_SUFFIX: &str = ".lease";
const LEASE_LOCK_FILE: &str = ".leases.lock";
const LEASE_MAX_BYTES: u64 = 512;
const LEASE_MAX_FILES: usize = 64;
const LEASE_MAX_DIRECTORY_ENTRIES: usize = LEASE_MAX_FILES + 1;
const LEASE_HEARTBEAT: Duration = Duration::from_millis(250);
pub(super) const LEASE_EXPIRY: Duration = Duration::from_secs(1);
const LEASE_ACQUIRE_RETRY_BUDGET: Duration = Duration::from_millis(1000);
const LEASE_CLEANUP_RETRY_BUDGET: Duration = Duration::from_millis(100);
const LEASE_ACQUIRE_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(1);
const LEASE_ACQUIRE_RETRY_MAX_DELAY: Duration = Duration::from_millis(16);

#[path = "managed_resident_lease_owner.rs"]
mod owner;
use owner::deadline_for_timeout;
pub(super) use owner::ClientLease;
#[path = "managed_resident_lease_record.rs"]
mod record;
use record::{lease_file_is_recent, lease_is_live, read_lease, remove_stale_lease, LeaseReadError};
#[path = "managed_resident_lease_retirement.rs"]
mod retirement;

pub(super) fn retire_clients_for_update(
    state_base: &Path,
    expected_digest: &str,
    deadline: Instant,
) -> Result<(), String> {
    retirement::retire_clients_for_update(state_base, expected_digest, deadline)
}

struct LeaseDirectoryLock {
    file: File,
}

impl Drop for LeaseDirectoryLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

fn lease_directory(state_base: &Path) -> Result<PathBuf, String> {
    let private_root = private_root_for_state_base(state_base)?;
    let base = ensure_private_directory_under(state_base, &private_root, false)?;
    ensure_private_directory_under(&base.join(LEASE_DIRECTORY), &private_root, true)
}

fn acquire_directory_lock(
    directory: &Path,
    private_root: &Path,
) -> Result<Option<LeaseDirectoryLock>, String> {
    let path = directory.join(LEASE_LOCK_FILE);
    #[cfg(windows)]
    let (file, _directory_binding) = crate::resident_state::private_lock_file(&path, private_root)?;
    #[cfg(not(windows))]
    let file = crate::resident_state::private_lock_file(&path, private_root)?;
    match fs2::FileExt::try_lock_exclusive(&file) {
        Ok(()) => Ok(Some(LeaseDirectoryLock { file })),
        Err(error) if crate::resident_state::is_lock_contention(&error) => {
            #[cfg(test)]
            notify_lock_busy_for_test();
            Ok(None)
        }
        Err(_) => Err("native_resident_lease_lock_failed".to_owned()),
    }
}

fn acquire_directory_lock_with_retry(
    directory: &Path,
    private_root: &Path,
    retry_budget: Duration,
) -> Result<LeaseDirectoryLock, String> {
    let deadline = Instant::now() + retry_budget;
    acquire_directory_lock_until(directory, private_root, deadline)
}

fn acquire_directory_lock_until(
    directory: &Path,
    private_root: &Path,
    deadline: Instant,
) -> Result<LeaseDirectoryLock, String> {
    acquire_directory_lock_with_clock(
        directory,
        private_root,
        deadline,
        Instant::now,
        thread::sleep,
    )
}

fn acquire_directory_lock_with_clock(
    directory: &Path,
    private_root: &Path,
    deadline: Instant,
    now: impl Fn() -> Instant,
    mut sleep: impl FnMut(Duration),
) -> Result<LeaseDirectoryLock, String> {
    let mut delay = LEASE_ACQUIRE_RETRY_INITIAL_DELAY;
    loop {
        if now() >= deadline {
            #[cfg(test)]
            notify_lock_retry_deadline_for_test(deadline);
            return Err("native_resident_lease_busy".to_owned());
        }
        if let Some(lock) = acquire_directory_lock(directory, private_root)? {
            if now() < deadline {
                return Ok(lock);
            }
            drop(lock);
            #[cfg(test)]
            notify_lock_retry_deadline_for_test(deadline);
            return Err("native_resident_lease_busy".to_owned());
        }
        let remaining = deadline.saturating_duration_since(now());
        if remaining.is_zero() {
            #[cfg(test)]
            notify_lock_retry_deadline_for_test(deadline);
            return Err("native_resident_lease_busy".to_owned());
        }
        sleep(delay.min(remaining));
        delay = (delay * 2).min(LEASE_ACQUIRE_RETRY_MAX_DELAY);
    }
}

pub(super) fn acquire(state_base: &Path) -> Result<ClientLease, String> {
    acquire_with_lock(state_base, |directory, private_root| {
        acquire_directory_lock_with_retry(directory, private_root, LEASE_ACQUIRE_RETRY_BUDGET)
    })
}

pub(super) fn acquire_until(state_base: &Path, deadline: Instant) -> Result<ClientLease, String> {
    acquire_with_lock(state_base, |directory, private_root| {
        acquire_directory_lock_until(directory, private_root, deadline)
    })
    .map(|lease| lease.with_deadline(deadline))
}

pub(crate) fn client_request(
    state_base: &Path,
    payload: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let overall_deadline = deadline_for_timeout(timeout)?;
    let client_lease = acquire_until(state_base, overall_deadline)?;
    super::client_request_with_deadline(state_base, payload, overall_deadline, &client_lease)
}

pub(super) fn client_request_with_lease(
    state_base: &Path,
    payload: &[u8],
    timeout: Duration,
    client_lease: &ClientLease,
) -> Result<Vec<u8>, String> {
    let overall_deadline = deadline_for_timeout(timeout)?;
    super::client_request_with_deadline(state_base, payload, overall_deadline, client_lease)
}

fn acquire_with_lock<F>(state_base: &Path, acquire_lock: F) -> Result<ClientLease, String>
where
    F: FnOnce(&Path, &Path) -> Result<LeaseDirectoryLock, String>,
{
    let private_root = private_root_for_state_base(state_base)?;
    let directory = lease_directory(state_base)?;
    let process_id = std::process::id();
    let start_marker = process_start_marker(process_id)?;
    let digest = crate::resident_state::runtime_digest()?;
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| "native_client_random_failed".to_owned())?;
    let nonce = crate::resident_state_encoding::hex_bytes(&nonce);
    let path = directory.join(format!("{LEASE_PREFIX}{process_id}-{nonce}{LEASE_SUFFIX}"));
    let contents = format!("{process_id}\n{start_marker}\n{digest}\n");
    let directory_lock = acquire_lock(&directory, &private_root)?;
    let mut file = crate::resident_state::private_file(&path, true, &private_root)?;
    let identity = match LeaseIdentity::from_file(&file) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = identity::remove_open_file_if_same(&path, &file);
            return Err(error);
        }
    };
    // Lease paths are nonce-qualified and identity-bound. Release the
    // directory lock before the durability flush so unrelated clients
    // are not serialized behind filesystem latency. Recent partial
    // records remain fail-closed as live until the write completes.
    drop(directory_lock);
    if file
        .write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .is_err()
    {
        let _ = identity.remove_if_same(&path);
        return Err("native_resident_lease_write_failed".to_owned());
    }
    Ok(ClientLease::new(
        directory,
        path,
        private_root,
        identity,
        contents,
    ))
}

fn any_live_with_digest(state_base: &Path, expected_digest: Option<&str>) -> bool {
    any_live_with_clock(state_base, expected_digest, SystemTime::now)
}

fn any_live_with_clock(
    state_base: &Path,
    expected_digest: Option<&str>,
    clock: impl FnOnce() -> SystemTime,
) -> bool {
    // A removed state base holds no leases. Retaining the resident here would
    // keep it running forever once its Guard home is deleted.
    let Ok(private_root) = private_root_for_state_base(state_base) else {
        return state_base_may_hold_leases(state_base);
    };
    let Ok(directory) = lease_directory(state_base) else {
        return state_base_may_hold_leases(state_base);
    };
    let _lock = match acquire_directory_lock(&directory, &private_root) {
        Ok(Some(lock)) => lock,
        // A client may be updating its lease while this liveness probe runs.
        // Retain the resident until a later probe can inspect the directory.
        Ok(None) => return true,
        // Preserve the existing fail-closed behavior for lock/open errors.
        Err(_) => return false,
    };
    // Renewal uses this same directory lock. An otherwise fresh lease must
    // not expire merely because a bounded ACL/file scan delays its heartbeat.
    // Take one reference time after acquiring the lock for the whole sweep.
    any_live_locked(&directory, &private_root, expected_digest, clock())
}

fn state_base_may_hold_leases(state_base: &Path) -> bool {
    !matches!(
        fs::symlink_metadata(state_base),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}

/// Run `action` only while no live lease of `digest` exists, holding the
/// lease directory lock across both. Every runtime takes this lock before it
/// publishes a lease, so no client of `digest` can start in between. Returns
/// `None` when the directory stays busy, is unavailable, or a lease is live.
pub(super) fn unless_live<T>(
    state_base: &Path,
    digest: &str,
    action: impl FnOnce() -> T,
) -> Option<T> {
    let private_root = private_root_for_state_base(state_base).ok()?;
    let directory = lease_directory(state_base).ok()?;
    let _lock =
        acquire_directory_lock_with_retry(&directory, &private_root, LEASE_HEARTBEAT).ok()?;
    if any_live_locked(&directory, &private_root, Some(digest), SystemTime::now()) {
        return None;
    }
    Some(action())
}

fn any_live_locked(
    directory: &Path,
    private_root: &Path,
    expected_digest: Option<&str>,
    observed_at: SystemTime,
) -> bool {
    let Ok(entries) = fs::read_dir(directory) else {
        return true;
    };
    let mut paths = Vec::with_capacity(LEASE_MAX_FILES);
    let mut stopped_before_end = false;
    for (entry_count, entry) in entries.enumerate() {
        if entry_count >= LEASE_MAX_DIRECTORY_ENTRIES {
            // Do not scan an attacker-controlled directory without a bound.
            // Any uninspected entry may be a live lease, so retain the resident
            // after this bounded pass. Stale records in the inspected batch are
            // still removed so a later probe can reach the remainder.
            stopped_before_end = true;
            break;
        }
        let Ok(entry) = entry else {
            let _ = batch_has_live_lease(&mut paths, expected_digest, private_root, observed_at);
            return true;
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(LEASE_PREFIX) || !name.ends_with(LEASE_SUFFIX) {
            continue;
        }
        if paths.len() >= LEASE_MAX_FILES
            && batch_has_live_lease(&mut paths, expected_digest, private_root, observed_at)
        {
            return true;
        }
        paths.push(entry.path());
    }
    let found_live = batch_has_live_lease(&mut paths, expected_digest, private_root, observed_at);
    found_live || stopped_before_end
}

fn batch_has_live_lease(
    paths: &mut Vec<PathBuf>,
    expected_digest: Option<&str>,
    private_root: &Path,
    observed_at: SystemTime,
) -> bool {
    paths.sort_unstable();
    let found_live = paths.drain(..).fold(false, |found_live, path| {
        if lease_is_live(&path, expected_digest, private_root, observed_at) {
            true
        } else {
            let _ = remove_stale_lease(&path, private_root, observed_at);
            found_live
        }
    });
    found_live
}

pub(super) fn any_live(state_base: &Path, expected_digest: &str) -> bool {
    any_live_with_digest(state_base, Some(expected_digest))
}

#[cfg(test)]
pub(super) fn any_live_for_home(state_base: &Path) -> bool {
    any_live_with_digest(state_base, None)
}

#[cfg(test)]
#[path = "managed_resident_lease_tests.rs"]
mod tests;
