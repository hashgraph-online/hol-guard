use std::fs;
use std::path::Path;
use std::time::{Instant, SystemTime};

use super::{
    acquire_directory_lock_until, lease_directory, lease_file_is_recent,
    private_root_for_state_base, process_is_definitively_gone, process_start_marker, read_lease,
    remove_stale_lease, LeaseReadError, LEASE_MAX_DIRECTORY_ENTRIES, LEASE_MAX_FILES, LEASE_PREFIX,
    LEASE_SUFFIX,
};

pub(super) fn retire_clients_for_update(
    state_base: &Path,
    expected_digest: &str,
    deadline: Instant,
) -> Result<(), String> {
    // The updater owns the cross-process replacement barrier. Revalidate each
    // lease identity before terminating its exact client so stale or reused
    // PIDs cannot authorize a process kill.
    let private_root = private_root_for_state_base(state_base)?;
    let directory = lease_directory(state_base)?;
    let _directory_lock = acquire_directory_lock_until(&directory, &private_root, deadline)?;
    let observed_at = SystemTime::now();
    let mut paths = Vec::with_capacity(LEASE_MAX_FILES);
    for (entry_count, entry) in fs::read_dir(&directory)
        .map_err(|_| "native_resident_client_retirement_failed".to_owned())?
        .enumerate()
    {
        if entry_count >= LEASE_MAX_DIRECTORY_ENTRIES {
            return Err("native_resident_client_retirement_failed".to_owned());
        }
        let entry = entry.map_err(|_| "native_resident_client_retirement_failed".to_owned())?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(LEASE_PREFIX) && name.ends_with(LEASE_SUFFIX) {
            paths.push(entry.path());
        }
    }

    for path in paths {
        let record = match read_lease(&path, &private_root) {
            Ok(record) => record,
            Err(LeaseReadError::Missing) => continue,
            Err(LeaseReadError::Unavailable) => {
                return Err("native_resident_client_retirement_failed".to_owned());
            }
            Err(LeaseReadError::Malformed(file)) => {
                if lease_file_is_recent(file.modified, observed_at) {
                    return Err("native_resident_client_retirement_failed".to_owned());
                }
                let _ = file.remove_if_same(&path);
                continue;
            }
        };
        if !record.digest.eq_ignore_ascii_case(expected_digest) {
            continue;
        }
        let actual_start_marker = match process_start_marker(record.process_id) {
            Ok(marker) => marker,
            Err(_) if !lease_file_is_recent(record.modified, observed_at) => {
                if process_is_definitively_gone(record.process_id).unwrap_or(false) {
                    let _ = remove_stale_lease(&path, &private_root, observed_at);
                    continue;
                }
                return Err("native_resident_client_retirement_failed".to_owned());
            }
            Err(_) => return Err("native_resident_client_retirement_failed".to_owned()),
        };
        if actual_start_marker != record.start_marker {
            let _ = record.identity.remove_if_same(&path);
            continue;
        }
        if record.process_id == std::process::id()
            || crate::resident_process_identity::validate_runtime_process_identity(
                record.process_id,
                &record.start_marker,
                &record.digest,
            )
            .is_err()
        {
            return Err("native_resident_client_retirement_failed".to_owned());
        }
        let timeout = deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            return Err("native_resident_client_retirement_failed".to_owned());
        }
        crate::managed_resident::containment::terminate_client_process(
            record.process_id,
            &record.start_marker,
            &record.digest,
            timeout,
        )?;
        let _ = record.identity.remove_if_same(&path);
    }
    Ok(())
}
