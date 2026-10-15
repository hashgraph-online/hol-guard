use std::fs;
use std::path::Path;
use std::time::{Instant, SystemTime};

use super::{
    acquire_directory_lock_until, lease_directory, lease_file_is_recent,
    private_root_for_state_base, process_is_definitively_gone, process_start_marker, read_lease,
    remove_stale_lease, LeaseReadError, LEASE_MAX_DIRECTORY_ENTRIES, LEASE_MAX_FILES, LEASE_PREFIX,
    LEASE_SUFFIX,
};

fn retirement_failed(stage: &str) -> String {
    // Test output identifies the failing boundary without exposing process or
    // lease data. The production error contract remains unchanged.
    #[cfg(test)]
    eprintln!("resident client retirement failed at {stage}");
    #[cfg(not(test))]
    let _ = stage;
    "native_resident_client_retirement_failed".to_owned()
}

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
        .map_err(|_| retirement_failed("directory_read"))?
        .enumerate()
    {
        if entry_count >= LEASE_MAX_DIRECTORY_ENTRIES {
            return Err(retirement_failed("directory_capacity"));
        }
        let entry = entry.map_err(|_| retirement_failed("directory_entry"))?;
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
                return Err(retirement_failed("lease_unavailable"));
            }
            Err(LeaseReadError::Malformed(file)) => {
                if lease_file_is_recent(file.modified, observed_at) {
                    return Err(retirement_failed("recent_lease_malformed"));
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
                return Err(retirement_failed("old_process_identity_unavailable"));
            }
            Err(_) => return Err(retirement_failed("recent_process_identity_unavailable")),
        };
        if actual_start_marker != record.start_marker {
            let _ = record.identity.remove_if_same(&path);
            continue;
        }
        // On Windows an exited process keeps its start time while any handle
        // to it stays open, but its image can no longer be queried. The
        // marker already proved this is the lease owner, so it needs no
        // termination and its lease is stale.
        if process_is_definitively_gone(record.process_id).unwrap_or(false) {
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
            return Err(retirement_failed("runtime_process_identity"));
        }
        let timeout = deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            return Err(retirement_failed("deadline_after_identity_validation"));
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
