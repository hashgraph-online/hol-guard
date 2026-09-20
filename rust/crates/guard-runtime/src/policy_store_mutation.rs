//! Serialize authority writers with the existing snapshot reservation lock.

use super::*;
use std::fs::File;
use std::io::Write;

const GENERATION_LOCK_NAME: &str = "native-policy-snapshot-generation-v3.lock";

pub(super) struct AuthorityWriter {
    file: File,
    #[cfg(windows)]
    _binding: guard_runtime_windows_process::PrivateDirectoryBinding,
}

impl Drop for AuthorityWriter {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

pub(super) fn acquire_writer(state_base: &Path) -> Result<AuthorityWriter, String> {
    acquire_writer_with_hook(state_base, |_| {})
}

pub(super) fn acquire_writer_with_hook<F: FnOnce(&Path)>(
    state_base: &Path,
    after_open: F,
) -> Result<AuthorityWriter, String> {
    let root = crate::resident_state::private_root_for_state_base(state_base)?;
    validate_private_directory(&root)?;
    let path = root.join(GENERATION_LOCK_NAME);
    #[cfg(windows)]
    let (mut file, binding) = crate::resident_state::private_lock_file(&path, &root)?;
    #[cfg(not(windows))]
    let mut file = crate::resident_state::private_lock_file(&path, &root)?;
    let metadata = file
        .metadata()
        .map_err(|_| "native_policy_snapshot_writer_lock_invalid".to_owned())?;
    if metadata.len() > MAX_FLOOR_BYTES {
        return Err("native_policy_snapshot_writer_lock_invalid".to_owned());
    }
    after_open(&path);
    // The Python reservation lock uses flock on Unix and byte zero on Windows.
    // fs2's exclusive range overlaps that byte. Contention never starts a new
    // wait or retry budget inside an authority operation.
    fs2::FileExt::try_lock_exclusive(&file)
        .map_err(|_| "native_policy_snapshot_writer_busy".to_owned())?;
    let locked = file
        .metadata()
        .map_err(|_| "native_policy_snapshot_writer_lock_invalid".to_owned())?;
    if !locked.is_file() || locked.len() > MAX_FLOOR_BYTES {
        return Err("native_policy_snapshot_writer_lock_invalid".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let current = std::fs::symlink_metadata(&path)
            .map_err(|_| "native_policy_snapshot_writer_lock_invalid".to_owned())?;
        if current.file_type().is_symlink()
            || !current.is_file()
            || current.dev() != locked.dev()
            || current.ino() != locked.ino()
            || locked.nlink() != 1
            || locked.permissions().mode() & 0o077 != 0
        {
            return Err("native_policy_snapshot_writer_lock_invalid".to_owned());
        }
    }
    #[cfg(windows)]
    if !binding
        .matches_private_file(std::ffi::OsStr::new(GENERATION_LOCK_NAME), &file)
        .map_err(|_| "native_policy_snapshot_writer_lock_invalid".to_owned())?
    {
        return Err("native_policy_snapshot_writer_lock_invalid".to_owned());
    }
    #[cfg(all(not(unix), not(windows)))]
    return Err("native_policy_snapshot_writer_lock_unsupported".to_owned());
    if locked.len() == 0 {
        file.write_all(b"0")
            .and_then(|()| file.sync_all())
            .map_err(|_| "native_policy_snapshot_writer_lock_invalid".to_owned())?;
    }
    Ok(AuthorityWriter {
        file,
        #[cfg(windows)]
        _binding: binding,
    })
}

pub(super) struct DurableAuthority {
    pub(super) fingerprint: Option<String>,
    pub(super) floor: u64,
    pub(super) policy_digest: Option<String>,
    /// Existing snapshot validation succeeded at the observation. False also
    /// covers an expired embedded snapshot; it does not assert withdrawal.
    pub(super) usable_snapshot: bool,
}

/// Preserve durable revocations without importing another resident's policy.
/// The caller holds the writer lock and the store state mutex, in that order.
pub(super) fn refresh_floor(
    store: &PolicySnapshotStore,
    state: &mut PolicyState,
) -> Result<DurableAuthority, String> {
    let before = authority_fingerprint(&store.authority_path);
    let loaded = load_current_authority(
        &store.authority_path,
        &store.expected_runtime_identity,
        &store.expected_rule_digest,
        &store.expected_scope_digest,
        &store.verifier_key,
    )
    .inspect_err(|_| store.authority_changed.store(true, Ordering::SeqCst))?;
    if before != authority_fingerprint(&store.authority_path)
        || (before.is_none() && (loaded.generation_floor != 0 || state.generation_floor != 0))
        || loaded.invalid_on_startup
        || loaded.generation_floor < state.generation_floor
        || (loaded.generation_floor == state.generation_floor
            && loaded.policy_digest != state.policy_digest)
    {
        store.authority_changed.store(true, Ordering::SeqCst);
        return Err("native_policy_snapshot_durable_authority_changed".to_owned());
    }
    let current = DurableAuthority {
        fingerprint: before,
        floor: loaded.generation_floor,
        policy_digest: loaded.policy_digest.clone(),
        usable_snapshot: loaded.snapshot.is_some(),
    };
    if loaded.generation_floor != state.generation_floor
        || loaded.policy_digest != state.policy_digest
        || loaded.canonical_bytes != state.canonical_bytes
        || loaded.snapshot.is_some() != state.snapshot.is_some()
        || loaded.command_control_floor != state.command_control_floor
    {
        state.generation_floor = loaded.generation_floor;
        state.policy_digest = loaded.policy_digest;
        state.command_control_floor = loaded.command_control_floor;
        state.snapshot = None;
        state.canonical_bytes.clear();
        store.authority_changed.store(true, Ordering::SeqCst);
    }
    Ok(current)
}
