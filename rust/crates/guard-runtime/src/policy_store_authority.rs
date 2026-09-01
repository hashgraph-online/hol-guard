use super::policy_store_migration::load_legacy_authority;
use super::policy_store_persistence::{read_generation_floor, read_private_json};
use super::*;
use guard_policy_snapshot::{canonical_json_bytes, generation_floor_mac, SnapshotError};
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const AUTHORITY_WATCH_INTERVAL: Duration = Duration::from_millis(5);

/// Return a cryptographic identity for the bounded authority object and its metadata, identity, and bytes.
pub(super) fn authority_fingerprint(path: &Path) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return None;
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path).ok()?;
    let opened = file.metadata().ok()?;
    if !opened.is_file() || opened.len() != metadata.len() {
        return None;
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(AUTHORITY_RECORD_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > AUTHORITY_RECORD_MAX_BYTES {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(b"hol-guard-authority-fingerprint-v2\0");
    hasher.update(metadata.len().to_be_bytes());
    hasher.update([u8::from(metadata.permissions().readonly())]);
    if let Ok(modified) = metadata.modified() {
        if let Ok(duration) = modified.duration_since(UNIX_EPOCH) {
            hasher.update(duration.as_secs().to_be_bytes());
            hasher.update(duration.subsec_nanos().to_be_bytes());
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        hasher.update(metadata.dev().to_be_bytes());
        hasher.update(metadata.ino().to_be_bytes());
        hasher.update(metadata.permissions().mode().to_be_bytes());
        hasher.update(metadata.uid().to_be_bytes());
        hasher.update(metadata.gid().to_be_bytes());
        hasher.update(metadata.nlink().to_be_bytes());
        hasher.update(opened.dev().to_be_bytes());
        hasher.update(opened.ino().to_be_bytes());
    }
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Some(hex::encode(hasher.finalize()))
}

/// Watch durable authority identities without reparsing policy on requests.
pub(super) fn start_authority_watcher(
    path: PathBuf,
    observed: Arc<Mutex<Option<String>>>,
    changed: Weak<AtomicBool>,
) {
    let _ = thread::Builder::new()
        .name("hol-guard-policy-authority-watch".to_owned())
        .spawn(move || loop {
            let Some(changed) = changed.upgrade() else {
                break;
            };
            let current = authority_fingerprint(&path);
            let different = observed
                .lock()
                .map(|expected| *expected != current)
                .unwrap_or(true);
            if different {
                changed.store(true, Ordering::SeqCst);
            }
            thread::sleep(AUTHORITY_WATCH_INTERVAL);
        });
}

pub(super) fn encode_ack(
    snapshot: &PolicySnapshotV3,
    idempotent: bool,
    resident_generation: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&PolicySnapshotAckV1 {
        status: "accepted".to_owned(),
        generation: snapshot.generation,
        policy_digest: snapshot.policy_digest.clone(),
        idempotent,
        resident_generation,
    })
    .map_err(|_| "native_policy_snapshot_ack_encode_failed".to_owned())
}

pub(super) fn encode_requires_new_generation(
    state: &PolicyState,
    resident_generation: u64,
) -> Result<Vec<u8>, String> {
    let Some(policy_digest) = state.policy_digest.as_ref() else {
        return Err("native_policy_snapshot_invalid".to_owned());
    };
    if state.generation_floor == 0 {
        return Err("native_policy_snapshot_invalid".to_owned());
    }
    serde_json::to_vec(&PolicySnapshotAckV1 {
        status: POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION.to_owned(),
        generation: state.generation_floor,
        policy_digest: policy_digest.clone(),
        idempotent: false,
        resident_generation,
    })
    .map_err(|_| "native_policy_snapshot_ack_encode_failed".to_owned())
}

pub(super) fn snapshot_error(error: SnapshotError) -> String {
    error.to_string()
}

pub(super) fn now_ms() -> Result<u64, String> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "native_resident_clock_invalid".to_owned())?
        .as_millis();
    u64::try_from(value).map_err(|_| "native_resident_clock_invalid".to_owned())
}

pub(super) fn authorities_unchanged(store: &PolicySnapshotStore) -> bool {
    let policy_current = authority_fingerprint(&store.authority_path);
    let approval_current = store
        .approval_authority
        .as_ref()
        .map(|authority| authority_fingerprint(&authority.path))
        .unwrap_or_else(|| {
            authority_fingerprint(
                &store
                    .authority_path
                    .with_file_name(approval_authority::APPROVAL_AUTHORITY_FILE_NAME),
            )
        });
    let policy_matches = store
        .authority_observed
        .lock()
        .map(|observed| *observed == policy_current)
        .unwrap_or(false);
    let approval_matches = store
        .approval_authority_observed
        .lock()
        .map(|observed| *observed == approval_current)
        .unwrap_or(false);
    let approval_v4_current = store
        .approval_v4_authority
        .as_ref()
        .and_then(|authority| authority_fingerprint(&authority.path));
    let approval_v4_current = approval_v4_current.or_else(|| {
        authority_fingerprint(
            &store
                .authority_path
                .with_file_name(approval_v4_authority::AUTHORITY_FILE_NAME),
        )
    });
    let approval_v4_matches = store
        .approval_v4_authority_observed
        .lock()
        .map(|observed| *observed == approval_v4_current)
        .unwrap_or(false);
    policy_matches && approval_matches && approval_v4_matches
}

pub(super) fn authority_unchanged_fenced(store: &PolicySnapshotStore) -> bool {
    let unchanged = authorities_unchanged(store);
    if !unchanged {
        store.authority_changed.store(true, Ordering::SeqCst);
    }
    unchanged
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn scope_digest(guard_home: &str) -> String {
    scope_digest_string(&canonical_scope_text(guard_home))
}

pub(super) fn scope_digest_string(guard_home: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(guard_home.as_bytes());
    hex::encode(digest.finalize())
}

pub(super) fn normalize_scope_text(value: &str) -> String {
    #[cfg(windows)]
    {
        let mut normalized = value.replace('/', "\\");
        let folded = normalized.to_ascii_lowercase();
        if folded.starts_with("\\\\?\\unc\\") {
            normalized = format!("\\\\{}", &normalized[8..]);
        } else if folded.starts_with("\\\\?\\") {
            normalized = normalized[4..].to_owned();
        }
        while normalized.len() > 3 && normalized.ends_with('\\') {
            normalized.pop();
        }
        normalized.to_ascii_lowercase()
    }
    #[cfg(not(windows))]
    {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        if let Some(stripped) = value.strip_prefix("/private/") {
            return format!("/{stripped}");
        }
        value.to_owned()
    }
}

pub(super) fn canonical_scope_text(value: &str) -> String {
    let canonical = fs::canonicalize(value)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| value.to_owned());
    normalize_scope_text(&canonical)
}

pub(super) fn scope_binding_for_state_base(state_base: &Path) -> (String, String) {
    let guard_home = if state_base
        .file_name()
        .is_some_and(|name| name == "native-runtime")
    {
        state_base.parent().unwrap_or(state_base)
    } else {
        state_base
    };
    let canonical = canonical_scope_text(&guard_home.to_string_lossy());
    let digest = scope_digest_string(&canonical);
    (canonical, digest)
}

pub(super) fn validate_private_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "native_policy_snapshot_parent_invalid".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("native_policy_snapshot_parent_invalid".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("native_policy_snapshot_parent_not_private".to_owned());
        }
    }
    #[cfg(windows)]
    crate::resident_state::verify_windows_private_path(path, true)?;
    Ok(())
}

pub(super) fn read_verifier_key(state_base: &Path) -> Result<[u8; VERIFIER_KEY_BYTES], String> {
    let path = state_base.join(VERIFIER_KEY_FILE_NAME);
    #[cfg(windows)]
    let mut file =
        crate::resident_state::open_private_read(&path, MAX_KEY_FILE_BYTES, "policy_verifier_key")
            .map_err(map_verifier_read_error)?
            .ok_or_else(|| "native_policy_verifier_key_missing".to_owned())?;
    #[cfg(not(windows))]
    let mut file = {
        let path_metadata = fs::symlink_metadata(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                "native_policy_verifier_key_missing".to_owned()
            } else {
                "native_policy_verifier_key_stat_failed".to_owned()
            }
        })?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_file()
            || path_metadata.len() != MAX_KEY_FILE_BYTES
        {
            return Err("native_policy_verifier_key_invalid".to_owned());
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        options
            .open(&path)
            .map_err(|_| "native_policy_verifier_key_read_failed".to_owned())?
    };
    let metadata = file
        .metadata()
        .map_err(|_| "native_policy_verifier_key_invalid".to_owned())?;
    if !metadata.is_file() || metadata.len() != MAX_KEY_FILE_BYTES {
        return Err("native_policy_verifier_key_invalid".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let owner = fs::symlink_metadata(state_base)
            .map_err(|_| "native_policy_verifier_key_not_private".to_owned())?
            .uid();
        if metadata.uid() != owner || metadata.permissions().mode() & 0o077 != 0 {
            return Err("native_policy_verifier_key_not_private".to_owned());
        }
    }
    let mut key = [0u8; VERIFIER_KEY_BYTES];
    file.read_exact(&mut key)
        .map_err(|_| "native_policy_verifier_key_read_failed".to_owned())?;
    let mut trailing = [0u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| "native_policy_verifier_key_read_failed".to_owned())?
        != 0
    {
        return Err("native_policy_verifier_key_invalid".to_owned());
    }
    Ok(key)
}

pub(super) fn load_authority(
    authority_path: &Path,
    legacy_floor_path: &Path,
    expected_runtime_identity: &str,
    expected_rule_digest: &str,
    expected_scope_digest: &str,
    verifier_key: &[u8; VERIFIER_KEY_BYTES],
) -> Result<LoadedAuthority, String> {
    let authority = match read_private_json(authority_path, AUTHORITY_RECORD_MAX_BYTES, "state") {
        Ok(value) => value,
        Err(error) => {
            // A pre-transactional snapshot can be left truncated or
            // otherwise unreadable. A valid authenticated legacy floor still
            // preserves the monotonic boundary, so migrate a floor-only
            // record and let the publisher install a strictly newer snapshot.
            if let Some(floor) = read_generation_floor(legacy_floor_path, verifier_key)? {
                return Ok(LoadedAuthority {
                    snapshot: None,
                    canonical_bytes: Vec::new(),
                    generation_floor: floor.generation,
                    policy_digest: Some(floor.policy_digest),
                    invalid_on_startup: true,
                    migrate: true,
                });
            }
            return Err(error);
        }
    };
    let Some((value, bytes)) = authority else {
        return load_legacy_authority(
            None,
            legacy_floor_path,
            expected_runtime_identity,
            expected_rule_digest,
            expected_scope_digest,
            verifier_key,
        );
    };
    match value.get("schema").and_then(Value::as_str) {
        Some(AUTHORITY_RECORD_SCHEMA) => load_combined_authority(
            &value,
            &bytes,
            expected_runtime_identity,
            expected_rule_digest,
            expected_scope_digest,
            verifier_key,
        ),
        // A v3 snapshot at the historical path is the pre-transactional
        // layout. Reconcile it with the old floor before replacing it with a
        // combined authority record.
        Some(guard_policy_snapshot::POLICY_SNAPSHOT_SCHEMA) => load_legacy_authority(
            Some((value, bytes)),
            legacy_floor_path,
            expected_runtime_identity,
            expected_rule_digest,
            expected_scope_digest,
            verifier_key,
        ),
        _ => {
            // Preserve a trusted floor even if an interrupted/legacy state
            // file has no parseable snapshot schema.
            if let Some(floor) = read_generation_floor(legacy_floor_path, verifier_key)? {
                Ok(LoadedAuthority {
                    snapshot: None,
                    canonical_bytes: Vec::new(),
                    generation_floor: floor.generation,
                    policy_digest: Some(floor.policy_digest),
                    invalid_on_startup: true,
                    migrate: true,
                })
            } else {
                Err("native_policy_snapshot_state_invalid".to_owned())
            }
        }
    }
}

/// Load only the transactional authority record used by the resident.
/// Legacy files are intentionally excluded from this path; upgrades invoke
/// `PolicySnapshotStore::migrate_legacy_state` explicitly before startup.
pub(super) fn load_current_authority(
    authority_path: &Path,
    expected_runtime_identity: &str,
    expected_rule_digest: &str,
    expected_scope_digest: &str,
    verifier_key: &[u8; VERIFIER_KEY_BYTES],
) -> Result<LoadedAuthority, String> {
    let Some((value, bytes)) =
        read_private_json(authority_path, AUTHORITY_RECORD_MAX_BYTES, "state")?
    else {
        return Ok(LoadedAuthority {
            snapshot: None,
            canonical_bytes: Vec::new(),
            generation_floor: 0,
            policy_digest: None,
            invalid_on_startup: false,
            migrate: false,
        });
    };
    if value.get("schema").and_then(Value::as_str) != Some(AUTHORITY_RECORD_SCHEMA) {
        return Err("native_policy_snapshot_state_invalid".to_owned());
    }
    load_combined_authority(
        &value,
        &bytes,
        expected_runtime_identity,
        expected_rule_digest,
        expected_scope_digest,
        verifier_key,
    )
}

pub(super) fn load_combined_authority(
    value: &Value,
    bytes: &[u8],
    expected_runtime_identity: &str,
    expected_rule_digest: &str,
    expected_scope_digest: &str,
    verifier_key: &[u8; VERIFIER_KEY_BYTES],
) -> Result<LoadedAuthority, String> {
    let record: PolicyAuthorityRecordV3 = serde_json::from_value(value.clone())
        .map_err(|_| "native_policy_snapshot_state_invalid".to_owned())?;
    let canonical = canonical_json_bytes(value).map_err(snapshot_error)?;
    if bytes != canonical
        || record.schema != AUTHORITY_RECORD_SCHEMA
        || record.generation_floor == 0
        || !is_lower_hex(&record.policy_digest, 64)
        || !is_lower_hex(&record.floor_mac, 64)
        || !crate::constant_time_eq(
            generation_floor_mac(record.generation_floor, &record.policy_digest, verifier_key)
                .as_bytes(),
            record.floor_mac.as_bytes(),
        )
    {
        return Err("native_policy_snapshot_state_invalid".to_owned());
    }
    let mut snapshot = None;
    let mut canonical_snapshot = Vec::new();
    let mut invalid_on_startup = false;
    if let Some(candidate) = record.snapshot {
        if candidate.generation != record.generation_floor
            || candidate.policy_digest != record.policy_digest
        {
            // The authenticated floor remains usable for a strictly newer
            // push, but this incoherent candidate must never authorize a hook.
            invalid_on_startup = true;
        } else if validate_v3(
            &candidate,
            record.generation_floor,
            expected_runtime_identity,
            expected_rule_digest,
            verifier_key,
            now_ms()?,
        )
        .is_ok()
            && candidate.scope_contract.scope_digest == expected_scope_digest
        {
            canonical_snapshot = snapshot_bytes(&candidate).map_err(snapshot_error)?;
            snapshot = Some(candidate);
        }
    }
    // A combined record is already authoritative; the old files are ignored
    // even when they contain an older generation or malformed data.
    Ok(LoadedAuthority {
        snapshot,
        canonical_bytes: canonical_snapshot,
        generation_floor: record.generation_floor,
        policy_digest: Some(record.policy_digest),
        invalid_on_startup,
        migrate: false,
    })
}
