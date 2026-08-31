use super::policy_store_migration::load_legacy_authority;
use super::policy_store_persistence::{read_generation_floor, read_private_json};
use super::*;
use guard_policy_snapshot::{canonical_json_bytes, generation_floor_mac, SnapshotError};
use std::fs;
#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn encode_ack(snapshot: &PolicySnapshotV3, idempotent: bool) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&PolicySnapshotAckV1 {
        status: "accepted".to_owned(),
        generation: snapshot.generation,
        policy_digest: snapshot.policy_digest.clone(),
        idempotent,
    })
    .map_err(|_| "native_policy_snapshot_ack_encode_failed".to_owned())
}

pub(super) fn encode_requires_new_generation(state: &PolicyState) -> Result<Vec<u8>, String> {
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

pub(super) fn scope_digest(guard_home: &str) -> String {
    let canonical = fs::canonicalize(guard_home)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| guard_home.to_owned());
    scope_digest_string(&normalize_scope_text(&canonical))
}

pub(super) fn scope_digest_string(guard_home: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(guard_home.as_bytes());
    hex::encode(digest.finalize())
}

pub(super) fn normalize_scope_text(value: &str) -> String {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    if let Some(stripped) = value.strip_prefix("/private/") {
        return format!("/{stripped}");
    }
    value.to_owned()
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
    let canonical = fs::canonicalize(guard_home)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| guard_home.to_string_lossy().into_owned());
    let canonical = normalize_scope_text(&canonical);
    let digest = scope_digest(&canonical);
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
