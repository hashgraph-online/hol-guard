#![forbid(unsafe_code)]

//! Native resident policy-snapshot state.
//!
//! The store is intentionally owned by the resident process. Hook requests
//! can only compare their envelope to this already-installed snapshot; they
//! cannot install or mutate policy while a decision is in flight.

use guard_policy_snapshot::{
    canonical_json_bytes, generation_floor_mac, snapshot_bytes, validate_v3, PolicySnapshotAckV1,
    PolicySnapshotPushV1, PolicySnapshotV3, SnapshotError,
    POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION, POLICY_SNAPSHOT_MAX_BYTES,
    POLICY_SNAPSHOT_PUSH_SCHEMA,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const SNAPSHOT_FILE_NAME: &str = "policy-snapshot-v3.json";
const GENERATION_FLOOR_FILE_NAME: &str = "policy-snapshot-generation-floor.json";
const VERIFIER_KEY_FILE_NAME: &str = "policy-verifier.key";
const VERIFIER_KEY_BYTES: usize = 32;
const MAX_KEY_FILE_BYTES: u64 = VERIFIER_KEY_BYTES as u64;
const MAX_FLOOR_BYTES: u64 = 8 * 1024;
const GENERATION_FLOOR_SCHEMA: &str = "guard-policy-snapshot-generation-floor.v1";
const AUTHORITY_RECORD_SCHEMA: &str = "guard-policy-snapshot-authority.v3";
const AUTHORITY_RECORD_MAX_BYTES: u64 = POLICY_SNAPSHOT_MAX_BYTES as u64 + 16 * 1024;

#[derive(Clone, Copy)]
#[repr(u8)]
enum PersistBoundary {
    TemporaryCreate = 1,
    Write = 2,
    FileSync = 3,
    Rename = 4,
    DirectorySync = 5,
}

#[cfg(test)]
thread_local! {
    static PERSIST_FAILPOINT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

fn persistence_fault(boundary: PersistBoundary) -> Result<(), String> {
    #[cfg(test)]
    if PERSIST_FAILPOINT.with(|failpoint| {
        if failpoint.get() == boundary as u8 {
            failpoint.set(0);
            true
        } else {
            false
        }
    }) {
        return Err("native_policy_snapshot_authority_persistence_failed".to_owned());
    }
    #[cfg(not(test))]
    let _ = boundary;
    Ok(())
}

/// One atomically replaced record is the durable source of truth for both the
/// accepted generation floor and the corresponding snapshot.  The old floor
/// and snapshot files are read only during migration; no push writes either
/// file independently.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyAuthorityRecordV3 {
    schema: String,
    generation_floor: u64,
    policy_digest: String,
    snapshot: Option<PolicySnapshotV3>,
    floor_mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationFloorV1 {
    schema: String,
    generation: u64,
    policy_digest: String,
    mac: String,
}

struct PolicyState {
    snapshot: Option<PolicySnapshotV3>,
    canonical_bytes: Vec<u8>,
    generation_floor: u64,
    /// Digest authenticated together with `generation_floor`.  It remains
    /// available when a restart recovered only the monotonic floor, so a
    /// retry can receive a typed, bounded recovery ACK without trusting the
    /// incoming snapshot as authority.
    policy_digest: Option<String>,
    invalid_on_startup: bool,
}

struct LoadedAuthority {
    snapshot: Option<PolicySnapshotV3>,
    canonical_bytes: Vec<u8>,
    generation_floor: u64,
    policy_digest: Option<String>,
    invalid_on_startup: bool,
    migrate: bool,
}

pub(crate) struct PolicySnapshotStore {
    /// The authority record lives at the historical snapshot path so older
    /// launchers still recognize that native policy state exists.
    authority_path: PathBuf,
    expected_runtime_identity: String,
    expected_rule_digest: String,
    expected_guard_home: String,
    expected_scope_digest: String,
    verifier_key: [u8; VERIFIER_KEY_BYTES],
    state: Mutex<PolicyState>,
}

impl PolicySnapshotStore {
    pub(crate) fn new(state_base: &Path, runtime_identity: &str) -> Result<Self, String> {
        validate_private_directory(state_base)?;
        let verifier_key = read_verifier_key(state_base)?;
        let authority_path = state_base.join(SNAPSHOT_FILE_NAME);
        let legacy_floor_path = state_base.join(GENERATION_FLOOR_FILE_NAME);
        recover_authority_replacement(&authority_path)?;
        let (expected_guard_home, expected_scope_digest) = scope_binding_for_state_base(state_base);
        let expected_rule_digest = guard_rule_contract::rule_digest();
        let loaded = load_authority(
            &authority_path,
            &legacy_floor_path,
            runtime_identity,
            &expected_rule_digest,
            &expected_scope_digest,
            &verifier_key,
        )?;
        if loaded.migrate {
            if let Some(digest) = loaded.policy_digest.as_deref() {
                persist_authority(
                    &authority_path,
                    loaded.generation_floor,
                    digest,
                    loaded.snapshot.as_ref(),
                    &verifier_key,
                )?;
            }
        }
        Ok(Self {
            authority_path,
            expected_runtime_identity: runtime_identity.to_owned(),
            expected_rule_digest,
            expected_guard_home,
            expected_scope_digest,
            verifier_key,
            state: Mutex::new(PolicyState {
                snapshot: loaded.snapshot,
                canonical_bytes: loaded.canonical_bytes,
                generation_floor: loaded.generation_floor,
                policy_digest: loaded.policy_digest,
                invalid_on_startup: loaded.invalid_on_startup,
            }),
        })
    }

    pub(crate) fn push(&self, value: &Value) -> Result<Vec<u8>, String> {
        let request: PolicySnapshotPushV1 = serde_json::from_value(value.clone())
            .map_err(|_| "native_policy_snapshot_push_invalid".to_owned())?;
        if request.schema != POLICY_SNAPSHOT_PUSH_SCHEMA {
            return Err("native_policy_snapshot_push_schema_mismatch".to_owned());
        }
        let snapshot_bytes = snapshot_bytes(&request.snapshot).map_err(snapshot_error)?;
        let now = now_ms()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "native_policy_snapshot_state_unavailable".to_owned())?;
        if state.invalid_on_startup && state.generation_floor == 0 {
            return Err("native_policy_snapshot_invalid".to_owned());
        }
        // Validate the candidate's own signature and all identity/expiry
        // bindings before considering floor recovery.  A malformed or
        // unauthenticated request can never elicit the recovery status.
        let minimum_generation = if state.snapshot.is_none()
            && state.policy_digest.is_some()
            && request.snapshot.generation <= state.generation_floor
        {
            1
        } else {
            state.generation_floor.max(1)
        };
        validate_v3(
            &request.snapshot,
            minimum_generation,
            &self.expected_runtime_identity,
            &self.expected_rule_digest,
            &self.verifier_key,
            now,
        )
        .map_err(snapshot_error)?;
        if let Some(current) = state.snapshot.as_ref() {
            if request.snapshot.generation < current.generation {
                return Err("native_policy_snapshot_generation_downgrade".to_owned());
            }
            if request.snapshot.generation == current.generation {
                if snapshot_bytes != state.canonical_bytes {
                    return Err("native_policy_snapshot_generation_reused".to_owned());
                }
                return encode_ack(current, true);
            }
        } else if request.snapshot.generation <= state.generation_floor {
            // There is no current snapshot to compare for normal idempotent
            // retry.  The authenticated floor is still authoritative, so
            // equal/older input must force the publisher to allocate a new
            // generation rather than silently reusing the floor.
            return encode_requires_new_generation(&state);
        }
        persist_authority(
            &self.authority_path,
            request.snapshot.generation,
            &request.snapshot.policy_digest,
            Some(&request.snapshot),
            &self.verifier_key,
        )?;
        state.generation_floor = request.snapshot.generation;
        state.policy_digest = Some(request.snapshot.policy_digest.clone());
        state.snapshot = Some(request.snapshot.clone());
        state.canonical_bytes = snapshot_bytes;
        state.invalid_on_startup = false;
        encode_ack(&request.snapshot, false)
    }

    pub(crate) fn validate_request_snapshot(
        &self,
        value: &Value,
        guard_home: &str,
        generation: u64,
    ) -> Result<PolicySnapshotV3, String> {
        let incoming: PolicySnapshotV3 = serde_json::from_value(value.clone())
            .map_err(|_| "native_policy_snapshot_invalid".to_owned())?;
        let incoming_bytes = snapshot_bytes(&incoming).map_err(snapshot_error)?;
        let now = now_ms()?;
        let state = self
            .state
            .lock()
            .map_err(|_| "native_policy_snapshot_state_unavailable".to_owned())?;
        if state.invalid_on_startup {
            return Err("native_policy_snapshot_invalid".to_owned());
        }
        let Some(current) = state.snapshot.as_ref() else {
            return Err("native_policy_snapshot_missing".to_owned());
        };
        validate_v3(
            current,
            state.generation_floor.max(1),
            &self.expected_runtime_identity,
            &self.expected_rule_digest,
            &self.verifier_key,
            now,
        )
        .map_err(snapshot_error)?;
        if generation != current.generation || incoming.generation != current.generation {
            return Err("native_policy_snapshot_not_current".to_owned());
        }
        if incoming_bytes != state.canonical_bytes {
            return Err("native_policy_snapshot_request_mismatch".to_owned());
        }
        if normalize_scope_text(guard_home) != self.expected_guard_home
            || current.scope_contract.scope_digest != self.expected_scope_digest
        {
            return Err("native_policy_snapshot_scope_mismatch".to_owned());
        }
        Ok(current.clone())
    }

    #[cfg(test)]
    pub(crate) fn current_generation(&self) -> Option<u64> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.snapshot.as_ref().map(|snapshot| snapshot.generation))
    }
}

fn encode_ack(snapshot: &PolicySnapshotV3, idempotent: bool) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&PolicySnapshotAckV1 {
        status: "accepted".to_owned(),
        generation: snapshot.generation,
        policy_digest: snapshot.policy_digest.clone(),
        idempotent,
    })
    .map_err(|_| "native_policy_snapshot_ack_encode_failed".to_owned())
}

fn encode_requires_new_generation(state: &PolicyState) -> Result<Vec<u8>, String> {
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

fn snapshot_error(error: SnapshotError) -> String {
    error.to_string()
}

fn now_ms() -> Result<u64, String> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "native_resident_clock_invalid".to_owned())?
        .as_millis();
    u64::try_from(value).map_err(|_| "native_resident_clock_invalid".to_owned())
}

fn scope_digest(guard_home: &str) -> String {
    let canonical = fs::canonicalize(guard_home)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| guard_home.to_owned());
    scope_digest_string(&normalize_scope_text(&canonical))
}

fn scope_digest_string(guard_home: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(guard_home.as_bytes());
    hex::encode(digest.finalize())
}

fn normalize_scope_text(value: &str) -> String {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    if let Some(stripped) = value.strip_prefix("/private/") {
        return format!("/{stripped}");
    }
    value.to_owned()
}

fn scope_binding_for_state_base(state_base: &Path) -> (String, String) {
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

fn validate_private_directory(path: &Path) -> Result<(), String> {
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

fn read_verifier_key(state_base: &Path) -> Result<[u8; VERIFIER_KEY_BYTES], String> {
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

fn load_authority(
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

fn load_combined_authority(
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
        || generation_floor_mac(record.generation_floor, &record.policy_digest, verifier_key)
            != record.floor_mac
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

fn load_legacy_authority(
    legacy_snapshot: Option<(Value, Vec<u8>)>,
    legacy_floor_path: &Path,
    expected_runtime_identity: &str,
    expected_rule_digest: &str,
    expected_scope_digest: &str,
    verifier_key: &[u8; VERIFIER_KEY_BYTES],
) -> Result<LoadedAuthority, String> {
    let floor = read_generation_floor(legacy_floor_path, verifier_key)?;
    let parsed_snapshot = legacy_snapshot
        .map(|(value, bytes)| parse_legacy_snapshot(&value, &bytes))
        .transpose();
    let parsed_snapshot = match parsed_snapshot {
        Ok(snapshot) => snapshot,
        Err(error) => {
            if let Some(floor) = floor {
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
    let Some((legacy_snapshot, legacy_bytes)) = parsed_snapshot else {
        let Some(floor) = floor else {
            return Ok(LoadedAuthority {
                snapshot: None,
                canonical_bytes: Vec::new(),
                generation_floor: 0,
                policy_digest: None,
                invalid_on_startup: false,
                migrate: false,
            });
        };
        return Ok(LoadedAuthority {
            snapshot: None,
            canonical_bytes: Vec::new(),
            generation_floor: floor.generation,
            policy_digest: Some(floor.policy_digest),
            invalid_on_startup: false,
            migrate: true,
        });
    };

    let floor_generation = floor.as_ref().map_or(0, |item| item.generation);
    let floor_digest = floor.as_ref().map(|item| item.policy_digest.as_str());
    let mut generation_floor = floor_generation.max(legacy_snapshot.generation);
    let mut invalid_on_startup = false;
    let mut snapshot = None;
    let mut canonical_bytes = Vec::new();
    if legacy_snapshot.generation < floor_generation
        || (legacy_snapshot.generation == floor_generation
            && floor_digest.is_some_and(|digest| digest != legacy_snapshot.policy_digest))
    {
        // Retain the highest authenticated floor and discard a stale or
        // same-generation-conflicting candidate. A newer push can recover the
        // missing current snapshot without reusing the floor.
        invalid_on_startup = true;
    } else if validate_v3(
        &legacy_snapshot,
        floor_generation.max(1),
        expected_runtime_identity,
        expected_rule_digest,
        verifier_key,
        now_ms()?,
    )
    .is_ok()
        && legacy_snapshot.scope_contract.scope_digest == expected_scope_digest
    {
        generation_floor = generation_floor.max(legacy_snapshot.generation);
        canonical_bytes = legacy_bytes;
        snapshot = Some(legacy_snapshot);
    } else {
        // Expired, incompatible, or damaged snapshot data cannot authorize a
        // hook. A trusted old floor still permits only a strictly newer push.
        invalid_on_startup = floor.is_none();
    }
    let policy_digest = snapshot
        .as_ref()
        .map(|candidate| candidate.policy_digest.clone())
        .or_else(|| floor.map(|item| item.policy_digest));
    Ok(LoadedAuthority {
        snapshot,
        canonical_bytes,
        generation_floor,
        policy_digest,
        invalid_on_startup,
        migrate: true,
    })
}

fn parse_legacy_snapshot(
    value: &Value,
    bytes: &[u8],
) -> Result<(PolicySnapshotV3, Vec<u8>), String> {
    let snapshot: PolicySnapshotV3 = serde_json::from_value(value.clone())
        .map_err(|_| "native_policy_snapshot_state_invalid".to_owned())?;
    let canonical = canonical_json_bytes(value).map_err(snapshot_error)?;
    if bytes != canonical {
        return Err("native_policy_snapshot_state_noncanonical".to_owned());
    }
    Ok((snapshot, canonical))
}

/// Recover the only intermediate states possible with a Windows replacement
/// sequence and discard fully written temporary candidates left by a crash.
/// POSIX rename is already a single atomic replacement; this cleanup remains
/// useful there for a process dying after temp fsync and before rename.
fn recover_authority_replacement(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "native_policy_snapshot_authority_parent_missing".to_owned())?;
    let target_exists = fs::symlink_metadata(path).is_ok();
    #[cfg(not(windows))]
    let _ = target_exists;
    #[cfg(windows)]
    {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("policy-snapshot-v3.json");
        let backup = parent.join(format!(".{file_name}.previous"));
        let backup_exists = fs::symlink_metadata(&backup).is_ok();
        if !target_exists && backup_exists {
            fs::rename(&backup, path)
                .map_err(|_| "native_policy_snapshot_authority_recovery_failed".to_owned())?;
        } else if target_exists && backup_exists {
            fs::remove_file(&backup)
                .map_err(|_| "native_policy_snapshot_authority_recovery_failed".to_owned())?;
        }
    }
    let prefix = format!(
        ".{}.",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("policy-snapshot-v3.json")
    );
    for entry in fs::read_dir(parent)
        .map_err(|_| "native_policy_snapshot_authority_recovery_failed".to_owned())?
    {
        let entry =
            entry.map_err(|_| "native_policy_snapshot_authority_recovery_failed".to_owned())?;
        let candidate = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(&prefix) || !name.ends_with(".tmp") {
            continue;
        }
        let metadata = fs::symlink_metadata(&candidate)
            .map_err(|_| "native_policy_snapshot_authority_recovery_failed".to_owned())?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("native_policy_snapshot_authority_recovery_failed".to_owned());
        }
        fs::remove_file(candidate)
            .map_err(|_| "native_policy_snapshot_authority_recovery_failed".to_owned())?;
    }
    Ok(())
}

fn read_generation_floor(
    path: &Path,
    verifier_key: &[u8; VERIFIER_KEY_BYTES],
) -> Result<Option<GenerationFloorV1>, String> {
    let Some((value, bytes)) = read_private_json(path, MAX_FLOOR_BYTES, "floor")? else {
        return Ok(None);
    };
    let floor: GenerationFloorV1 = serde_json::from_value(value.clone())
        .map_err(|_| "native_policy_snapshot_floor_invalid".to_owned())?;
    let canonical = canonical_json_bytes(&value).map_err(snapshot_error)?;
    if bytes != canonical
        || floor.schema != GENERATION_FLOOR_SCHEMA
        || floor.generation == 0
        || !is_lower_hex(&floor.policy_digest, 64)
        || !is_lower_hex(&floor.mac, 64)
        || generation_floor_mac(floor.generation, &floor.policy_digest, verifier_key) != floor.mac
    {
        return Err("native_policy_snapshot_floor_invalid".to_owned());
    }
    Ok(Some(floor))
}

fn persist_authority(
    path: &Path,
    generation_floor: u64,
    policy_digest: &str,
    snapshot: Option<&PolicySnapshotV3>,
    verifier_key: &[u8; VERIFIER_KEY_BYTES],
) -> Result<(), String> {
    if generation_floor == 0
        || !is_lower_hex(policy_digest, 64)
        || snapshot.is_some_and(|candidate| {
            candidate.generation != generation_floor || candidate.policy_digest != policy_digest
        })
    {
        return Err("native_policy_snapshot_authority_invalid".to_owned());
    }
    let record = PolicyAuthorityRecordV3 {
        schema: AUTHORITY_RECORD_SCHEMA.to_owned(),
        generation_floor,
        policy_digest: policy_digest.to_owned(),
        snapshot: snapshot.cloned(),
        floor_mac: generation_floor_mac(generation_floor, policy_digest, verifier_key),
    };
    let value = serde_json::to_value(record)
        .map_err(|_| "native_policy_snapshot_authority_encode_failed".to_owned())?;
    let bytes = canonical_json_bytes(&value).map_err(snapshot_error)?;
    persist_private_bytes(path, &bytes, AUTHORITY_RECORD_MAX_BYTES, "authority")
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(windows)]
fn map_private_read_error(kind: &str, error: String) -> String {
    if error.ends_with("_invalid") {
        format!("native_policy_snapshot_{kind}_invalid")
    } else if error.ends_with("_not_private") {
        format!("native_policy_snapshot_{kind}_not_private")
    } else {
        format!("native_policy_snapshot_{kind}_read_failed")
    }
}

#[cfg(windows)]
fn map_verifier_read_error(error: String) -> String {
    if error.ends_with("_invalid") {
        "native_policy_verifier_key_invalid".to_owned()
    } else if error.ends_with("_not_private") {
        "native_policy_verifier_key_not_private".to_owned()
    } else {
        "native_policy_verifier_key_read_failed".to_owned()
    }
}

fn read_private_json(
    path: &Path,
    maximum_bytes: u64,
    kind: &str,
) -> Result<Option<(Value, Vec<u8>)>, String> {
    #[cfg(windows)]
    let mut file = match crate::resident_state::open_private_read(path, maximum_bytes, kind)
        .map_err(|error| map_private_read_error(kind, error))?
    {
        Some(file) => file,
        None => return Ok(None),
    };
    #[cfg(not(windows))]
    let mut file = {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(format!("native_policy_snapshot_{kind}_stat_failed")),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > maximum_bytes
        {
            return Err(format!("native_policy_snapshot_{kind}_invalid"));
        }
        #[cfg(unix)]
        let mut options = {
            use std::os::unix::fs::OpenOptionsExt;
            let mut options = OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            options
        };
        #[cfg(not(unix))]
        let mut options = OpenOptions::new();
        options.read(true);
        options
            .open(path)
            .map_err(|_| format!("native_policy_snapshot_{kind}_read_failed"))?
    };
    let opened_metadata = file
        .metadata()
        .map_err(|_| format!("native_policy_snapshot_{kind}_invalid"))?;
    if !opened_metadata.is_file() || opened_metadata.len() > maximum_bytes {
        return Err(format!("native_policy_snapshot_{kind}_invalid"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let owner = path
            .parent()
            .and_then(|parent| fs::symlink_metadata(parent).ok())
            .map(|metadata| metadata.uid());
        if owner != Some(opened_metadata.uid()) || opened_metadata.permissions().mode() & 0o077 != 0
        {
            return Err(format!("native_policy_snapshot_{kind}_not_private"));
        }
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| format!("native_policy_snapshot_{kind}_read_failed"))?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(format!("native_policy_snapshot_{kind}_invalid"));
    }
    let value = crate::strict_json_value(&bytes)
        .map_err(|_| format!("native_policy_snapshot_{kind}_invalid"))?;
    Ok(Some((value, bytes)))
}

fn persist_private_bytes(
    path: &Path,
    bytes: &[u8],
    maximum_bytes: u64,
    kind: &str,
) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() as u64 > maximum_bytes {
        return Err(format!("native_policy_snapshot_{kind}_too_large"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("native_policy_snapshot_{kind}_parent_missing"))?;
    validate_private_directory(parent)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "native_resident_clock_invalid".to_owned())?
        .as_nanos();
    let temporary = parent.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("policy-state"),
        std::process::id(),
        stamp
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = match persistence_fault(PersistBoundary::TemporaryCreate).and_then(|()| {
        options
            .open(&temporary)
            .map_err(|_| format!("native_policy_snapshot_{kind}_write_failed"))
    }) {
        Ok(file) => file,
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
    };
    #[cfg(windows)]
    if let Err(error) = crate::resident_state::protect_windows_private_path(&temporary, false) {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    let write_result = persistence_fault(PersistBoundary::Write)
        .and_then(|()| {
            file.write_all(bytes)
                .map_err(|_| format!("native_policy_snapshot_{kind}_write_failed"))
        })
        .and_then(|()| persistence_fault(PersistBoundary::FileSync))
        .and_then(|()| {
            file.sync_all()
                .map_err(|_| format!("native_policy_snapshot_{kind}_write_failed"))
        });
    drop(file);
    let result = write_result.and_then(|()| {
        persistence_fault(PersistBoundary::Rename)?;
        replace_temporary(&temporary, path, kind)
    });
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return result;
    }
    #[cfg(unix)]
    {
        persistence_fault(PersistBoundary::DirectorySync)?;
        let directory =
            File::open(parent).map_err(|_| format!("native_policy_snapshot_{kind}_sync_failed"))?;
        directory
            .sync_all()
            .map_err(|_| format!("native_policy_snapshot_{kind}_sync_failed"))?;
    }
    // Windows has no directory fsync primitive exposed by std. Keep a
    // separate fault boundary for the post-replacement durability point so
    // recovery tests still exercise the ACK/retry state transition.
    #[cfg(windows)]
    persistence_fault(PersistBoundary::DirectorySync)?;
    Ok(())
}

#[cfg(not(windows))]
fn replace_temporary(temporary: &Path, path: &Path, kind: &str) -> Result<(), String> {
    fs::rename(temporary, path).map_err(|_| format!("native_policy_snapshot_{kind}_replace_failed"))
}

#[cfg(windows)]
fn replace_temporary(temporary: &Path, path: &Path, kind: &str) -> Result<(), String> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("policy-state");
    let backup = path.with_file_name(format!(".{file_name}.previous"));
    if fs::symlink_metadata(&backup).is_ok() {
        fs::remove_file(&backup)
            .map_err(|_| format!("native_policy_snapshot_{kind}_replace_failed"))?;
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!("native_policy_snapshot_{kind}_replace_failed"));
        }
        fs::rename(path, &backup)
            .map_err(|_| format!("native_policy_snapshot_{kind}_replace_failed"))?;
    }
    if let Err(_) = fs::rename(temporary, path) {
        let _ = fs::rename(&backup, path);
        return Err(format!("native_policy_snapshot_{kind}_replace_failed"));
    }
    if fs::symlink_metadata(&backup).is_ok() {
        fs::remove_file(&backup)
            .map_err(|_| format!("native_policy_snapshot_{kind}_replace_failed"))?;
    }
    crate::resident_state::verify_windows_private_path(path, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_contracts::{
        GuardHookEdgeResultV2, GuardHookEnvelopeV2, GuardHookSourceMetadataV2,
        GUARD_HOOK_ENVELOPE_V2_SCHEMA,
    };
    use guard_policy_snapshot::{
        config_digest, integrity_mac, policy_digest, verifier_key_id, EffectiveNativePolicyV3,
        ScopeContractV3, SnapshotIntegrityV3, POLICY_SNAPSHOT_INTEGRITY_ALGORITHM,
        POLICY_SNAPSHOT_SCHEMA,
    };
    use std::collections::BTreeMap;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn policy() -> EffectiveNativePolicyV3 {
        EffectiveNativePolicyV3 {
            protection_posture: "protected".into(),
            security_level: "balanced".into(),
            default_action: "warn".into(),
            unknown_publisher_action: "review".into(),
            changed_hash_action: "require-reapproval".into(),
            new_network_domain_action: "warn".into(),
            subprocess_action: "warn".into(),
            risk_actions: BTreeMap::new(),
            harness_risk_actions: BTreeMap::new(),
            harness_actions: BTreeMap::new(),
            publisher_actions: BTreeMap::new(),
            artifact_actions: BTreeMap::new(),
            sandbox_analysis: "off".into(),
            receipt_redaction_level: "full".into(),
        }
    }

    fn policy_with_default(default_action: &str) -> EffectiveNativePolicyV3 {
        let mut value = policy();
        value.default_action = default_action.to_owned();
        value
    }

    fn signed_snapshot(generation: u64, key: &[u8], guard_home: &Path) -> PolicySnapshotV3 {
        signed_snapshot_with_policy(generation, key, guard_home, policy())
    }

    fn signed_snapshot_with_policy(
        generation: u64,
        key: &[u8],
        guard_home: &Path,
        effective_policy: EffectiveNativePolicyV3,
    ) -> PolicySnapshotV3 {
        let mut snapshot = PolicySnapshotV3 {
            schema: POLICY_SNAPSHOT_SCHEMA.into(),
            version: 3,
            generation,
            policy_digest: String::new(),
            config_digest: config_digest(&effective_policy).unwrap(),
            rule_digest: guard_rule_contract::rule_digest(),
            runtime_identity: "a".repeat(64),
            protocol_version: 1,
            mode: "enforce".into(),
            scope_contract: ScopeContractV3 {
                schema: "guard-native-scope.v1".into(),
                kind: "guard-home".into(),
                scope_digest: scope_digest(guard_home.to_string_lossy().as_ref()),
                workspace_binding: "request-source".into(),
            },
            effective_policy,
            issued_at_ms: now_ms().unwrap().saturating_sub(1),
            expires_at_ms: now_ms().unwrap() + 60_000,
            integrity: SnapshotIntegrityV3 {
                algorithm: POLICY_SNAPSHOT_INTEGRITY_ALGORITHM.into(),
                key_id: verifier_key_id(key),
                mac: String::new(),
            },
        };
        snapshot.policy_digest = policy_digest(&snapshot).unwrap();
        snapshot.integrity.mac = integrity_mac(&snapshot, key).unwrap();
        snapshot
    }

    fn test_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "hol-guard-policy-store-{label}-{}-{}",
            std::process::id(),
            now_ms().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    fn install_test_key(root: &Path, value: u8) -> [u8; VERIFIER_KEY_BYTES] {
        let key = [value; VERIFIER_KEY_BYTES];
        let path = root.join(VERIFIER_KEY_FILE_NAME);
        fs::write(&path, key).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        key
    }

    fn legacy_floor_value(generation: u64, policy_digest: &str, key: &[u8]) -> Value {
        serde_json::to_value(GenerationFloorV1 {
            schema: GENERATION_FLOOR_SCHEMA.to_owned(),
            generation,
            policy_digest: policy_digest.to_owned(),
            mac: generation_floor_mac(generation, policy_digest, key),
        })
        .unwrap()
    }

    #[test]
    fn missing_snapshot_is_not_ready_but_push_can_install_it() {
        let root = std::env::temp_dir().join(format!(
            "hol-guard-policy-store-{}-{}",
            std::process::id(),
            now_ms().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = [7u8; 32];
        fs::write(root.join(VERIFIER_KEY_FILE_NAME), key).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(
            root.join(VERIFIER_KEY_FILE_NAME),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        let snapshot = signed_snapshot(1, &key, &root);
        let request = serde_json::json!({
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": snapshot,
        });
        let ack: PolicySnapshotAckV1 =
            serde_json::from_slice(&store.push(&request).unwrap()).unwrap();
        assert_eq!(ack.generation, 1);
        assert!(!ack.idempotent);
        assert_eq!(store.current_generation(), Some(1));
        let duplicate: PolicySnapshotAckV1 =
            serde_json::from_slice(&store.push(&request).unwrap()).unwrap();
        assert!(duplicate.idempotent);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn generation_rollback_and_same_generation_mutation_are_rejected() {
        let root = std::env::temp_dir().join(format!(
            "hol-guard-policy-store-rollback-{}-{}",
            std::process::id(),
            now_ms().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = [8u8; 32];
        fs::write(root.join(VERIFIER_KEY_FILE_NAME), key).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(
            root.join(VERIFIER_KEY_FILE_NAME),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        let first = signed_snapshot(3, &key, &root);
        let first_request = serde_json::json!({
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": first,
        });
        store.push(&first_request).unwrap();
        let rollback = signed_snapshot(2, &key, &root);
        let rollback_request = serde_json::json!({
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": rollback,
        });
        assert_eq!(
            store.push(&rollback_request).unwrap_err(),
            "snapshot_generation_downgrade"
        );
        let mut mutated = first_request["snapshot"].clone();
        mutated["mode"] = Value::String("observe".into());
        let mutated_request = serde_json::json!({
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": mutated,
        });
        assert_eq!(
            store.push(&mutated_request).unwrap_err(),
            "snapshot_digest_mismatch"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restart_rehydrates_snapshot_and_hook_validation_uses_memory() {
        let root = std::env::temp_dir().join(format!(
            "hol-guard-policy-store-restart-{}-{}",
            std::process::id(),
            now_ms().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = [9u8; 32];
        let key_path = root.join(VERIFIER_KEY_FILE_NAME);
        fs::write(&key_path, key).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        let snapshot = signed_snapshot(4, &key, &root);
        let request = serde_json::json!({
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": snapshot,
        });
        store.push(&request).unwrap();
        let restored = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        assert_eq!(restored.current_generation(), Some(4));
        let snapshot_value = request["snapshot"].clone();
        assert!(restored
            .validate_request_snapshot(&snapshot_value, root.to_string_lossy().as_ref(), 4,)
            .is_ok());
        fs::remove_file(root.join(SNAPSHOT_FILE_NAME)).unwrap();
        assert!(restored
            .validate_request_snapshot(&snapshot_value, root.to_string_lossy().as_ref(), 4,)
            .is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restarted_resident_applies_installed_policy_without_request_time_io() {
        let root = std::env::temp_dir().join(format!(
            "hol-guard-policy-store-evaluate-{}-{}",
            std::process::id(),
            now_ms().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = [11u8; 32];
        let key_path = root.join(VERIFIER_KEY_FILE_NAME);
        fs::write(&key_path, key).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        let snapshot = signed_snapshot_with_policy(1, &key, &root, policy_with_default("block"));
        let snapshot_value = serde_json::to_value(&snapshot).unwrap();
        store
            .push(&serde_json::json!({
                "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
                "snapshot": snapshot_value,
            }))
            .unwrap();
        let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        let envelope = GuardHookEnvelopeV2 {
            schema: GUARD_HOOK_ENVELOPE_V2_SCHEMA.to_owned(),
            request_id: Some("resident-policy-test".into()),
            harness: "claude-code".into(),
            event: "PreToolUse".into(),
            raw_payload: serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "read_file",
                "tool_input": {"file_path": "README.md"}
            }),
            deadline_budget_ms: Some(750),
            policy_generation: 1,
            policy_snapshot: serde_json::to_value(&snapshot).unwrap(),
            source: GuardHookSourceMetadataV2 {
                cwd: Some("/workspace".into()),
                home_dir: "/home/test".into(),
                guard_home: root.to_string_lossy().into_owned(),
                source_ref_external_allowed: false,
            },
        };
        let result = crate::edge::evaluate_envelope_with_store(envelope, &restarted).unwrap();
        let result: GuardHookEdgeResultV2 = serde_json::from_slice(&result).unwrap();
        assert_eq!(result.result["minimum_action"], "block");
        assert_eq!(result.result["authority"], "rust");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn authenticated_edge_preserves_clean_default_warning() {
        let root = std::env::temp_dir().join(format!(
            "hol-guard-policy-store-warning-edge-{}-{}",
            std::process::id(),
            now_ms().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = [12u8; 32];
        let key_path = root.join(VERIFIER_KEY_FILE_NAME);
        fs::write(&key_path, key).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        let snapshot = signed_snapshot(1, &key, &root);
        store
            .push(&serde_json::json!({
                "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
                "snapshot": snapshot,
            }))
            .unwrap();
        let envelope = GuardHookEnvelopeV2 {
            schema: GUARD_HOOK_ENVELOPE_V2_SCHEMA.to_owned(),
            request_id: Some("warning-edge-test".into()),
            harness: "claude-code".into(),
            event: "PreToolUse".into(),
            raw_payload: serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_input": {"command": "pwd"}
            }),
            deadline_budget_ms: Some(750),
            policy_generation: 1,
            policy_snapshot: serde_json::to_value(&snapshot).unwrap(),
            source: GuardHookSourceMetadataV2 {
                cwd: Some("/workspace".into()),
                home_dir: "/home/test".into(),
                guard_home: root.to_string_lossy().into_owned(),
                source_ref_external_allowed: false,
            },
        };
        let result = crate::edge::evaluate_envelope_with_store(envelope, &store).unwrap();
        let result: GuardHookEdgeResultV2 = serde_json::from_slice(&result).unwrap();
        assert_eq!(result.result["minimum_action"], "warn");
        assert_eq!(result.result["decision"], "allow");
        assert_eq!(result.result["authority"], "rust");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn authenticated_observe_edge_preserves_intrinsic_pretool_floor() {
        let root = test_root("observe-edge");
        let key = install_test_key(&root, 15);
        let mut snapshot = signed_snapshot(1, &key, &root);
        snapshot.mode = "observe".into();
        snapshot.policy_digest = policy_digest(&snapshot).unwrap();
        snapshot.integrity.mac = integrity_mac(&snapshot, &key).unwrap();
        let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        store
            .push(&serde_json::json!({
                "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
                "snapshot": snapshot,
            }))
            .unwrap();
        let envelope = GuardHookEnvelopeV2 {
            schema: GUARD_HOOK_ENVELOPE_V2_SCHEMA.to_owned(),
            request_id: Some("observe-edge-test".into()),
            harness: "claude-code".into(),
            event: "PreToolUse".into(),
            raw_payload: serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /"}
            }),
            deadline_budget_ms: Some(750),
            policy_generation: 1,
            policy_snapshot: serde_json::to_value(&snapshot).unwrap(),
            source: GuardHookSourceMetadataV2 {
                cwd: Some("/workspace".into()),
                home_dir: "/home/test".into(),
                guard_home: root.to_string_lossy().into_owned(),
                source_ref_external_allowed: false,
            },
        };
        let result = crate::edge::evaluate_envelope_with_store(envelope, &store).unwrap();
        let result: GuardHookEdgeResultV2 = serde_json::from_slice(&result).unwrap();
        assert_eq!(result.result["minimum_action"], "block");
        assert_eq!(result.result["decision"], "deny");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn push_rejects_unknown_fields_without_mutating_state() {
        let root = std::env::temp_dir().join(format!(
            "hol-guard-policy-store-unknown-{}-{}",
            std::process::id(),
            now_ms().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = [10u8; 32];
        let key_path = root.join(VERIFIER_KEY_FILE_NAME);
        fs::write(&key_path, key).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        let snapshot = signed_snapshot(1, &key, &root);
        let request = serde_json::json!({
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": snapshot,
            "unexpected": true,
        });
        assert_eq!(
            store.push(&request).unwrap_err(),
            "native_policy_snapshot_push_invalid"
        );
        assert_eq!(store.current_generation(), None);
        assert!(!root.join(SNAPSHOT_FILE_NAME).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_snapshot_and_floor_migrate_to_one_authority_record() {
        let root = test_root("legacy-migration");
        let key = install_test_key(&root, 13);
        let snapshot = signed_snapshot(7, &key, &root);
        let snapshot_value = serde_json::to_value(&snapshot).unwrap();
        fs::write(
            root.join(SNAPSHOT_FILE_NAME),
            canonical_json_bytes(&snapshot_value).unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            root.join(SNAPSHOT_FILE_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let floor_value = legacy_floor_value(7, &snapshot.policy_digest, &key);
        fs::write(
            root.join(GENERATION_FLOOR_FILE_NAME),
            canonical_json_bytes(&floor_value).unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            root.join(GENERATION_FLOOR_FILE_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        assert_eq!(store.current_generation(), Some(7));
        let (authority, _) = read_private_json(
            &root.join(SNAPSHOT_FILE_NAME),
            AUTHORITY_RECORD_MAX_BYTES,
            "state",
        )
        .unwrap()
        .unwrap();
        assert_eq!(authority["schema"], AUTHORITY_RECORD_SCHEMA);
        assert_eq!(authority["generation_floor"], 7);
        assert!(authority["snapshot"].is_object());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn floor_only_migration_preserves_generation_and_allows_only_newer_push() {
        let root = test_root("floor-only-migration");
        let key = install_test_key(&root, 14);
        let digest = "b".repeat(64);
        let floor_value = legacy_floor_value(9, &digest, &key);
        fs::write(
            root.join(GENERATION_FLOOR_FILE_NAME),
            canonical_json_bytes(&floor_value).unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            root.join(GENERATION_FLOOR_FILE_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        assert_eq!(store.current_generation(), None);
        let older_snapshot = signed_snapshot(8, &key, &root);
        let older_request = serde_json::json!({
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": older_snapshot,
        });
        let older_ack: PolicySnapshotAckV1 =
            serde_json::from_slice(&store.push(&older_request).unwrap()).unwrap();
        assert_eq!(
            older_ack.status,
            guard_policy_snapshot::POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION
        );
        assert_eq!(older_ack.generation, 9);
        assert_eq!(older_ack.policy_digest, digest);
        assert!(!older_ack.idempotent);
        let equal_snapshot = signed_snapshot(9, &key, &root);
        let equal_request = serde_json::json!({
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": equal_snapshot,
        });
        let equal_ack: PolicySnapshotAckV1 = serde_json::from_slice(
            &crate::evaluate_resident_bytes(
                &canonical_json_bytes(&serde_json::json!({
                    "operation": "policy_snapshot_push",
                    "request": equal_request,
                }))
                .unwrap(),
                Some(&store),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            equal_ack.status,
            guard_policy_snapshot::POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION
        );
        assert_eq!(equal_ack.generation, 9);
        assert_eq!(equal_ack.policy_digest, digest);
        assert!(!equal_ack.idempotent);
        let snapshot = signed_snapshot(10, &key, &root);
        let request = serde_json::json!({
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": snapshot,
        });
        let ack: PolicySnapshotAckV1 =
            serde_json::from_slice(&store.push(&request).unwrap()).unwrap();
        assert_eq!(ack.generation, 10);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn authority_write_failures_at_each_boundary_are_retryable_without_rollback() {
        for boundary in [
            PersistBoundary::TemporaryCreate,
            PersistBoundary::Write,
            PersistBoundary::FileSync,
            PersistBoundary::Rename,
            PersistBoundary::DirectorySync,
        ] {
            let root = test_root("fault-boundary");
            let key = install_test_key(&root, boundary as u8 + 20);
            let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
            let snapshot = signed_snapshot(1, &key, &root);
            let request = serde_json::json!({
                "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
                "snapshot": snapshot,
            });
            PERSIST_FAILPOINT.with(|failpoint| failpoint.set(boundary as u8));
            assert!(store.push(&request).is_err());
            let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
            let ack: PolicySnapshotAckV1 =
                serde_json::from_slice(&restarted.push(&request).unwrap()).unwrap();
            if matches!(boundary, PersistBoundary::DirectorySync) {
                assert!(ack.idempotent);
            } else {
                assert!(!ack.idempotent);
            }
            let has_temporary = fs::read_dir(&root)
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"));
            assert!(!has_temporary);
            fs::remove_dir_all(root).unwrap();
        }
        PERSIST_FAILPOINT.with(|failpoint| failpoint.set(0));
    }
}
