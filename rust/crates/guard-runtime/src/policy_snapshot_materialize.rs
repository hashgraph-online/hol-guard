//! Build or reuse the publisher's generation-bound snapshot under its lock.
//!
//! The publisher retains each signed snapshot before any resident sees it, so
//! the cache, the generation state and the crash-recovery candidate move
//! together under one owner-private lock. A retained snapshot whose content
//! still matches is returned unchanged; anything else takes the next
//! generation, and the generation is durable before the bytes leave here.
#![forbid(unsafe_code)]

use super::policy_store_persistence::{is_lower_hex, persist_private_bytes, read_private_json};
use crate::policy_snapshot_build::{
    present_business_binding, read_request, seal, unsigned_snapshot, PublisherKey, SnapshotContent,
};
use guard_contracts::NativeCommandControlBindingV1;
use guard_policy_snapshot::{
    business_policy::BusinessPolicyBindingV1, canonical_json_bytes, integrity_mac, snapshot_bytes,
    verifier_key_id, EffectiveNativePolicyV3, PolicySnapshotV3, ScopeContractV3,
    POLICY_SNAPSHOT_MAX_BYTES,
};
use serde::Deserialize;
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SCHEMA: &str = "guard-native-policy-materialize.v1";
const ERROR: &str = "native_policy_snapshot_build_invalid";
const RUNTIME_DIRECTORY: &str = "native-runtime";
const CACHE_NAME: &str = "policy-snapshot-publisher-v3.json";
const PENDING_NAME: &str = "policy-snapshot-publisher-v3.pending.json";
const STATE_NAME: &str = "native-policy-snapshot-generation-v3.json";
const LOCK_NAME: &str = "native-policy-snapshot-generation-v3.lock";
const STATE_SCHEMA: &str = "guard-native-policy-snapshot-generation.v3";
const RESIDENT_STATE_NAMES: [&str; 2] = [
    "policy-snapshot-generation-floor.json",
    "policy-snapshot-v3.json",
];
const MAX_STATE_BYTES: u64 = 4096;
const LOCK_POLL: Duration = Duration::from_millis(10);
/// The longest a publisher waits for the generation lock; the caller's own
/// process deadline is far shorter.
const MAX_LOCK_WAIT_MS: u64 = 60_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterializeRequest {
    schema: String,
    version: u16,
    verifier_key: PublisherKey,
    guard_home: PathBuf,
    runtime_identity: String,
    rule_digest: String,
    mode: String,
    scope_contract: ScopeContractV3,
    effective_policy: EffectiveNativePolicyV3,
    #[serde(default)]
    command_extensions: Option<NativeCommandControlBindingV1>,
    #[serde(default, deserialize_with = "present_business_binding")]
    business_policy: Option<BusinessPolicyBindingV1>,
    issued_at_ms: u64,
    expires_at_ms: u64,
    #[serde(default)]
    renew_after_generation: Option<u64>,
    lock_wait_ms: u64,
}

/// The committed generation and the policy digest it was allocated for.
type Generation = (u64, String);

struct Home {
    root: PathBuf,
    runtime: PathBuf,
}

impl Home {
    fn cache(&self) -> PathBuf {
        self.runtime.join(CACHE_NAME)
    }

    fn pending(&self) -> PathBuf {
        self.runtime.join(PENDING_NAME)
    }

    fn state(&self) -> PathBuf {
        self.root.join(STATE_NAME)
    }
}

pub(crate) fn materialize_from_reader(reader: impl Read) -> Result<Vec<u8>, String> {
    let (bytes, filled) = read_request(reader)?;
    let request: MaterializeRequest =
        serde_json::from_slice(&bytes[..filled]).map_err(|_| ERROR.to_owned())?;
    if request.schema != SCHEMA || request.version != 1 {
        return Err(ERROR.into());
    }
    if request.renew_after_generation == Some(0) {
        return Err("native_policy_snapshot_generation_invalid".into());
    }
    if request.lock_wait_ms > MAX_LOCK_WAIT_MS {
        return Err(ERROR.into());
    }
    let home = Home {
        runtime: request.guard_home.join(RUNTIME_DIRECTORY),
        root: request.guard_home,
    };
    let key = request.verifier_key;
    let mut snapshot = unsigned_snapshot(SnapshotContent {
        runtime_identity: request.runtime_identity,
        rule_digest: request.rule_digest,
        mode: request.mode,
        scope_contract: request.scope_contract,
        effective_policy: request.effective_policy,
        command_extensions: request.command_extensions,
        business_policy: request.business_policy,
        issued_at_ms: request.issued_at_ms,
        expires_at_ms: request.expires_at_ms,
    })?;
    let _lock = GenerationLock::acquire(&home, Duration::from_millis(request.lock_wait_ms))?;
    // The resident authenticates snapshots with the home's verifier key, so a
    // generation sealed under any other key could never be read. Refuse it
    // before anything is written.
    if let Some(existing) = crate::policy_verifier_key_provision::existing_key(&home.runtime)? {
        if !crate::resident_transport::constant_time_eq(&existing, key.bytes()) {
            return Err("native_policy_verifier_key_mismatch".into());
        }
    }
    recover_pending(&home, key.bytes())?;
    let current = read_generation(&home)?;
    let mut renew = request.renew_after_generation;
    if let Some(cached) = read_snapshot(&home.cache(), &home.root, key.bytes())? {
        if cached.0.business_policy.is_some() && snapshot.business_policy.is_none() {
            // Omission by an ordinary caller is not authenticated removal
            // authority; never discard a signed business binding to recover.
            return Err("native_business_policy_removal_requires_authority".into());
        }
        if same_content(&cached.0, &snapshot) {
            let generation = cached.0.generation;
            if current.as_ref() != Some(&(generation, snapshot.policy_digest.clone())) {
                return Err("native_policy_snapshot_generation_state_invalid".into());
            }
            let fresh = cached.0.expires_at_ms > now_ms()?;
            if fresh && renew.is_none_or(|after| generation > after) {
                return Ok(cached.1);
            }
            if !fresh {
                renew = Some(renew.unwrap_or(0).max(generation));
            }
        }
    }
    let generation = next_generation(&home, current.as_ref(), &snapshot.policy_digest, renew)?;
    let payload = seal(&mut snapshot, generation, key.bytes())?;
    commit(&home, &payload, generation, &snapshot.policy_digest)?;
    Ok(payload)
}

fn same_content(cached: &PolicySnapshotV3, built: &PolicySnapshotV3) -> bool {
    cached.mode == built.mode
        && cached.config_digest == built.config_digest
        && cached.policy_digest == built.policy_digest
        && cached.runtime_identity == built.runtime_identity
        && cached.rule_digest == built.rule_digest
        && cached.scope_contract.scope_digest == built.scope_contract.scope_digest
}

fn next_generation(
    home: &Home,
    current: Option<&Generation>,
    policy_digest: &str,
    minimum: Option<u64>,
) -> Result<u64, String> {
    if let Some((generation, digest)) = current {
        if digest == policy_digest && minimum.is_none_or(|after| *generation > after) {
            // The committed generation names this content, so its snapshot
            // must still be retained; never re-sign it under the same number.
            return Err("native_policy_snapshot_cache_missing".into());
        }
    }
    let exhausted = "native_policy_snapshot_generation_exhausted";
    if current.is_some_and(|(generation, _)| *generation == u64::MAX) || minimum == Some(u64::MAX) {
        return Err(exhausted.into());
    }
    let floor = minimum.map_or(1, |after| after + 1);
    match current {
        Some((generation, _)) => Ok((generation + 1).max(floor)),
        None => {
            if minimum.is_none()
                && RESIDENT_STATE_NAMES
                    .iter()
                    .any(|name| home.runtime.join(name).exists())
            {
                // A resident already admitted generations this home no longer
                // records; restarting at one would be refused as a rollback.
                return Err("native_policy_snapshot_generation_state_missing".into());
            }
            Ok(floor)
        }
    }
}

/// Retain the candidate, then the cache, then the generation, then drop the
/// candidate. A crash at any point leaves state `recover_pending` completes.
fn commit(home: &Home, payload: &[u8], generation: u64, policy_digest: &str) -> Result<(), String> {
    write_snapshot(home, &home.pending(), payload)?;
    write_snapshot(home, &home.cache(), payload)?;
    write_generation(home, generation, policy_digest)?;
    clear_pending(home)
}

/// Complete a cache and generation transaction a crashed publisher left.
fn recover_pending(home: &Home, key: &[u8; 32]) -> Result<(), String> {
    let Some((pending, pending_bytes)) = read_snapshot(&home.pending(), &home.root, key)? else {
        return Ok(());
    };
    let generation = pending.generation;
    if generation == 0 || !is_lower_hex(&pending.policy_digest, 64) {
        return Err("native_policy_snapshot_transaction_invalid".into());
    }
    let current = read_generation(home)?;
    if let Some((committed, digest)) = &current {
        if *committed > generation {
            // A newer generation is committed; the candidate can never be
            // retried without breaking monotonic order.
            return clear_pending(home);
        }
        if *committed == generation && *digest != pending.policy_digest {
            return Err("native_policy_snapshot_transaction_conflict".into());
        }
    }
    match read_snapshot(&home.cache(), &home.root, key)? {
        Some((cached, cached_bytes)) if cached_bytes != pending_bytes => {
            if cached.generation > generation {
                return Err("native_policy_snapshot_transaction_conflict".into());
            }
            write_snapshot(home, &home.cache(), &pending_bytes)?;
        }
        Some(_) => {}
        None => write_snapshot(home, &home.cache(), &pending_bytes)?,
    }
    if current.is_none_or(|(committed, _)| committed < generation) {
        write_generation(home, generation, &pending.policy_digest)?;
    }
    clear_pending(home)
}

/// Read one exact, canonical, authenticated snapshot from a private file.
fn read_snapshot(
    path: &Path,
    private_root: &Path,
    key: &[u8; 32],
) -> Result<Option<(PolicySnapshotV3, Vec<u8>)>, String> {
    let read = read_private_json(
        path,
        POLICY_SNAPSHOT_MAX_BYTES as u64,
        "cache",
        private_root,
    )
    .map_err(|error| {
        if error.ends_with("_stat_failed") {
            "native_policy_snapshot_cache_read_failed".to_owned()
        } else if error.ends_with("_not_private") {
            "native_policy_snapshot_cache_invalid".to_owned()
        } else {
            error
        }
    })?;
    let Some((value, bytes)) = read else {
        return Ok(None);
    };
    let snapshot: PolicySnapshotV3 = serde_json::from_value(value)
        .map_err(|_| "native_policy_snapshot_cache_invalid".to_owned())?;
    if snapshot_bytes(&snapshot).ok().as_deref() != Some(bytes.as_slice()) {
        return Err("native_policy_snapshot_cache_noncanonical".into());
    }
    let authentic = snapshot.integrity.key_id == verifier_key_id(key)
        && integrity_mac(&snapshot, key).is_ok_and(|mac| {
            crate::constant_time_eq(mac.as_bytes(), snapshot.integrity.mac.as_bytes())
        });
    if !authentic {
        return Err("native_policy_snapshot_cache_integrity_invalid".into());
    }
    Ok(Some((snapshot, bytes)))
}

fn write_snapshot(home: &Home, path: &Path, payload: &[u8]) -> Result<(), String> {
    persist_private_bytes(
        path,
        payload,
        POLICY_SNAPSHOT_MAX_BYTES as u64,
        "cache",
        &home.root,
    )
}

#[cfg(windows)]
fn clear_pending(home: &Home) -> Result<(), String> {
    crate::resident_state::remove_windows_private_file(&home.pending(), &home.root)
        .map(|_| ())
        .map_err(|_| "native_policy_snapshot_cache_write_failed".to_owned())
}

#[cfg(not(windows))]
fn clear_pending(home: &Home) -> Result<(), String> {
    match std::fs::remove_file(home.pending()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("native_policy_snapshot_cache_write_failed".into()),
    }
}

fn read_generation(home: &Home) -> Result<Option<Generation>, String> {
    let invalid = || "native_policy_snapshot_generation_state_invalid".to_owned();
    let Some((value, bytes)) = read_private_json(
        &home.state(),
        MAX_STATE_BYTES,
        "generation_state",
        &home.root,
    )
    .map_err(|_| invalid())?
    else {
        return Ok(None);
    };
    let object = value.as_object().ok_or_else(invalid)?;
    let generation = object.get("generation").and_then(Value::as_u64);
    let digest = object.get("policy_digest").and_then(Value::as_str);
    match (generation, digest) {
        (Some(generation), Some(digest))
            if object.len() == 3
                && object.get("schema").and_then(Value::as_str) == Some(STATE_SCHEMA)
                && generation >= 1
                && is_lower_hex(digest, 64)
                && canonical_json_bytes(&value).ok().as_deref() == Some(bytes.as_slice()) =>
        {
            Ok(Some((generation, digest.to_owned())))
        }
        _ => Err(invalid()),
    }
}

fn write_generation(home: &Home, generation: u64, policy_digest: &str) -> Result<(), String> {
    let value = serde_json::json!({
        "generation": generation,
        "policy_digest": policy_digest,
        "schema": STATE_SCHEMA,
    });
    let payload = canonical_json_bytes(&value)
        .map_err(|_| "native_policy_snapshot_generation_state_write_failed".to_owned())?;
    write_state_file(home, &payload)
        .map_err(|_| "native_policy_snapshot_generation_state_write_failed".to_owned())
}

/// The Guard home is owner-only for writes, not reads, so the generation
/// file cannot use the private-directory writer the runtime directory uses.
#[cfg(unix)]
fn write_state_file(home: &Home, payload: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(std::io::Error::other)?;
    let temporary = home
        .root
        .join(format!(".{STATE_NAME}.{}.tmp", hex::encode(nonce)));
    let written = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        file.write_all(payload)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, home.state())?;
        std::fs::set_permissions(home.state(), std::fs::Permissions::from_mode(0o600))?;
        File::open(&home.root)?.sync_all()
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written
}

#[cfg(not(unix))]
fn write_state_file(home: &Home, payload: &[u8]) -> Result<(), String> {
    persist_private_bytes(
        &home.state(),
        payload,
        MAX_STATE_BYTES,
        "generation_state",
        &home.root,
    )
}

fn now_ms() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .ok_or_else(|| "native_resident_clock_invalid".to_owned())
}

/// The owner-private advisory lock every publisher of this home takes.
struct GenerationLock {
    file: File,
    #[cfg(windows)]
    _binding: guard_runtime_windows_process::PrivateDirectoryBinding,
}

impl GenerationLock {
    fn acquire(home: &Home, wait: Duration) -> Result<Self, String> {
        let invalid = || "native_policy_snapshot_generation_lock_invalid".to_owned();
        let path = home.root.join(LOCK_NAME);
        #[cfg(windows)]
        let (file, binding) =
            crate::resident_state::private_lock_file(&path, &home.root).map_err(|_| invalid())?;
        #[cfg(not(windows))]
        let file = open_unix_lock(&path, &home.root).ok_or_else(invalid)?;
        let deadline = Instant::now().checked_add(wait).ok_or_else(invalid)?;
        loop {
            match fs2::FileExt::try_lock_exclusive(&file) {
                Ok(()) => break,
                Err(error) if crate::resident_state::is_lock_contention(&error) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err("native_policy_snapshot_generation_lock_timeout".into());
                    }
                    std::thread::sleep(remaining.min(LOCK_POLL));
                }
                Err(_) => return Err(invalid()),
            }
        }
        Ok(Self {
            file,
            #[cfg(windows)]
            _binding: binding,
        })
    }
}

impl Drop for GenerationLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

#[cfg(not(windows))]
fn open_unix_lock(path: &Path, home: &Path) -> Option<File> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_STATE_BYTES {
        return None;
    }
    #[cfg(unix)]
    {
        let owner = std::fs::metadata(home).ok()?.uid();
        if metadata.uid() != owner || metadata.permissions().mode() & 0o077 != 0 {
            return None;
        }
    }
    #[cfg(not(unix))]
    let _ = home;
    if metadata.len() == 0 {
        file.write_all(b"0").ok()?;
        file.sync_all().ok()?;
    }
    Some(file)
}

#[cfg(test)]
#[path = "policy_snapshot_materialize_tests.rs"]
mod tests;
