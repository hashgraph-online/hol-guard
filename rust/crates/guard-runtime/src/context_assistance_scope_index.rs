//! Bounded native cache attribution. No paths, sources, grants or SDK authority.
use super::*;
use guard_context_assistance::{
    EvidenceCache, EvidenceCacheLocation, EvidenceGenerationStore, EvidenceScope,
    EvidenceScopeOwner, RuntimeError,
};
use std::collections::BTreeSet;

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Index {
    schema: String,
    owners: Vec<EvidenceScopeOwner>,
}
fn data_error(code: String) -> RuntimeError {
    if code.ends_with("commit_outcome_unknown") {
        RuntimeError::StorageOutcomeUnknown
    } else if code.ends_with("_busy") {
        RuntimeError::Busy
    } else {
        RuntimeError::StorageRepairRequired
    }
}
fn write_error(f: crate::guard_config_update::Failure) -> RuntimeError {
    data_error(storage_error(f))
}
fn message(home: &Path, payload: &str) -> Result<Vec<u8>, RuntimeError> {
    serde_json::to_vec(&(
        "hol-guard-cigar-scope-index.v1",
        format!("{:x}", Sha256::digest(home.as_os_str().as_encoded_bytes())),
        payload,
    ))
    .map_err(|_| RuntimeError::StorageRepairRequired)
}
fn decode(home: &Path, raw: Option<&[u8]>, key: Option<&[u8; 32]>) -> Result<Index, RuntimeError> {
    let Some(raw) = raw else {
        return Ok(Index {
            schema: "guard-cigar-scope-index.v1".into(),
            owners: Vec::new(),
        });
    };
    let envelope: Envelope = crate::strict_json_value(raw)
        .and_then(|v| crate::strict_json::from_value(v).map_err(|_| error("scope_index_invalid")))
        .map_err(data_error)?;
    if envelope.schema != "guard-cigar-sealed-scope-index.v1"
        || envelope.payload.len() > 24 * 1024
        || !is_lower_hex(&envelope.mac, 64)
    {
        return Err(RuntimeError::StorageRepairRequired);
    }
    hmac::verify(
        &hmac::Key::new(
            hmac::HMAC_SHA256,
            key.ok_or(RuntimeError::StorageRepairRequired)?,
        ),
        &message(home, &envelope.payload)?,
        &hex::decode(envelope.mac).map_err(|_| RuntimeError::StorageRepairRequired)?,
    )
    .map_err(|_| RuntimeError::StorageRepairRequired)?;
    let index: Index = crate::strict_json_value(envelope.payload.as_bytes())
        .and_then(|v| crate::strict_json::from_value(v).map_err(|_| error("scope_index_invalid")))
        .map_err(data_error)?;
    let mut unique = BTreeSet::new();
    if index.schema != "guard-cigar-scope-index.v1"
        || index.owners.len() > 64
        || index
            .owners
            .iter()
            .any(|row| !row.valid() || !unique.insert((&row.location, &row.slot_key)))
    {
        return Err(RuntimeError::StorageRepairRequired);
    }
    Ok(index)
}
fn seal(home: &Path, index: &Index, key: &[u8; 32]) -> Result<Vec<u8>, RuntimeError> {
    let payload = serde_json::to_string(index).map_err(|_| RuntimeError::StorageRepairRequired)?;
    if payload.len() > 24 * 1024 {
        return Err(RuntimeError::ResourceLimit);
    }
    let mac = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, key),
        &message(home, &payload)?,
    );
    serde_json::to_vec(&Envelope {
        schema: "guard-cigar-sealed-scope-index.v1".into(),
        payload,
        mac: hex::encode(mac.as_ref()),
    })
    .map_err(|_| RuntimeError::StorageRepairRequired)
}
/// Called only with the actor's actual owned cache and freshly granted native
/// app/workspace. This cannot be supplied as an operator wire payload.
pub(crate) fn remember(
    home: &Path,
    cache: &EvidenceCache,
    scope: &EvidenceScope,
    key: &str,
) -> Result<(), RuntimeError> {
    let home = fs::canonicalize(home).map_err(|_| RuntimeError::StorageRepairRequired)?;
    let location = cache.scope_location(&home)?;
    let keys = cache.slot_keys()?;
    let row = EvidenceScopeOwner {
        location: location.clone(),
        slot_key: key.into(),
        scope_sha256: scope.namespace_sha256().into(),
    };
    if !row.valid() {
        return Err(RuntimeError::RequestInvalid);
    }
    let lock = WriteLock::acquire(&home).map_err(write_error)?;
    DataRemoval::check_clear(&home)?;
    let raw = lock
        .lifecycle_bytes(LifecycleFile::ScopeIndex)
        .map_err(write_error)?;
    let mut key_bytes_current = key_bytes(&lock).map_err(data_error)?;
    if key_bytes_current.is_none()
        && (lock
            .lifecycle_bytes(LifecycleFile::Record)
            .map_err(write_error)?
            .is_some()
            || lock
                .lifecycle_bytes(LifecycleFile::InitialSelection)
                .map_err(write_error)?
                .is_some())
    {
        return Err(RuntimeError::StorageRepairRequired);
    }
    let mut index = decode(&home, raw.as_deref(), key_bytes_current.as_deref())?;
    let before = index.clone();
    let live = EvidenceGenerationStore::existing(&home)?
        .map(|s| s.list())
        .transpose()?
        .unwrap_or_default();
    if let EvidenceCacheLocation::Generation { generation_id } = &location {
        if !live
            .iter()
            .any(|g| g["generation_id"] == generation_id.as_str())
        {
            return Err(RuntimeError::StorageRepairRequired);
        }
    }
    index.owners.retain(|e| match &e.location {
        EvidenceCacheLocation::Legacy => true,
        EvidenceCacheLocation::Generation { generation_id } => live
            .iter()
            .any(|g| g["generation_id"] == generation_id.as_str()),
    });
    index
        .owners
        .retain(|e| e.location != location || keys.contains(&e.slot_key) || e.slot_key == key);
    if let Some(existing) = index
        .owners
        .iter()
        .find(|e| e.location == location && e.slot_key == key)
    {
        if existing != &row {
            return Err(RuntimeError::StorageRepairRequired);
        }
    } else {
        index.owners.push(row);
    }
    index.owners.sort();
    if index.owners.len() > 64 {
        return Err(RuntimeError::ResourceLimit);
    }
    if index == before {
        return Ok(());
    }
    if key_bytes_current.is_none() {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| RuntimeError::StorageRepairRequired)?;
        lock.publish_lifecycle(LifecycleFile::Key, None, bytes.as_ref())
            .map_err(write_error)?;
        key_bytes_current = key_bytes(&lock).map_err(data_error)?;
        if key_bytes_current.as_deref() != Some(&*bytes) {
            return Err(RuntimeError::StorageRepairRequired);
        }
    }
    let key = key_bytes_current
        .as_deref()
        .ok_or(RuntimeError::StorageRepairRequired)?;
    lock.publish_lifecycle(
        LifecycleFile::ScopeIndex,
        raw.as_deref(),
        &seal(&home, &index, key)?,
    )
    .map_err(write_error)
}
pub(crate) fn owners(owner: &Owner) -> Result<Vec<EvidenceScopeOwner>, RuntimeError> {
    let lock = WriteLock::acquire(&owner.home).map_err(write_error)?;
    owners_locked(owner, &lock)
}
pub(super) fn owners_locked(
    owner: &Owner,
    lock: &WriteLock,
) -> Result<Vec<EvidenceScopeOwner>, RuntimeError> {
    owner.check(lock).map_err(data_error)?;
    let raw = lock
        .lifecycle_bytes(LifecycleFile::ScopeIndex)
        .map_err(write_error)?;
    Ok(decode(&owner.home, raw.as_deref(), owner.key.as_deref())?.owners)
}
pub(super) fn forget_scope(owner: &Owner, scope: &str) -> Result<(), RuntimeError> {
    let lock = WriteLock::acquire(&owner.home).map_err(write_error)?;
    owner.check(&lock).map_err(data_error)?;
    let raw = lock
        .lifecycle_bytes(LifecycleFile::ScopeIndex)
        .map_err(write_error)?;
    let mut index = decode(&owner.home, raw.as_deref(), owner.key.as_deref())?;
    let count = index.owners.len();
    index.owners.retain(|e| e.scope_sha256 != scope);
    if index.owners.len() == count {
        return Ok(());
    }
    let key = owner
        .key
        .as_deref()
        .ok_or(RuntimeError::StorageRepairRequired)?;
    lock.publish_lifecycle(
        LifecycleFile::ScopeIndex,
        raw.as_deref(),
        &seal(&owner.home, &index, key)?,
    )
    .map_err(write_error)
}

/// Passive saved-data inspection does not provision a key or a namespace.
pub(crate) fn validate_present(home: &Path) -> Result<(), RuntimeError> {
    match fs::symlink_metadata(home.join("cigar-scopes.json")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(RuntimeError::StorageRepairRequired),
        Ok(_) => {}
    }
    let home = fs::canonicalize(home).map_err(|_| RuntimeError::StorageRepairRequired)?;
    let lock = WriteLock::acquire(&home).map_err(write_error)?;
    let raw = lock
        .lifecycle_bytes(LifecycleFile::ScopeIndex)
        .map_err(write_error)?;
    let key = key_bytes(&lock).map_err(data_error)?;
    decode(&home, raw.as_deref(), key.as_deref()).map(|_| ())
}
#[cfg(all(test, unix))]
#[path = "context_assistance_scope_index_tests.rs"]
mod tests;
