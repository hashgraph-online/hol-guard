//! A sealed data-reduction intent can resume while off without recreating an
//! SDK scope. Its MAC role is separate from runtime selection and approvals.
use super::*;
use guard_context_assistance::{
    EvidenceCache, EvidenceErasureScope, EvidenceGenerationStore, EvidenceScope,
    EvidenceScopeErasure, RuntimeError,
};
use std::collections::BTreeSet;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    scope_sha256: String,
    legacy_keys: BTreeSet<String>,
    request_id: String,
}
pub(crate) struct ScopeRemoval {
    owner: Owner,
    raw: Vec<u8>,
    scope: EvidenceErasureScope,
}
#[cfg(test)]
thread_local! { static AFTER_PURGE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

fn data_error(code: String) -> RuntimeError {
    if code.ends_with("commit_outcome_unknown") {
        RuntimeError::StorageOutcomeUnknown
    } else if code.ends_with("_busy") {
        RuntimeError::Busy
    } else {
        RuntimeError::StorageRepairRequired
    }
}
fn write_error(failure: crate::guard_config_update::Failure) -> RuntimeError {
    data_error(storage_error(failure))
}
fn intent_message(home: &Path, payload: &str) -> Result<Vec<u8>, RuntimeError> {
    serde_json::to_vec(&(
        "hol-guard-cigar-scope-erasure-intent.v1",
        format!("{:x}", Sha256::digest(home.as_os_str().as_encoded_bytes())),
        payload,
    ))
    .map_err(|_| RuntimeError::StorageRepairRequired)
}
fn decode_intent(owner: &Owner, raw: &[u8]) -> Result<EvidenceErasureScope, RuntimeError> {
    let envelope: Envelope = crate::strict_json_value(raw)
        .and_then(|v| crate::strict_json::from_value(v).map_err(|_| error("erase_intent_invalid")))
        .map_err(data_error)?;
    if envelope.schema != "guard-cigar-sealed-scope-erasure.v1"
        || envelope.payload.len() > 3072
        || !is_lower_hex(&envelope.mac, 64)
    {
        return Err(RuntimeError::StorageRepairRequired);
    }
    let key = owner
        .key
        .as_deref()
        .ok_or(RuntimeError::StorageRepairRequired)?;
    hmac::verify(
        &hmac::Key::new(hmac::HMAC_SHA256, key),
        &intent_message(&owner.home, &envelope.payload)?,
        &hex::decode(&envelope.mac).map_err(|_| RuntimeError::StorageRepairRequired)?,
    )
    .map_err(|_| RuntimeError::StorageRepairRequired)?;
    let intent: Intent = crate::strict_json_value(envelope.payload.as_bytes())
        .and_then(|v| crate::strict_json::from_value(v).map_err(|_| error("erase_intent_invalid")))
        .map_err(data_error)?;
    if intent.schema != "guard-cigar-scope-erasure.v1" || !is_lower_hex(&intent.request_id, 32) {
        return Err(RuntimeError::StorageRepairRequired);
    }
    EvidenceErasureScope::from_authenticated_intent(&intent.scope_sha256, intent.legacy_keys)
}
impl ScopeRemoval {
    #[cfg(test)]
    pub(crate) fn fail_next_after_purge() {
        AFTER_PURGE.with(|f| f.set(true));
    }
    pub(crate) fn acquire(
        home: &Path,
        scope: &EvidenceScope,
        workers: &BTreeSet<String>,
        current: Option<&EvidenceCache>,
    ) -> Result<Self, RuntimeError> {
        let mut owner = Owner::acquire(home).map_err(data_error)?;
        DataRemoval::check_clear(&owner.home)?;
        if owner
            .record
            .as_ref()
            .and_then(|r| r.transaction.as_ref())
            .is_some_and(|t| !t.phase.terminal())
        {
            return Err(RuntimeError::StorageRepairRequired);
        }
        let scope = EvidenceErasureScope::capture(&owner.home, scope, workers)?;
        let scope = scope.ensure_attributed(&owner.home, current, &scope_index::owners(&owner)?)?;
        let lock = WriteLock::acquire(&owner.home).map_err(write_error)?;
        owner.check(&lock).map_err(data_error)?;
        if lock
            .lifecycle_bytes(LifecycleFile::Erasure)
            .map_err(write_error)?
            .is_some()
        {
            return Err(RuntimeError::StorageRepairRequired);
        }
        owner.provision(&lock).map_err(data_error)?;
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| RuntimeError::StorageRepairRequired)?;
        let payload = serde_json::to_string(&Intent {
            schema: "guard-cigar-scope-erasure.v1".into(),
            scope_sha256: scope.namespace_sha256().into(),
            legacy_keys: scope.legacy_keys().clone(),
            request_id: hex::encode(nonce),
        })
        .map_err(|_| RuntimeError::StorageRepairRequired)?;
        let key = owner
            .key
            .as_deref()
            .ok_or(RuntimeError::StorageRepairRequired)?;
        let mac = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, key),
            &intent_message(&owner.home, &payload)?,
        );
        let raw = serde_json::to_vec(&Envelope {
            schema: "guard-cigar-sealed-scope-erasure.v1".into(),
            payload,
            mac: hex::encode(mac.as_ref()),
        })
        .map_err(|_| RuntimeError::StorageRepairRequired)?;
        lock.publish_lifecycle(LifecycleFile::Erasure, None, &raw)
            .map_err(write_error)?;
        Ok(Self { owner, raw, scope })
    }
    /// Explicit access-reduction repair, permitted while disabled. The private
    /// MAC and exact-byte check precede all cache mutation.
    pub(crate) fn resume(home: &Path) -> Result<Self, RuntimeError> {
        let owner = Owner::acquire(home).map_err(data_error)?;
        let lock = WriteLock::acquire(&owner.home).map_err(write_error)?;
        owner.check(&lock).map_err(data_error)?;
        let raw = lock
            .lifecycle_bytes(LifecycleFile::Erasure)
            .map_err(write_error)?
            .ok_or(RuntimeError::StorageRepairRequired)?;
        lock.check_erasure_intent(&raw).map_err(write_error)?;
        let scope = decode_intent(&owner, &raw)?;
        Ok(Self { owner, raw, scope })
    }
    pub(crate) fn remove(
        self,
        current: Option<&EvidenceCache>,
    ) -> Result<EvidenceScopeErasure, RuntimeError> {
        let scope = self.scope.ensure_attributed(
            &self.owner.home,
            current,
            &scope_index::owners(&self.owner)?,
        )?;
        let erased = EvidenceGenerationStore::forget_scope_copies(
            &self.owner.home,
            &scope,
            current,
            crate::context_assistance_data::now_ms(),
        )?;
        #[cfg(test)]
        if AFTER_PURGE.with(|f| f.replace(false)) {
            return Err(RuntimeError::StorageOutcomeUnknown);
        }
        scope_index::forget_scope(&self.owner, self.scope.namespace_sha256())?;
        let lock = WriteLock::acquire(&self.owner.home).map_err(write_error)?;
        self.owner.check(&lock).map_err(data_error)?;
        lock.complete_scope_erasure(&self.raw)
            .map_err(write_error)?;
        Ok(erased)
    }
}
