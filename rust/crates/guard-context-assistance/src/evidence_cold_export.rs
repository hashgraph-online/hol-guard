//! Explicit closed-profile data export. Ownership rows must come from the
//! native MAC-verified scope index; they contain hashes, never project paths.
use super::*;
use crate::{
    ContextAssistanceConfig, EvidenceCacheLocation, EvidenceScopeOwner, EvidenceUpgradeProducer,
    VerifiedNoteTransfer, VerifiedRuntime,
};
use transfer::TransferData;
impl EvidenceCache {
    fn cold_slot(&self, key: &str, now: u64) -> Result<Option<EvidenceSlot>, RuntimeError> {
        let _operation = self.root.operation()?;
        if !valid_key(key) || now == 0 {
            return Err(RuntimeError::RequestInvalid);
        }
        let directory = self.root.directory.child(key, false)?;
        let state = load(&directory, key)?;
        if state.intent.is_some() || directory.names(3)?.iter().any(|s| s == "state.next") {
            return Err(RuntimeError::StorageOutcomeUnknown);
        }
        if now < state.last_seen_ms {
            return Err(RuntimeError::StorageRepairRequired);
        }
        if now >= state.expires_at_ms {
            return Ok(None);
        }
        if !self.root.active()?.insert(key.into()) {
            return Err(RuntimeError::Busy);
        }
        let slot = EvidenceSlot {
            lease: Arc::new(Lease {
                root: Arc::clone(&self.root),
                key: key.into(),
            }),
            directory,
            state,
            poisoned: false,
        };
        slot.check(now)?;
        Ok(Some(slot))
    }
    /// Requires the native profile lifecycle lease and complete authenticated
    /// attribution. It neither sweeps nor observes/rewrites source manifests.
    pub fn export_cold_notes(
        &self,
        home: &Path,
        owners: &[EvidenceScopeOwner],
        producer: &EvidenceUpgradeProducer,
        runtime: &mut VerifiedRuntime,
        config: &ContextAssistanceConfig,
        now: u64,
    ) -> Result<Vec<VerifiedNoteTransfer>, RuntimeError> {
        if config.enabled
            || config.storage.mode != crate::StorageMode::Sqlite
            || !producer.data_preparation_qualified()
        {
            return Err(RuntimeError::ScopeDenied);
        }
        producer.revalidate_runtime(runtime)?;
        let location = self.scope_location(home)?;
        if owners.len() > 64 || owners.iter().any(|o| !o.valid()) {
            return Err(RuntimeError::StorageRepairRequired);
        }
        let mut map = BTreeMap::new();
        for owner in owners.iter().filter(|o| o.location == location) {
            if map
                .insert(owner.slot_key.clone(), owner.scope_sha256.clone())
                .is_some()
            {
                return Err(RuntimeError::StorageRepairRequired);
            }
        }
        let keys = self.slot_keys()?;
        if keys.iter().any(|k| !map.contains_key(k)) {
            return Err(RuntimeError::StorageRepairRequired);
        }
        if matches!(location, EvidenceCacheLocation::Generation { .. })
            && keys.iter().any(|k| {
                transfer::target_key(&map[k], producer.identity_sha256()).as_ref() != Ok(k)
            })
        {
            return Err(RuntimeError::ScopeDenied);
        }
        let mut data_config = config.clone();
        data_config.enabled = true;
        let mut exports = Vec::new();
        for key in keys {
            let Some(slot) = self.cold_slot(&key, now)? else {
                continue;
            };
            let raw = slot.directory.read("state.json")?;
            let domain = runtime.open_persistent_broker_domain(
                &slot.domain_name(),
                &data_config,
                slot.broker_storage()?,
            )?;
            let proof = runtime.cold_note_proof(
                &domain,
                &slot.directory.child("sdk", false)?.path,
                &slot.state.notes_version,
                slot.state.notes.as_ref(),
                now,
            );
            let closed = runtime.close_broker_domain(&domain);
            if let Err(e) = closed {
                runtime.close();
                return Err(e);
            }
            let proof = proof?;
            if slot.directory.read("state.json")? != raw {
                return Err(RuntimeError::ContextStale);
            }
            let mut notes = slot.state.notes.clone();
            let expires = slot
                .state
                .expires_at_ms
                .min(proof.valid_until_ms.unwrap_or(slot.state.expires_at_ms));
            if let Some(n) = &mut notes {
                n.valid_until_ms = n.valid_until_ms.min(expires);
            }
            let data = TransferData {
                schema: "guard-cigar-reviewed-note-transfer.v1".into(),
                scope_sha256: map[&key].clone(),
                source_key: key.clone(),
                source_producer_sha256: producer.identity_sha256().into(),
                source_release: producer.release_binding()?,
                source_manifest_sha256: format!("{:x}", Sha256::digest(&raw)),
                source_notes_version: slot.state.notes_version.clone(),
                source_observed_at_ms: proof.observed_at_ms,
                source_created_at_ms: slot.state.created_at_ms,
                expires_at_ms: expires,
                captured_at_ms: now,
                basis_sha256: proof.basis_sha256,
                notes,
            };
            data.validate(now)?;
            exports.push(VerifiedNoteTransfer { data });
        }
        Ok(exports)
    }
}
