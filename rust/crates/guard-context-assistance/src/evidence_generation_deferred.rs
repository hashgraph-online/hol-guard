//! Carry unadmitted reviewed data through reselection without relabeling its
//! original SDK provenance. The source record has already passed its MAC check.
use super::*;
pub(super) fn inherited(
    _source: &PreparedEvidenceGeneration,
    record: &Record,
    cache: &EvidenceCache,
    now: u64,
) -> Result<Vec<Entry>, RuntimeError> {
    let keys: BTreeSet<_> = cache.slot_keys()?.into_iter().collect();
    let mut result = Vec::new();
    for e in &record.entries {
        match e {
            Entry::Deferred { transfer } => {
                let target = transfer::target_key(e.scope(), &record.target_producer_sha256)?;
                if keys.contains(&target) {
                    let directory = cache.root.directory.child(&target, false)?;
                    let manifest = load(&directory, &target)?;
                    if manifest.notes_version != "0"
                        || manifest.notes.is_some()
                        || manifest.intent.is_some()
                        || directory.names(3)?.iter().any(|n| n == "state.next")
                    {
                        return Err(RuntimeError::StorageRepairRequired);
                    }
                }
                if now < transfer.captured_at_ms {
                    return Err(RuntimeError::StorageRepairRequired);
                }
                if now < transfer.expires_at_ms
                    && transfer
                        .notes
                        .as_ref()
                        .is_none_or(|n| now < n.valid_until_ms)
                {
                    transfer.validate(now)?;
                    result.push(e.clone());
                }
            }
            Entry::Imported {
                target_key,
                expires_at_ms,
                ..
            } if now < *expires_at_ms && !keys.contains(target_key) => {
                return Err(RuntimeError::StorageRepairRequired)
            }
            _ => {}
        }
    }
    Ok(result)
}
impl PreparedEvidenceGeneration {
    pub fn has_deferred_scope(
        &self,
        scope: &EvidenceScope,
        target: &EvidenceUpgradeProducer,
    ) -> Result<bool, RuntimeError> {
        let _lock = self.root.lock()?;
        let r = self.read()?;
        if r.phase == Phase::Preparing || r.target_producer_sha256 != target.identity_sha256() {
            return Err(RuntimeError::ContextConflict);
        }
        Ok(r.entries
            .iter()
            .any(|e| e.scope() == scope.namespace_sha256() && matches!(e, Entry::Deferred { .. })))
    }
    /// Fresh source admission and current note-read consent are supplied by
    /// the engine. No view/client is created here, and mutations are not replayed.
    pub fn admit_deferred_scope(
        &self,
        scope: &EvidenceScope,
        target: &EvidenceUpgradeProducer,
        slot: &mut EvidenceSlot,
        runtime: &mut VerifiedRuntime,
        domain: &BrokerDomainHandle,
        now: u64,
    ) -> Result<(), RuntimeError> {
        if slot.directory.path.parent() != Some(self.directory.path.join("cache").as_path()) {
            return Err(RuntimeError::ScopeDenied);
        }
        if !self.has_deferred_scope(scope, target)? {
            return Err(RuntimeError::ScopeDenied);
        }
        let transfer = self.transfer(scope, target, now)?;
        if slot.has_pending_write() || slot.notes_version() != "0" {
            slot.recover_reviewed_note_import(scope, target, runtime, domain, &transfer, now)?;
        } else {
            slot.import_deferred_reviewed_notes(scope, target, runtime, domain, &transfer, now)?;
        }
        self.finish_scope(scope, target, slot, runtime, domain, now)
    }
}
