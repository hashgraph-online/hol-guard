//! Host-only handoff of reviewed data, never SDK client/view credentials.
use super::*;
use guard_context_assistance::{
    EvidenceScope, EvidenceUpgradeProducer, PreparedEvidenceGeneration, VerifiedNoteTransfer,
};

impl Backend {
    pub(in super::super) fn defer_scope(
        &mut self,
        generation: std::sync::Arc<PreparedEvidenceGeneration>,
        scope: EvidenceScope,
        producer: EvidenceUpgradeProducer,
    ) {
        self.deferred_scope = Some((generation, scope, producer));
    }
    pub(in super::super) fn upgrade_notes(
        &self,
        runtime: &mut VerifiedRuntime,
        scope: &EvidenceScope,
        producer: &EvidenceUpgradeProducer,
        now: u64,
    ) -> Result<Option<VerifiedNoteTransfer>, RuntimeError> {
        match (&self.cache, &self.mode) {
            (Some(slot), Some(Mode::Shared(domain))) => slot
                .export_reviewed_notes(scope, producer, runtime, domain, now)
                .map(Some),
            // Do not silently lose reviewed memory-only data. Its explicit
            // ephemeral transfer path is still required by the switch owner.
            (None, _) if !self.notes.is_empty() => Err(RuntimeError::DataPreparationUnsupported),
            (None, _) => Ok(None),
            _ => Err(RuntimeError::ScopeDenied),
        }
    }
    pub(in super::super) fn import_upgrade_notes(
        &mut self,
        runtime: &mut VerifiedRuntime,
        scope: &EvidenceScope,
        producer: &EvidenceUpgradeProducer,
        generation: &PreparedEvidenceGeneration,
        now: u64,
    ) -> Result<(), RuntimeError> {
        let Some(Mode::Shared(domain)) = &self.mode else {
            return Err(RuntimeError::ScopeDenied);
        };
        let slot = self.cache.as_mut().ok_or(RuntimeError::ScopeDenied)?;
        if generation.has_deferred_scope(scope, producer)? {
            if !self.access.read {
                return Ok(());
            }
            generation.admit_deferred_scope(scope, producer, slot, runtime, domain, now)?;
        } else {
            let transfer = generation.transfer(scope, producer, now)?;
            slot.import_reviewed_notes(scope, producer, runtime, domain, &transfer, now)?;
            generation.finish_scope(scope, producer, slot, runtime, domain, now)?;
        }
        self.deferred_scope = None;
        self.refresh_imported_notes(runtime, now)
    }
    pub(super) fn refresh_imported_notes(
        &mut self,
        runtime: &mut VerifiedRuntime,
        now: u64,
    ) -> Result<(), RuntimeError> {
        let Some(Mode::Shared(domain)) = &self.mode else {
            return Err(RuntimeError::ScopeDenied);
        };
        let slot = self.cache.as_ref().ok_or(RuntimeError::ScopeDenied)?;
        let revision = runtime.broker_source_revision(domain, "guard:notes")?;
        self.notes = slot
            .notes()
            .map_or_else(Vec::new, |notes| notes.documents.clone());
        self.note_basis = slot
            .notes()
            .map_or_else(BTreeSet::new, |notes| notes.basis.clone());
        self.note_expires = slot.notes().map(|notes| {
            Instant::now() + Duration::from_millis(notes.valid_until_ms.saturating_sub(now))
        });
        self.note_revision = Some(revision);
        self.digests.insert(
            "guard:notes".into(),
            format!(
                "{:x}",
                Sha256::digest(
                    serde_json::to_vec(&self.notes).map_err(|_| RuntimeError::RequestInvalid)?
                )
            ),
        );
        self.restored = runtime.broker_storage_status(domain)?["restored"]
            .as_bool()
            .ok_or(RuntimeError::HandshakeFailed)?;
        Ok(())
    }
}
