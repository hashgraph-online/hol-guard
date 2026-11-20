//! Memory-only reviewed notes remain memory-only throughout preparation.
use super::*;
use guard_context_assistance::{EphemeralReviewedNotes, EvidenceScope, EvidenceUpgradeProducer};

impl Backend {
    pub(in super::super) fn upgrade_memory_notes(
        &self,
        runtime: &mut VerifiedRuntime,
        scope: &EvidenceScope,
        producer: &EvidenceUpgradeProducer,
    ) -> Result<Option<EphemeralReviewedNotes>, RuntimeError> {
        if self.cache.is_some() || self.notes.is_empty() {
            return Ok(None);
        }
        let Some(Mode::Shared(domain)) = &self.mode else {
            return Err(RuntimeError::ScopeDenied);
        };
        let version = &self
            .note_revision
            .as_ref()
            .ok_or(RuntimeError::ContextStale)?
            .version;
        runtime
            .export_ephemeral_reviewed_notes(
                domain,
                scope,
                producer,
                &self.notes,
                version,
                &self.note_basis,
            )
            .map(Some)
    }
    pub(in super::super) fn import_upgrade_memory_notes(
        &mut self,
        runtime: &mut VerifiedRuntime,
        scope: &EvidenceScope,
        producer: &EvidenceUpgradeProducer,
        transfer: &EphemeralReviewedNotes,
    ) -> Result<(), RuntimeError> {
        if self.cache.is_some() || !self.access.read || !self.notes.is_empty() {
            return Err(RuntimeError::ScopeDenied);
        }
        let Some(Mode::Shared(domain)) = &self.mode else {
            return Err(RuntimeError::ScopeDenied);
        };
        let (revision, notes) =
            runtime.import_ephemeral_reviewed_notes(domain, scope, producer, transfer)?;
        self.digests.insert(
            "guard:notes".into(),
            format!(
                "{:x}",
                Sha256::digest(
                    serde_json::to_vec(&notes.documents)
                        .map_err(|_| RuntimeError::RequestInvalid)?
                )
            ),
        );
        self.notes = notes.documents;
        self.note_basis = notes.basis;
        self.note_expires = Some(
            Instant::now()
                + Duration::from_millis(
                    notes.valid_until_ms.saturating_sub(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis()
                            .try_into()
                            .unwrap_or(u64::MAX),
                    ),
                ),
        );
        self.note_revision = Some(revision);
        Ok(())
    }
}

#[cfg(all(test, target_os = "macos"))]
impl Backend {
    /// Empty memory domains intentionally have no transferable review object.
    /// Verify their actual SDK revision/digest instead of inventing a transfer.
    pub(in super::super) fn empty_memory_note_summary(
        &self,
        runtime: &mut VerifiedRuntime,
    ) -> Result<Option<Value>, RuntimeError> {
        if self.cache.is_some() || !self.notes.is_empty() {
            return Ok(None);
        }
        let Some(Mode::Shared(domain)) = &self.mode else {
            return Err(RuntimeError::ScopeDenied);
        };
        let status = runtime.broker_storage_status(domain)?;
        if status["mode"] != "memory" || status["restored"] != false {
            return Err(RuntimeError::ScopeDenied);
        }
        let (revision, digest) = runtime.broker_source_digest(domain, "guard:notes")?;
        let empty = format!("{:x}", Sha256::digest(b"[]"));
        if revision.version != "0" && digest.as_deref() != Some(empty.as_str()) {
            return Err(RuntimeError::ContextStale);
        }
        Ok(Some(
            json!({"notes":0,"documents_sha256":empty,"storage":"memory",
            "sdk_note_revision":revision.version,"authority_restored":false}),
        ))
    }
}
