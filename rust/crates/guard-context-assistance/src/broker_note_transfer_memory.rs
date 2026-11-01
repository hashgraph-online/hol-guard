//! Nonserializable reviewed data for a live, memory-only switch. Original
//! SDK provenance and expiry survive; no disk manifest or SDK grant is invented.
use super::*;
use crate::evidence_cache::records;
use crate::{EvidenceScope, EvidenceUpgradeProducer};

#[derive(Clone)]
pub struct EphemeralReviewedNotes {
    scope_sha256: String,
    source_producer: EvidenceUpgradeProducer,
    observed_at_ms: u64,
    basis_sha256: BTreeMap<String, String>,
    notes: SavedNotes,
}
impl EphemeralReviewedNotes {
    fn validate(&self, now: u64) -> Result<(), RuntimeError> {
        if !digest(&self.scope_sha256)
            || !self.source_producer.metadata_preparation_qualified()
            || self.observed_at_ms == 0
            || self.observed_at_ms > now
            || self.notes.valid_until_ms <= now
            || self.notes.valid_until_ms > self.observed_at_ms.saturating_add(720 * 3_600_000)
            || self.notes.documents.is_empty()
            || self.notes.version == "0"
            || self.basis_sha256.len() > 32
            || self
                .basis_sha256
                .iter()
                .any(|(name, hash)| !records::source_id(name) || !digest(hash))
            || self.notes.basis != self.basis_sha256.keys().cloned().collect()
        {
            return Err(RuntimeError::ContextStale);
        }
        records::version(&self.notes.version)?;
        records::documents_hash(&self.notes.documents)?;
        Ok(())
    }
    /// Canonical complete reviewed data, independent of query ranking.
    pub fn documents_sha256(&self) -> Result<String, RuntimeError> {
        records::documents_hash(&self.notes.documents)
    }
    pub fn semantic_sha256(&self) -> Result<String, RuntimeError> {
        let bytes = serde_json::to_vec(&(
            "guard-cigar-ephemeral-reviewed-notes.v1",
            &self.scope_sha256,
            self.source_producer.identity_sha256(),
            self.source_producer.describe(),
            self.observed_at_ms,
            &self.basis_sha256,
            &self.notes.version,
            self.notes.valid_until_ms,
            records::documents_hash(&self.notes.documents)?,
        ))
        .map_err(|_| RuntimeError::RequestInvalid)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
    pub fn describe(&self) -> Value {
        json!({"schema":"guard-cigar-ephemeral-reviewed-note-summary.v1","scope_sha256":self.scope_sha256,
            "source_producer":self.source_producer.describe(),
            "notes":self.notes.documents.len(),"observed_at_ms":self.observed_at_ms,
            "valid_until_ms":self.notes.valid_until_ms,"storage":"memory","authority_restored":false})
    }
}
impl VerifiedRuntime {
    fn check_memory_note_domain(
        &self,
        handle: &BrokerDomainHandle,
        producer: &EvidenceUpgradeProducer,
    ) -> Result<(), RuntimeError> {
        producer.revalidate_runtime(self)?;
        let domain = self.brokers.domain(handle)?;
        if !producer.metadata_preparation_qualified()
            || !self.status().shared_compile_verified
            || domain.storage.is_some()
            || domain.private_execution
            || domain.restored
        {
            return Err(RuntimeError::ScopeDenied);
        }
        Ok(())
    }
    /// The caller supplies its native reviewed vector; the actual SDK must
    /// independently prove its digest, revision and reviewed provenance.
    pub fn export_ephemeral_reviewed_notes(
        &mut self,
        handle: &BrokerDomainHandle,
        scope: &EvidenceScope,
        producer: &EvidenceUpgradeProducer,
        documents: &[ContextDocument],
        version: &str,
        basis: &BTreeSet<String>,
    ) -> Result<EphemeralReviewedNotes, RuntimeError> {
        self.check_memory_note_domain(handle, producer)?;
        let now = now_ms();
        let mut notes = SavedNotes {
            documents: documents.to_vec(),
            basis: basis.clone(),
            version: version.into(),
            valid_until_ms: now,
        };
        records::documents_hash(&notes.documents)?;
        let proof = self.note_content_proof(handle, version, Some(&notes), now)?;
        notes.valid_until_ms = proof.valid_until_ms.ok_or(RuntimeError::ContextStale)?;
        let transfer = EphemeralReviewedNotes {
            scope_sha256: scope.namespace_sha256().into(),
            source_producer: producer.clone(),
            observed_at_ms: proof.observed_at_ms,
            basis_sha256: proof.basis_sha256,
            notes,
        };
        transfer.validate(now)?;
        Ok(transfer)
    }
    /// This accepts only a native memory value, never a request body or a
    /// recovered file. Fresh source content must match the old SDK's basis.
    pub fn import_ephemeral_reviewed_notes(
        &mut self,
        handle: &BrokerDomainHandle,
        scope: &EvidenceScope,
        producer: &EvidenceUpgradeProducer,
        transfer: &EphemeralReviewedNotes,
    ) -> Result<(BrokerRevision, SavedNotes), RuntimeError> {
        self.check_memory_note_domain(handle, producer)?;
        let now = now_ms();
        transfer.validate(now)?;
        if transfer.scope_sha256 != scope.namespace_sha256() {
            return Err(RuntimeError::ScopeDenied);
        }
        self.check_note_basis(handle, &transfer.basis_sha256, true)?;
        let mut notes = transfer.notes.clone();
        notes.valid_until_ms =
            notes
                .valid_until_ms
                .min(transfer.observed_at_ms.saturating_add(
                    u64::from(self.brokers.domain(handle)?.retention_hours) * 3_600_000,
                ));
        if notes.valid_until_ms <= now {
            return Err(RuntimeError::ContextStale);
        }
        let revision = self.import_note_content(
            handle,
            Some(&notes),
            transfer.observed_at_ms,
            notes.valid_until_ms,
            &transfer.basis_sha256,
        )?;
        notes.version = revision.version.clone();
        Ok((revision, notes))
    }
}
