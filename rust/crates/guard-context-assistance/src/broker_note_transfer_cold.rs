//! Closed-store provenance inspection never populates the native source catalog.
use super::*;
impl VerifiedRuntime {
    pub(crate) fn cold_note_proof(
        &mut self,
        handle: &BrokerDomainHandle,
        path: &Path,
        version: &str,
        notes: Option<&SavedNotes>,
        now: u64,
    ) -> Result<NoteProof, RuntimeError> {
        self.transfer_storage(handle, path)?;
        if !self.brokers.domain(handle)?.sources.is_empty()
            || !self.brokers.domain(handle)?.restored
        {
            return Err(RuntimeError::ScopeDenied);
        }
        let (current, digest) = self.broker_source_digest(handle, "guard:notes")?;
        if current.version != version {
            return Err(RuntimeError::ContextStale);
        }
        if version == "0" && notes.is_none() {
            return Ok(NoteProof {
                observed_at_ms: now,
                valid_until_ms: None,
                basis_sha256: BTreeMap::new(),
            });
        }
        let docs = notes.map_or(&[][..], |n| n.documents.as_slice());
        if digest.as_deref() != Some(crate::evidence_cache::records::documents_hash(docs)?.as_str())
        {
            return Err(RuntimeError::StorageRepairRequired);
        }
        let raw = self.rpc(
            json!({"op":"broker_provenance","domain":handle.id,"source":"guard:notes"}),
            TIMEOUT,
        )?;
        let provenance: resume::Provenance =
            serde_json::from_value(raw).map_err(|_| RuntimeError::StorageRepairRequired)?;
        if provenance.observed_at_ms > now
            || provenance.derived_from.len() > 32
            || (notes.is_some()
                && (provenance.origin != "reviewed_proposal"
                    || provenance.valid_until_ms.is_none_or(|t| t <= now)))
        {
            return Err(RuntimeError::ContextStale);
        }
        let mut basis = BTreeMap::new();
        for dependency in provenance.derived_from {
            dependency.revision.validate()?;
            if !crate::evidence_cache::records::source_id(&dependency.source)
                || dependency.revision.epoch != current.epoch
                || self.broker_source_revision(handle, &dependency.source)? != dependency.revision
            {
                return Err(RuntimeError::ContextStale);
            }
            let (revision, digest) = self.broker_source_digest(handle, &dependency.source)?;
            if revision != dependency.revision
                || basis
                    .insert(dependency.source, digest.ok_or(RuntimeError::ContextStale)?)
                    .is_some()
            {
                return Err(RuntimeError::ContextStale);
            }
        }
        if basis.keys().cloned().collect::<BTreeSet<_>>()
            != notes.map_or_else(BTreeSet::new, |n| n.basis.clone())
            || self.broker_source_revision(handle, "guard:notes")? != current
        {
            return Err(RuntimeError::ContextStale);
        }
        // No native document catalog, client, view, ticket or source grant was
        // reconstructed by these metadata/provenance queries.
        if !self.brokers.domain(handle)?.sources.is_empty() {
            return Err(RuntimeError::ScopeDenied);
        }
        Ok(NoteProof {
            observed_at_ms: provenance.observed_at_ms,
            valid_until_ms: provenance.valid_until_ms,
            basis_sha256: basis,
        })
    }
    pub(crate) fn import_deferred_note_data(
        &mut self,
        handle: &BrokerDomainHandle,
        path: &Path,
        transfer: &TransferData,
    ) -> Result<BrokerRevision, RuntimeError> {
        self.check_note_transfer_target(handle, path, transfer, false)?;
        if self.broker_source_revision(handle, "guard:notes")?.version != "0" {
            return Err(RuntimeError::ContextConflict);
        }
        self.import_note_content(
            handle,
            transfer.notes.as_ref(),
            transfer.source_observed_at_ms,
            transfer.expires_at_ms,
            &transfer.basis_sha256,
        )
    }
}
