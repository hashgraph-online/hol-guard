//! Semantic data transfer through existing SDK source APIs, never raw SQLite.
use super::*;
use crate::evidence_cache::transfer::TransferData;
use crate::SavedNotes;
use std::path::Path;
#[path = "broker_note_transfer_cold.rs"]
mod cold;
#[path = "broker_note_transfer_memory.rs"]
mod memory;
pub use memory::EphemeralReviewedNotes;

pub(crate) struct NoteProof {
    pub observed_at_ms: u64,
    pub valid_until_ms: Option<u64>,
    pub basis_sha256: BTreeMap<String, String>,
}
impl VerifiedRuntime {
    fn transfer_storage(
        &self,
        domain: &BrokerDomainHandle,
        path: &Path,
    ) -> Result<(), RuntimeError> {
        let storage = self
            .brokers
            .domain(domain)?
            .storage
            .as_ref()
            .ok_or(RuntimeError::ScopeDenied)?;
        if !storage.matches_directory(path)? {
            return Err(RuntimeError::ScopeDenied);
        }
        Ok(())
    }
    pub(crate) fn reviewed_note_proof(
        &mut self,
        handle: &BrokerDomainHandle,
        path: &Path,
        version: &str,
        notes: Option<&SavedNotes>,
        now: u64,
    ) -> Result<NoteProof, RuntimeError> {
        self.transfer_storage(handle, path)?;
        self.note_content_proof(handle, version, notes, now)
    }
    fn note_content_proof(
        &mut self,
        handle: &BrokerDomainHandle,
        version: &str,
        notes: Option<&SavedNotes>,
        now: u64,
    ) -> Result<NoteProof, RuntimeError> {
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
            serde_json::from_value(raw).map_err(|_| RuntimeError::ContextStale)?;
        if provenance.observed_at_ms > now
            || (notes.is_some()
                && (provenance.origin != "reviewed_proposal"
                    || provenance.valid_until_ms.is_none_or(|until| until <= now)))
        {
            return Err(RuntimeError::ContextStale);
        }
        let source = self
            .brokers
            .domain(handle)?
            .sources
            .get("guard:notes")
            .ok_or(RuntimeError::ScopeDenied)?;
        let expected: BTreeSet<_> = source.basis.keys().cloned().collect();
        if notes.map_or_else(BTreeSet::new, |n| n.basis.clone()) != expected
            || source.revision != current
            || provenance.derived_from.len() != source.basis.len()
            || provenance
                .derived_from
                .iter()
                .any(|d| source.basis.get(&d.source) != Some(&d.revision))
        {
            return Err(RuntimeError::ContextStale);
        }
        let basis = source.basis.clone();
        let mut digests = BTreeMap::new();
        for (name, expected) in basis {
            if self
                .brokers
                .domain(handle)?
                .sources
                .get(&name)
                .is_none_or(|s| s.revision != expected)
            {
                return Err(RuntimeError::ScopeDenied);
            }
            let (actual, hash) = self.broker_source_digest(handle, &name)?;
            if actual != expected {
                return Err(RuntimeError::ContextStale);
            }
            digests.insert(name, hash.ok_or(RuntimeError::ContextStale)?);
        }
        if self.broker_source_revision(handle, "guard:notes")? != current {
            return Err(RuntimeError::ContextStale);
        }
        Ok(NoteProof {
            observed_at_ms: provenance.observed_at_ms,
            valid_until_ms: provenance.valid_until_ms,
            basis_sha256: digests,
        })
    }
    fn check_note_basis(
        &mut self,
        handle: &BrokerDomainHandle,
        basis: &BTreeMap<String, String>,
        fresh: bool,
    ) -> Result<(), RuntimeError> {
        if fresh
            && (self.brokers.domain(handle)?.restored
                || self.broker_source_revision(handle, "guard:notes")?.version != "0")
        {
            return Err(RuntimeError::ContextConflict);
        }
        for (name, expected) in basis {
            let admitted = self
                .brokers
                .domain(handle)?
                .sources
                .get(name)
                .ok_or(RuntimeError::ScopeDenied)?
                .revision
                .clone();
            let (actual, hash) = self.broker_source_digest(handle, name)?;
            if actual != admitted || hash.as_ref() != Some(expected) {
                return Err(RuntimeError::ContextStale);
            }
        }
        Ok(())
    }
    pub(crate) fn check_note_transfer_target(
        &mut self,
        handle: &BrokerDomainHandle,
        path: &Path,
        transfer: &TransferData,
        fresh: bool,
    ) -> Result<(), RuntimeError> {
        self.transfer_storage(handle, path)?;
        transfer.validate(now_ms())?;
        self.check_note_basis(handle, &transfer.basis_sha256, fresh)
    }
    pub(crate) fn import_verified_note_data(
        &mut self,
        handle: &BrokerDomainHandle,
        path: &Path,
        transfer: &TransferData,
    ) -> Result<BrokerRevision, RuntimeError> {
        self.check_note_transfer_target(handle, path, transfer, true)?;
        self.import_note_content(
            handle,
            transfer.notes.as_ref(),
            transfer.source_observed_at_ms,
            transfer.expires_at_ms,
            &transfer.basis_sha256,
        )
    }
    fn import_note_content(
        &mut self,
        handle: &BrokerDomainHandle,
        notes: Option<&SavedNotes>,
        observed_at_ms: u64,
        expires_at_ms: u64,
        basis_sha256: &BTreeMap<String, String>,
    ) -> Result<BrokerRevision, RuntimeError> {
        let values = notes.map_or_else(Vec::new, |n| n.documents.clone());
        let docs = documents(values, 16384)?;
        let domain = self.brokers.domain(handle)?;
        let retained: usize = domain
            .sources
            .values()
            .flat_map(|s| s.documents.values())
            .map(|d| d.text.len())
            .sum();
        if retained + docs.values().map(|d| d.text.len()).sum::<usize>() > 4194304
            || domain.sources.len() >= 128
            || docs.keys().any(|id| {
                domain
                    .sources
                    .values()
                    .any(|s| s.documents.contains_key(id))
            })
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let basis: BTreeMap<_, _> = basis_sha256
            .keys()
            .map(|name| (name.clone(), domain.sources[name].revision.clone()))
            .collect();
        let expected = BrokerRevision {
            epoch: domain.epoch.clone(),
            version: "0".into(),
        };
        let provenance = json!({"authority":"hol_guard_native",
            "upstream_revision":crate::evidence_cache::records::documents_hash(&docs.values().cloned().collect::<Vec<_>>())?,
            "origin":if notes.is_some(){"reviewed_proposal"}else{"host"},"observed_at_ms":observed_at_ms,
            "valid_until_ms":notes.map(|n|n.valid_until_ms.min(expires_at_ms)),
            "derived_from":basis.iter().map(|(source,revision)|json!({"source":source,"revision":revision})).collect::<Vec<_>>()});
        let epoch = expected.epoch.clone();
        let result=self.rpc(json!({"op":"broker_replace","domain":handle.id,"source":"guard:notes","expected":expected,
            "documents":wire_documents("guard:notes",&docs),"provenance":provenance}),TIMEOUT)?;
        let current = revision(&result["revision"], &epoch).inspect_err(|_| self.close())?;
        if current.version != "1" {
            self.close();
            return Err(RuntimeError::TransportFailed);
        }
        self.brokers
            .domains
            .get_mut(&handle.id)
            .ok_or(RuntimeError::ScopeDenied)?
            .sources
            .insert(
                "guard:notes".into(),
                Source {
                    revision: current.clone(),
                    documents: docs,
                    basis,
                },
            );
        Ok(current)
    }
}
