//! Previously reviewed notes are data. Export requires the old SDK's actual
//! provenance; import requires fresh target source admission and exact content.
use super::upgrade::producer_binding::EvidenceProducerBinding;
use super::*;
use crate::{BrokerDomainHandle, EvidenceUpgradeProducer, VerifiedRuntime};

#[cfg(test)]
thread_local! { pub(super) static INTERRUPT_BEFORE_NOTE_COMMIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

pub struct EvidenceScope {
    app: String,
    workspace: PathBuf,
    namespace: String,
}
impl EvidenceScope {
    pub fn new(app: &str, workspace: &Path) -> Result<Self, RuntimeError> {
        EvidenceCache::key(app, workspace, &"0".repeat(64))?;
        let bytes = serde_json::to_vec(&("guard-cigar-evidence-scope.v1", app, workspace))
            .map_err(|_| RuntimeError::RequestInvalid)?;
        Ok(Self {
            app: app.into(),
            workspace: workspace.into(),
            namespace: format!("{:x}", Sha256::digest(bytes)),
        })
    }
    pub(super) fn legacy_key(&self, worker_sha256: &str) -> Result<String, RuntimeError> {
        EvidenceCache::key(&self.app, &self.workspace, worker_sha256)
    }
    pub fn namespace_sha256(&self) -> &str {
        &self.namespace
    }
    pub fn key(&self, producer: &EvidenceUpgradeProducer) -> Result<String, RuntimeError> {
        target_key(&self.namespace, producer.identity_sha256())
    }
}
pub(super) fn target_key(scope: &str, producer: &str) -> Result<String, RuntimeError> {
    if !valid_key(scope) || !valid_key(producer) {
        return Err(RuntimeError::RequestInvalid);
    }
    let bytes = serde_json::to_vec(&("guard-cigar-evidence-slot.v2", scope, producer))
        .map_err(|_| RuntimeError::RequestInvalid)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferData {
    pub schema: String,
    pub scope_sha256: String,
    pub source_key: String,
    pub source_producer_sha256: String,
    pub source_release: EvidenceProducerBinding,
    pub source_manifest_sha256: String,
    pub source_notes_version: String,
    pub source_observed_at_ms: u64,
    pub source_created_at_ms: u64,
    pub expires_at_ms: u64,
    pub captured_at_ms: u64,
    pub basis_sha256: BTreeMap<String, String>,
    pub notes: Option<SavedNotes>,
}
impl TransferData {
    pub(crate) fn validate(&self, now: u64) -> Result<(), RuntimeError> {
        if self.schema != "guard-cigar-reviewed-note-transfer.v1"
            || [
                &self.scope_sha256,
                &self.source_key,
                &self.source_producer_sha256,
                &self.source_manifest_sha256,
            ]
            .iter()
            .any(|s| !valid_key(s))
            || self.source_release.validate().is_err()
            || self.source_created_at_ms == 0
            || self.source_created_at_ms > self.captured_at_ms
            || self.source_observed_at_ms > self.captured_at_ms
            || self.captured_at_ms > now
            || now >= self.expires_at_ms
            || self.expires_at_ms > self.source_created_at_ms.saturating_add(720 * 3_600_000)
            || self.basis_sha256.len() > 32
            || self
                .basis_sha256
                .iter()
                .any(|(s, digest)| !records::source_id(s) || !valid_key(digest))
        {
            return Err(RuntimeError::StorageRepairRequired);
        }
        records::version(&self.source_notes_version)?;
        if let Some(notes) = &self.notes {
            records::documents_hash(&notes.documents)?;
            if notes.documents.is_empty()
                || notes.version != self.source_notes_version
                || notes.version == "0"
                || notes.basis != self.basis_sha256.keys().cloned().collect()
                || notes.valid_until_ms <= now
                || notes.valid_until_ms > self.expires_at_ms
            {
                return Err(RuntimeError::StorageRepairRequired);
            }
        } else if !self.basis_sha256.is_empty() {
            return Err(RuntimeError::StorageRepairRequired);
        }
        Ok(())
    }
}
/// Has no wire deserializer, public constructor, or credential. A durable copy
/// can only be recovered after the generation store verifies its private MAC.
pub struct VerifiedNoteTransfer {
    pub(crate) data: TransferData,
}
impl VerifiedNoteTransfer {
    /// Complete canonical reviewed data, independent of ranked query output.
    pub fn documents_sha256(&self) -> Result<String, RuntimeError> {
        records::documents_hash(
            self.data
                .notes
                .as_ref()
                .map_or(&[][..], |n| n.documents.as_slice()),
        )
    }
    /// Final cutover comparison excludes capture time and mutable cache
    /// bookkeeping, while retaining every reviewed-data/provenance boundary.
    pub fn semantic_sha256(&self) -> Result<String, RuntimeError> {
        let note_digest = self
            .data
            .notes
            .as_ref()
            .map(|n| records::documents_hash(&n.documents))
            .transpose()?;
        let bytes = serde_json::to_vec(&(
            "guard-cigar-reviewed-note-semantic.v1",
            &self.data.scope_sha256,
            &self.data.source_key,
            &self.data.source_producer_sha256,
            &self.data.source_release,
            &self.data.source_notes_version,
            self.data.source_observed_at_ms,
            self.data.source_created_at_ms,
            self.data.expires_at_ms,
            &self.data.basis_sha256,
            note_digest,
            self.data.notes.as_ref().map(|n| n.valid_until_ms),
        ))
        .map_err(|_| RuntimeError::RequestInvalid)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
    pub fn describe(&self) -> serde_json::Value {
        serde_json::json!({"schema":"guard-cigar-note-transfer-summary.v1", "scope_sha256":self.data.scope_sha256,
            "source_producer_sha256":self.data.source_producer_sha256, "source_release":self.data.source_release,
            "source_notes_version":self.data.source_notes_version,"notes":self.data.notes.as_ref().map_or(0, |n| n.documents.len()),
            "expires_at_ms":self.data.expires_at_ms,"data_role":true,"authority_restored":false})
    }
    pub fn target_key(
        &self,
        scope: &EvidenceScope,
        producer: &EvidenceUpgradeProducer,
    ) -> Result<String, RuntimeError> {
        if scope.namespace != self.data.scope_sha256 {
            return Err(RuntimeError::ScopeDenied);
        }
        scope.key(producer)
    }
}
impl EvidenceSlot {
    /// Caller already owns a currently granted scope. The SDK domain must be
    /// using this exact native slot; a matching digest in another domain is
    /// insufficient. This operation changes neither notes nor old checkpoint.
    pub fn export_reviewed_notes(
        &self,
        scope: &EvidenceScope,
        producer: &EvidenceUpgradeProducer,
        runtime: &mut VerifiedRuntime,
        domain: &BrokerDomainHandle,
        now: u64,
    ) -> Result<VerifiedNoteTransfer, RuntimeError> {
        self.check(now)?;
        producer.check_runtime(runtime)?;
        let legacy = EvidenceCache::key(
            &scope.app,
            &scope.workspace,
            &runtime.bundle_approval().worker_sha256,
        )?;
        if self.lease.key != legacy && self.lease.key != scope.key(producer)? {
            return Err(RuntimeError::ScopeDenied);
        }
        let raw = self.directory.read("state.json")?;
        let state: Manifest =
            serde_json::from_slice(&raw).map_err(|_| RuntimeError::StorageRepairRequired)?;
        state.validate(&self.lease.key)?;
        if state.intent.is_some() || self.directory.names(3)?.iter().any(|n| n == "state.next") {
            return Err(RuntimeError::StorageOutcomeUnknown);
        }
        let proof = runtime.reviewed_note_proof(
            domain,
            &self.directory.child("sdk", false)?.path,
            &state.notes_version,
            state.notes.as_ref(),
            now,
        )?;
        if self.directory.read("state.json")? != raw {
            return Err(RuntimeError::ContextStale);
        }
        let mut notes = state.notes;
        let expires = state
            .expires_at_ms
            .min(proof.valid_until_ms.unwrap_or(state.expires_at_ms));
        if let Some(notes) = &mut notes {
            notes.valid_until_ms = notes.valid_until_ms.min(expires);
        }
        let data = TransferData {
            schema: "guard-cigar-reviewed-note-transfer.v1".into(),
            scope_sha256: scope.namespace.clone(),
            source_key: self.lease.key.clone(),
            source_producer_sha256: producer.identity_sha256().into(),
            source_release: producer.release_binding()?,
            source_manifest_sha256: format!("{:x}", Sha256::digest(&raw)),
            source_notes_version: state.notes_version,
            source_observed_at_ms: proof.observed_at_ms,
            source_created_at_ms: state.created_at_ms,
            expires_at_ms: expires,
            captured_at_ms: now,
            basis_sha256: proof.basis_sha256,
            notes,
        };
        data.validate(now)?;
        Ok(VerifiedNoteTransfer { data })
    }
    /// Seed only a newly created target. Original creation/expiry survives, so
    /// preparing a new generation never resets retention or resurrects expiry.
    pub fn import_reviewed_notes(
        &mut self,
        scope: &EvidenceScope,
        producer: &EvidenceUpgradeProducer,
        runtime: &mut VerifiedRuntime,
        domain: &BrokerDomainHandle,
        transfer: &VerifiedNoteTransfer,
        now: u64,
    ) -> Result<(), RuntimeError> {
        self.import_checked_notes(scope, producer, runtime, domain, transfer, (now, false))
    }
    /// Only the MAC-verified generation owner may admit deferred data. A
    /// reopened target is allowed only while both native/SDK notes are empty.
    pub(super) fn import_deferred_reviewed_notes(
        &mut self,
        scope: &EvidenceScope,
        producer: &EvidenceUpgradeProducer,
        runtime: &mut VerifiedRuntime,
        domain: &BrokerDomainHandle,
        transfer: &VerifiedNoteTransfer,
        now: u64,
    ) -> Result<(), RuntimeError> {
        self.import_checked_notes(scope, producer, runtime, domain, transfer, (now, true))
    }
    fn import_checked_notes(
        &mut self,
        scope: &EvidenceScope,
        producer: &EvidenceUpgradeProducer,
        runtime: &mut VerifiedRuntime,
        domain: &BrokerDomainHandle,
        transfer: &VerifiedNoteTransfer,
        stamp: (u64, bool),
    ) -> Result<(), RuntimeError> {
        let (now, deferred) = stamp;
        transfer.data.validate(now)?;
        producer.check_runtime(runtime)?;
        if self.lease.key != transfer.target_key(scope, producer)?
            || self.state.notes_version != "0"
            || self.state.notes.is_some()
            || self.state.intent.is_some()
        {
            return Err(RuntimeError::ContextConflict);
        }
        let sdk = self.directory.child("sdk", false)?;
        runtime.check_note_transfer_target(domain, &sdk.path, &transfer.data, !deferred)?;
        let retention_ms = self
            .state
            .expires_at_ms
            .saturating_sub(self.state.created_at_ms);
        let expires = transfer.data.expires_at_ms.min(
            transfer
                .data
                .source_created_at_ms
                .saturating_add(retention_ms),
        );
        if expires <= now {
            return Err(RuntimeError::ContextStale);
        }
        let mut state = Manifest::new(&self.lease.key, 720, transfer.data.source_created_at_ms);
        state.expires_at_ms = expires;
        state.last_seen_ms = now;
        self.save(state)?;
        let documents = transfer
            .data
            .notes
            .as_ref()
            .map_or_else(Vec::new, |n| n.documents.clone());
        self.stage_notes("0", &documents, now)?;
        let mut bounded = transfer.data.clone();
        bounded.expires_at_ms = expires;
        if let Some(notes) = &mut bounded.notes {
            notes.valid_until_ms = notes.valid_until_ms.min(expires);
        }
        let revision = if deferred {
            runtime.import_deferred_note_data(domain, &sdk.path, &bounded)?
        } else {
            runtime.import_verified_note_data(domain, &sdk.path, &bounded)?
        };
        #[cfg(test)]
        if INTERRUPT_BEFORE_NOTE_COMMIT.with(|fault| fault.replace(false)) {
            return Err(RuntimeError::StorageOutcomeUnknown);
        }
        let notes = transfer.data.notes.clone().map(|mut notes| {
            notes.version = revision.version.clone();
            notes.valid_until_ms = notes.valid_until_ms.min(self.state.expires_at_ms);
            notes
        });
        self.commit_notes(&revision.version, notes, now)
    }
    /// Reconcile an uncertain target write using actual SDK provenance. Never
    /// resubmit a mutation. Fresh sources must be admitted before this call.
    pub fn recover_reviewed_note_import(
        &mut self,
        scope: &EvidenceScope,
        producer: &EvidenceUpgradeProducer,
        runtime: &mut VerifiedRuntime,
        domain: &BrokerDomainHandle,
        transfer: &VerifiedNoteTransfer,
        now: u64,
    ) -> Result<(), RuntimeError> {
        transfer.data.validate(now)?;
        producer.check_runtime(runtime)?;
        self.check(now)?;
        if self.lease.key != transfer.target_key(scope, producer)? {
            return Err(RuntimeError::ScopeDenied);
        }
        if self.state.created_at_ms != transfer.data.source_created_at_ms
            || self.state.expires_at_ms > transfer.data.expires_at_ms
            || self.state.notes.as_ref().is_some_and(|notes| {
                transfer.data.notes.as_ref().is_none_or(|original| {
                    notes.basis != original.basis || notes.valid_until_ms > original.valid_until_ms
                })
            })
        {
            return Err(RuntimeError::ContextConflict);
        }
        runtime.check_note_transfer_target(
            domain,
            &self.directory.child("sdk", false)?.path,
            &transfer.data,
            false,
        )?;
        let (revision, digest) = runtime.broker_source_digest(domain, "guard:notes")?;
        let documents = transfer
            .data
            .notes
            .as_ref()
            .map_or_else(Vec::new, |n| n.documents.clone());
        if revision.version != "1"
            || digest.as_deref() != Some(records::documents_hash(&documents)?.as_str())
        {
            return Err(RuntimeError::ContextConflict);
        }
        runtime.resume_broker_source(domain, "guard:notes", documents)?;
        if self.has_pending_write() {
            let notes = transfer.data.notes.clone().map(|mut notes| {
                notes.version = revision.version.clone();
                notes.valid_until_ms = notes.valid_until_ms.min(self.state.expires_at_ms);
                notes
            });
            self.commit_notes(&revision.version, notes, now)
        } else {
            self.reconcile_notes(&revision.version, digest.as_deref(), now)
        }
    }
}
