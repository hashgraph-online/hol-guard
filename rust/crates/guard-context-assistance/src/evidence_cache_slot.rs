use super::*;
use records::{documents_hash, version, Intent};

impl EvidenceSlot {
    pub fn domain_name(&self) -> String {
        format!("cache:{}", self.lease.key)
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.state.expires_at_ms
    }
    pub fn notes(&self) -> Option<&SavedNotes> {
        self.state.notes.as_ref()
    }
    pub fn notes_version(&self) -> &str {
        &self.state.notes_version
    }
    pub fn has_pending_write(&self) -> bool {
        self.state.intent.is_some()
    }
    pub fn check(&self, now: u64) -> Result<(), RuntimeError> {
        if self.poisoned {
            return Err(RuntimeError::StorageOutcomeUnknown);
        }
        self.lease.root.check()?;
        self.directory.check()?;
        slot_files(&self.directory)?;
        if now < self.state.last_seen_ms {
            return Err(RuntimeError::StorageRepairRequired);
        }
        if now >= self.state.expires_at_ms {
            return Err(RuntimeError::ContextStale);
        }
        Ok(())
    }
    pub fn revalidate(&mut self, now: u64) -> Result<(), RuntimeError> {
        self.check(now)?;
        self.state.observe(720, now)
    }
    /// The returned SDK capability keeps the native slot lease and root lock
    /// alive, even if the coordinator or slot is dropped before the worker.
    pub fn broker_storage(&self) -> Result<BrokerStorage, RuntimeError> {
        if self.poisoned {
            return Err(RuntimeError::StorageOutcomeUnknown);
        }
        if Arc::strong_count(&self.lease) != 1 {
            return Err(RuntimeError::Busy);
        }
        self.lease.root.check()?;
        let sdk = self.directory.child("sdk", false)?;
        let mut storage = BrokerStorage::inspect(&sdk.path)?;
        storage.cache_owner = Some(Arc::clone(&self.lease) as Arc<dyn Send + Sync>);
        Ok(storage)
    }
    pub(super) fn save(&mut self, state: Manifest) -> Result<(), RuntimeError> {
        state.validate(&self.lease.key)?;
        let bytes = serde_json::to_vec(&state).map_err(|_| RuntimeError::RequestInvalid)?;
        if self.directory.write_state(&bytes).is_err() {
            self.poisoned = true;
            return Err(RuntimeError::StorageOutcomeUnknown);
        }
        self.state = state;
        Ok(())
    }
    /// Call only for a human-requested admission or explicit note removal,
    /// before the SDK mutation. No proposed text is written by this operation.
    pub fn stage_notes(
        &mut self,
        expected_version: &str,
        documents: &[ContextDocument],
        now: u64,
    ) -> Result<(), RuntimeError> {
        self.revalidate(now)?;
        if self.state.intent.is_some() || expected_version != self.state.notes_version {
            return Err(RuntimeError::StorageRepairRequired);
        }
        version(expected_version)?
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        let mut state = self.state.clone();
        state.intent = Some(Intent {
            expected_version: expected_version.into(),
            documents_sha256: documents_hash(documents)?,
        });
        self.save(state)
    }
    /// Acknowledge admission only after the SDK commit and this private commit.
    pub fn commit_notes(
        &mut self,
        next_version: &str,
        notes: Option<SavedNotes>,
        now: u64,
    ) -> Result<(), RuntimeError> {
        self.revalidate(now)?;
        let intent = self
            .state
            .intent
            .as_ref()
            .ok_or(RuntimeError::StorageRepairRequired)?;
        let docs: &[ContextDocument] = notes.as_ref().map_or(&[], |n| n.documents.as_slice());
        if version(next_version)?
            != version(&intent.expected_version)?
                .checked_add(1)
                .ok_or(RuntimeError::ResourceLimit)?
            || documents_hash(docs)? != intent.documents_sha256
            || notes
                .as_ref()
                .is_some_and(|n| n.version != next_version || n.valid_until_ms <= now)
        {
            return Err(RuntimeError::StorageRepairRequired);
        }
        let mut state = self.state.clone();
        state.notes_version = next_version.into();
        state.notes = notes;
        state.intent = None;
        self.save(state)
    }
    /// Reconcile actual SDK provenance after restart, never retry a mutation.
    /// If SDK-admitted text was lost before the native commit, preserve the
    /// store for explicit repair. A digest cannot reconstruct reviewed text.
    pub fn reconcile_notes(
        &mut self,
        actual_version: &str,
        actual_digest: Option<&str>,
        now: u64,
    ) -> Result<(), RuntimeError> {
        self.revalidate(now)?;
        version(actual_version)?;
        if actual_version == self.state.notes_version
            && actual_digest == self.state.committed_hash()?.as_deref()
        {
            if self.state.intent.is_some() {
                let mut state = self.state.clone();
                state.intent = None;
                self.save(state)?;
            }
            return Ok(());
        }
        if let Some(intent) = &self.state.intent {
            if version(actual_version)? == version(&intent.expected_version)?.saturating_add(1)
                && actual_digest == Some(intent.documents_sha256.as_str())
            {
                if documents_hash(&[])? == intent.documents_sha256 {
                    return self.commit_notes(actual_version, None, now);
                }
                if let Some(mut notes) = self.state.notes.clone().filter(|n| {
                    documents_hash(&n.documents).ok().as_ref() == Some(&intent.documents_sha256)
                }) {
                    notes.version = actual_version.into();
                    return self.commit_notes(actual_version, Some(notes), now);
                }
            }
        }
        Err(RuntimeError::StorageRepairRequired)
    }
    /// The SDK domain must be closed first. A live storage capability makes
    /// deletion busy and retains the directory lock after this value drops.
    pub fn remove(self) -> Result<(), RuntimeError> {
        if Arc::strong_count(&self.lease) != 1 {
            return Err(RuntimeError::Busy);
        }
        let root = Arc::clone(&self.lease.root);
        let key = self.lease.key.clone();
        drop(self);
        EvidenceCache { root }.forget(&key)
    }
}
