//! Serialized native lifecycle cleanup. Retention references are metadata;
//! they never authorize opening a scope or restoring SDK authority.
use super::*;
use guard_cigar_release::SelectionRecord;

impl EvidenceGenerationStore {
    /// The native caller must own its profile lifecycle lease and supply the
    /// authenticated selection it just read. Browser-supplied protected-ID
    /// lists are not accepted by the native control API.
    pub fn discard_unselected(
        &self,
        id: &str,
        request: &str,
        selection: &SelectionRecord,
    ) -> Result<(), RuntimeError> {
        selection
            .validate()
            .map_err(|_| RuntimeError::StorageRepairRequired)?;
        if !request_id(request) {
            return Err(RuntimeError::RequestInvalid);
        }
        let _lock = self.root.lock()?;
        let mut pending = selection
            .retained_generations()
            .map_err(|_| RuntimeError::StorageRepairRequired)?;
        let mut retained = BTreeSet::new();
        while let Some(reference) = pending.pop() {
            if !retained.insert(reference.clone()) {
                continue;
            }
            if retained.len() > MAX_GENERATIONS {
                return Err(RuntimeError::StorageRepairRequired);
            }
            let generation = self.load_locked(&reference)?;
            let record = generation.read()?;
            if !record.preserved_source_keys.is_empty() {
                if let Some(source) = record.source_generation {
                    pending.push(source);
                }
            }
        }
        if retained.contains(id) {
            return Err(RuntimeError::ScopeDenied);
        }
        let generation = self.load_locked(id)?;
        if generation.read()?.request_id != request {
            return Err(RuntimeError::ScopeDenied);
        }
        // All cache/SQLite ownership checks are repeated before deletion. A
        // queued cancellation cannot erase the still-running target's store.
        cleanup::remove(&self.root.directory, id, &generation.directory)
    }
}
