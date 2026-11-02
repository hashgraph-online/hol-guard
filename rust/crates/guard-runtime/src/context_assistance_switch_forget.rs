//! Durable explicit full deletion owns the preparation lease. Its private
//! marker survives every data/selection boundary and cannot authorize startup.
use super::*;
use guard_context_assistance::{EvidenceCache, EvidenceGenerationStore, RuntimeError};

#[cfg(test)]
thread_local! { static AFTER_LEGACY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

pub(crate) struct DataRemoval {
    home: PathBuf,
    _lease: fs::File,
    intent: Vec<u8>,
}
impl DataRemoval {
    #[cfg(all(test, unix))]
    pub(crate) fn fail_next_after_legacy() {
        AFTER_LEGACY.with(|f| f.set(true));
    }
    /// Presence is sufficient to deny admission, even for corrupt or linked
    /// markers. Absence remains a read-only check and creates no namespace.
    pub(crate) fn check_clear(home: &Path) -> Result<(), RuntimeError> {
        match fs::symlink_metadata(home.join("cigar-erasure.json")) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(RuntimeError::StorageRepairRequired),
        }
    }
    pub(crate) fn acquire(home: &Path) -> Result<Self, RuntimeError> {
        let lease = preparation::lifecycle_lease(home).map_err(data_error)?;
        let home = fs::canonicalize(home).map_err(|_| RuntimeError::StorageRepairRequired)?;
        let lock = WriteLock::acquire(&home).map_err(|_| RuntimeError::Busy)?;
        let intent = match lock
            .lifecycle_bytes(LifecycleFile::Erasure)
            .map_err(|_| RuntimeError::StorageRepairRequired)?
        {
            Some(bytes) => {
                // An explicit retry observes the prior intent instead of
                // replaying an unacknowledged publication or trusting JSON.
                lock.check_erasure_intent(&bytes)
                    .map_err(|_| RuntimeError::StorageRepairRequired)?;
                bytes
            }
            None => {
                let mut nonce = [0_u8; 16];
                getrandom::fill(&mut nonce).map_err(|_| RuntimeError::StorageRepairRequired)?;
                let bytes=serde_json::to_vec(&json!({"schema":"guard-cigar-full-erasure.v1","scope":"all_saved","request_id":hex::encode(nonce)})).map_err(|_| RuntimeError::StorageRepairRequired)?;
                lock.publish_lifecycle(LifecycleFile::Erasure, None, &bytes)
                    .map_err(|_| RuntimeError::StorageOutcomeUnknown)?;
                bytes
            }
        };
        Ok(Self {
            home,
            _lease: lease,
            intent,
        })
    }
    /// All paths converge here after SDK/cache owners have acknowledged close.
    /// No source/SDK path from a record is used as a filesystem destination.
    pub(crate) fn remove(self) -> Result<(), RuntimeError> {
        if let Some(cache) = EvidenceCache::existing(&self.home)? {
            cache.forget_all()?;
        }
        #[cfg(test)]
        if AFTER_LEGACY.with(|f| f.replace(false)) {
            return Err(RuntimeError::StorageOutcomeUnknown);
        }
        EvidenceGenerationStore::forget_existing(&self.home)?;
        self.finish()
    }
    fn finish(self) -> Result<(), RuntimeError> {
        if EvidenceCache::existing(&self.home)?
            .is_some_and(|cache| cache.summary().map_or(true, |s| s.slots != 0))
            || EvidenceGenerationStore::existing(&self.home)?
                .is_some_and(|store| store.list().map_or(true, |s| !s.is_empty()))
        {
            return Err(RuntimeError::StorageRepairRequired);
        }
        let lock = WriteLock::acquire(&self.home).map_err(|_| RuntimeError::Busy)?;
        lock.complete_saved_erasure(&self.intent)
            .map_err(|_| RuntimeError::StorageRepairRequired)
    }
}
fn data_error(code: String) -> RuntimeError {
    if code.ends_with("_busy") {
        RuntimeError::Busy
    } else {
        RuntimeError::StorageRepairRequired
    }
}
