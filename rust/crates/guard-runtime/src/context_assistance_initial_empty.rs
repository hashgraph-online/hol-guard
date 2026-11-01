//! Native empty-data proof. A caller cannot deserialize one or supply its hash.
use super::*;
use guard_context_assistance::{EvidenceCache, EvidenceGenerationStore};

pub(crate) struct EmptyDataProof {
    home: PathBuf,
    sha256: String,
}
fn fingerprint(owner: &Owner, lock: &WriteLock) -> Result<String, String> {
    DataRemoval::check_clear(&owner.home).map_err(|e| error(e.code()))?;
    owner.check(lock)?;
    let owners = scope_index::owners_locked(owner, lock).map_err(|e| error(e.code()))?;
    let cache = EvidenceCache::existing(&owner.home).map_err(|e| error(e.code()))?;
    let snapshot = if let Some(cache) = cache {
        if cache.summary().map_err(|e| error(e.code()))?.slots != 0 {
            return Err(error("initial_selection_data_choice_required"));
        }
        Some(
            cache
                .upgrade_inventory(jobs::now()?)
                .map_err(|e| error(e.code()))?
                .snapshot_sha256()
                .to_owned(),
        )
    } else {
        None
    };
    let generations =
        EvidenceGenerationStore::existing(&owner.home).map_err(|e| error(e.code()))?;
    let generations_present = generations.is_some();
    if let Some(generations) = generations {
        if !generations.list().map_err(|e| error(e.code()))?.is_empty() {
            return Err(error("initial_selection_data_choice_required"));
        }
    }
    let identity = lock.root_identity().map_err(storage_error)?;
    let data = serde_json::to_vec(&(
        "guard-cigar-initial-empty-data.v1",
        identity,
        snapshot,
        generations_present,
        owners,
    ))
    .map_err(|_| error("initial_selection_data_invalid"))?;
    Ok(format!("{:x}", Sha256::digest(data)))
}
impl EmptyDataProof {
    pub(crate) fn capture(owner: &Owner) -> Result<Self, String> {
        if owner.record().is_some() {
            return Err(error("initial_selection_recovery_required"));
        }
        let lock = WriteLock::acquire(&owner.home).map_err(storage_error)?;
        Ok(Self {
            home: owner.home.clone(),
            sha256: fingerprint(owner, &lock)?,
        })
    }
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }
    /// Rebuild proof after a process exit, only for this pending initial target.
    pub(crate) fn capture_for_initial(owner: &Owner, id: &str) -> Result<Self, String> {
        let plan = owner
            .initial_record()
            .filter(|p| p.request_id == id && !p.phase.terminal())
            .ok_or_else(|| error("initial_selection_conflict"))?;
        if owner.record().is_some_and(|r| {
            r.current != plan.target
                || r.revision != 1
                || r.last_good.is_some()
                || r.transaction.is_some()
        }) {
            return Err(error("initial_selection_conflict"));
        }
        let lock = WriteLock::acquire(&owner.home).map_err(storage_error)?;
        let sha256 = fingerprint(owner, &lock)?;
        if sha256 != plan.empty_data_sha256 {
            return Err(error("initial_selection_data_changed"));
        }
        Ok(Self {
            home: owner.home.clone(),
            sha256,
        })
    }
    pub(super) fn check(&self, owner: &Owner, lock: &WriteLock) -> Result<(), String> {
        if self.home != owner.home || fingerprint(owner, lock)? != self.sha256 {
            return Err(error("initial_selection_data_changed"));
        }
        Ok(())
    }
}
