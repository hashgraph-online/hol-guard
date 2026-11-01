//! Scope deletion follows authenticated lineage, never guessed file locators.
//! The native caller must hold the profile lease and durable erasure intent.
use super::*;

#[derive(Clone, Debug, serde::Serialize, Eq, PartialEq)]
pub struct EvidenceScopeErasure {
    pub changed_records: usize,
    pub removed_slots: usize,
    pub removed_staging_records: usize,
}
/// Native data intent only. Construction from disk requires the caller's
/// authenticated intent; this value never starts a runtime or grants a scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceErasureScope {
    namespace: String,
    legacy_keys: BTreeSet<String>,
}
impl EvidenceErasureScope {
    pub fn capture(
        home: &Path,
        scope: &EvidenceScope,
        workers: &BTreeSet<String>,
    ) -> Result<Self, RuntimeError> {
        if workers.len() > MAX_SLOTS {
            return Err(RuntimeError::ResourceLimit);
        }
        let mut measured = workers.clone();
        if let Some(store) = EvidenceGenerationStore::existing(home)? {
            let _lock = store.root.lock()?;
            for id in store.root.ids()? {
                let record = store.load_locked(&id)?.read()?;
                for binding in [&record.source_release, &record.target_release] {
                    if let EvidenceProducerBinding::Enrolled(binding) = binding {
                        measured.insert(binding.approval.worker_sha256.clone());
                    }
                }
            }
        }
        let keys = measured
            .iter()
            .map(|w| scope.legacy_key(w))
            .collect::<Result<_, _>>()?;
        Self::from_authenticated_intent(scope.namespace_sha256(), keys)
    }
    pub fn from_authenticated_intent(
        namespace: &str,
        legacy_keys: BTreeSet<String>,
    ) -> Result<Self, RuntimeError> {
        if !valid_key(namespace)
            || legacy_keys.len() > 16
            || legacy_keys.iter().any(|k| !valid_key(k))
        {
            return Err(RuntimeError::StorageRepairRequired);
        }
        Ok(Self {
            namespace: namespace.into(),
            legacy_keys,
        })
    }
    pub fn namespace_sha256(&self) -> &str {
        &self.namespace
    }
    pub fn legacy_keys(&self) -> &BTreeSet<String> {
        &self.legacy_keys
    }
}
pub(super) struct ScopeCopies {
    pub(super) keys: BTreeMap<Option<String>, BTreeSet<String>>,
    pub(super) records: Vec<(PreparedEvidenceGeneration, Record)>,
}
impl ScopeCopies {
    fn insert(&mut self, generation: Option<String>, key: String) {
        self.keys.entry(generation).or_default().insert(key);
    }
    pub(super) fn collect(
        store: Option<&EvidenceGenerationStore>,
        scope: &EvidenceErasureScope,
    ) -> Result<Self, RuntimeError> {
        let mut result = Self {
            keys: BTreeMap::new(),
            records: Vec::new(),
        };
        for key in scope.legacy_keys() {
            result.insert(None, key.clone());
        }
        let Some(store) = store else {
            return Ok(result);
        };
        for id in store.root.ids()? {
            let generation = store.load_locked(&id)?;
            let record = generation.read()?;
            result.insert(
                Some(id),
                transfer::target_key(scope.namespace_sha256(), &record.target_producer_sha256)?,
            );
            result.insert(
                record.source_generation.clone(),
                transfer::target_key(scope.namespace_sha256(), &record.source_producer_sha256)?,
            );
            for entry in &record.entries {
                if entry.scope() != scope.namespace_sha256() {
                    continue;
                }
                if !entry.deferred() {
                    result.insert(
                        record.source_generation.clone(),
                        entry.source_key().to_owned(),
                    );
                }
            }
            result.records.push((generation, record));
        }
        Ok(result)
    }
}
pub(super) fn owned_cache(
    directory: Directory,
    current: Option<&EvidenceCache>,
) -> Result<EvidenceCache, RuntimeError> {
    if let Some(current) = current.filter(|c| c.root.directory.path == directory.path) {
        current.root.directory.check()?;
        return Ok(current.clone());
    }
    EvidenceCache::from_directory(directory)
}
fn matching_keys(
    cache: &EvidenceCache,
    keys: &BTreeSet<String>,
) -> Result<Vec<String>, RuntimeError> {
    let keys: Vec<_> = cache
        .keys()?
        .into_iter()
        .filter(|k| keys.contains(k))
        .collect();
    if keys.iter().any(|key| {
        cache
            .root
            .active()
            .map_or(true, |active| active.contains(key))
    }) {
        return Err(RuntimeError::Busy);
    }
    Ok(keys)
}
impl EvidenceGenerationStore {
    /// Erase only copies attributable to this app/workspace and measured legacy
    /// workers. Unknown legacy namespaces are not silently claimed as erased.
    /// A live current cache may be borrowed only after this scope's SDK domain
    /// has closed; other scopes keep their original cache and slot leases.
    pub fn forget_scope_existing(
        home: &Path,
        scope: &EvidenceScope,
        workers: &BTreeSet<String>,
        current: Option<&EvidenceCache>,
        now: u64,
    ) -> Result<EvidenceScopeErasure, RuntimeError> {
        let scope = EvidenceErasureScope::capture(home, scope, workers)?;
        Self::forget_scope_copies(home, &scope, current, now)
    }
    /// Resume a previously authenticated native scope intent without project
    /// files, an interpreter, a current SDK scope or renewed access grants.
    pub fn forget_scope_copies(
        home: &Path,
        scope: &EvidenceErasureScope,
        current: Option<&EvidenceCache>,
        now: u64,
    ) -> Result<EvidenceScopeErasure, RuntimeError> {
        if now == 0 {
            return Err(RuntimeError::RequestInvalid);
        }
        let store = Self::existing(home)?;
        let _lock = store.as_ref().map(|s| s.root.lock()).transpose()?;
        let mut copies = ScopeCopies::collect(store.as_ref(), scope)?;
        let legacy_path = home.join("context-assistance/saved-evidence");
        if let Some(current) = current {
            let known = current.root.directory.path == legacy_path
                || copies
                    .records
                    .iter()
                    .any(|(g, _)| current.root.directory.path == g.directory.path.join("cache"));
            if !known {
                return Err(RuntimeError::ScopeDenied);
            }
        }
        // Acquire every existing native cache owner before changing records.
        // Actual SQLite ownership is checked again by forget at removal.
        let mut caches = Vec::new();
        let legacy = if current.is_some_and(|c| c.root.directory.path == legacy_path) {
            current.cloned()
        } else {
            EvidenceCache::existing(home)?
        };
        if let Some(cache) = legacy {
            let keys = copies.keys.get(&None).cloned().unwrap_or_default();
            let keys = matching_keys(&cache, &keys)?;
            caches.push((cache, keys));
        }
        for (generation, _) in &copies.records {
            if !generation.directory.names(3)?.iter().any(|n| n == "cache") {
                continue;
            }
            let cache = owned_cache(generation.directory.child("cache", false)?, current)?;
            let keys = copies
                .keys
                .get(&Some(generation.id.clone()))
                .cloned()
                .unwrap_or_default();
            let keys = matching_keys(&cache, &keys)?;
            caches.push((cache, keys));
        }
        let mut result = EvidenceScopeErasure {
            changed_records: 0,
            removed_slots: 0,
            removed_staging_records: 0,
        };
        for (generation, record) in &mut copies.records {
            let mut changed = false;
            for entry in &mut record.entries {
                if entry.scope() != scope.namespace_sha256() {
                    continue;
                }
                let source_key = match entry {
                    Entry::Pending { transfer } | Entry::Deferred { transfer } => {
                        transfer.source_key.clone()
                    }
                    Entry::Imported { source_key, .. } => source_key.clone(),
                    Entry::Expired { .. } => continue,
                };
                *entry = Entry::Expired {
                    deferred: entry.deferred(),
                    scope_sha256: scope.namespace_sha256().into(),
                    source_key,
                    expires_at_ms: entry.expires().min(now),
                };
                changed = true;
            }
            let source_keys = copies.keys.get(&record.source_generation);
            let before = record.preserved_source_keys.len();
            record
                .preserved_source_keys
                .retain(|key| source_keys.is_none_or(|keys| !keys.contains(key)));
            changed |= record.preserved_source_keys.len() != before;
            let staged = generation
                .directory
                .names(3)?
                .iter()
                .any(|n| n == "state.next");
            if changed {
                generation
                    .directory
                    .write_state_limit(&generation.root.authority.seal(record)?, RECORD_BYTES)?;
                result.changed_records += 1;
            } else if staged {
                // Profile/store owners exclude active native writers. This
                // uncommitted staging file is never recovery authority.
                generation
                    .directory
                    .remove_file("state.next", RECORD_BYTES)?;
            }
            if staged {
                result.removed_staging_records += 1;
            }
        }
        for (cache, keys) in caches {
            for key in keys {
                cache.forget(&key)?;
                result.removed_slots += 1;
            }
        }
        Ok(result)
    }
}
