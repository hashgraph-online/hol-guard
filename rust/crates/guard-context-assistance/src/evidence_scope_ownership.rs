//! Native-authenticated attribution is data, never a restored source grant.
use super::scope_erasure::{owned_cache, ScopeCopies};
use super::*;

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidenceCacheLocation {
    Legacy,
    Generation { generation_id: String },
}
impl EvidenceCacheLocation {
    pub fn valid(&self) -> bool {
        match self {
            Self::Legacy => true,
            Self::Generation { generation_id } => valid_key(generation_id),
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct EvidenceScopeOwner {
    pub location: EvidenceCacheLocation,
    pub slot_key: String,
    pub scope_sha256: String,
}
impl EvidenceScopeOwner {
    pub fn valid(&self) -> bool {
        self.location.valid() && valid_key(&self.slot_key) && valid_key(&self.scope_sha256)
    }
}
impl EvidenceCache {
    pub fn scope_location(&self, home: &Path) -> Result<EvidenceCacheLocation, RuntimeError> {
        self.root.check()?;
        if self.root.directory.path == home.join("context-assistance/saved-evidence") {
            return Ok(EvidenceCacheLocation::Legacy);
        }
        let relative = self
            .root
            .directory
            .path
            .strip_prefix(home.join("context-assistance/evidence-generations"))
            .map_err(|_| RuntimeError::ScopeDenied)?;
        let parts: Vec<_> = relative.components().collect();
        if parts.len() != 2 || parts[1].as_os_str() != "cache" {
            return Err(RuntimeError::ScopeDenied);
        }
        let id = parts[0]
            .as_os_str()
            .to_str()
            .filter(|s| valid_key(s))
            .ok_or(RuntimeError::ScopeDenied)?;
        Ok(EvidenceCacheLocation::Generation {
            generation_id: id.into(),
        })
    }
    pub fn slot_keys(&self) -> Result<Vec<String>, RuntimeError> {
        let _operation = self.root.operation()?;
        self.keys()
    }
}
fn location(id: &Option<String>) -> EvidenceCacheLocation {
    id.as_ref().map_or(EvidenceCacheLocation::Legacy, |id| {
        EvidenceCacheLocation::Generation {
            generation_id: id.clone(),
        }
    })
}
type Owners = BTreeMap<(EvidenceCacheLocation, String), String>;
fn insert(
    owners: &mut Owners,
    location: EvidenceCacheLocation,
    key: String,
    scope: String,
) -> Result<(), RuntimeError> {
    if let Some(old) = owners.insert((location, key), scope.clone()) {
        if old != scope {
            return Err(RuntimeError::StorageRepairRequired);
        }
    }
    Ok(())
}
impl EvidenceErasureScope {
    /// The native caller supplies only MAC-verified ownership rows. Every real
    /// slot must be attributable before a scoped intent can promise deletion.
    /// No scope, project file, interpreter or SDK is opened by this check.
    pub fn ensure_attributed(
        &self,
        home: &Path,
        current: Option<&EvidenceCache>,
        attributed: &[EvidenceScopeOwner],
    ) -> Result<Self, RuntimeError> {
        if attributed.len() > 64 || attributed.iter().any(|a| !a.valid()) {
            return Err(RuntimeError::StorageRepairRequired);
        }
        let store = EvidenceGenerationStore::existing(home)?;
        let _lock = store.as_ref().map(|s| s.root.lock()).transpose()?;
        let copies = ScopeCopies::collect(store.as_ref(), self)?;
        if let Some(current) = current {
            let loc = current.scope_location(home)?;
            if let EvidenceCacheLocation::Generation { generation_id } = loc {
                if !copies.records.iter().any(|(g, _)| g.id == generation_id) {
                    return Err(RuntimeError::ScopeDenied);
                }
            }
        }
        let mut owners = Owners::new();
        for row in attributed {
            insert(
                &mut owners,
                row.location.clone(),
                row.slot_key.clone(),
                row.scope_sha256.clone(),
            )?;
        }
        for (g, record) in &copies.records {
            for entry in &record.entries {
                if !entry.deferred() {
                    insert(
                        &mut owners,
                        location(&record.source_generation),
                        entry.source_key().to_owned(),
                        entry.scope().into(),
                    )?;
                }
                insert(
                    &mut owners,
                    location(&Some(g.id.clone())),
                    transfer::target_key(entry.scope(), &record.target_producer_sha256)?,
                    entry.scope().into(),
                )?;
            }
        }
        for (root, keys) in &copies.keys {
            for key in keys {
                insert(
                    &mut owners,
                    location(root),
                    key.clone(),
                    self.namespace_sha256().into(),
                )?;
            }
        }
        let mut caches = Vec::new();
        let legacy = if current.is_some_and(|c| {
            c.root.directory.path == home.join("context-assistance/saved-evidence")
        }) {
            current.cloned()
        } else {
            EvidenceCache::existing(home)?
        };
        if let Some(cache) = legacy {
            caches.push((EvidenceCacheLocation::Legacy, cache));
        }
        for (g, _) in &copies.records {
            if g.directory.names(3)?.iter().any(|n| n == "cache") {
                caches.push((
                    location(&Some(g.id.clone())),
                    owned_cache(g.directory.child("cache", false)?, current)?,
                ));
            }
        }
        let mut legacy_keys = BTreeSet::new();
        for (loc, cache) in caches {
            for key in cache.slot_keys()? {
                let owner = owners
                    .get(&(loc.clone(), key.clone()))
                    .ok_or(RuntimeError::StorageRepairRequired)?;
                if owner != self.namespace_sha256() {
                    continue;
                }
                match &loc {
                    EvidenceCacheLocation::Legacy => {
                        legacy_keys.insert(key);
                    }
                    EvidenceCacheLocation::Generation { generation_id } => {
                        if !copies
                            .keys
                            .get(&Some(generation_id.clone()))
                            .is_some_and(|keys| keys.contains(&key))
                        {
                            return Err(RuntimeError::StorageRepairRequired);
                        }
                    }
                }
            }
        }
        Self::from_authenticated_intent(self.namespace_sha256(), legacy_keys)
    }
}
