//! Retention and explicit removal include prepared copies. Unknown files,
//! active native caches and surviving SQLite owners are preserved/refused.
use super::*;

fn cache(directory: &Directory) -> Result<Option<EvidenceCache>, RuntimeError> {
    if !directory.names(3)?.iter().any(|n| n == "cache") {
        return Ok(None);
    }
    EvidenceCache::from_directory(directory.child("cache", false)?).map(Some)
}
fn inspect_tree(directory: &Directory) -> Result<(), RuntimeError> {
    for name in directory.names(3)? {
        match name.as_str() {
            "state.json" | "state.next" => {
                directory.open_file(&name, Access::Read, RECORD_BYTES)?;
            }
            "cache" => {
                if let Some(cache) = cache(directory)? {
                    cache.summary()?;
                }
            }
            _ => return Err(RuntimeError::ScopeDenied),
        }
    }
    Ok(())
}
pub(super) fn remove(
    root: &Directory,
    id: &str,
    directory: &Directory,
) -> Result<(), RuntimeError> {
    inspect_tree(directory)?;
    if let Some(cache) = cache(directory)? {
        cache.forget_all()?;
        drop(cache);
        let cached = directory.child("cache", false)?;
        cached.remove_file("cache.lock", 0)?;
        directory.remove_child("cache", &cached)?;
    }
    for name in directory.names(2)? {
        if !matches!(name.as_str(), "state.json" | "state.next") {
            return Err(RuntimeError::ScopeDenied);
        }
        directory.remove_file(&name, RECORD_BYTES)?;
    }
    root.remove_child(id, directory)
}
impl EvidenceGenerationStore {
    /// Explicit deletion needs no damaged/missing MAC key. It still requires
    /// the exact private profile namespace, bounded recognized files, native
    /// cache locks and the real SQLite-owner checks before any root is removed.
    pub fn forget_existing(home: &Path) -> Result<usize, RuntimeError> {
        match std::fs::symlink_metadata(home) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(_) => return Err(RuntimeError::ArtifactUnreadable),
            Ok(_) => {}
        }
        let home = Directory::inspect(home)?;
        if !home.names(1024)?.iter().any(|n| n == "context-assistance") {
            return Ok(0);
        }
        let assistance = home.child("context-assistance", false)?;
        if !assistance
            .names(64)?
            .iter()
            .any(|n| n == "evidence-generations")
        {
            return Ok(0);
        }
        let root = assistance.child("evidence-generations", false)?;
        let file = root.open_file("store.lock", Access::WriteOrCreate, 0)?;
        let _lock = access::lock(file)?;
        let mut ids = Vec::new();
        for name in root.names(MAX_GENERATIONS + 2)? {
            if matches!(name.as_str(), "authority.key" | "store.lock") {
                continue;
            }
            if !valid_key(&name) {
                return Err(RuntimeError::ScopeDenied);
            }
            inspect_tree(&root.child(&name, false)?)?;
            ids.push(name);
        }
        for id in &ids {
            remove(&root, id, &root.child(id, false)?)?;
        }
        if root.names(2)?.iter().any(|n| n == "authority.key") {
            root.remove_file("authority.key", 4096)?;
        }
        // Retain the lock inode. Concurrent stale handles must fail key checks;
        // a new explicit open may provision only this now-empty data role.
        Ok(ids.len())
    }

    /// Explicit removal is permitted even for corrupt metadata after complete
    /// bounded path/owner/SQLite checks. It cannot remove an active cache.
    pub fn forget_all(&self) -> Result<usize, RuntimeError> {
        let _lock = self.root.lock()?;
        let ids = self.root.ids()?;
        for id in &ids {
            inspect_tree(&self.root.directory.child(id, false)?)?;
        }
        for id in &ids {
            remove(
                &self.root.directory,
                id,
                &self.root.directory.child(id, false)?,
            )?;
        }
        Ok(ids.len())
    }
    /// Drops only preparation that has never become ready. Lifecycle selection
    /// and retained-generation removal belong to the serialized native owner.
    pub fn discard_prepared(&self, id: &str) -> Result<(), RuntimeError> {
        let _lock = self.root.lock()?;
        let generation = self.load_locked(id)?;
        if generation.read()?.phase == Phase::Ready {
            return Err(RuntimeError::ScopeDenied);
        }
        remove(&self.root.directory, id, &generation.directory)
    }
    /// Expired transfer text is removed independently of SDK ownership. Cache
    /// cleanup is delegated to the same bounded, actual-owner-aware cache used
    /// by the active actor; busy caches retain their live owner's maintenance.
    pub fn sweep(&self, retention_hours: u32, now: u64) -> Result<(), RuntimeError> {
        if !(1..=720).contains(&retention_hours) || now == 0 {
            return Err(RuntimeError::RequestInvalid);
        }
        let _lock = self.root.lock()?;
        for id in self.root.ids()? {
            let generation = self.load_locked(&id)?;
            let mut record = generation.read()?;
            let mut changed = false;
            for entry in &mut record.entries {
                let deferred = entry.deferred();
                if let Entry::Pending { transfer } | Entry::Deferred { transfer } = entry {
                    let expires = transfer
                        .expires_at_ms
                        .min(
                            transfer
                                .notes
                                .as_ref()
                                .map_or(transfer.expires_at_ms, |n| n.valid_until_ms),
                        )
                        .min(
                            transfer
                                .source_created_at_ms
                                .saturating_add(u64::from(retention_hours) * 3_600_000),
                        );
                    if now < transfer.captured_at_ms {
                        return Err(RuntimeError::StorageRepairRequired);
                    }
                    if now >= expires {
                        *entry = Entry::Expired {
                            deferred,
                            scope_sha256: transfer.scope_sha256.clone(),
                            source_key: transfer.source_key.clone(),
                            expires_at_ms: expires,
                        };
                        changed = true;
                    } else if transfer.expires_at_ms != expires
                        || transfer
                            .notes
                            .as_ref()
                            .is_some_and(|n| n.valid_until_ms > expires)
                    {
                        transfer.expires_at_ms = expires;
                        if let Some(notes) = &mut transfer.notes {
                            notes.valid_until_ms = notes.valid_until_ms.min(expires);
                        }
                        changed = true;
                    }
                }
            }
            if changed {
                generation
                    .directory
                    .write_state_limit(&self.root.authority.seal(&record)?, RECORD_BYTES)?;
            }
            match cache(&generation.directory) {
                Ok(Some(cache)) => match cache.sweep(retention_hours, now) {
                    Ok(_) | Err(RuntimeError::Busy) => {}
                    Err(error) => return Err(error),
                },
                Ok(None) | Err(RuntimeError::Busy) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}
