//! Saved evidence is readmitted only after the current protected file grants.
//! Private persistence uses a broker without enabling app-to-app sharing.
use super::*;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
impl Backend {
    pub(in super::super) fn expire_cache(
        &mut self,
        runtime: &mut VerifiedRuntime,
    ) -> Result<bool, RuntimeError> {
        #[cfg(unix)]
        if self
            .cache
            .as_ref()
            .is_some_and(|c| now_ms() >= c.expires_at_ms())
        {
            self.forget(runtime)?;
            return Ok(true);
        }
        #[cfg(not(unix))]
        let _ = runtime;
        Ok(false)
    }
    #[cfg(unix)]
    pub(in super::super) fn open_saved(
        runtime: &mut VerifiedRuntime,
        config: &ContextAssistanceConfig,
        access: NotesAccess,
        slot: guard_context_assistance::EvidenceSlot,
    ) -> Result<Self, RuntimeError> {
        Self::validate_open(runtime, config, access)?;
        if config.storage.mode != guard_context_assistance::StorageMode::Sqlite
            || !runtime.status().persistence_compile_verified
        {
            return Err(RuntimeError::ScopeDenied);
        }
        let domain = runtime
            .open_persistent_broker_domain(&slot.domain_name(), config, slot.broker_storage()?)
            .map_err(|error| {
                if error == RuntimeError::WorkerRejected {
                    // This worker already passed the independent storage doctor. A
                    // rejected user store is preserved for explicit data repair.
                    RuntimeError::StorageRepairRequired
                } else {
                    error
                }
            })?;
        let restored = runtime.broker_storage_status(&domain)?["restored"]
            .as_bool()
            .ok_or(RuntimeError::HandshakeFailed)?;
        let mut result = Self::from_mode(Mode::Shared(domain), config, access);
        result.restored = restored;
        result.cache = Some(slot);
        Ok(result)
    }
    pub(super) fn has_cache(&self) -> bool {
        #[cfg(unix)]
        {
            self.cache.is_some()
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
    pub(super) fn check_cache(&mut self) -> Result<(), RuntimeError> {
        #[cfg(unix)]
        if let Some(cache) = &mut self.cache {
            cache.revalidate(now_ms())?;
        }
        Ok(())
    }
    pub(super) fn check_cache_read(&self) -> Result<(), RuntimeError> {
        #[cfg(unix)]
        if let Some(cache) = &self.cache {
            cache.check(now_ms())?;
        }
        Ok(())
    }
    pub(super) fn stage_notes(
        &mut self,
        runtime: &mut VerifiedRuntime,
        expected: &str,
        documents: &[ContextDocument],
    ) -> Result<(), RuntimeError> {
        #[cfg(unix)]
        if let Some(cache) = &mut self.cache {
            if let Err(error) = cache.stage_notes(expected, documents, now_ms()) {
                runtime.close();
                return Err(error);
            }
        }
        #[cfg(not(unix))]
        let _ = (runtime, expected, documents);
        Ok(())
    }
    pub(super) fn commit_notes(
        &mut self,
        runtime: &mut VerifiedRuntime,
        version: &str,
        notes: Option<(Vec<ContextDocument>, BTreeSet<String>)>,
    ) -> Result<(), RuntimeError> {
        #[cfg(unix)]
        if let Some(cache) = &mut self.cache {
            let saved = notes.map(|(documents, basis)| guard_context_assistance::SavedNotes {
                documents,
                basis,
                version: version.into(),
                valid_until_ms: cache.expires_at_ms(),
            });
            if let Err(error) = cache.commit_notes(version, saved, now_ms()) {
                runtime.close();
                return Err(error);
            }
        }
        #[cfg(not(unix))]
        let _ = (runtime, version, notes);
        Ok(())
    }
    pub(in super::super) fn finish_sources(
        &mut self,
        runtime: &mut VerifiedRuntime,
    ) -> Result<(), RuntimeError> {
        #[cfg(unix)]
        if let Some((generation, scope, producer)) = self.deferred_scope.take() {
            if !self.access.read {
                self.deferred_scope = Some((generation, scope, producer));
                return Ok(());
            }
            let Some(Mode::Shared(domain)) = &self.mode else {
                return Err(RuntimeError::ScopeDenied);
            };
            let slot = self.cache.as_mut().ok_or(RuntimeError::ScopeDenied)?;
            generation.admit_deferred_scope(&scope, &producer, slot, runtime, domain, now_ms())?;
            return self.refresh_imported_notes(runtime, now_ms());
        }
        #[cfg(unix)]
        if self.cache.is_some() {
            return self.restore_notes(runtime);
        }
        if self.access.read {
            self.replace_source(runtime, "guard:notes", Vec::new())?;
        }
        Ok(())
    }
    #[cfg(unix)]
    fn restore_notes(&mut self, runtime: &mut VerifiedRuntime) -> Result<(), RuntimeError> {
        let Some(Mode::Shared(domain)) = &self.mode else {
            return Err(RuntimeError::ScopeDenied);
        };
        let (current, digest) = runtime.broker_source_digest(domain, "guard:notes")?;
        let cache = self.cache.as_mut().ok_or(RuntimeError::ScopeDenied)?;
        cache.reconcile_notes(&current.version, digest.as_deref(), now_ms())?;
        let saved = cache.notes().cloned();
        if self.restored && current.version != "0" && (self.access.read || saved.is_none()) {
            let docs = saved
                .as_ref()
                .map_or_else(Vec::new, |n| n.documents.clone());
            match runtime.resume_broker_source(domain, "guard:notes", docs.clone()) {
                Ok(revision) => {
                    self.note_revision = Some(revision);
                    self.notes = docs;
                    self.digests.insert(
                        "guard:notes".into(),
                        digest.ok_or(RuntimeError::ContextStale)?,
                    );
                    if let Some(saved) = saved {
                        self.note_basis = saved.basis;
                        self.note_expires = Some(
                            Instant::now()
                                + Duration::from_millis(
                                    saved.valid_until_ms.saturating_sub(now_ms()),
                                ),
                        );
                    }
                    return Ok(());
                }
                Err(RuntimeError::ContextStale) => {}
                Err(error) => return Err(error),
            }
        }
        self.replace_source(runtime, "guard:notes", Vec::new())
    }
    pub(in super::super) fn forget(
        &mut self,
        runtime: &mut VerifiedRuntime,
    ) -> Result<(), RuntimeError> {
        self.close(runtime)?;
        #[cfg(unix)]
        if let Some(cache) = self.cache.take() {
            cache.remove()?;
        }
        Ok(())
    }
}
