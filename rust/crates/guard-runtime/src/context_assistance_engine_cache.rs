use super::*;

impl Engine {
    pub(super) fn saved_data(&self) -> Value {
        if let Some(cache) = &self.cache {
            return crate::context_assistance_data::describe(Some(cache))
                .and_then(|value| {
                    crate::context_assistance_data::validate_generations(&self.home)?;
                    Ok(value)
                })
                .unwrap_or_else(crate::context_assistance_data::failure);
        }
        crate::context_assistance_data::sweep(&self.home, self.retention_hours)
            .map_or_else(crate::context_assistance_data::failure, |_| {
                crate::context_assistance_data::inspect(&self.home)
            })
    }
    /// Explicit withdrawal/note removal drops the whole old SDK checkpoint,
    /// including its bounded journal, then rereads only the remaining grants.
    pub(super) fn reset_scope(
        &mut self,
        runtime: &mut VerifiedRuntime,
        id: &str,
        withdrawn: Option<&str>,
    ) -> Result<Value, RuntimeError> {
        let mut scope = self.scopes.remove(id).ok_or(RuntimeError::ScopeDenied)?;
        let mut changed = false;
        let result = (|| {
            policy_current(&self.home, &mut scope, runtime)?;
            if withdrawn.is_some_and(|s| !scope.sources.contains_key(s)) {
                return Err(RuntimeError::ScopeDenied);
            }
            let access = scope.graph.access();
            let removal =
                crate::policy_store::context_assistance_registry::switching::ScopeRemoval::acquire(
                    &self.home,
                    &guard_context_assistance::EvidenceScope::new(&scope.app, scope.root.path())?,
                    &BTreeSet::from([runtime.bundle_approval().worker_sha256.clone()]),
                    self.cache.as_ref(),
                )?;
            changed = true;
            scope.graph.forget(runtime)?;
            scope.clear_contexts();
            scope.history.clear();
            scope.receipts.clear();
            let erasure = removal.remove(self.cache.as_ref())?;
            if let Some(source) = withdrawn {
                scope.sources.remove(source);
            }
            let mut sources = BTreeMap::new();
            for source in scope.sources.values() {
                let fresh = scope.root.read(&source.relative_path)?;
                sources.insert(fresh.source_id.clone(), fresh);
            }
            scope.sources = sources;
            scope.graph =
                self.open_backend(runtime, id, &scope.root, &scope.app, &scope.policy, access)?;
            initialize_graph(
                runtime,
                &mut scope.graph,
                &scope.sources,
                &scope.policy,
                &scope.revision,
            )?;
            current_sources(&scope)?;
            policy_current(&self.home, &mut scope, runtime)?;
            let mut result = metadata(id, &scope);
            result["saved_copy_erasure"] =
                serde_json::to_value(erasure).map_err(|_| RuntimeError::RequestInvalid)?;
            Ok(result)
        })();
        if result.is_err() && changed {
            scope.revoked = true;
            scope.clear_contexts();
            scope.history.clear();
            scope.sources.clear();
            let _ = scope.graph.close(runtime);
        }
        self.scopes.insert(id.into(), scope);
        result
    }
    pub(super) fn sweep_saved(&self) -> Result<(), RuntimeError> {
        if let Some(cache) = &self.cache {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX);
            cache.sweep(self.retention_hours, now)?;
        }
        Ok(())
    }
    pub(super) fn forget_saved(
        &mut self,
        removal: crate::policy_store::context_assistance_registry::switching::DataRemoval,
    ) -> Result<(), RuntimeError> {
        if self.cache.is_none() {
            self.cache = guard_context_assistance::EvidenceCache::existing(&self.home)?;
        }
        if let Some(cache) = &self.cache {
            cache.forget_all()?;
        }
        self.cache = None; // release the current cache lock before clearing generations
        self.data_generation = None;
        // Also removes the legacy root when this cache was a generation.
        removal.remove()?;
        self.producer = None;
        Ok(())
    }
    pub(super) fn open_backend(
        &mut self,
        runtime: &mut VerifiedRuntime,
        id: &str,
        root: &SourceRoot,
        app: &str,
        config: &ContextAssistanceConfig,
        access: NotesAccess,
    ) -> Result<Backend, RuntimeError> {
        crate::policy_store::context_assistance_registry::switching::DataRemoval::check_clear(
            &self.home,
        )?;
        // Settings can change between service admission and this queued job.
        // Persistence and a newly selected runtime need a fresh generation.
        if config.runtime_id != self.runtime_id
            || (config.storage.mode == guard_context_assistance::StorageMode::Sqlite
                && self.storage_mode != guard_context_assistance::StorageMode::Sqlite)
        {
            return Err(RuntimeError::ScopeDenied);
        }
        if config.storage.mode == guard_context_assistance::StorageMode::Memory {
            return Backend::open(runtime, id, config, access);
        }
        if !runtime.status().persistence_compile_verified {
            return Err(RuntimeError::HandshakeFailed);
        }
        if self.cache.is_none() {
            self.cache = Some(match &self.data_generation {
                Some(generation) => generation.open_cache()?,
                None => guard_context_assistance::EvidenceCache::open(&self.home)?,
            });
        }
        let cache = self.cache.as_ref().ok_or(RuntimeError::ScopeDenied)?;
        let namespace = guard_context_assistance::EvidenceScope::new(app, root.path())?;
        let key = match &self.producer {
            Some(producer) => namespace.key(producer)?,
            None => guard_context_assistance::EvidenceCache::key(
                app,
                root.path(),
                &runtime.status().worker_fingerprint,
            )?,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        crate::policy_store::context_assistance_registry::switching::scope_index::remember(
            &self.home, cache, &namespace, &key,
        )?;
        let deferred = match (&self.data_generation, &self.producer) {
            (Some(generation), Some(producer))
                if generation.has_deferred_scope(&namespace, producer)? =>
            {
                Some((Arc::clone(generation), producer.clone()))
            }
            _ => None,
        };
        let slot = cache.open_slot(&key, config.storage.retention_hours, now)?;
        let mut backend = Backend::open_saved(runtime, config, access, slot)?;
        if let Some((generation, producer)) = deferred {
            backend.defer_scope(generation, namespace, producer);
        }
        Ok(backend)
    }
}

pub(super) fn initialize_graph(
    runtime: &mut VerifiedRuntime,
    graph: &mut Backend,
    sources: &BTreeMap<String, AdmittedFile>,
    policy: &ContextAssistanceConfig,
    revision: &str,
) -> Result<(), RuntimeError> {
    for source in sources.values() {
        graph.replace_source(runtime, &source.source_id, source.documents.clone())?;
    }
    if policy.sources.native_policy_facts {
        graph.replace_source(runtime, "guard:policy", vec![policy_document()])?;
    }
    let persistent = policy.storage.mode == guard_context_assistance::StorageMode::Sqlite;
    if policy.sources.sanitized_receipt_facts || persistent {
        graph.replace_source(runtime, "guard:receipts", Vec::new())?;
    }
    if persistent {
        graph.replace_source(runtime, "guard:action", Vec::new())?;
    }
    graph.finish_sources(runtime)?;
    graph.create_view(runtime, "app", allowed(sources, policy), revision, false)
}
