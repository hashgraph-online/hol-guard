//! Prepare actual target scopes outside the old actor and settings lock.
use super::*;

impl UpgradeCapture {
    pub(crate) fn build(
        self,
        mut runtime: VerifiedRuntime,
        notifications: Option<Arc<Notifications>>,
    ) -> Result<ReplacementEngine, RuntimeError> {
        self.target_producer.revalidate_runtime(&runtime)?;
        if (self.target_config.features.shared_agents && !runtime.status().shared_compile_verified)
            || (self.target_config.storage.mode == guard_context_assistance::StorageMode::Sqlite
                && !runtime.status().persistence_compile_verified)
        {
            return Err(RuntimeError::HandshakeFailed);
        }
        #[cfg(target_os = "macos")]
        if self.require_execution_lane && !runtime.status().execution_handoff_verified {
            return Err(RuntimeError::HandshakeFailed);
        }
        let mut engine = Engine::new(self.home.clone(), &self.target_config, notifications);
        engine.producer = (!self.legacy_keys).then(|| self.target_producer.clone());
        engine.data_generation = self.generation.clone();
        #[cfg(target_os = "macos")]
        if self.target_config.features.execution_context
            && runtime.status().execution_handoff_verified
        {
            engine.set_execution_lane(Some(Engine::prewarm_execution(
                &mut runtime,
                &self.target_config,
            )?));
        }
        if let Some(generation) = &self.generation {
            engine.cache = Some(generation.open_cache()?);
        }
        for intent in self.scopes {
            intent.root.revalidate()?;
            if effective(&self.home, &intent.root)? != intent.policy {
                return Err(RuntimeError::ContextStale);
            }
            let mut policy = intent.policy.clone();
            policy.runtime_id = self.target_config.runtime_id.clone();
            let mut sources = BTreeMap::new();
            for (id, (path, expected)) in &intent.sources {
                let fresh = intent.root.read(path)?;
                if &fresh.source_id != id || &fresh.sha256 != expected {
                    return Err(RuntimeError::ContextStale);
                }
                sources.insert(id.clone(), fresh);
            }
            let mut graph = engine.open_backend(
                &mut runtime,
                &intent.id,
                &intent.root,
                &intent.app,
                &policy,
                intent.access,
            )?;
            for source in sources.values() {
                graph.replace_source(&mut runtime, &source.source_id, source.documents.clone())?;
            }
            if policy.sources.native_policy_facts {
                graph.replace_source(&mut runtime, "guard:policy", vec![policy_document()])?;
            }
            if policy.sources.sanitized_receipt_facts
                || policy.storage.mode == guard_context_assistance::StorageMode::Sqlite
            {
                graph.replace_source(
                    &mut runtime,
                    "guard:receipts",
                    intent.receipts.iter().map(ReceiptFact::document).collect(),
                )?;
            }
            if policy.storage.mode == guard_context_assistance::StorageMode::Sqlite {
                graph.replace_source(&mut runtime, "guard:action", Vec::new())?;
                if self.restore_existing {
                    graph.finish_sources(&mut runtime)?;
                } else {
                    let namespace = EvidenceScope::new(&intent.app, intent.root.path())?;
                    graph.import_upgrade_notes(
                        &mut runtime,
                        &namespace,
                        &self.target_producer,
                        self.generation.as_ref().ok_or(RuntimeError::ScopeDenied)?,
                        now_ms(),
                    )?;
                }
            } else if let Some(notes) = &intent.ephemeral_notes {
                let namespace = EvidenceScope::new(&intent.app, intent.root.path())?;
                graph.import_upgrade_memory_notes(
                    &mut runtime,
                    &namespace,
                    &self.target_producer,
                    notes,
                )?;
            } else {
                graph.finish_sources(&mut runtime)?;
            }
            let revision = revision(&policy)?;
            graph.create_view(
                &mut runtime,
                "app",
                allowed(&sources, &policy),
                &revision,
                false,
            )?;
            let mut history = intent.history;
            history.set_current_producer(&self.target_producer);
            history.expire(policy.storage.retention_hours);
            engine.scopes.insert(
                intent.id,
                Scope {
                    root: intent.root,
                    app: intent.app,
                    policy,
                    revision,
                    graph,
                    sources,
                    contexts: BTreeMap::new(),
                    agent_contexts: BTreeMap::new(),
                    action_context: None,
                    history,
                    revoked: false,
                    epoch: Default::default(),
                    receipts: intent.receipts,
                    receipts_dropped: intent.receipts_dropped,
                },
            );
        }
        let current = crate::guard_config_load::context_assistance_config(&self.home)
            .map_err(|_| RuntimeError::ScopeDenied)?;
        if current.effective != self.source_config
            || current.diagnostic.is_some()
            || !current.verification_permitted
        {
            return Err(RuntimeError::ContextStale);
        }
        if self
            .generation
            .as_ref()
            .is_some_and(|g| g.describe().map_or(true, |v| v["phase"] != "ready"))
        {
            return Err(RuntimeError::StorageOutcomeUnknown);
        }
        Ok(ReplacementEngine {
            runtime,
            engine,
            source_semantic_sha256: self.source_semantic_sha256,
            data_generation: self.generation.as_ref().map(|g| g.id().into()),
        })
    }
}
