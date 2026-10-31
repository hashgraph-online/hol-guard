//! Candidate preparation retains native source intent and readonly history.
//! It serializes no grant and carries no old SDK view, client, context or handoff.
use super::*;
use guard_context_assistance::{
    EvidenceGenerationStore, EvidencePreparation, EvidenceScope, EvidenceUpgradeProducer,
    PreparedEvidenceGeneration, VerifiedNoteTransfer,
};

#[path = "context_assistance_engine_upgrade_boundary.rs"]
mod boundary;
pub(crate) use boundary::UpgradeBoundary;
#[path = "context_assistance_engine_upgrade_build.rs"]
mod build;

#[derive(Clone)]
pub(crate) struct ScopeIntent {
    id: String,
    root: SourceRoot,
    app: String,
    policy: ContextAssistanceConfig,
    access: NotesAccess,
    sources: BTreeMap<String, (String, String)>,
    history: crate::context_assistance_history::History,
    receipts: VecDeque<ReceiptFact>,
    receipts_dropped: u64,
    note_semantic_sha256: Option<String>,
    ephemeral_notes: Option<guard_context_assistance::EphemeralReviewedNotes>,
}
/// Only the existing actor's live scopes can construct this value. It is
/// deliberately not serializable or accepted as an operator request payload.
pub(crate) struct UpgradeCapture {
    home: PathBuf,
    source_config: ContextAssistanceConfig,
    target_config: ContextAssistanceConfig,
    scopes: Vec<ScopeIntent>,
    source_semantic_sha256: String,
    target_producer: EvidenceUpgradeProducer,
    generation: Option<Arc<PreparedEvidenceGeneration>>,
    restore_existing: bool,
    legacy_keys: bool,
    #[cfg(target_os = "macos")]
    require_execution_lane: bool,
}
pub(crate) struct ReplacementEngine {
    pub(crate) runtime: VerifiedRuntime,
    pub(crate) engine: Engine,
    pub(crate) source_semantic_sha256: String,
    pub(crate) data_generation: Option<String>,
}
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
fn fingerprint(
    scopes: &[ScopeIntent],
    config: &ContextAssistanceConfig,
    producer: &EvidenceUpgradeProducer,
) -> Result<String, RuntimeError> {
    let fields: Vec<_> = scopes
        .iter()
        .map(|s| {
            (
                &s.id,
                s.root.path(),
                &s.app,
                &s.policy,
                s.access,
                &s.sources,
                &s.note_semantic_sha256,
            )
        })
        .collect();
    let bytes = serde_json::to_vec(&(
        "guard-cigar-live-upgrade-snapshot.v1",
        config,
        producer.identity_sha256(),
        fields,
    ))
    .map_err(|_| RuntimeError::RequestInvalid)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
impl Engine {
    pub(crate) fn upgrade_selection_data(
        &self,
        home: &std::path::Path,
    ) -> Result<guard_cigar_release::SelectionData, RuntimeError> {
        if self
            .home
            .canonicalize()
            .map_err(|_| RuntimeError::ScopeDenied)?
            != home
        {
            return Err(RuntimeError::ScopeDenied);
        }
        Ok(if let Some(generation) = &self.data_generation {
            guard_cigar_release::SelectionData::Generation {
                generation_id: generation.id().into(),
            }
        } else if self.storage_mode == guard_context_assistance::StorageMode::Memory {
            guard_cigar_release::SelectionData::Memory
        } else {
            guard_cigar_release::SelectionData::LegacySaved
        })
    }
    #[cfg(target_os = "macos")]
    pub(crate) fn upgrade_execution_ready(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.execution_lane
            .as_ref()
            .map(|lane| Arc::clone(&lane.ready))
            .unwrap_or_default()
    }
    pub(crate) fn set_selected_data(
        &mut self,
        selection: crate::policy_store::context_assistance_registry::switching::ActivationSelection,
    ) {
        self.producer = selection.producer;
        self.data_generation = selection.generation;
    }
    fn capture_scope_intent(
        &mut self,
        runtime: &mut VerifiedRuntime,
        producer: &EvidenceUpgradeProducer,
    ) -> Result<(Vec<ScopeIntent>, Vec<VerifiedNoteTransfer>), RuntimeError> {
        producer.revalidate_runtime(runtime)?;
        self.expire_notes(runtime)?;
        self.drain_receipts(runtime)?;
        let mut intents = Vec::new();
        let mut notes = Vec::new();
        for (id, scope) in self.scopes.iter_mut().filter(|(_, s)| !s.revoked) {
            policy_current(&self.home, scope, runtime)?;
            current_sources(scope)?;
            let namespace = EvidenceScope::new(&scope.app, scope.root.path())?;
            let ephemeral_notes = scope
                .graph
                .upgrade_memory_notes(runtime, &namespace, producer)?;
            let transfer = if ephemeral_notes.is_some() {
                None
            } else {
                scope
                    .graph
                    .upgrade_notes(runtime, &namespace, producer, now_ms())?
            };
            let semantic = match &ephemeral_notes {
                Some(notes) => Some(notes.semantic_sha256()?),
                None => transfer
                    .as_ref()
                    .map(VerifiedNoteTransfer::semantic_sha256)
                    .transpose()?,
            };
            intents.push(ScopeIntent {
                id: id.clone(),
                root: scope.root.clone(),
                app: scope.app.clone(),
                policy: scope.policy.clone(),
                access: scope.graph.access(),
                sources: scope
                    .sources
                    .iter()
                    .map(|(id, file)| {
                        (
                            id.clone(),
                            (file.relative_path.clone(), file.sha256.clone()),
                        )
                    })
                    .collect(),
                history: scope.history.clone().for_upgrade(
                    producer,
                    &runtime.status().package_version,
                    &runtime.status().worker_fingerprint,
                ),
                receipts: scope.receipts.clone(),
                receipts_dropped: scope.receipts_dropped,
                note_semantic_sha256: semantic,
                ephemeral_notes,
            });
            if let Some(transfer) = transfer {
                notes.push(transfer);
            }
        }
        Ok((intents, notes))
    }
    /// Execute only on the old actor lane. It holds that lane for the bounded
    /// capture/record write, not for target SDK startup or source readmission.
    pub(crate) fn prepare_upgrade_capture(
        &mut self,
        runtime: &mut VerifiedRuntime,
        source_config: ContextAssistanceConfig,
        target_config: ContextAssistanceConfig,
        from: EvidenceUpgradeProducer,
        to: EvidenceUpgradeProducer,
        request_id: &str,
    ) -> Result<UpgradeCapture, RuntimeError> {
        source_config
            .validate()
            .map_err(|_| RuntimeError::RequestInvalid)?;
        target_config
            .validate()
            .map_err(|_| RuntimeError::RequestInvalid)?;
        let mut expected_target = source_config.clone();
        expected_target.runtime_id = target_config.runtime_id.clone();
        if source_config.runtime_id != self.runtime_id
            || target_config.runtime_id == self.runtime_id
            || target_config != expected_target
            || !source_config.enabled
        {
            return Err(RuntimeError::ScopeDenied);
        }
        let current = crate::guard_config_load::context_assistance_config(&self.home)
            .map_err(|_| RuntimeError::ScopeDenied)?;
        if current.diagnostic.is_some()
            || !current.verification_permitted
            || current.effective != source_config
        {
            return Err(RuntimeError::ContextStale);
        }
        let (scopes, notes) = self.capture_scope_intent(runtime, &from)?;
        let semantic = fingerprint(&scopes, &source_config, &from)?;
        let generation =
            if source_config.storage.mode == guard_context_assistance::StorageMode::Sqlite {
                if self.cache.is_none() {
                    self.cache = Some(guard_context_assistance::EvidenceCache::open(&self.home)?);
                }
                let cache = self.cache.as_ref().ok_or(RuntimeError::ScopeDenied)?;
                let snapshot = cache.upgrade_inventory(now_ms())?;
                Some(Arc::new(
                    EvidenceGenerationStore::open(&self.home)?.prepare(
                        EvidencePreparation {
                            request_id,
                            source: cache,
                            snapshot: &snapshot,
                            from: &from,
                            to: &to,
                            notes: &notes,
                        },
                        now_ms(),
                    )?,
                ))
            } else {
                None
            };
        Ok(UpgradeCapture {
            home: self.home.clone(),
            source_config,
            target_config,
            scopes,
            source_semantic_sha256: semantic,
            target_producer: to,
            generation,
            restore_existing: false,
            legacy_keys: false,
            #[cfg(target_os = "macos")]
            require_execution_lane: self
                .execution_lane
                .as_ref()
                .is_some_and(|lane| lane.ready.load(std::sync::atomic::Ordering::Acquire)),
        })
    }
    /// Ordinary compilation may update SDK/manifest timestamps and history.
    /// Only a real scope, policy, source or reviewed-note change makes this fail.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn upgrade_semantic_sha256(
        &mut self,
        runtime: &mut VerifiedRuntime,
        config: &ContextAssistanceConfig,
        producer: &EvidenceUpgradeProducer,
    ) -> Result<String, RuntimeError> {
        let current = crate::guard_config_load::context_assistance_config(&self.home)
            .map_err(|_| RuntimeError::ScopeDenied)?;
        if config.runtime_id != self.runtime_id
            || current.effective != *config
            || current.diagnostic.is_some()
            || !current.verification_permitted
        {
            return Err(RuntimeError::ContextStale);
        }
        let (scopes, _) = self.capture_scope_intent(runtime, producer)?;
        fingerprint(&scopes, config, producer)
    }
}
#[cfg(all(test, target_os = "macos"))]
impl UpgradeCapture {
    pub(crate) fn describe(&self) -> Value {
        json!({"schema":"guard-cigar-engine-preparation.v1", "scopes":self.scopes.len(),
            "reviewed_scopes":self.scopes.iter().filter(|s| s.note_semantic_sha256.is_some()).count(),
            "source_semantic_sha256":self.source_semantic_sha256,
            "target_producer_sha256":self.target_producer.identity_sha256(),
            "prepared_data_generation":self.generation.as_ref().map(|g|g.id()),
            "requires_explicit_reconnect_acknowledgement":true,"authority_restored":false})
    }
}

#[cfg(all(test, target_os = "macos"))]
#[path = "context_assistance_engine_upgrade_actual_tests.rs"]
mod actual_tests;
#[cfg(all(test, target_os = "macos"))]
pub(crate) use actual_tests::fixture::{
    admit as upgrade_admit, memory_summary as upgrade_memory_summary,
    reviewed_summary as upgrade_reviewed_summary, Fixture as UpgradeFixture,
};
#[cfg(all(test, target_os = "macos"))]
#[path = "context_assistance_engine_switch_actual_tests.rs"]
mod switch_actual_tests;
