//! Final native observations at the old actor's admission boundary. No SDK
//! context, execution handoff, session or serialized grant crosses this value.
use super::*;

#[derive(Clone)]
pub(crate) struct UpgradeBoundary {
    pub(crate) semantic: String,
    scopes: Vec<ScopeIntent>,
    #[cfg(target_os = "macos")]
    require_execution_lane: bool,
}
impl UpgradeBoundary {
    /// This value exists only while the native cutover owner remains alive.
    /// Rebuild scope intent with fresh SDK authority after exact source selection.
    pub(crate) fn restore(
        self,
        home: PathBuf,
        config: ContextAssistanceConfig,
        producer: EvidenceUpgradeProducer,
        selection: crate::policy_store::context_assistance_registry::switching::ActivationSelection,
        runtime: VerifiedRuntime,
        notifications: Option<Arc<Notifications>>,
    ) -> Result<ReplacementEngine, RuntimeError> {
        if fingerprint(&self.scopes, &config, &producer)? != self.semantic {
            return Err(RuntimeError::ContextStale);
        }
        UpgradeCapture {
            home,
            source_config: config.clone(),
            target_config: config,
            scopes: self.scopes,
            source_semantic_sha256: self.semantic,
            target_producer: producer,
            generation: selection.generation,
            restore_existing: true,
            legacy_keys: selection.producer.is_none(),
            #[cfg(target_os = "macos")]
            require_execution_lane: self.require_execution_lane,
        }
        .build(runtime, notifications)
    }
}
impl Engine {
    pub(crate) fn upgrade_boundary(
        &mut self,
        runtime: &mut VerifiedRuntime,
        config: &ContextAssistanceConfig,
        producer: &EvidenceUpgradeProducer,
    ) -> Result<UpgradeBoundary, RuntimeError> {
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
        Ok(UpgradeBoundary {
            semantic: fingerprint(&scopes, config, producer)?,
            scopes,
            #[cfg(target_os = "macos")]
            require_execution_lane: self
                .upgrade_execution_ready()
                .load(std::sync::atomic::Ordering::Acquire),
        })
    }
    pub(crate) fn apply_upgrade_boundary(
        &mut self,
        runtime: &mut VerifiedRuntime,
        snapshot: UpgradeBoundary,
    ) -> Result<(), RuntimeError> {
        let producer = self
            .producer
            .as_ref()
            .ok_or(RuntimeError::ApprovalMismatch)?;
        producer.revalidate_runtime(runtime)?;
        let expected: BTreeSet<_> = self
            .scopes
            .iter()
            .filter(|(_, s)| !s.revoked)
            .map(|(id, _)| id.clone())
            .collect();
        if expected != snapshot.scopes.iter().map(|s| s.id.clone()).collect() {
            return Err(RuntimeError::ContextStale);
        }
        for intent in snapshot.scopes {
            let scope = self
                .scopes
                .get_mut(&intent.id)
                .ok_or(RuntimeError::ContextStale)?;
            if scope.policy.sources.sanitized_receipt_facts
                || scope.policy.storage.mode == guard_context_assistance::StorageMode::Sqlite
            {
                scope.graph.replace_source(
                    runtime,
                    "guard:receipts",
                    intent.receipts.iter().map(ReceiptFact::document).collect(),
                )?;
            }
            let mut history = intent.history;
            history.set_current_producer(producer);
            history.expire(scope.policy.storage.retention_hours);
            scope.history = history;
            scope.receipts = intent.receipts;
            scope.receipts_dropped = intent.receipts_dropped;
        }
        Ok(())
    }
}
