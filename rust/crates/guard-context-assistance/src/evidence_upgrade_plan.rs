//! Compatibility is based on exact producers and shipped formats. A matching
//! SQLite label alone does not authorize reuse of an opaque SDK checkpoint.
use super::*;
use crate::StorageMode;
use guard_cigar_release::{DataTransition, Feature};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataCompatibility {
    Readable,
    Migratable,
    Incompatible,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceUpgradeStrategy {
    MemoryRebuild,
    ReuseCompatible,
    FreshBrokerReadmission,
    Blocked,
}
#[derive(Clone, Debug, Serialize)]
pub struct EvidenceUpgradePlan {
    pub schema: &'static str,
    pub compatibility: DataCompatibility,
    pub strategy: EvidenceUpgradeStrategy,
    pub code: &'static str,
    pub snapshot_sha256: String,
    pub observed_at_ms: u64,
    pub source_slots: usize,
    pub retained_bytes: u64,
    pub required_extra_bytes: u64,
    pub required_extra_slots: usize,
    pub retention_capacity_available: bool,
    pub requires_prepared_copy: bool,
    pub requires_quiescent_recheck: bool,
    pub requires_fresh_authority: bool,
    pub previous_checkpoint_preserved: bool,
    pub raw_sdk_checkpoint_copied: bool,
    pub transition_after_preparation: Option<DataTransition>,
    pub features_added: Vec<Feature>,
    pub features_removed: Vec<Feature>,
    pub authority_restored: bool,
}
impl EvidenceUpgradeInventory {
    /// Planning never touches an SDK checkpoint or changes enablement, scopes,
    /// retention or approval decisions. The switch owner must obtain and check
    /// a fresh protected snapshot after the old actor has quiesced.
    pub fn preflight(
        &self,
        from_producer: &EvidenceUpgradeProducer,
        to_producer: &EvidenceUpgradeProducer,
        storage: StorageMode,
        requested: &[Feature],
    ) -> Result<EvidenceUpgradePlan, RuntimeError> {
        let from = from_producer;
        let to = to_producer;
        if requested.len() > 4
            || !requested.contains(&Feature::Graph)
            || requested.iter().collect::<BTreeSet<_>>().len() != requested.len()
        {
            return Err(RuntimeError::RequestInvalid);
        }
        let mut plan = EvidenceUpgradePlan {
            schema: "guard-cigar-evidence-preflight.v1",
            compatibility: DataCompatibility::Readable,
            strategy: EvidenceUpgradeStrategy::MemoryRebuild,
            code: "memory_rebuild",
            snapshot_sha256: self.snapshot_sha256.clone(),
            observed_at_ms: self.observed_at_ms,
            source_slots: self.slots.len(),
            retained_bytes: self.bytes,
            required_extra_bytes: 0,
            required_extra_slots: 0,
            retention_capacity_available: true,
            requires_prepared_copy: false,
            requires_quiescent_recheck: self.slots.iter().any(|s| s.active),
            requires_fresh_authority: true,
            previous_checkpoint_preserved: true,
            raw_sdk_checkpoint_copied: false,
            transition_after_preparation: Some(DataTransition::MemoryRebuild),
            features_added: to
                .features
                .iter()
                .filter(|f| !from.features.contains(f))
                .copied()
                .collect(),
            features_removed: from
                .features
                .iter()
                .filter(|f| !to.features.contains(f))
                .copied()
                .collect(),
            authority_restored: false,
        };
        let blocked =
            if !to.activation_qualified() || requested.iter().any(|f| !to.features.contains(f)) {
                Some((DataCompatibility::Incompatible, "cigar_feature_unqualified"))
            } else if storage == StorageMode::Memory {
                None
            } else if !to.features.contains(&Feature::Persistence) {
                Some((DataCompatibility::Incompatible, "cigar_feature_unqualified"))
            } else if !from.supported_data_format()
                || !to.supported_data_format()
                || self
                    .slots
                    .iter()
                    .any(|s| s.state == RecordState::UnknownSchema)
            {
                Some((
                    DataCompatibility::Unknown,
                    "cigar_storage_schema_unsupported",
                ))
            } else if self.slots.iter().any(|s| s.state == RecordState::Invalid) {
                Some((
                    DataCompatibility::Incompatible,
                    "context_storage_repair_required",
                ))
            } else if self
                .slots
                .iter()
                .any(|s| s.state == RecordState::PendingWrite)
            {
                Some((
                    DataCompatibility::Unknown,
                    "context_storage_outcome_unknown",
                ))
            } else {
                None
            };
        if let Some((compatibility, code)) = blocked {
            plan.compatibility = compatibility;
            plan.strategy = EvidenceUpgradeStrategy::Blocked;
            plan.code = code;
            plan.transition_after_preparation = None;
            return Ok(plan);
        }
        if storage == StorageMode::Memory {
            return Ok(plan);
        }
        if self.slots.is_empty() {
            plan.code = "empty_saved_evidence";
            return Ok(plan);
        }
        if from_producer.fingerprint == to_producer.fingerprint {
            plan.strategy = EvidenceUpgradeStrategy::ReuseCompatible;
            plan.code = "reuse_exact_producer";
            plan.transition_after_preparation = Some(DataTransition::ReuseCompatible);
            return Ok(plan);
        }
        let slots = self
            .slots
            .iter()
            .filter(|s| s.state != RecordState::Expired)
            .count();
        // Reserve the full bounded target checkpoint/journal and both manifest
        // writes. The prior bytes remain under the existing retention/delete
        // policy. No raw database copy or undocumented SDK migration is used.
        plan.required_extra_bytes =
            slots as u64 * (DATABASE_BYTES + JOURNAL_BYTES + 2 * STATE_BYTES);
        plan.required_extra_slots = slots;
        // A target has its own bounded generation/cache; a full source cache
        // does not require deleting saved scopes merely to prepare an update.
        plan.retention_capacity_available =
            plan.required_extra_bytes <= self.max_bytes && slots <= MAX_SLOTS;
        plan.required_extra_bytes += 4 * 1024 * 1024; // sealed state plus atomic replacement
        plan.compatibility = if plan.retention_capacity_available {
            DataCompatibility::Migratable
        } else {
            DataCompatibility::Incompatible
        };
        plan.strategy = if plan.retention_capacity_available {
            EvidenceUpgradeStrategy::FreshBrokerReadmission
        } else {
            EvidenceUpgradeStrategy::Blocked
        };
        plan.code = if plan.retention_capacity_available {
            "fresh_broker_preparation_required"
        } else {
            "cigar_storage_preparation_capacity_required"
        };
        plan.requires_prepared_copy = true;
        plan.transition_after_preparation = if plan.retention_capacity_available {
            Some(DataTransition::PreparedCopy)
        } else {
            None
        };
        Ok(plan)
    }
}
