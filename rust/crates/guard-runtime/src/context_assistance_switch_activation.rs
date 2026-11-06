//! Fresh activation/recovery revalidates the selected installation and the
//! sealed ready generation before creating any new app scope or SDK client.
use super::*;
use guard_cigar_release::{SelectionData, SelectionRecovery};
use guard_context_assistance::{
    ContextAssistanceConfig, EvidenceGenerationStore, EvidenceUpgradeProducer,
    PreparedEvidenceGeneration, StorageMode,
};
use std::sync::Arc;

pub(crate) struct ActivationSelection {
    pub(crate) producer: Option<EvidenceUpgradeProducer>,
    pub(crate) generation: Option<Arc<PreparedEvidenceGeneration>>,
}
pub(crate) fn prepare_activation(
    home: &Path,
    installation: &Installation,
    runtime: &VerifiedRuntime,
    config: &ContextAssistanceConfig,
) -> Result<Option<ActivationSelection>, String> {
    DataRemoval::check_clear(home).map_err(|e| error(e.code()))?;
    let mut owner = Owner::acquire(home)?;
    owner.check_initial_clear()?;
    let Some(record) = owner.record() else {
        return Ok(None);
    };
    let selected = if record.current.runtime.installation_id == config.runtime_id {
        record.current.clone()
    } else if let Some(t) = &record.transaction {
        if t.from.runtime.installation_id == config.runtime_id {
            t.from.clone()
        } else if t.to.runtime.installation_id == config.runtime_id {
            t.to.clone()
        } else {
            return Err(error("switch_selection_conflict"));
        }
    } else {
        return Err(error("switch_selection_conflict"));
    };
    let selection = verify_selected(home, &selected, installation, runtime, config)?;
    let text = crate::guard_config_update::read_home_config(home).map_err(storage_error)?;
    let current = crate::guard_config_load::context_assistance_config(home)
        .map_err(|_| error("configuration_unavailable"))?;
    if &current.effective != config
        || current.diagnostic.is_some()
        || !current.verification_permitted
    {
        return Err(error("switch_settings_conflict"));
    }
    let record = owner
        .record()
        .ok_or_else(|| error("switch_selection_missing"))?;
    let phase = record.transaction.as_ref().map(|t| t.phase);
    let target = record.transaction.as_ref().is_none_or(|t| t.to == selected);
    let previous = record
        .transaction
        .as_ref()
        .is_none_or(|t| t.from == selected);
    let recovery = record
        .recovery(
            &config.runtime_id,
            &settings::settings_hash(text.as_deref()),
            current.requested.enabled && current.effective.enabled,
            target,
            previous,
        )
        .map_err(state_error)?;
    use SelectionPhase::*;
    match recovery {
        SelectionRecovery::PreservePrevious => match phase {
            Some(Prepared | StopIntent) => owner.advance(Cancelled)?,
            Some(CommitIntent) => {
                owner.advance(RestoreIntent)?;
                owner.advance(RolledBack)?;
            }
            Some(RestoreIntent) => owner.advance(RolledBack)?,
            _ => {}
        },
        SelectionRecovery::VerifyTarget => {
            if phase == Some(CommitIntent) {
                owner.advance(Committed)?;
            }
            if owner
                .record()
                .and_then(|r| r.transaction.as_ref())
                .is_some_and(|t| t.phase == Committed)
            {
                owner.advance(Healthy)?;
            }
            owner.advance(Completed)?;
        }
        SelectionRecovery::KeepTarget | SelectionRecovery::PreserveDisabled(_) => {}
        SelectionRecovery::RestorePrevious | SelectionRecovery::RequireOperatorRecovery => {
            return Err(error("switch_recovery_required"));
        }
    }
    // Legacy saved slots keep their original worker key until an actual data
    // migration. No namespace relabeling is inferred from an SDK version.
    Ok(Some(selection))
}
pub(super) fn verify_selected(
    home: &Path,
    selected: &guard_cigar_release::SelectionPointer,
    installation: &Installation,
    runtime: &VerifiedRuntime,
    config: &ContextAssistanceConfig,
) -> Result<ActivationSelection, String> {
    if matches!(selected.data, SelectionData::Memory) && config.storage.mode != StorageMode::Memory
    {
        return Err(error("switch_data_settings_conflict"));
    }
    let (measured, producer) =
        installation.measured_selection(home, runtime, selected.data.clone())?;
    if &measured != selected {
        return Err(error("switch_installation_changed"));
    }
    let generation = if let Some(id) = selected.data.generation_id() {
        let generation = EvidenceGenerationStore::existing(home)
            .map_err(|e| error(e.code()))?
            .ok_or_else(|| error("switch_data_generation_missing"))?
            .load(id)
            .map_err(|e| error(e.code()))?;
        let summary = generation.describe().map_err(|e| error(e.code()))?;
        if summary["phase"] != "ready"
            || summary["target_producer_sha256"] != producer.identity_sha256()
        {
            return Err(error("switch_data_generation_mismatch"));
        }
        Some(Arc::new(generation))
    } else {
        None
    };
    Ok(ActivationSelection {
        producer: (!matches!(selected.data, SelectionData::LegacySaved)).then_some(producer),
        generation,
    })
}
