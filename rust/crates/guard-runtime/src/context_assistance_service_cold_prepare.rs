//! Verify actual source/target installations and seal closed-store data. No
//! actor, project read, app view, client or grant is constructed on this path.
use super::*;
use guard_cigar_release::SelectionTransaction;
use guard_context_assistance::{EvidencePreparation, EvidenceUpgradeProducer};

use super::super::private::PrivateRuntime;
pub(super) struct Prepared {
    pub(super) settings: switching::SwitchSettings,
    pub(super) target: PrivateRuntime,
    pub(super) target_install: registry::Installation,
    cache: Option<EvidenceCache>,
    source_generation: Option<PreparedEvidenceGeneration>,
    source_generation_semantic: Option<String>,
    snapshot: EvidenceUpgradeInventory,
    generation: Option<PreparedEvidenceGeneration>,
    generation_semantic: Option<String>,
}
impl Prepared {
    pub(super) fn check_data(&self) -> Result<(), String> {
        if let Some(cache) = &self.cache {
            if cache
                .upgrade_inventory(jobs::now()?)
                .map_err(|e| error(e.code()))?
                .snapshot_sha256()
                != self.snapshot.snapshot_sha256()
            {
                return Err(error("switch_source_changed"));
            }
        }
        for (generation, expected) in [
            (&self.source_generation, &self.source_generation_semantic),
            (&self.generation, &self.generation_semantic),
        ] {
            if let Some(generation) = generation {
                if Some(generation.semantic_sha256().map_err(|e| error(e.code()))?) != *expected {
                    return Err(error("switch_source_changed"));
                }
                if generation.describe().map_err(|e| error(e.code()))?["phase"] != "ready" {
                    return Err(error("switch_data_generation_mismatch"));
                }
            }
        }
        Ok(())
    }
}
fn source_data(
    owner: &switching::Owner,
    config: &guard_context_assistance::ContextAssistanceConfig,
) -> Result<SelectionData, String> {
    let data = owner
        .record()
        .map(|r| {
            if r.current.runtime.installation_id != config.runtime_id {
                return Err(error("switch_selection_conflict"));
            }
            Ok(r.current.data.clone())
        })
        .transpose()?
        .unwrap_or_else(|| {
            if config.storage.mode == StorageMode::Memory {
                SelectionData::Memory
            } else {
                SelectionData::LegacySaved
            }
        });
    if matches!(data, SelectionData::Memory) != (config.storage.mode == StorageMode::Memory) {
        return Err(error("switch_data_settings_conflict"));
    }
    Ok(data)
}
fn cache(
    home: &Path,
    data: &SelectionData,
    producer: &EvidenceUpgradeProducer,
) -> Result<(Option<EvidenceCache>, Option<PreparedEvidenceGeneration>), String> {
    if matches!(data, SelectionData::Memory) {
        return Ok((None, None));
    }
    if let Some(id) = data.generation_id() {
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
        Ok((
            Some(generation.open_cache().map_err(|e| error(e.code()))?),
            Some(generation),
        ))
    } else {
        Ok((
            Some(EvidenceCache::open(home).map_err(|e| error(e.code()))?),
            None,
        ))
    }
}
pub(super) fn run(
    shared: &Weak<Mutex<State>>,
    home: &Path,
    source: &Source,
    owner: &mut switching::Owner,
    job: &mut SwitchJob,
    signal: &Arc<Signal>,
) -> Result<Prepared, String> {
    check(shared, source, signal)?;
    let settings = switching::SwitchSettings::capture(
        home,
        &source.settings.effective,
        &job.request.target_runtime_id,
    )?;
    if settings.source_settings() != &source.settings || settings.target().enabled {
        return Err(error("switch_settings_conflict"));
    }
    let source_install = registry::load(home, &source.settings.effective.runtime_id)?;
    let target_install = registry::load(home, &job.request.target_runtime_id)?;
    crate::guard_config_load::cigar_updates::check_installation(
        home,
        settings.update_preferences(),
        &target_install,
    )?;
    super::super::worker::step(home, job, signal, JobPhase::Verifying, "verifying")?;
    let mut original = PrivateRuntime::start(&source_install, home, settings.source(), signal)?;
    let data = source_data(owner, settings.source())?;
    let (from, producer) =
        source_install.measured_selection(home, &original.runtime, data.clone())?;
    owner.initialize(from.clone())?;
    let (cache, source_generation) = cache(home, &data, &producer)?;
    let owners = switching::scope_index::owners(owner).map_err(|e| error(e.code()))?;
    super::super::worker::step(home, job, signal, JobPhase::PreparingData, "preparing_data")?;
    let exported_at = jobs::now()?;
    let notes = cache
        .as_ref()
        .map(|cache| {
            cache.export_cold_notes(
                home,
                &owners,
                &producer,
                &mut original.runtime,
                settings.source(),
                exported_at,
            )
        })
        .transpose()
        .map_err(|e| error(e.code()))?
        .unwrap_or_default();
    // Closing may checkpoint SQLite. Bind the inventory only after closure.
    drop(original);
    let observed_at = jobs::now()?;
    let snapshot = cache
        .as_ref()
        .map(|cache| cache.upgrade_inventory(observed_at))
        .transpose()
        .map_err(|e| error(e.code()))?
        .unwrap_or(EvidenceUpgradeInventory::empty(jobs::now()?).map_err(|e| error(e.code()))?);
    check(shared, source, signal)?;
    settings.check_current()?;
    let target = PrivateRuntime::start(&target_install, home, settings.target(), signal)?;
    let (target_stamp, to) =
        target_install.measured_selection(home, &target.runtime, SelectionData::Memory)?;
    owner.check_rollback_target(&job.request, &target_stamp.runtime)?;
    let generation = cache
        .as_ref()
        .map(|cache| {
            EvidenceGenerationStore::open(home)?.prepare_cold(
                EvidencePreparation {
                    request_id: &job.request.job_id,
                    source: cache,
                    snapshot: &snapshot,
                    from: &producer,
                    to: &to,
                    notes: &notes,
                },
                jobs::now().map_err(|_| guard_context_assistance::RuntimeError::RequestInvalid)?,
            )
        })
        .transpose()
        .map_err(|e| error(e.code()))?;
    job.prepared_data_generation = generation.as_ref().map(|g| g.id().to_owned());
    let data = job
        .prepared_data_generation
        .clone()
        .map_or(SelectionData::Memory, |generation_id| {
            SelectionData::Generation { generation_id }
        });
    let (to, _) = target_install.measured_selection(home, &target.runtime, data)?;
    let source_generation_semantic = source_generation
        .as_ref()
        .map(|g| g.semantic_sha256())
        .transpose()
        .map_err(|e| error(e.code()))?;
    let generation_semantic = generation
        .as_ref()
        .map(|g| g.semantic_sha256())
        .transpose()
        .map_err(|e| error(e.code()))?;
    let prepared = Prepared {
        settings,
        target,
        target_install,
        cache,
        source_generation,
        source_generation_semantic,
        snapshot,
        generation,
        generation_semantic,
    };
    prepared.check_data()?;
    prepared.settings.check_current()?;
    check(shared, source, signal)?;
    owner.begin(SelectionTransaction {
        request_id: job.request.job_id.clone(),
        expected_service_generation: source.generation,
        before_settings_sha256: prepared.settings.before_sha256(),
        after_settings_sha256: prepared.settings.after_sha256(),
        source_semantic_sha256: prepared.snapshot.snapshot_sha256().into(),
        from,
        to,
        was_enabled: false,
        activate_target: false,
        reconnect_acknowledged: false,
        cancel_requested: false,
        phase: SelectionPhase::Prepared,
    })?;
    Ok(prepared)
}
