//! Native consent and precommit cleanup; neither method restores a process.
use super::*;

impl Owner {
    pub(crate) fn acknowledge_reconnect(&mut self, id: &str) -> Result<(), String> {
        let mut next = self
            .record
            .as_ref()
            .ok_or_else(|| error("switch_selection_missing"))?
            .clone();
        let t = next
            .transaction
            .as_mut()
            .ok_or_else(|| error("switch_transaction_missing"))?;
        if t.request_id != id || t.phase != SelectionPhase::Prepared || t.cancel_requested {
            return Err(error("switch_selection_conflict"));
        }
        t.reconnect_acknowledged = true;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or_else(|| error("switch_generation_exhausted"))?;
        let lock = WriteLock::acquire(&self.home).map_err(storage_error)?;
        self.publish_locked(&lock, next)
    }
    /// Inspect an uncertain metadata write before any subsequent action.
    /// The profile lease excludes other legitimate selection publishers.
    pub(crate) fn reload(&mut self) -> Result<(), String> {
        let lock = WriteLock::acquire(&self.home).map_err(storage_error)?;
        if lock.root_identity().map_err(storage_error)? != self.root_identity {
            return Err(error("switch_home_changed"));
        }
        let key = key_bytes(&lock)?;
        if self.key.is_some() && self.key.as_deref() != key.as_deref() {
            return Err(error("switch_key_changed"));
        }
        let raw = lock
            .lifecycle_bytes(LifecycleFile::Record)
            .map_err(storage_error)?;
        let record = raw
            .as_ref()
            .map(|bytes| {
                decode(
                    &self.home,
                    bytes,
                    key.as_deref().ok_or_else(|| error("switch_key_missing"))?,
                )
            })
            .transpose()?;
        let initial = initial::State::load(&self.home, &lock, key.as_deref())?;
        self.key = key;
        self.raw = raw;
        self.record = record;
        self.initial = initial;
        Ok(())
    }
    pub(crate) fn cancel_precommit(&mut self, id: &str) -> Result<(), String> {
        self.reload()?;
        let Some(record) = self.record.as_ref() else {
            return Ok(());
        };
        let Some(t) = &record.transaction else {
            return Ok(());
        };
        if t.request_id != id {
            return Err(error("switch_selection_conflict"));
        }
        if t.phase == SelectionPhase::Cancelled {
            return Ok(());
        }
        if !matches!(
            t.phase,
            SelectionPhase::Prepared | SelectionPhase::StopIntent
        ) {
            return Err(error("switch_recovery_required"));
        }
        let current = crate::guard_config_load::context_assistance_config(&self.home)
            .map_err(|_| error("configuration_unavailable"))?;
        if current.requested.runtime_id != t.from.runtime.installation_id {
            return Err(error("switch_recovery_required"));
        }
        self.advance(SelectionPhase::Cancelled)
    }
    pub(crate) fn discard_job_data(&self, id: &str) -> Result<usize, String> {
        let Some(selection) = self.record() else {
            return Ok(0);
        };
        let Some(store) = guard_context_assistance::EvidenceGenerationStore::existing(&self.home)
            .map_err(|e| error(e.code()))?
        else {
            return Ok(0);
        };
        let mut removed = 0;
        for generation in store.list().map_err(|e| error(e.code()))? {
            if generation["request_id"] != id {
                continue;
            }
            let data = generation["generation_id"]
                .as_str()
                .ok_or_else(|| error("switch_data_invalid"))?;
            store
                .discard_unselected(data, id, selection)
                .map_err(|e| error(e.code()))?;
            removed += 1;
        }
        Ok(removed)
    }
}
