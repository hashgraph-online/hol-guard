//! Native saved-data inspection and repair. These functions never construct a
//! verified runtime, probe Python, read project files or contact the SDK.
use guard_context_assistance::RuntimeError;
use serde_json::{json, Value};
use std::path::Path;

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
pub(crate) fn failure(error: RuntimeError) -> Value {
    let status = match error {
        RuntimeError::Busy => "busy",
        RuntimeError::PlatformUnqualified => "unsupported",
        RuntimeError::StorageRepairRequired
        | RuntimeError::StorageOutcomeUnknown
        | RuntimeError::ScopeDenied
        | RuntimeError::ContextStale => "repair_required",
        _ => "unavailable",
    };
    json!({"schema":"guard-cigar-saved-evidence.v1","status":status,"slots":null,"active_slots":null,
        "bytes":null,"max_slots":8,"max_bytes":528_u64*1024*1024,"unresolved_writes":null,
        "invalid_records":null,"expired_slots":null,"diagnostic":error.code(),"authority_restored":false,
        "storage":"private_posix_files"})
}
pub(crate) fn describe(
    cache: Option<&guard_context_assistance::EvidenceCache>,
) -> Result<Value, RuntimeError> {
    let health = cache.map(|c| c.health(now_ms())).transpose()?;
    let summary = health
        .as_ref()
        .map(|h| h.summary.clone())
        .unwrap_or_else(guard_context_assistance::EvidenceCache::empty_summary);
    let unresolved = health.as_ref().map_or(0, |h| h.unresolved_writes);
    let invalid = health.as_ref().map_or(0, |h| h.invalid_records);
    let expired = health.as_ref().map_or(0, |h| h.expired_slots);
    let diagnostic = if invalid > 0 {
        Some("context_storage_repair_required")
    } else if unresolved > 0 {
        Some("context_storage_outcome_unknown")
    } else {
        None
    };
    Ok(
        json!({"schema":"guard-cigar-saved-evidence.v1","status":if diagnostic.is_some(){"repair_required"}else if summary.slots==0{"empty"}else{"saved"},
        "slots":summary.slots,"active_slots":summary.active_slots,"bytes":summary.bytes,
        "max_slots":summary.max_slots,"max_bytes":summary.max_bytes,"unresolved_writes":unresolved,
        "invalid_records":invalid,"expired_slots":expired,"diagnostic":diagnostic,"authority_restored":false,"storage":"private_posix_files"}),
    )
}
pub(crate) fn validate_generations(home: &Path) -> Result<(), RuntimeError> {
    crate::policy_store::context_assistance_registry::switching::scope_index::validate_present(
        home,
    )?;
    if let Some(store) = guard_context_assistance::EvidenceGenerationStore::existing(home)? {
        store.list()?;
    }
    Ok(())
}
pub(crate) fn inspect(home: &Path) -> Value {
    let result =
        crate::policy_store::context_assistance_registry::switching::DataRemoval::check_clear(home)
            .and_then(|_| guard_context_assistance::EvidenceCache::existing(home))
            .and_then(|cache| describe(cache.as_ref()))
            .and_then(|value| {
                validate_generations(home)?;
                Ok(value)
            });
    result.unwrap_or_else(failure)
}
#[cfg(all(test, unix))]
pub(crate) fn remove(home: &Path) -> Result<(), RuntimeError> {
    let removal =
        crate::policy_store::context_assistance_registry::switching::DataRemoval::acquire(home)?;
    removal.remove()
}
/// Retention housekeeping never starts the SDK, including while off. Active
/// cache ownership returns busy; its actor maintains that cache independently.
pub(crate) fn sweep(home: &Path, retention_hours: u32) -> Result<(), RuntimeError> {
    // Prepared copies expire even while the original cache has a live
    // actor. This maintenance is independent of optional SDK authority.
    if let Some(store) = guard_context_assistance::EvidenceGenerationStore::existing(home)? {
        store.sweep(retention_hours, now_ms())?;
    }
    if let Some(cache) = guard_context_assistance::EvidenceCache::existing(home)? {
        cache.sweep(retention_hours, now_ms())?;
    }
    Ok(())
}
pub(crate) fn empty_summary(saved: Value, history: bool, removed: bool) -> Value {
    json!({"schema":"guard-cigar-data-summary.v2","storage":"memory","history_storage":"memory","data_role":true,
        "active_scopes":0,"selected_files":0,"current_contexts":0,"history_entries":0,"history_encoded_bytes":0,
        "agent_sessions":0,"max_history_entries_per_scope":8,"max_history_encoded_bytes_per_scope":524288,
        "saved_context":"unavailable","saved_evidence":saved,"cleared_history":history,"cleared_saved":removed})
}
