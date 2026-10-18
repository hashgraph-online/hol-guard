//! `persist_deferred_post_hook_command_activity`
//! (`cli/commands_support_command_activity.py`:208-246), the post-hook half of
//! the evidence writer's command-activity persistence.
//!
//! It is kept beside [`crate::hook_evidence_writer`] rather than inside it:
//! the worker there owns queueing, batching and the journal, while this is one
//! decision about how a post observation may touch a stored pre-hook row.

use serde_json::Value;

use crate::hook_evidence_writer::{
    CommandActivityRecord, EvidenceStoreApi, EvidenceWriterDeps, PersistOutcome,
};

/// `_activity_id()` — `f"activity:{secrets.token_hex(16)}"`.
///
/// `None` when the OS has no randomness to give: the caller retries instead of
/// falling back to a predictable id, because this value is a primary key.
fn unpaired_activity_id() -> Option<String> {
    let mut buffer = [0u8; 16];
    getrandom::fill(&mut buffer).ok()?;
    Some(format!("activity:{}", hex::encode(buffer)))
}

/// `persist_deferred_post_hook_command_activity`
/// (`cli/commands_support_command_activity.py`:208-246).
///
/// A post event carries no verdict of its own. When it pairs with a stored
/// pre-hook row it may only promote that row's proof; when it pairs with
/// nothing it is written as explicitly unpaired, so a post observation can
/// never invent a decision the pre hook did not make.
pub(crate) fn persist_deferred_post_hook_command_activity(
    store: &(dyn EvidenceStoreApi + Send + Sync),
    deps: &EvidenceWriterDeps,
    record: &CommandActivityRecord,
) -> PersistOutcome {
    if let Some(correlation) = record.correlation.as_ref() {
        let previous = match store.command_activity_by_request_correlation(correlation) {
            Ok(previous) => previous,
            Err(_) => return PersistOutcome::Retry,
        };
        if let Some(previous) = previous {
            let status = previous
                .get("execution_status")
                .and_then(Value::as_str)
                .unwrap_or_default();
            // A prevented command never ran, so no post event can describe
            // it; the stored row stands.
            if status == "prevented" {
                return PersistOutcome::Done;
            }
            let expected = if record.succeeded {
                "confirmed_success"
            } else {
                "confirmed_failure"
            };
            if status == expected {
                return PersistOutcome::Done;
            }
            if status != "allowed_unconfirmed" {
                // Two different outcomes claim the same pre-hook decision.
                // Record the conflict rather than overwriting either.
                return match store
                    .record_command_activity_observation_conflict(&deps.journal.now_utc_iso())
                {
                    Ok(()) => PersistOutcome::Done,
                    Err(_) => PersistOutcome::Retry,
                };
            }
            let current = match deps.correlation.build_correlated_post_activity(
                &previous,
                correlation,
                record.succeeded,
            ) {
                Ok(current) => current,
                Err(_) => return PersistOutcome::Retry,
            };
            return match store.transition_command_activity(&current) {
                Ok(_) => PersistOutcome::Done,
                Err(_) => PersistOutcome::Retry,
            };
        }
    }
    if !record.has_command {
        return PersistOutcome::Done;
    }
    let Some(activity_id) = unpaired_activity_id() else {
        // Without randomness the id could repeat and collide with a stored
        // row's primary key; retry rather than write a guessable one.
        return PersistOutcome::Retry;
    };
    let evidence = match deps.correlation.build_unpaired_post_evidence(
        &activity_id,
        &deps.journal.now_utc_iso(),
        &record.harness,
        record.succeeded,
    ) {
        Ok(evidence) => evidence,
        Err(_) => return PersistOutcome::Retry,
    };
    match store.record_command_activity(&evidence, record.invocation_preview.as_deref()) {
        Ok(_) => PersistOutcome::Done,
        Err(_) => PersistOutcome::Retry,
    }
}
