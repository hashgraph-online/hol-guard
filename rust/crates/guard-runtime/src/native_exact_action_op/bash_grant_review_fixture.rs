//! Explicit review setup for low-level owner unit tests, not production code.
//! End-to-end inbox/resolution tests use the normal source APIs separately.

use super::*;
use crate::policy_store::policy_store_approval::bash_journal::BashOperationJournal;
use rusqlite::OptionalExtension;

pub(super) fn seed_once_review(
    request: &NativeBashCaptureV1,
    store: &PolicySnapshotStore,
    claim: &ClaimApprovalReuseDecisionsRequestV1,
    operation_id: &str,
) {
    if store.require_guard_home(&claim.guard_home).is_err()
        || store.require_store_path(&claim.store_path).is_err()
    {
        return;
    }
    let Some(decision) = claim.decisions.first() else {
        return;
    };
    if decision
        .get("approval_id")
        .and_then(Value::as_str)
        .is_none()
    {
        return;
    }
    let (Some(request_id), Some(hash)) = (
        decision.get("request_id").and_then(Value::as_str),
        decision.get("artifact_hash").and_then(Value::as_str),
    ) else {
        return;
    };
    let Ok(connection) = Connection::open(&claim.store_path) else {
        return;
    };
    let envelope: Option<String> = connection
        .query_row(
            "SELECT action_envelope_json FROM approval_requests WHERE request_id=?1",
            [request_id],
            |row| row.get(0),
        )
        .optional()
        .unwrap_or(None);
    let Some(envelope) = envelope else {
        return;
    };
    let envelope: Value = serde_json::from_str(&envelope).unwrap();
    // A reviewed once grant never moves to a different operation. Replays
    // and cancellation retries must use the existing operation's identity.
    if envelope.pointer("/native_bash/review_lineage").is_some() {
        return;
    }
    let Ok(journal) = BashOperationJournal::open(store, &claim.store_path, operation_id, hash)
    else {
        return;
    };
    let lineage = journal
        .pending_review(&request.harness, &request.workspace)
        .unwrap();
    connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    let current: String = connection
        .query_row(
            "SELECT action_envelope_json FROM approval_requests WHERE request_id=?1",
            [request_id],
            |row| row.get(0),
        )
        .unwrap();
    let mut current: Value = serde_json::from_str(&current).unwrap();
    if current.pointer("/native_bash/review_lineage").is_none() {
        current["native_bash"]["review_lineage"] = serde_json::to_value(lineage).unwrap();
        connection
            .execute(
                "UPDATE approval_requests SET action_envelope_json=?1 WHERE request_id=?2",
                params![current.to_string(), request_id],
            )
            .unwrap();
    }
    connection.execute_batch("COMMIT").unwrap();
}

pub(super) fn run_operation(
    request: &NativeBashCaptureV1,
    store: &PolicySnapshotStore,
    envelope: &GuardHookEnvelopeV2,
    claim: &ClaimApprovalReuseDecisionsRequestV1,
    operation_id: &str,
) -> std::io::Result<guard_contained_process::CapturedOutput> {
    seed_once_review(request, store, claim, operation_id);
    bash_grant::execute_saved(
        request,
        envelope,
        store,
        claim,
        operation_id,
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(false),
    )
    .and_then(|result| {
        result
            .output
            .ok_or(std::io::ErrorKind::AlreadyExists.into())
    })
    .map_err(|failure| failure.error)
}
