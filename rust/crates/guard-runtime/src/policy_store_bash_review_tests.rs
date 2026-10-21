use super::*;
use crate::policy_store::{PolicySnapshotStore, VERIFIER_KEY_FILE_NAME};
use guard_policy_snapshot::local_authority_integrity::sign_local_authority_payload;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;

const OPERATION: &str = "review-operation-0001";
const HASH: &str = "guard-approval-context:v1:fixture";

fn store() -> (tempfile::TempDir, PolicySnapshotStore, String) {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = root.path().join(VERIFIER_KEY_FILE_NAME);
    std::fs::write(&key, [37u8; 32]).unwrap();
    std::fs::set_permissions(key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let store = PolicySnapshotStore::new(root.path(), &"a".repeat(64)).unwrap();
    let path = root.path().join("guard.db").to_str().unwrap().to_owned();
    Connection::open(&path).unwrap();
    (root, store, path)
}

fn queue(journal: &BashOperationJournal<'_>, lineage: &NativeBashReviewLineageV1, action: &str) {
    journal.connection.execute_batch(
        "CREATE TABLE approval_requests(request_id TEXT, status TEXT, resolution_action TEXT,
         action_envelope_json TEXT, harness TEXT, artifact_id TEXT, artifact_hash TEXT, workspace TEXT)"
    ).unwrap();
    journal.connection.execute(
        "INSERT INTO approval_requests VALUES('request-1','resolved',?1,?2,'omp',?3,?4,'/project')",
        params![action, json!({"native_bash":{"artifact_hash":HASH,"review_lineage":lineage}}).to_string(),
            guard_contracts::NATIVE_BASH_ARTIFACT_ID, HASH],
    ).unwrap();
}

fn reseal(journal: &BashOperationJournal<'_>, payload: Value, purpose: &str) {
    // Test-only known key; never reads an operator's key or credential store.
    let key = [37u8; 32];
    let signed = sign_local_authority_payload(
        &payload,
        &key,
        &guard_policy_snapshot::verifier_key_id(&key),
        purpose,
        "2026-10-18T00:00:00Z",
    )
    .unwrap();
    let integrity = json!({"integrity_version":signed.integrity_version,"payload_hash":signed.payload_hash,
        "payload_mac":signed.payload_mac,"integrity_key_id":signed.integrity_key_id,"signed_at":signed.signed_at});
    journal
        .connection
        .execute(
            "UPDATE guard_bash_reviews SET payload=?1,integrity=?2",
            params![payload.to_string(), integrity.to_string()],
        )
        .unwrap();
}

#[test]
fn pending_lineage_survives_restart_and_never_reserves_execution() {
    let (root, store, path) = store();
    let journal = BashOperationJournal::open(&store, &path, OPERATION, HASH).unwrap();
    let first = journal.pending_review("omp", "/project").unwrap();
    assert_eq!(first.expires_at_ms - first.created_at_ms, LIFETIME_MS);
    assert_eq!(first.lineage_id.len(), 64);
    assert!(journal.read().unwrap().is_none());
    drop(journal);
    drop(store);
    let store = PolicySnapshotStore::new(root.path(), &"a".repeat(64)).unwrap();
    let journal = BashOperationJournal::open(&store, &path, OPERATION, HASH).unwrap();
    assert_eq!(journal.pending_review("omp", "/project").unwrap(), first);
    let other =
        BashOperationJournal::open(&store, &path, "review-new-operation-0002", HASH).unwrap();
    assert_ne!(
        other.pending_review("omp", "/project").unwrap().lineage_id,
        first.lineage_id
    );
}

#[test]
fn context_changes_and_unsigned_edits_cannot_rebind_pending_lineage() {
    let (_root, store, path) = store();
    let journal = BashOperationJournal::open(&store, &path, OPERATION, HASH).unwrap();
    journal.pending_review("omp", "/project").unwrap();
    assert!(journal.pending_review("pi", "/project").is_err());
    assert!(journal.pending_review("omp", "/other-project").is_err());
    let changed = BashOperationJournal::open(&store, &path, OPERATION, "changed-context").unwrap();
    assert!(changed.pending_review("omp", "/project").is_err());
    journal
        .connection
        .execute(
            "UPDATE guard_bash_reviews SET payload=json_set(payload,'$.blocked',1)",
            [],
        )
        .unwrap();
    assert!(journal.review_kept_blocked().is_err());
    assert!(journal.pending_review("omp", "/project").is_err());
}

#[test]
fn valid_mac_from_another_purpose_cannot_authenticate_a_review() {
    let (_root, store, path) = store();
    let journal = BashOperationJournal::open(&store, &path, OPERATION, HASH).unwrap();
    journal.pending_review("omp", "/project").unwrap();
    let record = journal.read_review().unwrap().unwrap();
    reseal(
        &journal,
        serde_json::to_value(record).unwrap(),
        "guard-native-bash-operation-v1",
    );
    assert!(journal.pending_review("omp", "/project").is_err());
}

#[test]
fn expired_or_future_lineage_cannot_be_refreshed_into_a_new_review() {
    for future in [false, true] {
        let (_root, store, path) = store();
        let journal = BashOperationJournal::open(&store, &path, OPERATION, HASH).unwrap();
        journal.pending_review("omp", "/project").unwrap();
        let mut record = journal.read_review().unwrap().unwrap();
        let now = crate::policy_store::now_ms().unwrap();
        record.lineage.created_at_ms = if future {
            now + 60_000
        } else {
            now - LIFETIME_MS - 60_000
        };
        record.lineage.expires_at_ms = record.lineage.created_at_ms + LIFETIME_MS;
        reseal(&journal, serde_json::to_value(record).unwrap(), PURPOSE);
        assert!(journal.pending_review("omp", "/project").is_err());
        assert!(journal.review_kept_blocked().is_err());
    }
}

#[test]
fn native_block_evidence_survives_request_deletion_and_resident_restart() {
    let (root, store, path) = store();
    let journal = BashOperationJournal::open(&store, &path, OPERATION, HASH).unwrap();
    let lineage = journal.pending_review("omp", "/project").unwrap();
    queue(&journal, &lineage, "block");
    assert!(journal.review_kept_blocked().unwrap());
    journal
        .connection
        .execute("DELETE FROM approval_requests", [])
        .unwrap();
    assert!(journal.review_kept_blocked().unwrap());
    assert!(journal.pending_review("omp", "/project").is_err());
    assert!(journal.read().unwrap().is_none());
    drop(journal);
    drop(store);
    let store = PolicySnapshotStore::new(root.path(), &"a".repeat(64)).unwrap();
    let journal = BashOperationJournal::open(&store, &path, OPERATION, HASH).unwrap();
    assert!(journal.review_kept_blocked().unwrap());
}

#[test]
fn final_once_claim_must_belong_to_the_linked_review_request() {
    let (_root, store, path) = store();
    let journal = BashOperationJournal::open(&store, &path, OPERATION, HASH).unwrap();
    let lineage = journal.pending_review("omp", "/project").unwrap();
    queue(&journal, &lineage, "allow");
    let mut claim: ClaimApprovalReuseDecisionsRequestV1 = serde_json::from_value(json!({
        "schema":guard_contracts::CLAIM_APPROVAL_REUSE_REQUEST_SCHEMA,"request_id":"claim-test",
        "guard_home":store.expected_guard_home,"store_path":path,
        "now":"2026-10-18T00:00:00Z","consume_local_once":true,
        "decisions":[{"approval_id":"once-1","request_id":"another-request"}],
    }))
    .unwrap();
    journal.connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(journal.require_review_authority(Some(&claim)).is_err());
    journal.connection.execute_batch("ROLLBACK").unwrap();
    claim.decisions[0]["request_id"] = json!("request-1");
    journal.connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    journal.require_review_authority(Some(&claim)).unwrap();
    journal.connection.execute_batch("COMMIT").unwrap();
    let other = BashOperationJournal::open(&store, &path, "another-operation-0001", HASH).unwrap();
    other.connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(other.require_review_authority(Some(&claim)).is_err());
    other.connection.execute_batch("ROLLBACK").unwrap();
    journal
        .connection
        .execute("UPDATE approval_requests SET resolution_action='block'", [])
        .unwrap();
    journal.connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(journal.require_review_authority(Some(&claim)).is_err());
    journal.connection.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn absent_native_lineage_never_admits_a_once_claim() {
    let (_root, store, path) = store();
    let journal = BashOperationJournal::open(&store, &path, OPERATION, HASH).unwrap();
    let claim: ClaimApprovalReuseDecisionsRequestV1 = serde_json::from_value(json!({
        "schema":guard_contracts::CLAIM_APPROVAL_REUSE_REQUEST_SCHEMA,"request_id":"claim-test",
        "guard_home":store.expected_guard_home,"store_path":path,
        "now":"2026-10-18T00:00:00Z","consume_local_once":true,
        "decisions":[{"approval_id":"legacy-once","request_id":"missing-request"}],
    }))
    .unwrap();
    // There is deliberately no approval_requests table, native request row,
    // native pending record, or caller capability that could supply lineage.
    journal.connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(journal.require_review_authority(Some(&claim)).is_err());
    journal.connection.execute_batch("ROLLBACK").unwrap();
    assert!(journal.read().unwrap().is_none());
}
