use super::*;
use crate::policy_store::{
    workspace_review_business_queue as discovery, workspace_review_decision as decisions,
    workspace_review_secure_state as claims,
};

fn saved(fixture: &Fixture) -> Vec<u8> {
    let prepared = prepare(input(b"PRIVATE_QUEUE_LIFECYCLE_CANARY", &[])).unwrap();
    persist_prepared_review(&fixture.store, "business-test", &prepared, || true).unwrap();
    canonical_json_bytes(&super::super::super::tests::owned_input_tests::owned_decision(fixture))
        .unwrap()
}

#[test]
fn consumed_request_disappears_without_changing_snapshot_or_reopening_replay() {
    let fixture = Fixture::new("business-queue-consumed");
    let decision = saved(&fixture);
    assert_eq!(
        local_queue(&fixture).unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let path = fixture
        .root
        .join("workspace-review-requests/business-test.json");
    let before = std::fs::read(&path).unwrap();
    decisions::claim_owned_business_request(&fixture.store, "business-test", &decision).unwrap();
    assert_eq!(local_queue(&fixture).unwrap()["items"], json!([]));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(
        super::super::super::super::workspace_review_local_summary::build(
            &fixture.store,
            "business-test"
        )
        .unwrap_err(),
        "native_local_business_summary_unavailable"
    );
    assert!(
        decisions::claim_owned_business_request(&fixture.store, "business-test", &decision)
            .is_err()
    );
    let restarted = crate::policy_store::PolicySnapshotStore::new(
        &fixture.root,
        &fixture.snapshot.runtime_identity,
    )
    .unwrap();
    let request =
        super::super::super::super::workspace_review_request::load(&restarted, "business-test")
            .unwrap();
    assert!(discovery::consumed(&restarted, &request).unwrap());
}

#[test]
fn consumed_before_release_expiry_is_not_pending_even_without_an_attempt_journal() {
    let fixture = Fixture::new("business-queue-consumed-before-expiry");
    let decision = saved(&fixture);
    let value: Value = serde_json::from_slice(&decision).unwrap();
    let now = value["issued_at_ms"].as_u64().unwrap();
    let expired = value["expires_at_ms"].as_u64().unwrap();
    assert!(decisions::claim_owned_business_request_at_for_test(
        &fixture.store,
        "business-test",
        &decision,
        [now, expired]
    )
    .is_err());
    assert!(!fixture
        .root
        .join("workspace-review-business-attempts")
        .exists());
    assert_eq!(local_queue(&fixture).unwrap()["items"], json!([]));
}

#[test]
fn cloud_staged_history_and_unsigned_business_rows_do_not_enter_producer_discovery() {
    let fixture = Fixture::new("business-queue-cloud-history");
    let prepared = prepare(input(b"PRIVATE_NATIVE_BODY", &[])).unwrap();
    persist_prepared_review(&fixture.store, "native-owned", &prepared, || true).unwrap();
    let directory = fixture.root.join("workspace-review-requests");
    for index in 0..4097 {
        std::fs::write(
            directory.join(format!("sql-history-{index}.json")),
            b"not-a-native-request",
        )
        .unwrap();
    }
    let mut staged: Value =
        serde_json::from_slice(&std::fs::read(directory.join("native-owned.json")).unwrap())
            .unwrap();
    staged["request_id"] = json!("sql-business");
    super::super::super::tests::write(&fixture.root, &directory.join("sql-business.json"), &staged);
    let queue = local_queue(&fixture).unwrap();
    assert_eq!(queue["items"].as_array().unwrap().len(), 1);
    assert_eq!(queue["items"][0]["request_id"], "native-owned");
    assert!(!queue.to_string().contains("PRIVATE_NATIVE_BODY"));
}

#[test]
fn changed_selector_binding_and_corrupt_claim_anchor_are_not_an_empty_queue() {
    let fixture = Fixture::new("business-queue-selector-binding");
    let decision = saved(&fixture);
    let marker = fixture
        .root
        .join("workspace-review-business-queue/business-test.json");
    let original: Value = serde_json::from_slice(&std::fs::read(&marker).unwrap()).unwrap();
    let mut changed = original.clone();
    changed["request_snapshot_digest"] = json!("f".repeat(64));
    super::super::super::tests::write(&fixture.root, &marker, &changed);
    assert!(local_queue(&fixture).is_err());
    super::super::super::tests::write(&fixture.root, &marker, &original);
    decisions::claim_owned_business_request(&fixture.store, "business-test", &decision).unwrap();
    let state = claims::load(&fixture.root).unwrap().unwrap();
    let root = state.claim_index.unwrap().root;
    let node = fixture
        .root
        .join("workspace-review-claims")
        .join(&root[..2])
        .join(format!("{root}.json"));
    super::super::super::tests::write(&fixture.root, &node, &json!({}));
    assert!(local_queue(&fixture).is_err());
}

#[test]
fn legacy_inline_consumed_semantics_are_not_pending() {
    let fixture = Fixture::new("business-queue-inline-consumed");
    let decision = saved(&fixture);
    decisions::claim_owned_business_request(&fixture.store, "business-test", &decision).unwrap();
    let mut state = claims::load(&fixture.root).unwrap().unwrap();
    let request =
        super::super::super::super::workspace_review_request::load(&fixture.store, "business-test")
            .unwrap();
    let digest = decisions::owned_request_digest(&request, &state).unwrap();
    let claim = super::super::super::super::workspace_review_claim_index::find_semantic(
        &fixture.root,
        state.claim_index.as_ref().unwrap(),
        &digest,
    )
    .unwrap()
    .unwrap();
    state.claim_index = None;
    state.consumed_claims = vec![claim];
    claims::store(&fixture.root, &state).unwrap();
    assert_eq!(local_queue(&fixture).unwrap()["items"], json!([]));
    assert!(
        decisions::claim_owned_business_request(&fixture.store, "business-test", &decision)
            .is_err()
    );
}
