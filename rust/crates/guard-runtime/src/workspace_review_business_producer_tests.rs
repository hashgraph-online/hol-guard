use super::super::tests::{input, Fixture};
use super::*;
use guard_policy_snapshot::{integrity_mac, policy_digest};

#[test]
fn rollback_between_verification_and_claim_callback_spends_without_callback() {
    let fixture = Fixture::new("business-claim-callback-rollback");
    let prepared = prepare(input(b"private-worker-body", &[])).unwrap();
    persist_prepared_review(&fixture.store, "business-test", &prepared, || true).unwrap();
    let value = super::super::tests::owned_input_tests::owned_decision(&fixture);
    let now = value["issued_at_ms"].as_u64().unwrap();
    let bytes = canonical_json_bytes(&value).unwrap();
    let mut times = [now, now + 1, now, now].into_iter();
    let callbacks = std::cell::Cell::new(0);
    let result =
        super::super::super::workspace_review_decision::claim_owned_business_request_with_clock(
            &fixture.store,
            "business-test",
            &bytes,
            || times.next().ok_or_else(|| "test_clock_exhausted".into()),
            |_, _| {
                callbacks.set(callbacks.get() + 1);
                Ok(())
            },
        );
    assert_eq!(
        result.err().unwrap(),
        "native_workspace_review_clock_rollback"
    );
    assert_eq!(callbacks.get(), 0);
    assert!(
        super::super::super::workspace_review_decision::claim_owned_business_request(
            &fixture.store,
            "business-test",
            &bytes
        )
        .is_err()
    );
}

#[test]
fn expiry_and_clock_rollback_during_journal_persistence_spend_without_release() {
    for rollback in [false, true] {
        let fixture = Fixture::new(if rollback {
            "business-journal-clock-rollback"
        } else {
            "business-journal-expiry"
        });
        let prepared = prepare(input(b"private-worker-body", &[])).unwrap();
        persist_prepared_review(&fixture.store, "business-test", &prepared, || true).unwrap();
        let value = super::super::tests::owned_input_tests::owned_decision(&fixture);
        let now = value["issued_at_ms"].as_u64().unwrap();
        let expires = value["expires_at_ms"].as_u64().unwrap();
        let bytes = canonical_json_bytes(&value).unwrap();
        let mut times = [now, now, now, if rollback { now - 1 } else { expires }].into_iter();
        let result =
            super::super::super::workspace_review_decision::claim_owned_business_request_with_clock(
                &fixture.store,
                "business-test",
                &bytes,
                || times.next().ok_or_else(|| "test_clock_exhausted".into()),
                |owned, _| {
                    journal::Journal::claimed_unlocked(
                        &fixture.store,
                        "business-test",
                        owned.binding(),
                    )
                },
            );
        assert!(result.is_err());
        assert!(fixture
            .root
            .join("workspace-review-business-attempts/business-test.json")
            .exists());
        assert!(
            super::super::super::workspace_review_decision::claim_owned_business_request(
                &fixture.store,
                "business-test",
                &bytes
            )
            .is_err()
        );
    }
}

#[test]
fn producer_shared_claim_path_persists_before_return_and_refuses_replay() {
    let fixture = Fixture::new("business-producer-journal-return");
    let prepared = prepare(input(b"private-frozen-worker-body", &[])).unwrap();
    let binding = prepared.binding().to_owned();
    persist_prepared_review(&fixture.store, "business-test", &prepared, || true).unwrap();
    let decision = canonical_json_bytes(&super::super::tests::owned_input_tests::owned_decision(
        &fixture,
    ))
    .unwrap();
    let claimed = claim_refreshed_review(
        &fixture.store,
        "business-test",
        &decision,
        &binding,
        prepared,
        |_| true,
        PreparedBusinessInputV1::binding,
    )
    .unwrap();
    assert_eq!(claimed.owned.binding(), binding);
    assert_eq!(claimed.input.primary_bytes(), b"private-frozen-worker-body");
    let bytes = std::fs::read(
        fixture
            .root
            .join("workspace-review-business-attempts/business-test.json"),
    )
    .unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["status"], "claimed");
    assert_eq!(value["input_binding"], binding);
    assert!(!String::from_utf8(bytes)
        .unwrap()
        .contains("private-frozen-worker-body"));
    assert!(
        super::super::super::workspace_review_decision::claim_owned_business_request(
            &fixture.store,
            "business-test",
            &decision
        )
        .is_err()
    );
}

#[test]
fn producer_shared_claim_path_persistence_failure_spends_approval_without_release() {
    let fixture = Fixture::new("business-producer-journal-failed");
    let prepared = prepare(input(b"private-frozen-worker-body", &[])).unwrap();
    let binding = prepared.binding().to_owned();
    persist_prepared_review(&fixture.store, "business-test", &prepared, || true).unwrap();
    let decision = canonical_json_bytes(&super::super::tests::owned_input_tests::owned_decision(
        &fixture,
    ))
    .unwrap();
    let directory = fixture.root.join("workspace-review-business-attempts");
    crate::resident_state::ensure_private_directory(&directory, true).unwrap();
    crate::resident_state::ensure_private_directory(&directory.join("business-test.json"), true)
        .unwrap();
    assert!(claim_refreshed_review(
        &fixture.store,
        "business-test",
        &decision,
        &binding,
        prepared,
        |_| true,
        PreparedBusinessInputV1::binding
    )
    .is_err());
    assert!(directory.join("business-test.json").is_dir());
    assert!(
        super::super::super::workspace_review_decision::claim_owned_business_request(
            &fixture.store,
            "business-test",
            &decision
        )
        .is_err()
    );
}

#[test]
fn expiry_after_persistence_removes_new_files_and_preserves_shared_input() {
    let fixture = Fixture::new("business-producer-rollback");
    let prepared = prepare(input(b"shared-private-body", &[])).unwrap();
    let fail_after_writes = || {
        let calls = std::cell::Cell::new(0);
        move || {
            calls.set(calls.get() + 1);
            calls.get() < 3
        }
    };
    assert_eq!(
        persist_prepared_review(
            &fixture.store,
            "business-failed",
            &prepared,
            fail_after_writes()
        )
        .unwrap_err(),
        "native_business_resolution_expired"
    );
    let requests = fixture.root.join("workspace-review-requests");
    let inputs = fixture.root.join(DIRECTORY);
    assert!(!requests.join("business-failed.json").exists());
    assert_eq!(std::fs::read_dir(&inputs).unwrap().count(), 0);
    persist_prepared_review(&fixture.store, "business-kept", &prepared, || true).unwrap();
    let kept = std::fs::read(requests.join("business-kept.json")).unwrap();
    assert_eq!(std::fs::read_dir(&inputs).unwrap().count(), 1);
    assert!(persist_prepared_review(
        &fixture.store,
        "business-other",
        &prepared,
        fail_after_writes()
    )
    .is_err());
    assert!(!requests.join("business-other.json").exists());
    assert_eq!(std::fs::read_dir(&inputs).unwrap().count(), 1);
    assert_eq!(
        std::fs::read(requests.join("business-kept.json")).unwrap(),
        kept
    );
    assert!(
        super::super::super::workspace_review_request::load(&fixture.store, "business-kept")
            .is_ok()
    );
    assert_eq!(
        persist_prepared_review(&fixture.store, "business-kept", &prepared, || true).unwrap_err(),
        "native_business_request_exists"
    );
    assert_eq!(
        std::fs::read(requests.join("business-kept.json")).unwrap(),
        kept
    );
}

#[test]
fn native_producer_materializes_authenticated_frozen_snapshot_without_exporting_body() {
    let fixture = Fixture::new("business-producer-owned");
    let value = input(b"private-source-body", &[]);
    let prepared = prepare(value).unwrap();
    persist_prepared_review(&fixture.store, "business-produced", &prepared, || true).unwrap();
    let loaded =
        super::super::super::workspace_review_request::load(&fixture.store, "business-produced")
            .unwrap();
    assert_eq!(loaded.business_input.unwrap().binding(), prepared.binding());
    let path = fixture
        .root
        .join("workspace-review-requests/business-produced.json");
    let state = std::fs::read(&path).unwrap();
    assert!(!String::from_utf8(state.clone())
        .unwrap()
        .contains("private-source-body"));
    let mut value: Value = serde_json::from_slice(&state).unwrap();
    value["action"]["action_envelope"]["business_context"]["prepared_input_binding"] =
        json!("0".repeat(64));
    super::super::tests::write(&fixture.root, &path, &value);
    assert!(super::super::super::workspace_review_request::load(
        &fixture.store,
        "business-produced"
    )
    .is_err());
}

#[test]
fn produced_snapshot_enters_existing_owned_claim_once_without_legacy_retry() {
    let fixture = Fixture::new("business-producer-single-claim");
    let prepared = prepare(input(b"frozen-provider-body", &[])).unwrap();
    persist_prepared_review(&fixture.store, "business-test", &prepared, || true).unwrap();
    let decision = super::super::tests::owned_input_tests::owned_decision(&fixture);
    let bytes = canonical_json_bytes(&decision).unwrap();
    let (_, claimed) =
        super::super::super::workspace_review_decision::claim_owned_business_request(
            &fixture.store,
            "business-test",
            &bytes,
        )
        .unwrap();
    assert_eq!(claimed.binding(), prepared.binding());
    assert_eq!(claimed.primary_bytes(), b"frozen-provider-body");
    assert!(
        super::super::super::workspace_review_decision::claim_owned_business_request(
            &fixture.store,
            "business-test",
            &bytes
        )
        .is_err()
    );
}

#[test]
fn stale_provider_evidence_and_default_off_policy_cannot_publish_a_review() {
    let fixture = Fixture::new("business-producer-stale");
    let prepared = prepare(input(b"body", &[])).unwrap();
    assert_eq!(
        persist_prepared_review(&fixture.store, "business-expired", &prepared, || false)
            .unwrap_err(),
        "native_business_resolution_expired"
    );
    assert!(!fixture
        .root
        .join("workspace-review-requests/business-expired.json")
        .exists());
    // An armed business source cannot be silently removed by a signed push.
    let mut snapshot = fixture.snapshot.clone();
    snapshot.generation += 1;
    snapshot.business_policy = None;
    snapshot.policy_digest = policy_digest(&snapshot).unwrap();
    snapshot.integrity.mac = integrity_mac(&snapshot, &fixture.key).unwrap();
    assert_eq!(
        fixture
            .store
            .push(&json!({"schema":"guard-policy-snapshot-push.v1","snapshot":snapshot}))
            .unwrap_err(),
        "native_business_policy_removal_requires_authority"
    );
    let default_off = Fixture::without_business_policy("business-producer-default-off");
    assert!(persist_prepared_review(
        &default_off.store,
        "business-default-off",
        &prepared,
        || true
    )
    .is_err());
    assert!(!default_off
        .root
        .join("workspace-review-requests/business-default-off.json")
        .exists());
}

#[test]
fn signed_business_block_floor_cannot_publish_a_review() {
    let fixture = Fixture::with_effect("business-producer-unresolved", "block");
    let prepared = prepare(input(b"body", &[])).unwrap();
    assert_eq!(
        persist_prepared_review(&fixture.store, "business-unresolved", &prepared, || true)
            .unwrap_err(),
        "native_workspace_review_business_blocked"
    );
    assert!(!fixture
        .root
        .join("workspace-review-requests/business-unresolved.json")
        .exists());
}
