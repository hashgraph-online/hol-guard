use super::super::super::tests::{input, Fixture};
use super::*;
use guard_policy_snapshot::business_source_anchor::{
    sign_business_source_anchor, BusinessSourcePhase,
};
use guard_policy_snapshot::business_source_authority::{
    sign_business_source, verify_business_source,
};
use guard_policy_snapshot::{integrity_mac, policy_digest};
use serde_json::{json, Value};

fn declaration(scope: &str) -> Value {
    json!({"schema":"guard.business-budget.v1","version":1,"id":format!("mail.{scope}"),"scope":scope,
    "windowMs":86400000,"maximumActions":2,"maximumRecipients":100,"maximumRecords":100,"maximumBytes":100000,
    "match":{"schema":"guard.business-policy-match.v1","version":1,"services":["google_gmail"],"operations":["mail_send"]}})
}
fn install(fixture: &Fixture, budgets: Value) {
    let mut snapshot = fixture.store.current_snapshot().unwrap();
    snapshot.generation += 1;
    let mut document = fixture.source_document.as_ref().unwrap().clone();
    document["metadata"]["revision"] = json!(snapshot.generation);
    document["spec"]["budgets"] = budgets;
    let record = sign_business_source(&document, snapshot.generation, &fixture.key).unwrap();
    let source = verify_business_source(&record, &fixture.key).unwrap();
    snapshot.business_policy = Some(source.compiled().binding().clone());
    let marker =
        sign_business_source_anchor(&source, BusinessSourcePhase::Committed, &fixture.key).unwrap();
    super::super::super::tests::write(
        &fixture.root,
        &fixture.root.join("business-source-anchor.v1.json"),
        &serde_json::from_slice(&marker).unwrap(),
    );
    snapshot.policy_digest = policy_digest(&snapshot).unwrap();
    snapshot.integrity.mac = integrity_mac(&snapshot, &fixture.key).unwrap();
    fixture
        .store
        .push(&json!({"schema":"guard-policy-snapshot-push.v1","snapshot":snapshot}))
        .unwrap();
}
fn prepared() -> PreparedBusinessInputV1 {
    super::super::super::prepare(input(b"private-input-body", &[])).unwrap()
}
fn actor() -> ActorBindings {
    ActorBindings {
        user: Some("c".repeat(64)),
        workflow: Some("d".repeat(64)),
    }
}
fn time(fixture: &Fixture) -> u64 {
    fixture.store.current_snapshot().unwrap().issued_at_ms + 1
}

#[test]
fn chunking_restarts_replay_and_uncertain_outcomes_keep_usage() {
    let fixture = Fixture::new("business-budget-durable");
    install(&fixture, json!([declaration("account")]));
    let now = time(&fixture);
    let input = prepared();
    let first = reserve_at(&fixture.store, "budget-first", &input, &actor(), now).unwrap();
    assert_eq!(first.input_binding, input.binding());
    assert_eq!(first.request_id, "budget-first");
    assert!(
        super::super::super::super::workspace_review_claim_index::valid_digest(&first.ledger_root)
    );
    // Dropping the only owned token, including after an unknown provider
    // outcome, never refunds. Every call reloads the protected durable root.
    drop(first);
    reserve_at(&fixture.store, "budget-second", &input, &actor(), now + 1).unwrap();
    assert_eq!(
        reserve_at(&fixture.store, "budget-third", &input, &actor(), now + 2)
            .err()
            .unwrap(),
        "native_business_budget_exceeded"
    );
    assert_eq!(
        reserve_at(&fixture.store, "budget-first", &input, &actor(), now + 2)
            .err()
            .unwrap(),
        "native_business_budget_reservation_replay"
    );
    assert_eq!(load(fixture.store.state_base()).unwrap().0.events.len(), 2);
}

#[test]
fn snapshot_mac_cannot_replace_the_reviewed_budget_source() {
    let fixture = Fixture::new("business-budget-source-binding");
    let mut budget = declaration("account");
    budget["maximumActions"] = json!(1);
    install(&fixture, json!([budget]));
    let mut snapshot = fixture.store.current_snapshot().unwrap();
    let generation = snapshot.generation;
    snapshot.generation += 1;
    snapshot
        .business_policy
        .as_mut()
        .unwrap()
        .budgets
        .as_mut()
        .unwrap()[0]
        .maximum_actions = 10;
    snapshot.policy_digest = policy_digest(&snapshot).unwrap();
    snapshot.integrity.mac = integrity_mac(&snapshot, &fixture.key).unwrap();
    assert_eq!(
        fixture
            .store
            .push(&json!({"schema":"guard-policy-snapshot-push.v1","snapshot":snapshot}))
            .unwrap_err(),
        "native_business_source_authority_not_current"
    );
    assert_eq!(
        fixture.store.current_snapshot().unwrap().generation,
        generation
    );
    let now = time(&fixture);
    reserve_at(
        &fixture.store,
        "budget-source-first",
        &prepared(),
        &actor(),
        now,
    )
    .unwrap();
    assert_eq!(
        reserve_at(
            &fixture.store,
            "budget-source-second",
            &prepared(),
            &actor(),
            now + 1
        )
        .err()
        .unwrap(),
        "native_business_budget_exceeded"
    );
}

#[test]
fn all_matching_scopes_commit_together_and_missing_actors_refuse() {
    let fixture = Fixture::new("business-budget-all-scopes");
    let mut user = declaration("user");
    user["maximumActions"] = json!(1);
    install(
        &fixture,
        json!([declaration("account"), user, declaration("workflow")]),
    );
    let now = time(&fixture);
    let input = prepared();
    let missing = ActorBindings {
        user: None,
        workflow: Some("d".repeat(64)),
    };
    assert!(reserve_at(&fixture.store, "budget-missing", &input, &missing, now).is_err());
    assert!(!fixture.root.join(DIRECTORY).exists());
    reserve_at(&fixture.store, "budget-all", &input, &actor(), now).unwrap();
    let (ledger, _) = load(&fixture.root).unwrap();
    assert_eq!(ledger.events[0].buckets.len(), 3);
    assert!(reserve_at(&fixture.store, "budget-denied", &input, &actor(), now + 1).is_err());
    assert_eq!(load(&fixture.root).unwrap().0.events.len(), 1);
}

#[test]
fn concurrent_sessions_cannot_exceed_one_shared_allowance() {
    let fixture = Fixture::new("business-budget-concurrency");
    let mut budget = declaration("account");
    budget["maximumActions"] = json!(1);
    install(&fixture, json!([budget]));
    let now = time(&fixture);
    let barrier = std::sync::Barrier::new(2);
    let wins = std::thread::scope(|scope| {
        let run = |id: &str| {
            barrier.wait();
            reserve_at(&fixture.store, id, &prepared(), &actor(), now).is_ok()
        };
        let left = scope.spawn(move || run("budget-left"));
        let right = scope.spawn(move || run("budget-right"));
        usize::from(left.join().unwrap()) + usize::from(right.join().unwrap())
    });
    assert_eq!(wins, 1);
    assert_eq!(load(&fixture.root).unwrap().0.events.len(), 1);
}

#[test]
fn window_boundary_and_policy_changes_preserve_history() {
    let fixture = Fixture::new("business-budget-policy-change");
    let mut budget = declaration("account");
    budget["maximumActions"] = json!(1);
    budget["windowMs"] = json!(2);
    install(&fixture, json!([budget]));
    let now = time(&fixture);
    let input = prepared();
    reserve_at(&fixture.store, "budget-original", &input, &actor(), now).unwrap();
    assert!(reserve_at(&fixture.store, "budget-too-soon", &input, &actor(), now + 1).is_err());
    reserve_at(&fixture.store, "budget-boundary", &input, &actor(), now + 2).unwrap();
    // Expired usage leaves the window but replay tombstones remain retained.
    assert!(reserve_at(&fixture.store, "budget-original", &input, &actor(), now + 3).is_err());
    let mut changed = declaration("account");
    changed["maximumActions"] = json!(1);
    install(&fixture, json!([changed]));
    assert!(reserve_at(
        &fixture.store,
        "budget-policy-reset",
        &input,
        &actor(),
        now + 3
    )
    .is_err());
    assert_eq!(load(&fixture.root).unwrap().0.events.len(), 2);
}

#[test]
fn changed_missing_rolled_back_ledgers_and_clock_rollback_refuse() {
    let fixture = Fixture::new("business-budget-rollback");
    install(&fixture, json!([declaration("account")]));
    let now = time(&fixture);
    let input = prepared();
    let first = reserve_at(&fixture.store, "budget-first", &input, &actor(), now).unwrap();
    let (old_path, _) = path(&fixture.root, &first.ledger_root, false).unwrap();
    let old = std::fs::read(old_path).unwrap();
    reserve_at(&fixture.store, "budget-second", &input, &actor(), now + 1).unwrap();
    assert_eq!(
        reserve_at(&fixture.store, "budget-clock", &input, &actor(), now)
            .err()
            .unwrap(),
        "native_business_budget_clock_rollback"
    );
    let current = anchor::load(&fixture.root).unwrap().unwrap();
    let (path, root) = path(&fixture.root, &current.root, false).unwrap();
    super::super::super::super::policy_store_persistence::persist_private_bytes(
        &path,
        &old,
        MAX_BYTES,
        "business_budget",
        &root,
    )
    .unwrap();
    assert!(reserve_at(&fixture.store, "budget-reset", &input, &actor(), now + 2).is_err());
    std::fs::remove_file(&path).unwrap();
    assert!(reserve_at(&fixture.store, "budget-missing", &input, &actor(), now + 2).is_err());
    std::fs::remove_file(fixture.root.join("business-budget-anchor.test.json")).unwrap();
    assert_eq!(
        reserve_at(
            &fixture.store,
            "budget-anchor-missing",
            &input,
            &actor(),
            now + 2
        )
        .err()
        .unwrap(),
        "native_business_budget_anchor_missing"
    );
}

#[test]
fn each_volume_limit_and_zero_allowance_refuse_before_persistence() {
    for field in [
        "maximumActions",
        "maximumRecipients",
        "maximumRecords",
        "maximumBytes",
    ] {
        let fixture = Fixture::new(field);
        let mut budget = declaration("account");
        budget[field] = json!(0);
        install(&fixture, json!([budget]));
        assert!(reserve_at(
            &fixture.store,
            "budget-zero",
            &prepared(),
            &actor(),
            time(&fixture)
        )
        .is_err());
        assert!(!fixture.root.join(DIRECTORY).exists());
    }
}

#[test]
fn expired_volume_compacts_but_permanent_replay_tombstones_remain() {
    let fixture = Fixture::new("business-budget-compaction");
    install(&fixture, json!([declaration("account")]));
    let now = time(&fixture);
    let input = prepared();
    reserve_at(&fixture.store, "budget-old", &input, &actor(), now).unwrap();
    let mut snapshot = fixture.store.current_snapshot().unwrap();
    snapshot.generation += 1;
    snapshot.issued_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    snapshot.expires_at_ms = snapshot.issued_at_ms
        + guard_policy_snapshot::business_budget::BUSINESS_BUDGET_MAX_WINDOW_MS;
    snapshot.policy_digest = policy_digest(&snapshot).unwrap();
    snapshot.integrity.mac = integrity_mac(&snapshot, &fixture.key).unwrap();
    fixture
        .store
        .push(&json!({"schema":"guard-policy-snapshot-push.v1","snapshot":snapshot}))
        .unwrap();
    let later = now + guard_policy_snapshot::business_budget::BUSINESS_BUDGET_MAX_WINDOW_MS;
    reserve_at(
        &fixture.store,
        "budget-after-window",
        &input,
        &actor(),
        later,
    )
    .unwrap();
    let (ledger, anchor) = load(&fixture.root).unwrap();
    assert_eq!(ledger.events.len(), 1);
    assert_eq!(anchor.unwrap().replay_index.claim_count, 2);
    assert_eq!(
        reserve_at(&fixture.store, "budget-old", &input, &actor(), later)
            .err()
            .unwrap(),
        "native_business_budget_reservation_replay"
    );
}

#[test]
fn failed_first_commit_recovers_from_authenticated_empty_anchor() {
    let fixture = Fixture::new("business-budget-index-failure");
    install(&fixture, json!([declaration("account")]));
    super::super::super::super::policy_store_persistence::persist_private_bytes(
        &fixture.root.join("workspace-review-claims"),
        b"{}",
        2048,
        "budget_test",
        &fixture.root,
    )
    .unwrap();
    assert!(reserve_at(
        &fixture.store,
        "budget-failed",
        &prepared(),
        &actor(),
        time(&fixture)
    )
    .is_err());
    assert_eq!(
        anchor::load(&fixture.root)
            .unwrap()
            .unwrap()
            .replay_index
            .claim_count,
        0
    );
    assert!(fixture.root.join(DIRECTORY).exists());
    assert!(load(&fixture.root).unwrap().0.events.is_empty());
    std::fs::remove_file(fixture.root.join("workspace-review-claims")).unwrap();
    reserve_at(
        &fixture.store,
        "budget-failed",
        &prepared(),
        &actor(),
        time(&fixture),
    )
    .unwrap();
    assert_eq!(load(&fixture.root).unwrap().0.events.len(), 1);
    std::fs::remove_file(fixture.root.join("business-budget-anchor.test.json")).unwrap();
    assert_eq!(
        reserve_at(
            &fixture.store,
            "budget-reinitialize",
            &prepared(),
            &actor(),
            time(&fixture)
        )
        .err()
        .unwrap(),
        "native_business_budget_anchor_missing"
    );
}

#[test]
fn declared_allowance_above_128_has_no_event_count_cap() {
    let fixture = Fixture::new("business-budget-large-allowance");
    let mut budget = declaration("account");
    for field in [
        "maximumActions",
        "maximumRecipients",
        "maximumRecords",
        "maximumBytes",
    ] {
        budget[field] = json!(1000000);
    }
    install(&fixture, json!([budget]));
    // This capacity test performs 129 durable writes. Parallel debug builds
    // can outlive the shared 60-second fixture; expiry is tested separately.
    let mut snapshot = fixture.store.current_snapshot().unwrap();
    snapshot.generation += 1;
    snapshot.expires_at_ms = snapshot.issued_at_ms + 600_000;
    snapshot.policy_digest = policy_digest(&snapshot).unwrap();
    snapshot.integrity.mac = integrity_mac(&snapshot, &fixture.key).unwrap();
    fixture
        .store
        .push(&json!({"schema":"guard-policy-snapshot-push.v1","snapshot":snapshot}))
        .unwrap();
    let now = time(&fixture);
    let input = prepared();
    for index in 0..129 {
        reserve_at(
            &fixture.store,
            &format!("budget-many-{index}"),
            &input,
            &actor(),
            now,
        )
        .unwrap();
    }
    assert_eq!(load(&fixture.root).unwrap().0.events.len(), 129);
}

#[test]
fn superseded_ledger_cleanup_preserves_current_usage_and_replay() {
    let fixture = Fixture::new("business-budget-cleanup");
    install(&fixture, json!([declaration("account")]));
    let now = time(&fixture);
    let input = prepared();
    let first = reserve_at(&fixture.store, "budget-first", &input, &actor(), now).unwrap();
    let (old, _) = path(&fixture.root, &first.ledger_root, false).unwrap();
    let second = reserve_at(&fixture.store, "budget-second", &input, &actor(), now).unwrap();
    assert!(!old.exists());
    assert!(path(&fixture.root, &second.ledger_root, false)
        .unwrap()
        .0
        .exists());
    assert_eq!(load(&fixture.root).unwrap().0.events.len(), 2);
    assert_eq!(
        reserve_at(&fixture.store, "budget-third", &input, &actor(), now)
            .err()
            .unwrap(),
        "native_business_budget_exceeded"
    );
    assert_eq!(
        reserve_at(&fixture.store, "budget-first", &input, &actor(), now)
            .err()
            .unwrap(),
        "native_business_budget_reservation_replay"
    );
}

#[test]
fn every_volume_metric_counts_split_actions_without_an_action_limit_masking_it() {
    let input = prepared();
    for (field, amount) in [
        ("maximumRecipients", input.facts().volume.recipient_count),
        ("maximumRecords", input.facts().volume.record_count),
        ("maximumBytes", input.facts().volume.byte_count),
    ] {
        let fixture = Fixture::new(field);
        let mut budget = declaration("account");
        budget["maximumActions"] = json!(100);
        budget[field] = json!(amount * 2);
        install(&fixture, json!([budget]));
        let now = time(&fixture);
        reserve_at(&fixture.store, "budget-chunk-one", &input, &actor(), now).unwrap();
        reserve_at(
            &fixture.store,
            "budget-chunk-two",
            &input,
            &actor(),
            now + 1,
        )
        .unwrap();
        assert_eq!(
            reserve_at(
                &fixture.store,
                "budget-chunk-three",
                &input,
                &actor(),
                now + 2
            )
            .err()
            .unwrap(),
            "native_business_budget_exceeded"
        );
        assert_eq!(load(&fixture.root).unwrap().0.events.len(), 2);
    }
}
