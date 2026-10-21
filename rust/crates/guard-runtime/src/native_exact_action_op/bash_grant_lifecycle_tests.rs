use super::*;

#[test]
fn bash_two_concurrent_retries_cannot_launch_with_the_same_once_grant() {
    let (_root, request) = tests::fixture();
    std::fs::write(
        Path::new(&request.cwd).join("maintenance.sh"),
        "printf reviewed\n",
    )
    .unwrap();
    let (store, envelope) = policy_store(&request);
    let claim = once(&request, &store, "2050-01-01T00:00:00+00:00");
    let store = Arc::new(store);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let workers = (0..2)
        .map(|_| {
            let request = request.clone();
            let envelope = envelope.clone();
            let claim = claim.clone();
            let store = store.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                run(&request, &store, &envelope, &claim)
            })
        })
        .collect::<Vec<_>>();
    let answers = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(answers.iter().filter(|answer| answer.is_ok()).count(), 1);
    let result = answers.into_iter().find_map(|answer| answer.ok()).unwrap();
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.stdout, b"reviewed");
    let connection = Connection::open(&claim.store_path).unwrap();
    let events: i64 = connection
        .query_row(
            "select count(*) from guard_events where event_name='approval.local_once_applied'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(events, 1);
}

#[test]
fn bash_prelaunch_cancellation_leaves_once_consent_available() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let claim = once(&request, &store, "2050-01-01T00:00:00+00:00");
    seed_once_review(&request, &store, &claim, "cancelled-operation-0001");
    assert!(bash_grant::execute_saved(
        &request,
        &envelope,
        &store,
        &claim,
        "cancelled-operation-0001",
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(true)
    )
    .is_err());
    assert!(!Path::new(&request.home_dir)
        .join("maintenance-report.tsv")
        .exists());
    assert_eq!(
        run_operation(
            &request,
            &store,
            &envelope,
            &claim,
            "cancelled-operation-0001"
        )
        .unwrap()
        .exit_code,
        Some(0)
    );
}

#[test]
fn bash_current_hard_deny_wins_and_harmless_republication_preserves_the_grant() {
    let (_root, request) = tests::fixture();
    let (store, mut envelope) = policy_store(&request);
    let claim = once(&request, &store, "2050-01-01T00:00:00+00:00");
    for (generation, action) in [(2, "block"), (3, "allow")] {
        let mut snapshot = store.current_snapshot().unwrap();
        snapshot.generation = generation;
        snapshot.effective_policy = crate::policy_enforcement::tests::policy(action);
        snapshot.config_digest =
            guard_policy_snapshot::config_digest(&snapshot.effective_policy).unwrap();
        snapshot.policy_digest = policy_digest(&snapshot).unwrap();
        snapshot.integrity.mac = integrity_mac(&snapshot, &[37u8; 32]).unwrap();
        store
            .push(&json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":snapshot}))
            .unwrap();
        envelope.policy_generation = generation;
        envelope.policy_snapshot = serde_json::to_value(snapshot).unwrap();
        let result = run_operation(
            &request,
            &store,
            &envelope,
            &claim,
            "policy-reissued-operation-0001",
        );
        if action == "block" {
            assert!(result.is_err());
            assert!(!Path::new(&request.home_dir)
                .join("maintenance-report.tsv")
                .exists());
        } else {
            assert_eq!(result.unwrap().exit_code, Some(0));
        }
    }
}
