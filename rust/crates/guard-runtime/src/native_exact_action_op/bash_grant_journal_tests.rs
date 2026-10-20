//! Lost replies, crashes, contention and integrity at the actual launch owner.
use super::*;
use crate::policy_store::policy_store_approval::bash_journal::BashOperationJournal;
use guard_contracts::NativeBashOperationStateV1 as State;

const OPERATION: &str = "test-logical-operation-0001";

fn execute(
    request: &NativeBashCaptureV1,
    store: &PolicySnapshotStore,
    envelope: &GuardHookEnvelopeV2,
    claim: &ClaimApprovalReuseDecisionsRequestV1,
) -> std::result::Result<bash_grant::LaunchOutput, bash_grant::LaunchFailure> {
    seed_once_review(request, store, claim, OPERATION);
    bash_grant::execute_saved(
        request,
        envelope,
        store,
        claim,
        OPERATION,
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(false),
    )
}

fn artifact(request: &NativeBashCaptureV1, store: &PolicySnapshotStore) -> String {
    let snapshot = store.current_admitted_snapshot().unwrap();
    let captured = capture_for_launch(request, &snapshot).unwrap();
    bash_grant::binding(&captured.subject, &snapshot).unwrap()
}

#[test]
fn two_reissues_of_one_reviewed_once_operation_produce_one_physical_append() {
    let (_root, request) = tests::fixture();
    std::fs::write(
        Path::new(&request.cwd).join("maintenance.sh"),
        ": >> \"$HOME/dispatch-count.txt\"\nprintf executed >> \"$HOME/dispatch-count.txt\"\n",
    )
    .unwrap();
    let (store, envelope) = policy_store(&request);
    let claim = once(&request, &store, "2050-01-01T00:00:00+00:00");
    seed_once_review(&request, &store, &claim, OPERATION);
    let store = Arc::new(store);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let workers = (0..2)
        .map(|_| {
            let (request, envelope, claim, store, barrier) = (
                request.clone(),
                envelope.clone(),
                claim.clone(),
                store.clone(),
                barrier.clone(),
            );
            std::thread::spawn(move || {
                barrier.wait();
                bash_grant::execute_saved(
                    &request,
                    &envelope,
                    &store,
                    &claim,
                    OPERATION,
                    Instant::now() + Duration::from_secs(5),
                    &AtomicBool::new(false),
                )
                .unwrap()
            })
        })
        .collect::<Vec<_>>();
    let answers = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(answers.iter().filter(|answer| !answer.replayed).count(), 1);
    assert_eq!(
        answers
            .iter()
            .filter(|answer| answer.output.is_some())
            .count(),
        1
    );
    assert_eq!(
        std::fs::read(Path::new(&request.home_dir).join("dispatch-count.txt")).unwrap(),
        b"executed"
    );
    let connection = Connection::open(&claim.store_path).unwrap();
    let spends: i64 = connection
        .query_row(
            "SELECT count(*) FROM guard_events WHERE event_name='approval.local_once_applied'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(spends, 1);
}

#[test]
fn bash_lost_reply_replays_completion_after_restart_without_reopening_report() {
    let (_root, request) = tests::fixture();
    let (store, mut envelope) = policy_store(&request);
    let mut claim = once(&request, &store, "2050-01-01T00:00:00+00:00");
    let first = execute(&request, &store, &envelope, &claim).unwrap();
    assert!(!first.replayed);
    let summary = first.operation.completion.unwrap();
    let output = first.output.unwrap();
    assert_eq!(
        summary.stdout_sha256,
        guard_policy_snapshot::digest_bytes(&output.stdout)
    );
    let report = Path::new(&request.home_dir).join("maintenance-report.tsv");
    std::fs::write(&report, "must not truncate on transport recovery").unwrap();
    drop(store);
    let store = PolicySnapshotStore::new(Path::new(&request.guard_home), &"a".repeat(64)).unwrap();
    envelope.request_id = Some("reissued-host-request".into());
    claim.request_id = "reissued-claim-request".into();
    let recovered = execute(&request, &store, &envelope, &claim).unwrap();
    assert!(recovered.replayed && recovered.grant_claimed && recovered.dispatch_acknowledged);
    assert!(
        recovered.output.is_none(),
        "a digest must not pretend to be original output"
    );
    assert_eq!(recovered.operation.completion, Some(summary));
    assert_eq!(
        std::fs::read_to_string(report).unwrap(),
        "must not truncate on transport recovery"
    );
}

#[test]
fn bash_same_operation_with_persistent_consent_executes_only_once_under_contention() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let claim = persistent(&request, &store);
    let store = Arc::new(store);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let workers = (0..2)
        .map(|_| {
            let (store, request, envelope, claim, barrier) = (
                store.clone(),
                request.clone(),
                envelope.clone(),
                claim.clone(),
                barrier.clone(),
            );
            std::thread::spawn(move || {
                barrier.wait();
                execute(&request, &store, &envelope, &claim).unwrap()
            })
        })
        .collect::<Vec<_>>();
    let answers = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        answers
            .iter()
            .filter(|answer| answer.output.is_some())
            .count(),
        1
    );
    assert_eq!(answers.iter().filter(|answer| answer.replayed).count(), 1);
    assert!(answers.iter().all(|answer| answer.grant_claimed));
}

#[test]
fn bash_crash_after_reservation_or_dispatch_never_auto_reexecutes_after_restart() {
    for dispatched in [false, true] {
        let (_root, request) = tests::fixture();
        let (store, envelope) = policy_store(&request);
        let claim = once(&request, &store, "2050-01-01T00:00:00+00:00");
        let artifact = artifact(&request, &store);
        seed_once_review(&request, &store, &claim, OPERATION);
        let journal =
            BashOperationJournal::open(&store, &claim.store_path, OPERATION, &artifact).unwrap();
        assert!(journal.reserve(&claim).unwrap());
        if dispatched {
            journal.dispatched().unwrap();
        }
        drop(journal);
        drop(store); // Simulate losing all resident process memory.
        let store =
            PolicySnapshotStore::new(Path::new(&request.guard_home), &"a".repeat(64)).unwrap();
        let recovered = execute(&request, &store, &envelope, &claim).unwrap();
        assert!(recovered.replayed && recovered.output.is_none());
        assert_eq!(recovered.dispatch_acknowledged, dispatched);
        assert_eq!(
            recovered.operation.state,
            if dispatched {
                State::Dispatched
            } else {
                State::Claimed
            }
        );
        assert!(!Path::new(&request.home_dir)
            .join("maintenance-report.tsv")
            .exists());
    }
}

#[test]
fn bash_journal_insert_failure_rolls_back_once_claim_and_allows_same_intent_retry() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let claim = once(&request, &store, "2050-01-01T00:00:00+00:00");
    let artifact = artifact(&request, &store);
    drop(BashOperationJournal::open(&store, &claim.store_path, OPERATION, &artifact).unwrap());
    let connection = Connection::open(&claim.store_path).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER reject_bash_operation BEFORE INSERT ON guard_bash_operations
        BEGIN SELECT RAISE(ABORT, 'injected journal failure'); END;",
        )
        .unwrap();
    let failure = execute(&request, &store, &envelope, &claim).err().unwrap();
    assert!(!failure.grant_claimed && !failure.dispatch_acknowledged);
    assert!(!Path::new(&request.home_dir)
        .join("maintenance-report.tsv")
        .exists());
    let claimed: Option<String> = connection
        .query_row(
            "SELECT claimed_at FROM guard_local_once_approvals WHERE approval_id=?1",
            [claim.decisions[0]["approval_id"].as_str().unwrap()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(claimed.is_none());
    connection
        .execute_batch("DROP TRIGGER reject_bash_operation")
        .unwrap();
    assert_eq!(
        execute(&request, &store, &envelope, &claim)
            .unwrap()
            .output
            .unwrap()
            .exit_code,
        Some(0)
    );
}

#[test]
fn bash_journal_tampering_and_record_transplant_refuse_without_effects() {
    for transplant in [false, true] {
        let (_root, request) = tests::fixture();
        let (store, envelope) = policy_store(&request);
        let claim = persistent(&request, &store);
        execute(&request, &store, &envelope, &claim).unwrap();
        let connection = Connection::open(&claim.store_path).unwrap();
        let operation = if transplant {
            let other = "other-logical-operation-0002";
            connection
                .execute(
                    "INSERT INTO guard_bash_operations SELECT ?1,payload,integrity
                FROM guard_bash_operations WHERE operation_id=?2",
                    params![other, OPERATION],
                )
                .unwrap();
            other
        } else {
            connection.execute("UPDATE guard_bash_operations SET payload=json_set(payload,'$.completion.exit_code',17)
                WHERE operation_id=?1", [OPERATION]).unwrap();
            OPERATION
        };
        let report = Path::new(&request.home_dir).join("maintenance-report.tsv");
        std::fs::write(&report, "protected report").unwrap();
        assert!(bash_grant::execute_saved(
            &request,
            &envelope,
            &store,
            &claim,
            operation,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false)
        )
        .is_err());
        assert_eq!(std::fs::read_to_string(report).unwrap(), "protected report");
    }
}

#[test]
fn bash_reusing_operation_id_for_changed_code_refuses_instead_of_running_new_intent() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let claim = persistent(&request, &store);
    execute(&request, &store, &envelope, &claim).unwrap();
    std::fs::write(
        Path::new(&request.cwd).join("maintenance.sh"),
        "printf changed\n",
    )
    .unwrap();
    assert!(execute(&request, &store, &envelope, &claim).is_err());
}
