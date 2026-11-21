//! Exercise allocation, durable completion and SDK acknowledgement via dispatch.
use super::*;
use guard_contracts::NativeBashAckResultV1;
#[path = "bash_post_delivery_tests.rs"]
mod post_delivery_tests;

#[test]
fn bash_reply_rejects_a_different_authenticated_invocation_for_the_current_call() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let mut execution = invocation(&request, &envelope);
    let first = execute(&execution, &store);
    assert_eq!(first.status, "ok", "{}", first.code);
    let old_id = first.operation.unwrap().operation_id;
    assert!(ack(&execution, &store, 0).acknowledged);
    execution.tool_call_id = Some("sdk-call-1".into());
    let mut current = execute(&execution, &store);
    let backed = crate::native_exact_action_op::bash_route::reply_is_backed;
    assert!(backed(&execution, &store, &current));
    let actual_id = current.operation.as_ref().unwrap().operation_id.clone();
    assert_ne!(actual_id, old_id);
    current.operation.as_mut().unwrap().operation_id = old_id;
    assert!(!backed(&execution, &store, &current));
    current.operation.as_mut().unwrap().operation_id = actual_id;
    if let Some(alias) = execution.capture.workspace.strip_prefix("/private") {
        execution.capture.workspace = alias.to_owned();
        assert!(
            backed(&execution, &store, &current),
            "physical workspace aliases share the allocation"
        );
    }
    execution.tool_call_id = Some("unallocated-sdk-call".into());
    assert!(!backed(&execution, &store, &current));
}

fn invocation(
    request: &NativeBashCaptureV1,
    envelope: &GuardHookEnvelopeV2,
) -> NativeBashExecuteRequestV1 {
    let mut execution = quiet(request, envelope);
    execution.operation_id = format!("bash-operation:{}", "a".repeat(64));
    execution.tool_call_id = Some("sdk-call-0".into());
    execution
}

fn ack(
    execution: &NativeBashExecuteRequestV1,
    store: &PolicySnapshotStore,
    code: i32,
) -> NativeBashAckResultV1 {
    serde_json::from_slice(
        &dispatch(
            "native_bash_ack",
            json!({
                "schema":"guard-native-bash-ack-request.v1", "request_id":"ack-delivery-test",
                "guard_home":execution.capture.guard_home,
                "store_path":execution.authorization.store_path(), "base_id":execution.operation_id,
                "harness":execution.capture.harness, "project":execution.capture.workspace,
                "tool_call_id":execution.tool_call_id, "exit_code":code,
            }),
            Some(store),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn bash_sdk_same_intent_distinct_acknowledged_calls_execute_across_restarts_and_old_calls_replay() {
    let (_root, request) = tests::fixture();
    let (mut store, envelope) = policy_store(&request);
    let mut execution = invocation(&request, &envelope);
    let report = Path::new(&request.home_dir).join("maintenance-report.tsv");
    let mut ids = std::collections::BTreeSet::new();
    for iteration in 0..10 {
        execution.tool_call_id = Some(format!("sdk-call-{iteration}"));
        std::fs::write(&report, "must be refreshed").unwrap();
        let result = execute(&execution, &store);
        assert_eq!(result.status, "ok", "{}", result.code);
        assert!(ids.insert(result.operation.unwrap().operation_id));
        assert!(std::fs::read_to_string(&report)
            .unwrap()
            .contains("local metadata"));
        assert!(ack(&execution, &store, 0).acknowledged);
        drop(store);
        store = PolicySnapshotStore::new(Path::new(&request.guard_home), &"a".repeat(64)).unwrap();
    }
    std::fs::write(&report, "old call must not execute").unwrap();
    execution.tool_call_id = Some("sdk-call-0".into());
    let old = execute(&execution, &store);
    assert!(old.replayed);
    assert_eq!(old.status, "recorded");
    assert!(
        !ack(&execution, &store, 0).acknowledged,
        "late ACK cannot advance the current call"
    );
    assert_eq!(
        std::fs::read_to_string(report).unwrap(),
        "old call must not execute"
    );
}

#[test]
fn bash_sdk_unacknowledged_completion_and_forged_exit_cannot_advance() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let mut execution = invocation(&request, &envelope);
    assert_eq!(ack(&execution, &store, 0).status, "error");
    let first = execute(&execution, &store);
    assert_eq!(first.status, "ok");
    assert_eq!(ack(&execution, &store, 7).status, "error");
    let report = Path::new(&request.home_dir).join("maintenance-report.tsv");
    std::fs::write(&report, "preserve unacknowledged result").unwrap();
    execution.tool_call_id = Some("sdk-distinct-before-ack".into());
    let pending = execute(&execution, &store);
    assert!(pending.replayed);
    assert_eq!(pending.operation, first.operation);
    assert_eq!(
        std::fs::read_to_string(&report).unwrap(),
        "preserve unacknowledged result"
    );
    // Receipt of native completion on recovery can be acknowledged, but that
    // call remains pinned. Only a later distinct call gets a new invocation.
    assert!(ack(&execution, &store, 0).acknowledged);
    assert!(execute(&execution, &store).replayed);
    execution.tool_call_id = Some("sdk-distinct-after-ack".into());
    assert_eq!(execute(&execution, &store).status, "ok");
}

#[test]
fn bash_sdk_deleted_journal_cannot_repeat_a_completed_invocation_or_advance() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let mut execution = invocation(&request, &envelope);
    let first = execute(&execution, &store);
    assert_eq!(first.status, "ok");
    assert!(ack(&execution, &store, 0).acknowledged);
    let report = Path::new(&request.home_dir).join("maintenance-report.tsv");
    std::fs::write(&report, "preserve after journal deletion").unwrap();
    Connection::open(execution.authorization.store_path())
        .unwrap()
        .execute(
            "DELETE FROM guard_bash_operations WHERE operation_id=?1",
            [first.operation.unwrap().operation_id],
        )
        .unwrap();
    assert_eq!(execute(&execution, &store).status, "error");
    execution.tool_call_id = Some("new-call-after-deletion".into());
    assert_eq!(execute(&execution, &store).status, "error");
    assert_eq!(
        std::fs::read_to_string(report).unwrap(),
        "preserve after journal deletion"
    );
}

#[test]
fn bash_sdk_unsigned_lifetime_edit_cannot_enable_a_new_invocation() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let mut execution = invocation(&request, &envelope);
    assert_eq!(execute(&execution, &store).status, "ok");
    Connection::open(execution.authorization.store_path()).unwrap().execute(
        "UPDATE guard_bash_invocations SET payload=json_set(payload,'$.acknowledged',json('true'))",
        [],
    ).unwrap();
    let report = Path::new(&request.home_dir).join("maintenance-report.tsv");
    std::fs::write(&report, "preserve after forged acknowledgement").unwrap();
    assert_eq!(ack(&execution, &store, 0).status, "error");
    execution.tool_call_id = Some("new-call-after-forgery".into());
    assert_eq!(execute(&execution, &store).status, "error");
    assert_eq!(
        std::fs::read_to_string(report).unwrap(),
        "preserve after forged acknowledgement"
    );
}

fn pending_inbox(
    execution: &NativeBashExecuteRequestV1,
    original: &guard_contracts::NativeBashReviewLineageV1,
) -> Connection {
    let connection = Connection::open(execution.authorization.store_path()).unwrap();
    // This low-level fixture normally contains only grant tables. A real
    // pending review also has the production inbox read/expiry surface.
    connection.execute_batch(
        "CREATE TABLE approval_requests(request_id TEXT PRIMARY KEY,status TEXT,
         resolution_action TEXT,resolution_scope TEXT,resolved_at TEXT,reason TEXT,
         action_envelope_json TEXT,harness TEXT,artifact_id TEXT,artifact_hash TEXT,workspace TEXT)",
    ).unwrap();
    connection
        .execute(
            "INSERT INTO approval_requests(request_id,status,action_envelope_json,harness,
         artifact_id,artifact_hash,workspace) VALUES('pending-version','pending',?1,?2,?3,?4,?5)",
            params![
                json!({"native_bash":{"review_lineage":original,
            "artifact_hash":original.artifact_hash}})
                .to_string(),
                execution.capture.harness,
                bash_grant::ARTIFACT,
                original.artifact_hash,
                execution.capture.workspace
            ],
        )
        .unwrap();
    connection
}

#[test]
fn bash_pending_helper_change_gets_fresh_review_and_can_follow_current_allow_policy() {
    pending_helper_change("sdk-call-0");
    pending_helper_change("sdk-reissued-after-helper-change");
}

fn pending_helper_change(changed_call: &str) {
    let (_root, request) = tests::fixture();
    let (store, mut envelope) = policy_store(&request);
    execution_floor(&store, &mut envelope, "require-reapproval");
    let mut execution = invocation(&request, &envelope);
    let initial = execute(&execution, &store);
    assert_eq!(initial.code, "native_bash_consent_required");
    let original = initial.review_lineage.unwrap();
    let connection = pending_inbox(&execution, &original);
    let helper = Path::new(&request.cwd).join("fixture-registry");
    let mut source = std::fs::read_to_string(&helper).unwrap();
    source.push_str("\nprintf 'updated metadata\\n'\n");
    std::fs::write(helper, source).unwrap();
    execution.tool_call_id = Some(changed_call.into());
    let changed = execute(&execution, &store);
    assert_eq!(
        changed.code, "native_bash_consent_required",
        "changed pending inputs must reach a fresh review: {}",
        changed.code
    );
    assert!(!changed.dispatch_acknowledged && !changed.grant_claimed);
    let updated = changed.review_lineage.unwrap();
    assert_ne!(updated.artifact_hash, original.artifact_hash);
    assert_ne!(updated.lineage_id, original.lineage_id);
    assert_eq!(
        connection
            .query_row(
                "SELECT status FROM approval_requests WHERE request_id='pending-version'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "expired"
    );
    let retired =
        crate::policy_store::policy_store_approval::bash_journal::BashOperationJournal::open(
            &store,
            execution.authorization.store_path(),
            &original.operation_id,
            &original.artifact_hash,
        )
        .unwrap();
    assert!(retired
        .pending_review(&request.harness, &request.workspace)
        .is_err());
    drop(retired);
    let report = Path::new(&request.home_dir).join("maintenance-report.tsv");
    assert!(!report.exists());
    execution.tool_call_id = Some("sdk-unchanged-pending-reissue".into());
    let repeated = execute(&execution, &store);
    assert_eq!(repeated.code, "native_bash_consent_required");
    assert_eq!(repeated.review_lineage.unwrap(), updated);

    // Current policy can allow the new code without resurrecting the old
    // pending review or accepting any saved consent for its previous bytes.
    execution_floor(&store, &mut execution.envelope, "allow");
    execution.tool_call_id = Some("sdk-now-policy-allowed".into());
    let allowed = execute(&execution, &store);
    assert_eq!(allowed.status, "ok", "{}", allowed.code);
    assert!(!allowed.grant_claimed && allowed.dispatch_acknowledged);
    assert!(std::fs::read_to_string(report)
        .unwrap()
        .contains("updated metadata"));
    assert!(ack(&execution, &store, 0).acknowledged);
}

#[test]
fn bash_pending_helper_change_cannot_erase_keep_blocked_when_the_inbox_row_disappears() {
    let (_root, request) = tests::fixture();
    let (store, mut envelope) = policy_store(&request);
    execution_floor(&store, &mut envelope, "require-reapproval");
    let mut execution = invocation(&request, &envelope);
    let original = execute(&execution, &store).review_lineage.unwrap();
    let connection = pending_inbox(&execution, &original);
    connection
        .execute(
            "UPDATE approval_requests SET status='resolved',resolution_action='block'",
            [],
        )
        .unwrap();
    let helper = Path::new(&request.cwd).join("fixture-registry");
    let changed = std::fs::read_to_string(&helper).unwrap() + "\n# changed version\n";
    std::fs::write(helper, changed).unwrap();
    execution.tool_call_id = Some("sdk-changed-after-keep-blocked".into());
    assert!(execute(&execution, &store).review_lineage.is_none());
    connection
        .execute("DELETE FROM approval_requests", [])
        .unwrap();
    let retried = execute(&execution, &store);
    assert_ne!(retried.status, "ok");
    assert!(!retried.dispatch_acknowledged && !retried.grant_claimed);
    assert!(
        retried.review_lineage.is_none(),
        "a missing inbox row must not erase the observed denial"
    );
    assert!(!Path::new(&request.home_dir)
        .join("maintenance-report.tsv")
        .exists());
}

#[test]
fn bash_pending_helper_change_cannot_renew_a_reserved_run_after_its_journal_row_is_lost() {
    use crate::policy_store::policy_store_approval::bash_journal::BashOperationJournal;
    for dispatched in [false, true] {
        let (_root, request) = tests::fixture();
        let (store, envelope) = policy_store(&request);
        let mut execution = invocation(&request, &envelope);
        let snapshot = store.current_admitted_snapshot().unwrap();
        let captured = capture_for_launch(&request, &snapshot).unwrap();
        let hash = bash_grant::binding(&captured.subject, &snapshot).unwrap();
        let allocator = BashOperationJournal::open(
            &store,
            execution.authorization.store_path(),
            &execution.operation_id,
            &hash,
        )
        .unwrap();
        let (operation_id, lifetime) = allocator
            .allocate_invocation(
                &request.harness,
                &request.workspace,
                execution.tool_call_id.as_deref(),
            )
            .unwrap();
        let mut journal = BashOperationJournal::open(
            &store,
            execution.authorization.store_path(),
            &operation_id,
            &hash,
        )
        .unwrap();
        journal.attach_invocation(lifetime);
        let lineage = journal
            .pending_review(&request.harness, &request.workspace)
            .unwrap();
        let connection = pending_inbox(&execution, &lineage);
        connection
            .execute(
                "UPDATE approval_requests SET status='resolved',resolution_action='allow'",
                [],
            )
            .unwrap();
        assert!(journal
            .reserve_allowed(&request.harness, &request.workspace)
            .unwrap());
        if dispatched {
            journal.dispatched().unwrap();
        }
        drop(journal);
        drop(allocator);
        connection
            .execute(
                "DELETE FROM guard_bash_operations WHERE operation_id=?1",
                [operation_id],
            )
            .unwrap();
        let helper = Path::new(&request.cwd).join("fixture-registry");
        let changed = std::fs::read_to_string(&helper).unwrap() + "\n# changed version\n";
        std::fs::write(helper, changed).unwrap();
        execution.tool_call_id = Some("sdk-after-reservation-row-loss".into());
        let result = execute(&execution, &store);
        assert_ne!(result.status, "ok");
        assert!(!result.dispatch_acknowledged && !result.grant_claimed);
        assert!(result.review_lineage.is_none());
        assert!(!Path::new(&request.home_dir)
            .join("maintenance-report.tsv")
            .exists());
    }
}
