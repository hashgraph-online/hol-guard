use super::*;
use guard_contracts::{
    NativeBashCancelRequestV1, NativeBashCancelResultV1, NATIVE_BASH_CANCEL_REQUEST_SCHEMA,
};

fn cancellation(request: &NativeBashExecuteRequestV1) -> NativeBashCancelRequestV1 {
    NativeBashCancelRequestV1 {
        schema: NATIVE_BASH_CANCEL_REQUEST_SCHEMA.into(),
        request_id: "cancel-bash-test".into(),
        operation_id: request.operation_id.clone(),
        guard_home: request.capture.guard_home.clone(),
    }
}

fn cancel(
    request: &NativeBashCancelRequestV1,
    store: &PolicySnapshotStore,
) -> NativeBashCancelResultV1 {
    serde_json::from_slice(
        &dispatch(
            "native_bash_cancel",
            serde_json::to_value(request).unwrap(),
            Some(store),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn bash_resident_cancellation_before_launch_preserves_once_consent_and_no_report() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let claim = once(&request, &store, "2050-01-01T00:00:00+00:00");
    let execution = execution(request, envelope, claim);
    let cancellation = cancellation(&execution);
    let store = Arc::new(store);
    // Hold the actual policy admission barrier, rather than relying on a
    // timing-dependent slow script. Registration precedes this lock.
    let fence = store.fence_for_launch(&execution.envelope).unwrap();
    let worker_store = Arc::clone(&store);
    let worker_request = execution.clone();
    let worker = std::thread::spawn(move || execute(&worker_request, &worker_store));
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if cancel(&cancellation, &store).cancel_requested {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "launch registration was not reached"
        );
        std::thread::yield_now();
    }
    drop(fence);
    let cancelled = worker.join().unwrap();
    assert_eq!(cancelled.code, "native_bash_launch_cancelled");
    assert!(!cancelled.grant_claimed && !cancelled.dispatch_acknowledged);
    assert!(cancelled.payload.is_none());
    assert!(!Path::new(&execution.capture.home_dir)
        .join("maintenance-report.tsv")
        .exists());
    assert!(!cancel(&cancellation, &store).cancel_requested);
    // An explicit later launch is still possible because no attempt claimed
    // the once grant. Cancellation does not impersonate Keep blocked.
    assert_eq!(
        execute(&execution, &store).payload.unwrap().exit_code,
        Some(0)
    );
}

#[test]
fn bash_cancel_requires_current_home_and_known_schema_without_cancelling_other_work() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let claim = once(&request, &store, "2050-01-01T00:00:00+00:00");
    let execution = execution(request, envelope, claim);
    let registration = store
        .bash_launches()
        .register(&execution.operation_id)
        .unwrap();
    let mut cancellation = cancellation(&execution);
    cancellation.guard_home = execution.capture.home_dir.clone();
    assert_eq!(
        dispatch(
            "native_bash_cancel",
            serde_json::to_value(&cancellation).unwrap(),
            Some(&store)
        )
        .unwrap_err(),
        "native_guard_home_mismatch"
    );
    cancellation.guard_home = execution.capture.guard_home.clone();
    cancellation.schema = "guard-native-bash-cancel-request.v99".into();
    assert!(!cancel(&cancellation, &store).cancel_requested);
    assert!(!registration
        .cancelled
        .load(std::sync::atomic::Ordering::Acquire));
    cancellation.schema = NATIVE_BASH_CANCEL_REQUEST_SCHEMA.into();
    assert!(cancel(&cancellation, &store).cancel_requested);
    assert!(registration
        .cancelled
        .load(std::sync::atomic::Ordering::Acquire));
    drop(registration);
    let absent = cancel(&cancellation, &store);
    assert!(!absent.cancel_requested);
    assert_eq!(absent.code, "native_bash_operation_not_running");
}
