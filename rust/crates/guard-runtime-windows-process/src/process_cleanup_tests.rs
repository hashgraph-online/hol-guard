use super::*;

fn failure(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[test]
fn original_setup_error_is_preserved_when_cleanup_succeeds() {
    let error = preserve_cleanup_error(io::Error::from_raw_os_error(5), Ok(()));
    assert_eq!(error.raw_os_error(), Some(5));
    assert!(!super::super::managed_cleanup_failed(&error));
}

#[test]
fn failed_cleanup_preserves_original_and_cleanup_causes() {
    let error = preserve_cleanup_error(
        failure("job assignment denied"),
        Err(failure("wait failed")),
    );
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(super::super::managed_cleanup_failed(&error));
    let detail = error
        .get_ref()
        .unwrap()
        .downcast_ref::<CleanupFailure>()
        .unwrap();
    assert_eq!(detail.original.to_string(), "job assignment denied");
    assert_eq!(detail.cleanup.to_string(), "wait failed");
}

#[test]
fn failed_job_termination_is_not_hidden_by_direct_child_exit() {
    let error = combine_cleanup_results(Err(failure("job denied")), Ok(()), Ok(())).unwrap_err();
    assert_eq!(error.to_string(), "job denied");
}

#[test]
fn signaled_owned_handle_proves_exit_after_termination_race() {
    assert!(combine_cleanup_results(Ok(()), Err(io::Error::from_raw_os_error(5)), Ok(())).is_ok());
}

#[test]
fn failed_termination_and_failed_wait_are_both_reported() {
    let error = combine_cleanup_results(
        Ok(()),
        Err(failure("terminate denied")),
        Err(io::Error::new(io::ErrorKind::TimedOut, "still running")),
    )
    .unwrap_err();
    assert!(error.to_string().contains("terminate denied"));
    assert!(error.to_string().contains("still running"));
}

#[test]
fn successful_termination_request_does_not_hide_wait_timeout() {
    let error = combine_cleanup_results(
        Ok(()),
        Ok(()),
        Err(io::Error::new(io::ErrorKind::TimedOut, "still running")),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[test]
fn no_job_cleanup_does_not_accept_direct_exit_observed_after_its_budget() {
    for (before, after) in [
        (Duration::ZERO, Duration::ZERO),
        (Duration::from_millis(1), Duration::ZERO),
    ] {
        let observation = require_timely_observation(before, after, Ok(()));
        let error = combine_cleanup_results(Ok(()), Ok(()), observation).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}

#[test]
fn late_failed_direct_wait_preserves_wait_error_and_deadline_failure() {
    let error = require_timely_observation(
        Duration::from_millis(1),
        Duration::ZERO,
        Err(failure("wait denied")),
    )
    .unwrap_err();
    assert!(error.to_string().contains("wait denied"));
    assert!(error.to_string().contains("observation timed out"));
}
