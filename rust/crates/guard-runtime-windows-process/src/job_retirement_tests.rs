use super::*;
use std::cell::{Cell, RefCell};

#[test]
fn nonzero_active_process_count_requires_later_observed_zero() {
    let counts = RefCell::new([2, 1, 0].into_iter());
    let pauses = Cell::new(0);
    poll_empty_job(
        || Ok(counts.borrow_mut().next().unwrap()),
        || Duration::from_millis(7),
        |duration| {
            assert_eq!(duration, Duration::from_millis(7));
            pauses.set(pauses.get() + 1);
        },
    )
    .unwrap();
    assert_eq!(pauses.get(), 2);
}

#[test]
fn direct_child_exit_does_not_prove_a_nonempty_job_retired() {
    let error = poll_empty_job(
        || Ok(1),
        || Duration::ZERO,
        |_| panic!("expired budget must not wait again"),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[test]
fn failed_job_accounting_query_is_not_an_empty_job() {
    let error = poll_empty_job(
        || Err(io::Error::from_raw_os_error(5)),
        || Duration::from_secs(2),
        |_| panic!("failed query must not be ignored"),
    )
    .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(5));
}

#[test]
fn expired_budget_does_not_start_another_accounting_query() {
    let error = poll_empty_job(
        || panic!("expired budget must not start another query"),
        || Duration::ZERO,
        |_| panic!("empty Job must not wait"),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[test]
fn empty_job_reported_after_the_deadline_does_not_pass() {
    let remaining = Cell::new(Duration::from_millis(1));
    let error = poll_empty_job(
        || {
            remaining.set(Duration::ZERO);
            Ok(0)
        },
        || remaining.get(),
        |_| panic!("late observation must not wait"),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[test]
fn a_fresh_grace_clock_cannot_extend_its_parent_cleanup_deadline() {
    for expire_during_query in [false, true] {
        let parent_remaining = Cell::new(if expire_during_query {
            Duration::from_millis(1)
        } else {
            Duration::ZERO
        });
        let queried = Cell::new(false);
        let error = poll_empty_job_with_parent(
            || {
                queried.set(true);
                parent_remaining.set(Duration::ZERO);
                Ok(0)
            },
            || parent_remaining.get(),
            || Duration::from_millis(250),
            |_| panic!("expired parent budget must not wait"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(queried.get(), expire_during_query);
    }
}
