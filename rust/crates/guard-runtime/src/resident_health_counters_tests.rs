use super::*;

use std::time::Duration;

/// The counters are process-wide and other tests in this binary move them, so
/// every assertion here is about a change this test caused, never an exact
/// figure. Counters only rise, which is what makes that safe.
#[test]
fn counts_a_served_request_with_its_service_time_and_size() {
    let before = snapshot();
    let accepted_at = Instant::now()
        .checked_sub(Duration::from_millis(3))
        .expect("the test process has been running for longer than three milliseconds");

    record_served(accepted_at, 4096);

    let after = snapshot();
    assert!(after.served_requests > before.served_requests);
    assert!(after.service_micros_total >= before.service_micros_total + 3_000);
    assert!(after.service_micros_max >= 3_000);
    assert!(after.request_bytes_total >= before.request_bytes_total + 4096);
    assert!(after.request_bytes_max >= 4096);
}

#[test]
fn separates_the_ways_a_request_can_fail() {
    // A caller reading these apart can tell a client that cannot authenticate
    // from one whose frames are truncated, from a resident that is simply too
    // slow for the budget it was given. One combined failure count would make
    // all three look like the same outage.
    let before = snapshot();

    record_auth_failure();
    record_frame_error();
    record_deadline_exceeded();
    record_digest_mismatch();
    record_panic();

    let after = snapshot();
    assert!(after.auth_failures > before.auth_failures);
    assert!(after.frame_errors > before.frame_errors);
    assert!(after.deadline_exceeded > before.deadline_exceeded);
    assert!(after.digest_mismatches > before.digest_mismatches);
    assert!(after.panics > before.panics);
}

#[test]
fn a_queue_depth_rises_to_its_peak_and_falls_back() {
    let queued = AtomicU64::new(0);
    let peak = AtomicU64::new(0);

    claim(&queued, &peak);
    claim(&queued, &peak);
    assert_eq!(queued.load(Ordering::Relaxed), 2);
    assert_eq!(peak.load(Ordering::Relaxed), 2);

    release(&queued);
    release(&queued);
    assert_eq!(queued.load(Ordering::Relaxed), 0);
    // The peak is what says the lane was ever that full. An emptied queue must
    // not erase the evidence that it had been at capacity.
    assert_eq!(peak.load(Ordering::Relaxed), 2);
}

#[test]
fn a_release_without_a_claim_leaves_the_depth_at_zero() {
    // Every admission path charges the queue before a worker takes the request
    // off it, but a depth that wrapped to u64::MAX on one mismatched release
    // would report a resident holding more work than it could ever admit.
    let queued = AtomicU64::new(0);

    release(&queued);
    release(&queued);

    assert_eq!(queued.load(Ordering::Relaxed), 0);
}

#[test]
fn a_total_stops_at_its_bound_instead_of_wrapping() {
    let total = AtomicU64::new(u64::MAX - 1);

    add(&total, 10);

    assert_eq!(total.load(Ordering::Relaxed), u64::MAX);
}

#[test]
fn an_event_count_stops_at_the_bound_instead_of_wrapping() {
    // Every event counter adds one through `add`. A wrapped total would read as
    // a resident that had suddenly served nothing at all, which is the one
    // reading a health check must never produce from a long uptime.
    let total = AtomicU64::new(u64::MAX);

    add(&total, 1);

    assert_eq!(total.load(Ordering::Relaxed), u64::MAX);
}

#[test]
fn the_two_lanes_keep_their_own_gauges() {
    let (evaluation_before, _) = lane_depth(QueueLane::Evaluation);
    let (control_before, _) = lane_depth(QueueLane::Control);

    enter_queue(QueueLane::Evaluation);
    let (evaluation_after, evaluation_peak) = lane_depth(QueueLane::Evaluation);
    let (control_after, _) = lane_depth(QueueLane::Control);
    leave_queue(QueueLane::Evaluation);

    assert!(evaluation_after > evaluation_before);
    assert!(evaluation_peak >= evaluation_after);
    assert_eq!(control_after, control_before);
}

#[test]
fn says_nothing_about_the_work_the_resident_served() {
    // The table is fixed at compile time. Nothing here is keyed by an
    // operation, a command, a path or a caller, so a diagnostic that may not
    // read requests may read all of it.
    let value = serde_json::to_value(snapshot()).unwrap();
    let mut fields: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();

    assert_eq!(
        fields,
        vec![
            "auth_failures",
            "deadline_exceeded",
            "digest_mismatches",
            "frame_errors",
            "panics",
            "request_bytes_max",
            "request_bytes_total",
            "served_requests",
            "service_micros_max",
            "service_micros_total",
        ]
    );
}
