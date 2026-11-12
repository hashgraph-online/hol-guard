use serde_json::json;

use super::*;

#[test]
fn a_pass_that_succeeded_waits_its_interval_and_any_other_its_backoff() {
    let job = &JOBS[0];
    assert_eq!(next_wait(job, Some(json!({"ok": true}))), job.interval);
    assert_eq!(next_wait(job, Some(json!({"ok": false}))), job.backoff);
    assert_eq!(next_wait(job, Some(json!({}))), job.backoff);
    assert_eq!(next_wait(job, None), job.backoff);
}

#[test]
fn every_job_names_a_worker_call() {
    for job in &JOBS {
        assert!(job.call.starts_with("worker."));
        assert!(job.interval >= job.backoff || job.call == "worker.maintain_activity");
    }
}

#[test]
fn an_idle_daemon_without_a_handshake_stops_after_its_timeout() {
    let reads = NativeReads::new(None);
    reads.mark_standalone();
    let mut slept = Vec::new();
    watch_idle(&reads, Duration::ZERO, |wait| slept.push(wait));
    assert!(slept.is_empty());
}

#[test]
fn an_open_connection_holds_an_idle_daemon() {
    let reads = Arc::new(NativeReads::new(None));
    reads.begin_connection();
    let mut slept = 0;
    let watcher = Arc::clone(&reads);
    watch_idle(&watcher, Duration::ZERO, |_| {
        slept += 1;
        if slept == 3 {
            reads.end_connection();
        }
    });
    assert_eq!(slept, 3);
}

#[test]
fn a_worker_host_that_keeps_exiting_backs_off_and_a_stable_one_restarts_soon() {
    let quick = Some(Duration::from_secs(1));
    assert_eq!(
        next_host_wait(HOST_RESTART_MIN, quick),
        HOST_RESTART_MIN * 2
    );
    assert_eq!(next_host_wait(HOST_RESTART_MAX, quick), HOST_RESTART_MAX);
    assert_eq!(next_host_wait(HOST_RESTART_MIN, None), HOST_RESTART_MIN * 2);
    assert_eq!(
        next_host_wait(HOST_RESTART_MAX, Some(HOST_STABLE)),
        HOST_RESTART_MIN
    );
}

#[test]
fn command_activity_aggregates_keep_thirteen_calendar_months() {
    assert_eq!(
        ticks::aggregate_cutoff("2026-11-10").as_deref(),
        Some("2025-11-01")
    );
    assert_eq!(
        ticks::aggregate_cutoff("2026-01-31").as_deref(),
        Some("2025-01-01")
    );
    assert_eq!(ticks::aggregate_cutoff("2026"), None);
}

#[test]
fn maintenance_passes_python_isoformat_instants_and_cutoffs() {
    // 2026-11-10T12:00:00.5+00:00
    let now = 1_794_312_000_500_000;
    let activity = ticks::activity_args(now, 90).expect("activity args");
    assert_eq!(activity["now"], "2026-11-10T12:00:00.500000+00:00");
    assert_eq!(activity["today"], "2026-11-10");
    assert_eq!(
        activity["detail_cutoff"],
        "2026-08-12T12:00:00.500000+00:00"
    );
    assert_eq!(activity["aggregate_cutoff"], "2025-11-01");
    let storage = ticks::storage_args(now, 90, 250_000, 250_000).expect("storage args");
    assert_eq!(storage["cutoff"], activity["detail_cutoff"]);
    assert_eq!(storage["cloud_cutoff"], "2026-11-03T12:00:00.500000+00:00");
    assert_eq!(storage["batch_size"], 500);
}
