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

fn reconcile_started(age: Duration) -> (Reconcile, mpsc::Sender<()>) {
    let (done, finished) = mpsc::channel();
    let started = Instant::now().checked_sub(age).expect("instant in range");
    (
        Reconcile {
            done: finished,
            started,
        },
        done,
    )
}

#[test]
fn a_reconcile_that_never_finishes_does_not_hold_the_daemon_past_its_budget() {
    let (reconcile, _held) = reconcile_started(Duration::ZERO);
    let waited = Instant::now();
    let pending = reconcile.wait_until(Duration::from_millis(50));
    assert!(pending.is_some());
    assert!(waited.elapsed() < Duration::from_secs(5));
}

#[test]
fn the_reconcile_budget_counts_from_when_the_reconcile_started() {
    let (reconcile, _held) = reconcile_started(Duration::from_secs(60));
    let waited = Instant::now();
    assert!(reconcile.wait_until(RECONCILE_READY_WAIT).is_some());
    assert!(waited.elapsed() < Duration::from_secs(5));
}

#[test]
fn a_reconcile_that_finishes_within_its_budget_is_waited_for() {
    let (reconcile, done) = reconcile_started(Duration::ZERO);
    let signal = thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        done.send(()).expect("waiter listening");
    });
    assert!(reconcile.wait_until(RECONCILE_READY_WAIT).is_none());
    signal.join().expect("signal thread");
}

#[test]
fn a_reconcile_thread_that_ends_without_a_signal_counts_as_finished() {
    let (reconcile, done) = reconcile_started(Duration::ZERO);
    drop(done);
    assert!(reconcile.wait_until(RECONCILE_READY_WAIT).is_none());
}

#[test]
fn the_reconcile_call_gives_up_before_the_library_would_stop_its_resident() {
    assert!(RECONCILE_CALL_WAIT < Duration::from_secs(120));
    assert!(RECONCILE_CALL_WAIT > RECONCILE_READY_WAIT);
}

#[test]
fn the_reconcile_names_the_daemon_it_runs_inside() {
    // The daemon has not reported ready while the reconcile runs, so a hook
    // install that records the daemon URL must not have to ask it.
    assert_eq!(
        reconcile_args(Some("/home/user"), 4781),
        json!({"home": "/home/user", "daemon_url": "http://127.0.0.1:4781"})
    );
    assert_eq!(
        reconcile_args(None, 1)["daemon_url"],
        json!("http://127.0.0.1:1")
    );
}
