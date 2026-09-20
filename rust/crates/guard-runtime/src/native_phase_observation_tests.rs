#[test]
fn disabled_collector_preserves_missing_phases() {
    let collector = Collector::new();
    assert!(collector.begin(Phase::ClientConnect).is_none());
    let report = snapshot_collector(&collector).unwrap();
    assert!(report.phases.iter().all(|phase| phase.statistics.is_none()));
    assert_eq!(report.active_observations_when_read, 0);
    assert!(!report.complete_run && !report.headline_timing_eligible);
    assert!(report.all_platform_socket_opens.is_none());
}

#[test]
fn successful_failed_abandoned_and_unwound_spans_are_distinct() {
    let collector = Collector::new();
    collector.enable();
    collector.begin(Phase::ClientAuthenticate).unwrap().finish(true);
    collector.begin(Phase::ClientAuthenticate).unwrap().finish(false);
    drop(collector.begin(Phase::ClientAuthenticate).unwrap());
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _span = collector.begin(Phase::ClientAuthenticate).unwrap();
        panic!("controlled observation unwind");
    }));
    assert!(panic.is_err());
    let report = snapshot_collector(&collector).unwrap();
    let aggregate = report.phases[Phase::ClientAuthenticate as usize].statistics.unwrap();
    assert_eq!(aggregate.retained_count, 4);
    assert_eq!((aggregate.returned_ok, aggregate.returned_err, aggregate.abandoned, aggregate.unwound),
               (1, 1, 1, 1));
    assert_eq!(report.active_observations_when_read, 0);
    assert!(report.phases[Phase::ResidentEvaluate as usize].statistics.is_none());
}

#[test]
fn contention_refuses_observation_without_waiting_or_inventing_zero() {
    let collector = Collector::new();
    collector.enable();
    let span = collector.begin(Phase::ResidentEvaluate).unwrap();
    let held = collector.aggregates.lock().unwrap();
    span.finish(true);
    assert!(snapshot_collector(&collector).is_none());
    drop(held);
    let report = snapshot_collector(&collector).unwrap();
    assert!(report.collector_loss_observed);
    assert!(report.phases[Phase::ResidentEvaluate as usize].statistics.is_none());
    assert_eq!(report.active_observations_when_read, 0);
}

#[test]
fn retention_and_duration_caps_remain_explicit() {
    let mut aggregate = Aggregate::EMPTY;
    aggregate.record(17, Outcome::ReturnedOk);
    aggregate.record(u128::MAX, Outcome::ReturnedErr);
    assert_eq!(aggregate.duration_ns_min, 17);
    assert_eq!(aggregate.duration_ns_max, MAX_DURATION_NS);
    assert_eq!(aggregate.duration_ns_sum, MAX_DURATION_NS + 17);
    assert!(aggregate.duration_clipped);
    aggregate.retained_count = MAX_OBSERVATIONS_PER_PHASE;
    let before = aggregate.duration_ns_sum;
    aggregate.record(9, Outcome::Abandoned);
    assert!(aggregate.observations_discarded_at_cap);
    assert_eq!(aggregate.retained_count, MAX_OBSERVATIONS_PER_PHASE);
    assert_eq!(aggregate.duration_ns_sum, before);
    assert_eq!(aggregate.abandoned, 0);
}

#[test]
fn maximum_fixed_report_remains_bounded() {
    let collector = Collector::new();
    let maximum = Aggregate {
        retained_count: MAX_OBSERVATIONS_PER_PHASE,
        returned_ok: MAX_OBSERVATIONS_PER_PHASE,
        returned_err: 0,
        abandoned: 0,
        unwound: 0,
        duration_ns_sum: MAX_DURATION_NS * MAX_OBSERVATIONS_PER_PHASE,
        duration_ns_min: MAX_DURATION_NS,
        duration_ns_max: MAX_DURATION_NS,
        duration_clipped: true,
        observations_discarded_at_cap: true,
    };
    *collector.aggregates.lock().unwrap() = [maximum; PHASE_COUNT];
    collector.active.store(usize::MAX, Ordering::Relaxed);
    let bytes = serde_json::to_vec(&snapshot_collector(&collector).unwrap()).unwrap();
    assert!(bytes.len() <= crate::native_phase_sink::MAX_DATAGRAM_BYTES - 2048);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["phases"].as_array().unwrap().len(), 7);
    assert_eq!(value["span_semantics"], "inclusive_do_not_sum");
}
