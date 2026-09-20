fn frame() -> Frame {
    Frame {
        schema: "hol-guard-native-phase-frame.v1",
        sender_pid: std::process::id(),
        sender_start_ticks: 1,
        role: Role::PersistentClient,
        ordinal: 1,
        max_export_attempts: MAX_EXPORT_ATTEMPTS,
        export_interval_ms: 50,
        max_datagram_bytes: MAX_DATAGRAM_BYTES,
        diagnostic_socket_opens: 1,
        diagnostic_socket_in_request_counts: false,
        prior_export_loss_observed: false,
        last_allowed_attempt: false,
        run_state_when_sampled: RunState::Running,
        complete_run: false,
        headline_timing_eligible: false,
        snapshot: native_phase_observation::snapshot(),
    }
}

#[test]
fn one_datagram_preserves_the_fixed_diagnostic_frame() {
    let (sender, receiver) = UnixDatagram::pair().unwrap();
    receiver.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let original = frame();
    let expected = serde_json::to_vec(&original).unwrap();
    assert!(send_frame(&sender, &original));
    let mut bytes = [0u8; MAX_DATAGRAM_BYTES];
    let count = receiver.recv(&mut bytes).unwrap();
    assert_eq!(&bytes[..count], expected);
    let report: serde_json::Value = serde_json::from_slice(&bytes[..count]).unwrap();
    assert_eq!(report["diagnostic_socket_in_request_counts"], false);
    assert_eq!(report["complete_run"], false);
}

#[test]
fn closed_receiver_is_a_failed_diagnostic_send_without_sigpipe() {
    let (sender, receiver) = UnixDatagram::pair().unwrap();
    drop(receiver);
    assert!(!send_frame(&sender, &frame()));
}

#[test]
fn full_receiver_never_waits_for_a_reader_or_retries() {
    let (sender, _receiver) = UnixDatagram::pair().unwrap();
    // The descriptor itself is deliberately blocking. MSG_DONTWAIT must still
    // make each individual export nonblocking.
    let sample = frame();
    let mut full = false;
    for _ in 0..1024 {
        if !send_frame(&sender, &sample) {
            full = true;
            break;
        }
    }
    assert!(full, "finite receiver-fill control did not reach backpressure");
    assert!(!send_frame(&sender, &sample));
}

#[test]
fn run_completion_records_only_a_fixed_outcome() {
    let state = Arc::new(AtomicU8::new(0));
    Exporter { run_state: Arc::clone(&state) }.finished(false);
    assert_eq!(state.load(Ordering::Relaxed), 2);
    Exporter { run_state: Arc::clone(&state) }.finished(true);
    assert_eq!(state.load(Ordering::Relaxed), 1);
    assert!(Role::from_command("supervise-managed").is_none());
    assert!(Role::from_command("unrecognized command").is_none());
    assert!(Role::from_command("resident-client-stream").is_some());
}
