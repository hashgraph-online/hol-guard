use super::*;
use std::sync::mpsc::sync_channel;
use std::time::Duration;

struct NullStream;

impl Read for NullStream {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl Write for NullStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ResidentStream for NullStream {
    fn set_resident_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_resident_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_resident_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn admit_connection_does_not_block_accept_on_full_auth_queue() {
    let (primary, primary_rx) = sync_channel(1);
    primary
        .try_send(Box::new(NullStream) as BoxedResidentStream)
        .expect("seed occupancy");
    let overflow_primary = primary.clone();
    let (overflow, overflow_rx) = sync_channel(1);
    thread::spawn(move || retry_overflow_admissions(overflow_primary, overflow_rx));
    let admission = ResidentAdmission {
        primary,
        overflow,
        workers: Vec::new(),
    };
    let started = Instant::now();
    admit_connection(&admission, Box::new(NullStream)).expect("overflow handoff");
    assert!(
        started.elapsed() < Duration::from_millis(20),
        "accept must keep moving when auth workers are busy"
    );
    let worker = thread::spawn(move || {
        thread::sleep(Duration::from_millis(30));
        let occupied = primary_rx.recv().expect("drain occupancy");
        let admitted = primary_rx.recv().expect("overflow retry");
        (occupied, admitted)
    });
    drop(worker.join().expect("overflow delivered"));
    drop(admission);
}

#[test]
fn spawn_workers_run_queued_jobs_in_parallel() {
    let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (sender, receiver) = sync_channel(4);
    spawn_workers(4, receiver, {
        let started = Arc::clone(&started);
        move |_item: u8| {
            started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            while started.load(std::sync::atomic::Ordering::SeqCst) < 4 {
                thread::sleep(Duration::from_millis(1));
            }
            thread::sleep(Duration::from_millis(40));
        }
    });
    for _ in 0..4 {
        sender.send(1).expect("enqueue parallel job");
    }
    drop(sender);
    // Each job waits until all four have started, so a worker pool that ran
    // one job at a time would never get past the first. Reaching four proves
    // the overlap; a wall-clock bound would only measure runner load.
    let deadline = Instant::now() + Duration::from_millis(400);
    while started.load(std::sync::atomic::Ordering::SeqCst) < 4 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        started.load(std::sync::atomic::Ordering::SeqCst),
        4,
        "queued auth/eval work must overlap instead of running one job at a time"
    );
}

#[derive(Clone, Default)]
struct RecordingStream(Arc<std::sync::Mutex<Vec<u8>>>);

impl Read for RecordingStream {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl Write for RecordingStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ResidentStream for RecordingStream {
    fn set_resident_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_resident_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_resident_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        Ok(())
    }
}

fn complete_request(stream: BoxedResidentStream, body: &[u8]) -> PendingRequest {
    let mut request_digest = [0u8; crate::FRAME_DIGEST_BYTES];
    request_digest.copy_from_slice(&Sha256::digest(body));
    PendingRequest {
        peer_identity: None,
        stream,
        request_id: [7u8; crate::FRAME_REQUEST_ID_BYTES],
        request_digest,
        length: body.len(),
        payload_prefix: body.to_vec(),
        accepted_at: Instant::now(),
    }
}

#[test]
fn regression_auth_worker_hands_a_fully_buffered_request_to_the_evaluation_pool() {
    let _gauges = crate::resident_health_counters::GAUGE_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    // An auth worker that evaluated a request whose payload arrived with its
    // header stayed busy for the whole evaluation, so a burst of hooks left
    // nobody to answer the next challenge and those callers fell back to the
    // daemon after AUTH_TIMEOUT.
    let (control_sender, control_rx) = sync_channel(1);
    let (evaluation_sender, evaluation_rx) = sync_channel(1);
    let stream = RecordingStream::default();
    let written = Arc::clone(&stream.0);
    let body = br#"{"operation":"pre_tool_decide"}"#;
    dispatch_authenticated(
        complete_request(Box::new(stream), body),
        &control_sender,
        &evaluation_sender,
        None,
    );
    let queued = evaluation_rx
        .try_recv()
        .expect("a complete request must queue for an evaluation worker");
    // Receiving is what an evaluation worker does, and the worker releases the
    // charge the admission took.
    crate::resident_health_counters::leave_queue(QueueLane::Evaluation);
    assert_eq!(queued.payload_prefix, body.to_vec());
    assert!(control_rx.try_recv().is_err());
    assert!(
        written.lock().unwrap().is_empty(),
        "the auth worker must not answer the request itself"
    );
}

#[test]
fn regression_auth_worker_evaluates_inline_when_the_evaluation_queue_is_full() {
    let _gauges = crate::resident_health_counters::GAUGE_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    // Answering native_overloaded here turned a busy evaluation pool into a
    // hook failure for requests the auth worker used to evaluate itself.
    let (control_sender, control_rx) = sync_channel(1);
    let (evaluation_sender, _evaluation_rx) = sync_channel(1);
    let body = br#"{"operation":"pre_tool_decide"}"#;
    evaluation_sender
        .try_send(complete_request(Box::new(NullStream), body))
        .expect("seed occupancy");
    let stream = RecordingStream::default();
    let written = Arc::clone(&stream.0);
    dispatch_authenticated(
        complete_request(Box::new(stream), body),
        &control_sender,
        &evaluation_sender,
        None,
    );
    let written = written.lock().unwrap();
    assert!(!written.is_empty(), "the request must be answered inline");
    assert!(
        !written
            .windows(b"native_overloaded".len())
            .any(|window| window == b"native_overloaded"),
        "a full evaluation queue must not turn into an overload answer"
    );
    assert!(control_rx.try_recv().is_err());
}

#[test]
fn auth_worker_answers_overloaded_for_a_fragmented_request_when_the_evaluation_queue_is_full() {
    let _gauges = crate::resident_health_counters::GAUGE_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    // Reading the rest of the payload would hold the auth worker on a slow
    // client, so a fragmented request is answered with retryable overload.
    let (control_sender, control_rx) = sync_channel(1);
    let (evaluation_sender, _evaluation_rx) = sync_channel(1);
    let body = br#"{"operation":"pre_tool_decide"}"#;
    evaluation_sender
        .try_send(complete_request(Box::new(NullStream), body))
        .expect("seed occupancy");
    let stream = RecordingStream::default();
    let written = Arc::clone(&stream.0);
    let mut pending = complete_request(Box::new(stream), body);
    pending.payload_prefix.truncate(10);
    dispatch_authenticated(pending, &control_sender, &evaluation_sender, None);
    let written = written.lock().unwrap();
    assert!(
        written
            .windows(b"native_overloaded".len())
            .any(|window| window == b"native_overloaded"),
        "a fragmented request on a full queue must answer retryable overload"
    );
    assert!(control_rx.try_recv().is_err());
}

#[test]
fn auth_worker_routes_a_complete_control_request_to_the_control_lane() {
    let _gauges = crate::resident_health_counters::GAUGE_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (control_sender, control_rx) = sync_channel(1);
    let (evaluation_sender, evaluation_rx) = sync_channel(1);
    let body = br#"{"operation":"catalog_read"}"#;
    dispatch_authenticated(
        complete_request(Box::new(NullStream), body),
        &control_sender,
        &evaluation_sender,
        None,
    );
    assert!(control_rx.try_recv().is_ok());
    crate::resident_health_counters::leave_queue(QueueLane::Control);
    assert!(evaluation_rx.try_recv().is_err());
}

#[test]
fn a_reply_counts_a_served_request_only_once_it_reached_the_caller() {
    // Counting a failed write as served would hide a resident that had stopped
    // answering behind a healthy served total, and the caller it never answered
    // would be counted twice over: once as served, once as the frame error it
    // really was.
    assert_eq!(reply_accounting(&Ok(()), false), ReplyAccounting::Served);
    assert_eq!(
        reply_accounting(&Err("native_frame_write_failed".to_owned()), false),
        ReplyAccounting::FrameError
    );
}

#[test]
fn a_request_that_already_broke_is_not_counted_as_a_second_broken_frame() {
    // A client that hangs up mid-payload fails the payload read, and the error
    // reply then fails to write to the same dead socket. That is one broken
    // frame, not two, and double counting it would make every disconnect look
    // like twice the transport trouble it was.
    assert_eq!(
        reply_accounting(&Err("native_frame_write_failed".to_owned()), true),
        ReplyAccounting::AlreadyCounted
    );
    // A successful reply still counts as served even on a request whose
    // payload read failed: the caller did get its error answer.
    assert_eq!(reply_accounting(&Ok(()), true), ReplyAccounting::Served);
}

#[test]
fn a_charge_that_never_reaches_the_channel_is_released() {
    let _gauges = crate::resident_health_counters::GAUGE_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    // The charge is taken before the send, so every path that does not leave
    // the request in the channel has to give it back. Dropping is what gives
    // it back, which is why no failure branch can forget to.
    let (before, _) = crate::resident_health_counters::lane_depth(QueueLane::Evaluation);

    drop(QueueCharge::take(QueueLane::Evaluation));

    let (after, _) = crate::resident_health_counters::lane_depth(QueueLane::Evaluation);
    assert_eq!(after, before);
}

#[test]
fn a_charge_the_channel_accepted_is_left_for_its_worker() {
    let _gauges = crate::resident_health_counters::GAUGE_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    // The worker that receives the request releases the charge. An admission
    // that released it too would let the gauge fall below the work the lane is
    // actually holding.
    let (before, _) = crate::resident_health_counters::lane_depth(QueueLane::Evaluation);

    QueueCharge::take(QueueLane::Evaluation).queued();
    let (queued, _) = crate::resident_health_counters::lane_depth(QueueLane::Evaluation);
    crate::resident_health_counters::leave_queue(QueueLane::Evaluation);

    let (released, _) = crate::resident_health_counters::lane_depth(QueueLane::Evaluation);
    assert_eq!(queued, before + 1);
    assert_eq!(released, before);
}

#[test]
fn a_served_request_that_carried_a_credential_leaves_none_of_it_in_a_health_reply() {
    let _gauges = crate::resident_health_counters::GAUGE_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    // Assembled from pieces so no file in this repository holds a whole token
    // of a shape a credential scanner recognises.
    let secret = format!("{}{}{}", "AKIA", "QYLPT3K7", "R4FXM2WD");
    let body = format!(
        r#"{{"operation":"pre_tool_decide","command":"aws configure set aws_access_key_id {secret}"}}"#
    );

    // Serve that request the way the transport serves one: the credential is
    // in the payload the pending request holds, and the reply is accounted for
    // from it. What the resident keeps of a payload it read is a length and a
    // duration, and a diagnostic reading the health reply afterwards must not
    // be able to recover the bytes from either.
    let before = health("req-before").1.counters.served_requests;
    let mut pending = complete_request(Box::new(RecordingStream::default()), body.as_bytes());
    finish_request(&mut pending, br#"{"decision":"allow"}"#, false);
    let (reply, after) = health("req-credential");

    assert!(
        after.counters.served_requests > before,
        "the request has to reach the accounting for this to say anything"
    );
    assert!(!reply.contains(&secret), "the reply repeats the credential");
    assert!(
        !reply.contains("aws_access_key_id"),
        "the reply names the field the credential was read from"
    );
    assert!(
        !reply.contains("pre_tool_decide"),
        "the reply names the operation the credential was sent to"
    );
}

/// Ask the resident how it is, the way a diagnostic on the control lane does.
///
/// Both the bytes the caller receives and what they parse to are returned: a
/// reading of the parsed struct alone would say nothing about anything the
/// reply carried outside its own fields.
fn health(request_id: &str) -> (String, guard_contracts::ResidentHealthResultV1) {
    let request = guard_contracts::ResidentHealthRequestV1 {
        schema: guard_contracts::RESIDENT_HEALTH_REQUEST_SCHEMA.to_owned(),
        request_id: request_id.to_owned(),
    };
    let encoded = crate::resident_health_op::evaluate_resident_health(&request)
        .expect("a health request on the control lane is answered");
    let reply = String::from_utf8(encoded).expect("the reply is JSON text");
    let parsed = serde_json::from_str(&reply).expect("the reply is a health result");
    (reply, parsed)
}
