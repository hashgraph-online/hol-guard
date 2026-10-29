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
