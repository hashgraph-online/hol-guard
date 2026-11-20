//! Context delivery stays bounded while its native workers are reused.
use super::*;
use std::collections::HashSet;
use std::sync::mpsc::Receiver;
use std::thread::ThreadId;

struct ObservedStream {
    inner: Box<dyn ResidentStream>,
    writer: Option<Sender<ThreadId>>,
}
impl Read for ObservedStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}
impl Write for ObservedStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(sender) = self.writer.take() {
            sender.send(thread::current().id()).unwrap();
        }
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl ResidentStream for ObservedStream {
    fn set_resident_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_resident_read_timeout(timeout)
    }
    fn set_resident_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_resident_write_timeout(timeout)
    }
    fn set_resident_nonblocking(&self, value: bool) -> io::Result<()> {
        self.inner.set_resident_nonblocking(value)
    }
}

fn observed(
    fixture: &Fixture,
    blocked: Option<(Sender<()>, Arc<Gate>)>,
) -> (PendingRequest, Output, Receiver<ThreadId>) {
    let mut body: Value = serde_json::from_slice(&context_at("workspace", &fixture.home)).unwrap();
    body["request"]["query"]["input"] = json!({"action":"list"});
    let (mut pending, output) = pending(serde_json::to_vec(&body).unwrap(), blocked);
    let (writer, received) = channel();
    pending.stream = Box::new(ObservedStream {
        inner: pending.stream,
        writer: Some(writer),
    });
    (pending, output, received)
}

fn submit(lane: &Arc<Lane>, fixture: &Fixture) -> ThreadId {
    let (pending, output, writer) = observed(fixture, None);
    handle_pending_request(pending, Some(Arc::clone(&fixture.store)), None, Some(lane));
    let worker = writer.recv_timeout(Duration::from_secs(1)).unwrap();
    lane.drain();
    let result = response(&output);
    assert_eq!(result["schema"], "guard-context-assistance-result.v1");
    assert_eq!(result["status"], "error");
    assert_eq!(result["code"], "native_context_assistance_disabled");
    assert_eq!(lane.state.lock().unwrap().active, 0);
    worker
}

#[test]
fn sequential_calls_reuse_one_worker_and_preserve_disabled_refusals() {
    let lane = Arc::new(Lane::default());
    let fixture = Fixture::new();
    let workers: HashSet<_> = (0..8).map(|_| submit(&lane, &fixture)).collect();
    lane.close();
    lane.drain();
    assert_eq!(
        workers.len(),
        1,
        "eight completed jobs need one native worker"
    );
}

#[test]
fn two_blocked_deliveries_keep_the_limit_then_reuse_an_existing_worker() {
    let lane = Arc::new(Lane::default());
    let fixture = Fixture::new();
    let gate = Arc::new(Gate::default());
    let release = Release(Arc::clone(&gate));
    let (entered, received) = channel();
    let mut workers = HashSet::new();
    for _ in 0..2 {
        let (pending, _, writer) = observed(&fixture, Some((entered.clone(), Arc::clone(&gate))));
        handle_pending_request(pending, Some(Arc::clone(&fixture.store)), None, Some(&lane));
        workers.insert(writer.recv_timeout(Duration::from_secs(1)).unwrap());
        received.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    assert_eq!(workers.len(), 2);
    let (third, output) = pending(context_at("workspace", &fixture.home), None);
    handle_pending_request(third, Some(Arc::clone(&fixture.store)), None, Some(&lane));
    assert_eq!(response(&output)["code"], "native_context_assistance_busy");
    assert_eq!(lane.state.lock().unwrap().active, 2);
    drop(release);
    lane.drain();
    let next = submit(&lane, &fixture);
    lane.close();
    lane.drain();
    assert!(
        workers.contains(&next),
        "the third completed job reuses an idle worker"
    );
}

#[test]
fn idle_workers_retire_and_later_requests_start_fresh_workers() {
    let lane = Arc::new(Lane::default());
    let fixture = Fixture::new();
    assert_eq!(
        Arc::strong_count(&lane),
        1,
        "the unused lane starts no worker"
    );
    let first = submit(&lane, &fixture);
    let deadline = Instant::now() + Duration::from_secs(3);
    while Arc::strong_count(&lane) != 1 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        Arc::strong_count(&lane),
        1,
        "idle worker ownership must retire"
    );
    let second = submit(&lane, &fixture);
    lane.close();
    lane.drain();
    assert_ne!(first, second);
}

#[test]
fn closing_a_warm_idle_lane_releases_worker_ownership() {
    let lane = Arc::new(Lane::default());
    let fixture = Fixture::new();
    submit(&lane, &fixture);
    let weak = Arc::downgrade(&lane);
    lane.close();
    lane.drain();
    drop(lane);
    let deadline = Instant::now() + Duration::from_secs(1);
    while weak.strong_count() != 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(weak.strong_count(), 0);
}

#[test]
fn a_closed_lane_refuses_before_dispatching_another_job() {
    let lane = Arc::new(Lane::default());
    let fixture = Fixture::new();
    submit(&lane, &fixture);
    lane.close();
    lane.drain();
    let (pending, output, writer) = observed(&fixture, None);
    handle_pending_request(pending, Some(Arc::clone(&fixture.store)), None, Some(&lane));
    assert_eq!(
        writer.recv_timeout(Duration::from_secs(1)).unwrap(),
        thread::current().id()
    );
    assert_eq!(response(&output)["code"], "native_context_assistance_busy");
    assert_eq!(lane.state.lock().unwrap().active, 0);
}

fn request_bytes(fixture: &Fixture) -> Vec<u8> {
    let mut body: Value = serde_json::from_slice(&context_at("workspace", &fixture.home)).unwrap();
    body["request"]["query"]["input"] = json!({"action":"list"});
    serde_json::to_vec(&body).unwrap()
}

#[test]
fn failed_initial_spawn_returns_a_bound_refusal_and_releases_its_slot() {
    let lane = Arc::new(Lane::default());
    let fixture = Fixture::new();
    let (pending, output, _writer) = observed(&fixture, None);
    let body = request_bytes(&fixture);
    let mut spawns = 0;
    lane.enqueue_with(
        pending,
        body.clone(),
        Some(Arc::clone(&fixture.store)),
        |_| {
            spawns += 1;
            Err(io::ErrorKind::Other.into())
        },
    );
    assert_eq!(spawns, 1);
    let result = response(&output);
    assert_eq!(result["code"], "native_context_assistance_busy");
    let request: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["request_id"], request["request"]["request_id"]);
    assert_eq!(
        result["request_sha256"],
        crate::package_authority_op::request_digest_with_limit(&request["request"], 64 * 1024)
            .unwrap()
    );
    {
        let state = lane.state.lock().unwrap();
        assert_eq!((state.active, state.workers, state.jobs.len()), (0, 0, 0));
    }
    submit(&lane, &fixture);
    lane.close();
    lane.drain();
}

#[test]
fn failed_second_spawn_keeps_the_active_worker_and_its_result() {
    let lane = Arc::new(Lane::default());
    let fixture = Fixture::new();
    let gate = Arc::new(Gate::default());
    let release = Release(Arc::clone(&gate));
    let (entered, received) = channel();
    let (first, output, writer) = observed(&fixture, Some((entered, Arc::clone(&gate))));
    handle_pending_request(first, Some(Arc::clone(&fixture.store)), None, Some(&lane));
    let first_worker = writer.recv_timeout(Duration::from_secs(1)).unwrap();
    received.recv_timeout(Duration::from_secs(1)).unwrap();
    let (second, refused, _second_writer) = observed(&fixture, None);
    lane.enqueue_with(
        second,
        request_bytes(&fixture),
        Some(Arc::clone(&fixture.store)),
        |_| Err(io::ErrorKind::Other.into()),
    );
    assert_eq!(response(&refused)["code"], "native_context_assistance_busy");
    {
        let state = lane.state.lock().unwrap();
        assert_eq!((state.active, state.workers, state.jobs.len()), (1, 1, 0));
    }
    drop(release);
    lane.drain();
    assert_eq!(
        response(&output)["code"],
        "native_context_assistance_disabled"
    );
    assert_eq!(submit(&lane, &fixture), first_worker);
    lane.close();
    lane.drain();
}

#[test]
fn losing_the_last_worker_refuses_unevaluated_jobs_and_releases_reservations() {
    let lane = Arc::new(Lane::default());
    let fixture = Fixture::new();
    let mut workers = Vec::new();
    let mut outputs = Vec::new();
    let mut writers = Vec::new();
    for _ in 0..2 {
        let (pending, output, writer) = observed(&fixture, None);
        lane.enqueue_with(
            pending,
            request_bytes(&fixture),
            Some(Arc::clone(&fixture.store)),
            |lane| {
                // Own a worker before its first dequeue, without running a job.
                workers.push(Worker {
                    lane,
                    registered: true,
                });
                Ok(())
            },
        );
        outputs.push(output);
        writers.push(writer);
    }
    drop(workers.pop().unwrap());
    assert!(outputs
        .iter()
        .all(|output| output.lock().unwrap().is_empty()));
    drop(workers);
    assert!(outputs
        .iter()
        .all(|output| response(output)["code"] == "native_context_assistance_busy"));
    {
        let state = lane.state.lock().unwrap();
        assert_eq!((state.active, state.workers, state.jobs.len()), (0, 0, 0));
    }
    submit(&lane, &fixture);
    lane.close();
    lane.drain();
}

#[test]
fn a_delivery_panic_releases_the_job_without_losing_its_worker() {
    let lane = Arc::new(Lane::default());
    let fixture = Fixture::new();
    let (pending, output, writer) = observed(&fixture, None);
    let poisoned = catch_unwind(AssertUnwindSafe(|| {
        let _guard = output.lock().unwrap();
        panic!("controlled delivery mutex failure");
    }));
    assert!(poisoned.is_err());
    handle_pending_request(pending, Some(Arc::clone(&fixture.store)), None, Some(&lane));
    let first = writer.recv_timeout(Duration::from_secs(1)).unwrap();
    lane.drain();
    assert_eq!(submit(&lane, &fixture), first);
    lane.close();
    lane.drain();
}

#[test]
fn close_preserves_already_admitted_deliveries_and_retires_both_workers() {
    let lane = Arc::new(Lane::default());
    let fixture = Fixture::new();
    let gate = Arc::new(Gate::default());
    let release = Release(Arc::clone(&gate));
    let (entered, received) = channel();
    let mut outputs = Vec::new();
    for _ in 0..2 {
        let (pending, output, writer) =
            observed(&fixture, Some((entered.clone(), Arc::clone(&gate))));
        handle_pending_request(pending, Some(Arc::clone(&fixture.store)), None, Some(&lane));
        writer.recv_timeout(Duration::from_secs(1)).unwrap();
        received.recv_timeout(Duration::from_secs(1)).unwrap();
        outputs.push(output);
    }
    lane.close();
    drop(release);
    lane.drain();
    let state = lane.state.lock().unwrap();
    assert_eq!((state.active, state.workers, state.jobs.len()), (0, 0, 0));
    assert!(outputs
        .iter()
        .all(|output| response(output)["code"] == "native_context_assistance_disabled"));
}

#[test]
fn a_job_expired_after_admission_refuses_before_evaluation() {
    let lane = Arc::new(Lane::default());
    let fixture = Fixture::new();
    let (mut pending, output, _writer) = observed(&fixture, None);
    pending.accepted_at = Instant::now() - crate::hardening::TOTAL_REQUEST_BUDGET;
    lane.enqueue(
        pending,
        request_bytes(&fixture),
        Some(Arc::clone(&fixture.store)),
    );
    lane.drain();
    assert_eq!(
        response(&output)["error"],
        "native_request_deadline_exceeded"
    );
    assert_eq!(lane.state.lock().unwrap().active, 0);
    lane.close();
    lane.drain();
}
