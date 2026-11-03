#[cfg(test)]
use std::io::{self, Read, Write};
#[cfg(test)]
use std::net::TcpStream;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::resident_diagnostics::{self, observe, Phase, Status};
use crate::resident_health_counters::{self as counters, QueueLane};
use sha2::{Digest, Sha256};
#[path = "resident_context_dispatch.rs"]
mod context;
#[path = "resident_control_dispatch.rs"]
mod control;
#[path = "resident_worker_pool.rs"]
mod worker_pool;
#[cfg(all(test, unix))]
use std::os::unix::net::UnixStream;
use worker_pool::spawn_workers;

#[path = "resident_stream.rs"]
mod stream;
pub(crate) use stream::{DisconnectInput, ResidentStream};
#[path = "resident_request_cancellation.rs"]
mod request_cancellation;

pub(crate) type BoxedResidentStream = Box<dyn ResidentStream>;

pub(crate) struct PendingRequest {
    // Trusted transport metadata; never filled from request JSON or exported.
    peer_identity: Option<crate::resident_peer_identity::UnixPeerIdentity>,
    pub(crate) stream: BoxedResidentStream,
    pub(crate) request_id: [u8; crate::FRAME_REQUEST_ID_BYTES],
    pub(crate) request_digest: [u8; crate::FRAME_DIGEST_BYTES],
    pub(crate) length: usize,
    pub(crate) payload_prefix: Vec<u8>,
    pub(crate) accepted_at: Instant,
}

impl PendingRequest {
    #[allow(dead_code)] // Future worker enrollment consumes this input, not a grant.
    pub(crate) fn kernel_peer_identity(
        &self,
    ) -> Option<&crate::resident_peer_identity::UnixPeerIdentity> {
        self.peer_identity.as_ref()
    }
}

#[path = "resident_auth_crypto.rs"]
mod auth_crypto;
pub(crate) use auth_crypto::{constant_time_eq, hmac_sha256};

fn authenticate_resident_stream(
    stream: &mut dyn ResidentStream,
    token: &[u8; crate::AUTH_TOKEN_BYTES],
) -> Result<(), String> {
    stream
        .set_resident_read_timeout(Some(crate::AUTH_TIMEOUT))
        .map_err(|_| "native_resident_auth_timeout_failed".to_owned())?;
    stream
        .set_resident_write_timeout(Some(crate::AUTH_TIMEOUT))
        .map_err(|_| "native_resident_auth_timeout_failed".to_owned())?;
    let _ = stream.configure_low_latency();

    // One deadline covers the whole handshake: a client that drips a byte
    // before each timeout would otherwise renew the timeout for as long as it
    // likes and hold an authentication worker the entire time.
    let deadline = Instant::now() + crate::AUTH_TIMEOUT;
    let mut nonce = [0u8; crate::AUTH_NONCE_BYTES];
    crate::hardening::read_exact_by(&mut *stream, &mut nonce, deadline)
        .map_err(|_| "native_resident_auth_nonce_failed".to_owned())?;
    let server_proof = hmac_sha256(token, crate::SERVER_PROOF_LABEL, &nonce);
    crate::hardening::write_all_by(&mut *stream, &server_proof, deadline)
        .map_err(|_| "native_resident_auth_proof_failed".to_owned())?;

    let mut client_proof = [0u8; crate::AUTH_PROOF_BYTES];
    crate::hardening::read_exact_by(&mut *stream, &mut client_proof, deadline)
        .map_err(|_| "native_resident_auth_client_failed".to_owned())?;
    let expected = hmac_sha256(token, crate::CLIENT_PROOF_LABEL, &nonce);
    if !constant_time_eq(&client_proof, &expected) {
        return Err("native_resident_auth_rejected".into());
    }
    Ok(())
}

fn read_request_header(stream: BoxedResidentStream) -> Result<PendingRequest, String> {
    observe(Phase::ResidentHeaderRead, || {
        read_request_header_inner(stream)
    })
}

fn read_request_header_inner(mut stream: BoxedResidentStream) -> Result<PendingRequest, String> {
    let peer_identity = stream.kernel_peer_identity()?;
    stream
        .set_resident_read_timeout(Some(crate::HEADER_TIMEOUT))
        .map_err(|_| "native_frame_timeout_failed".to_owned())?;
    // The header timeout bounds the whole header, not each read of it.
    let deadline = Instant::now() + crate::HEADER_TIMEOUT;
    let mut header = [0u8; crate::FRAME_HEADER_BYTES];
    crate::hardening::read_exact_by(&mut *stream, &mut header, deadline)
        .map_err(|_| "native_frame_header_failed".to_owned())?;
    if !constant_time_eq(&header[..4], crate::REQUEST_MAGIC) {
        return Err("native_frame_version_mismatch".to_owned());
    }
    let mut request_id = [0u8; crate::FRAME_REQUEST_ID_BYTES];
    request_id.copy_from_slice(&header[4..4 + crate::FRAME_REQUEST_ID_BYTES]);
    let digest_start = 4 + crate::FRAME_REQUEST_ID_BYTES;
    let mut request_digest = [0u8; crate::FRAME_DIGEST_BYTES];
    request_digest.copy_from_slice(&header[digest_start..digest_start + crate::FRAME_DIGEST_BYTES]);
    let length = u32::from_be_bytes(
        header[crate::FRAME_HEADER_BYTES - 4..]
            .try_into()
            .map_err(|_| "native_frame_header_failed".to_owned())?,
    ) as usize;
    if length == 0 || length > crate::MAX_NATIVE_REQUEST_BYTES {
        return Err("native_request_too_large".to_owned());
    }
    let pending = PendingRequest {
        peer_identity,
        stream,
        request_id,
        request_digest,
        length,
        payload_prefix: Vec::new(),
        accepted_at: Instant::now(),
    };
    resident_diagnostics::start(Phase::ResidentDispatchWait);
    Ok(pending)
}

fn write_bound_response(
    stream: &mut dyn ResidentStream,
    request_id: &[u8; crate::FRAME_REQUEST_ID_BYTES],
    response: &[u8],
) -> Result<(), String> {
    observe(Phase::ResidentResponseWrite, || {
        write_bound_response_inner(stream, request_id, response)
    })
}

/// What a finished reply charges to the counters.
#[derive(Debug, PartialEq, Eq)]
enum ReplyAccounting {
    /// The caller got its answer.
    Served,
    /// The reply never reached the caller: one more frame this resident could
    /// not move.
    FrameError,
    /// The reply failed on a request that already recorded a broken frame. A
    /// client that hangs up mid-payload fails the payload read and then the
    /// reply, and that is one broken frame, not two.
    AlreadyCounted,
}

fn reply_accounting(written: &Result<(), String>, frame_error_recorded: bool) -> ReplyAccounting {
    match (written, frame_error_recorded) {
        (Ok(()), _) => ReplyAccounting::Served,
        (Err(_), false) => ReplyAccounting::FrameError,
        (Err(_), true) => ReplyAccounting::AlreadyCounted,
    }
}

/// Reply to one request and account for it.
///
/// A request counts as served only once its reply reached the caller: a write
/// that failed served nobody, and counting it would hide a resident that had
/// stopped answering behind a healthy served total. A failed write is one more
/// frame this resident could not move, except when the same request already
/// recorded a frame error - a client that hung up mid-payload fails the read
/// and then the reply, and that is one broken frame, not two.
fn finish_request(pending: &mut PendingRequest, response: &[u8], frame_error_recorded: bool) {
    let written = write_bound_response(&mut *pending.stream, &pending.request_id, response);
    match reply_accounting(&written, frame_error_recorded) {
        ReplyAccounting::Served => counters::record_served(pending.accepted_at, pending.length),
        ReplyAccounting::FrameError => counters::record_frame_error(),
        ReplyAccounting::AlreadyCounted => {}
    }
}

fn write_bound_response_inner(
    stream: &mut dyn ResidentStream,
    request_id: &[u8; crate::FRAME_REQUEST_ID_BYTES],
    response: &[u8],
) -> Result<(), String> {
    if response.is_empty() || response.len() > crate::MAX_NATIVE_RESPONSE_BYTES {
        return Err("native_response_too_large".to_owned());
    }
    stream
        .set_resident_write_timeout(Some(crate::RESPONSE_TIMEOUT))
        .map_err(|_| "native_frame_timeout_failed".to_owned())?;
    let deadline = Instant::now() + crate::RESPONSE_TIMEOUT;
    let digest = Sha256::digest(response);
    let mut header = Vec::with_capacity(crate::FRAME_HEADER_BYTES);
    header.extend_from_slice(crate::RESPONSE_MAGIC);
    header.extend_from_slice(request_id);
    header.extend_from_slice(&digest);
    header.extend_from_slice(&(response.len() as u32).to_be_bytes());
    crate::hardening::write_all_by(&mut *stream, &header, deadline)
        .map_err(|error| crate::hardening::write_error(&error, "native_frame_write_failed"))?;
    crate::hardening::write_all_by(&mut *stream, response, deadline)
        .map_err(|error| crate::hardening::write_error(&error, "native_frame_write_failed"))?;
    stream
        .flush()
        .map_err(|error| crate::hardening::write_error(&error, "native_frame_write_failed"))?;
    Ok(())
}

fn write_overload(pending: &mut PendingRequest) {
    resident_diagnostics::finish_since(
        Phase::ResidentDispatchWait,
        Status::Error,
        pending.accepted_at,
    );
    crate::resident_health_op::record_overload();
    let response = crate::resident_protocol::error_response("native_overloaded", true);
    finish_request(pending, &response, false);
}

/// Continuation I/O can run for the caller's whole minute. Keep it off the
/// evaluation workers. Two side threads are enough; a third fails closed.
const CODEX_RESUME_RETRY_SIDE_LIMIT: usize = 2;
static CODEX_RESUME_RETRY_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

struct ContinuationSlot;

impl Drop for ContinuationSlot {
    fn drop(&mut self) {
        CODEX_RESUME_RETRY_IN_FLIGHT.fetch_sub(1, Ordering::AcqRel);
    }
}

fn reserve_continuation_slot() -> bool {
    let mut in_flight = CODEX_RESUME_RETRY_IN_FLIGHT.load(Ordering::Acquire);
    while in_flight < CODEX_RESUME_RETRY_SIDE_LIMIT {
        match CODEX_RESUME_RETRY_IN_FLIGHT.compare_exchange_weak(
            in_flight,
            in_flight + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(observed) => in_flight = observed,
        }
    }
    false
}

/// Only a resume retry sends a continuation; the other resume calls are
/// store reads and writes that stay on the evaluation workers.
fn is_codex_resume_retry(request: &[u8]) -> bool {
    crate::strict_json_value(request).is_ok_and(|value| {
        value.get("operation").and_then(serde_json::Value::as_str) == Some("codex_request_resume")
            && value
                .get("request")
                .and_then(|request| request.get("call"))
                .and_then(serde_json::Value::as_str)
                == Some("retry")
    })
}

/// Settle one evaluation into the bytes its client is answered with. An
/// evaluation that panicked is answered the way any other failure is — a
/// fixed, non-retryable code and a counted panic — so the worker that ran it
/// keeps serving instead of taking the connection, or the pool, down with it.
fn settle_evaluation(outcome: thread::Result<Result<Vec<u8>, String>>) -> Vec<u8> {
    match outcome {
        Ok(Ok(response)) => response,
        Ok(Err(reason)) => crate::resident_protocol::safe_error_response(&reason, false),
        Err(_panic) => {
            counters::record_panic();
            crate::resident_protocol::error_response("native_runtime_panicked", false)
        }
    }
}

/// The slot is already reserved. A thread that cannot be started drops the
/// connection and releases the slot.
fn spawn_codex_resume_retry(
    pending: PendingRequest,
    request: Vec<u8>,
    policy_store: Option<Arc<crate::policy_store::PolicySnapshotStore>>,
) {
    if thread::Builder::new()
        .spawn(move || {
            let slot = ContinuationSlot;
            let response = settle_evaluation(catch_unwind(AssertUnwindSafe(|| {
                observe(Phase::ResidentEvaluate, || {
                    crate::resident_protocol::evaluate_resident_bytes(
                        &request,
                        policy_store.as_deref(),
                    )
                })
            })));
            // Free the slot before replying so a caller that sends again on
            // receipt never sees this finished continuation as in flight.
            drop(slot);
            let mut pending = pending;
            finish_request(&mut pending, &response, false);
        })
        .is_err()
    {
        CODEX_RESUME_RETRY_IN_FLIGHT.fetch_sub(1, Ordering::AcqRel);
    }
}

fn handle_pending_request(
    mut pending: PendingRequest,
    policy_store: Option<Arc<crate::policy_store::PolicySnapshotStore>>,
    control_dispatch: Option<&SyncSender<PendingRequest>>,
    context_lane: Option<&Arc<context::Lane>>,
) {
    let expired = crate::hardening::request_expired(pending.accepted_at);
    resident_diagnostics::finish_since(
        Phase::ResidentDispatchWait,
        if expired { Status::Error } else { Status::Ok },
        pending.accepted_at,
    );
    if expired {
        counters::record_deadline_exceeded();
        let response =
            crate::resident_protocol::error_response("native_request_deadline_exceeded", true);
        finish_request(&mut pending, &response, false);
        return;
    }
    let _ = pending
        .stream
        .set_resident_read_timeout(Some(crate::PAYLOAD_TIMEOUT));
    // A payload may be megabytes, so its read ends at whichever comes first:
    // the payload timeout or what is left of the request's total budget. The
    // deadline is checked between reads, so a drip-feeding client cannot keep
    // an evaluation worker past the budget it was admitted under.
    let payload_deadline = (Instant::now() + crate::PAYLOAD_TIMEOUT)
        .min(pending.accepted_at + crate::hardening::TOTAL_REQUEST_BUDGET);
    let mut frame_error_recorded = false;
    let mut request = std::mem::take(&mut pending.payload_prefix);
    let prefix_length = request.len();
    request.resize(pending.length, 0);
    let response = if observe(Phase::ResidentPayloadRead, || {
        crate::hardening::read_exact_by(
            &mut *pending.stream,
            &mut request[prefix_length..],
            payload_deadline,
        )
    })
    .is_err()
    {
        counters::record_frame_error();
        frame_error_recorded = true;
        crate::resident_protocol::error_response("native_frame_read_failed", false)
    } else {
        let digest = Sha256::digest(&request);
        if !constant_time_eq(&digest, &pending.request_digest) {
            counters::record_digest_mismatch();
            crate::resident_protocol::error_response("native_request_digest_mismatch", false)
        } else if let Some(lane) = context_lane.filter(|_| context::is_request(&request)) {
            lane.enqueue(pending, request, policy_store);
            return;
        } else if let Some(sender) = control_dispatch.filter(|_| control::is_request(&request)) {
            // A fragmented request is routed only after its complete frame is
            // authenticated. Move its buffer rather than retaining a copy.
            pending.payload_prefix = request;
            control::enqueue(sender, pending);
            return;
        } else if is_codex_resume_retry(&request) {
            if reserve_continuation_slot() {
                spawn_codex_resume_retry(pending, request, policy_store.clone());
            } else {
                write_overload(&mut pending);
            }
            return;
        } else {
            settle_evaluation(catch_unwind(AssertUnwindSafe(|| {
                observe(Phase::ResidentEvaluate, || {
                    request_cancellation::evaluate(&mut pending, &request, policy_store.as_deref())
                })
            })))
        }
    };
    let is_shutdown_request = crate::strict_json_value(&request).is_ok_and(|value| {
        value.get("operation").and_then(serde_json::Value::as_str) == Some("shutdown")
    });
    finish_request(&mut pending, &response, frame_error_recorded);
    if is_shutdown_request {
        crate::managed_resident::shutdown_response_sent();
    }
}

pub(crate) struct ResidentAdmission {
    primary: SyncSender<BoxedResidentStream>,
    overflow: SyncSender<BoxedResidentStream>,
    workers: Vec<thread::JoinHandle<()>>,
    context_lane: Arc<context::Lane>,
    policy_store: Option<Arc<crate::policy_store::PolicySnapshotStore>>,
}

pub(crate) fn drain_resident_workers(admission: ResidentAdmission) {
    let ResidentAdmission {
        primary,
        overflow,
        workers,
        context_lane,
        policy_store,
    } = admission;
    context_lane.close();
    if let Some(store) = &policy_store {
        store.context_assistance().shutdown();
    }
    drop(primary);
    drop(overflow);
    worker_pool::drain(workers, Duration::from_secs(2));
    context_lane.drain();
    let deadline = Instant::now() + Duration::from_secs(2);
    while CODEX_RESUME_RETRY_IN_FLIGHT.load(Ordering::Acquire) > 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
}

fn retry_overflow_admissions(
    primary: SyncSender<BoxedResidentStream>,
    overflow: Receiver<BoxedResidentStream>,
) {
    while let Ok(mut stream) = overflow.recv() {
        let deadline = Instant::now() + crate::AUTH_TIMEOUT;
        loop {
            match primary.try_send(stream) {
                Ok(()) => break,
                Err(TrySendError::Disconnected(_)) => return,
                Err(TrySendError::Full(returned)) => {
                    stream = returned;
                    if Instant::now() >= deadline {
                        break;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }
}

/// One lane's queue charge, held from before the send until the request is
/// either in the channel or definitively not going into it.
///
/// The charge is taken before `try_send` because a worker can receive the
/// request and release its charge before `try_send` returns to this thread. A
/// release that ran ahead of its own charge saturates at zero, so the charge
/// that followed it would never be released and the lane would read one
/// request too deep for the rest of the process. Releasing on drop also means
/// a new failure branch cannot forget the release.
pub(super) struct QueueCharge(Option<QueueLane>);

impl QueueCharge {
    pub(super) fn take(lane: QueueLane) -> Self {
        counters::enter_queue(lane);
        Self(Some(lane))
    }

    /// The request reached the channel, so the worker that receives it owns
    /// the release from here.
    pub(super) fn queued(mut self) {
        self.0 = None;
    }
}

impl Drop for QueueCharge {
    fn drop(&mut self) {
        if let Some(lane) = self.0 {
            counters::leave_queue(lane);
        }
    }
}

/// Auth workers only authenticate and read the frame header. Evaluation runs
/// on the evaluation pool even when the whole payload arrived with the header:
/// an auth worker held by a slow evaluation cannot answer the next caller's
/// challenge, and that caller gives up after `AUTH_TIMEOUT` and falls back to
/// the daemon. Concurrent hooks then miss the direct lane in bursts.
///
/// A full evaluation queue leaves a fully buffered request on the auth
/// worker, as before the hand-off: answering `native_overloaded` would turn
/// saturation into a hook failure. A fragmented request is still answered
/// with overload so no auth worker ever waits on a client's payload.
fn dispatch_authenticated(
    pending: PendingRequest,
    control_sender: &SyncSender<PendingRequest>,
    evaluation_sender: &SyncSender<PendingRequest>,
    policy_store: Option<&Arc<crate::policy_store::PolicySnapshotStore>>,
    context_lane: &Arc<context::Lane>,
) {
    if pending.payload_prefix.len() == pending.length
        && control::is_request(&pending.payload_prefix)
    {
        control::enqueue(control_sender, pending);
        return;
    }
    let charge = QueueCharge::take(QueueLane::Evaluation);
    match evaluation_sender.try_send(pending) {
        Ok(()) => charge.queued(),
        // A fully buffered request needs no further reads, so the auth worker
        // evaluates it as it did before the hand-off existed. A fragmented one
        // would hold the auth worker in a payload read, so it is answered with
        // retryable overload instead.
        Err(TrySendError::Full(returned)) if returned.payload_prefix.len() == returned.length => {
            drop(charge);
            handle_pending_request(
                returned,
                policy_store.cloned(),
                Some(control_sender),
                Some(context_lane),
            );
        }
        Err(TrySendError::Full(mut returned)) => {
            drop(charge);
            write_overload(&mut returned);
        }
        Err(TrySendError::Disconnected(returned)) => {
            drop(charge);
            resident_diagnostics::finish_since(
                Phase::ResidentDispatchWait,
                Status::Error,
                returned.accepted_at,
            );
        }
    }
}

/// The worker count and queue capacity of each dispatch lane, as
/// [`start_resident_workers`] sizes them: evaluation first, then control.
///
/// A caller reading a queue depth or an overload count needs the lane it was
/// measured against, and only this module knows how the two lanes divide the
/// evaluation budget.
pub(crate) fn lane_shape() -> ((usize, usize), (usize, usize)) {
    (
        (
            crate::evaluation_workers() - control::WORKERS,
            crate::evaluation_queue_capacity() - control::capacity(),
        ),
        (control::WORKERS, control::capacity()),
    )
}

pub(crate) fn start_resident_workers(
    token: Arc<[u8; crate::AUTH_TOKEN_BYTES]>,
    policy_store: Option<Arc<crate::policy_store::PolicySnapshotStore>>,
) -> ResidentAdmission {
    crate::resident_health_op::mark_serving();
    let context_lane = Arc::new(context::Lane::default());
    let admission_store = policy_store.clone();
    let (control_sender, mut workers) = control::start(policy_store.clone());
    let (evaluation_sender, evaluation_receiver) =
        sync_channel::<PendingRequest>(crate::evaluation_queue_capacity() - control::capacity());
    let evaluation_policy_store = policy_store.clone();
    let evaluation_control_sender = control_sender.clone();
    let evaluation_context_lane = Arc::clone(&context_lane);
    workers.extend(spawn_workers(
        crate::evaluation_workers() - control::WORKERS,
        evaluation_receiver,
        move |pending| {
            counters::leave_queue(QueueLane::Evaluation);
            handle_pending_request(
                pending,
                evaluation_policy_store.clone(),
                Some(&evaluation_control_sender),
                Some(&evaluation_context_lane),
            );
        },
    ));

    let (authentication_sender, authentication_receiver) =
        sync_channel::<BoxedResidentStream>(crate::auth_queue_capacity());
    let authentication_context_lane = Arc::clone(&context_lane);
    workers.extend(spawn_workers(
        crate::auth_workers(),
        authentication_receiver,
        move |mut stream| {
            if observe(Phase::ResidentAuthenticate, || {
                authenticate_resident_stream(&mut *stream, &token)
            })
            .is_err()
            {
                counters::record_auth_failure();
                return;
            }
            let mut pending = match read_request_header(stream) {
                Ok(value) => value,
                Err(_) => {
                    counters::record_frame_error();
                    return;
                }
            };
            pending
                .payload_prefix
                .resize(pending.length.min(crate::AUTHENTICATED_PREFETCH_BYTES), 0);
            let available = match pending
                .stream
                .try_read_available(&mut pending.payload_prefix)
            {
                Ok(value) => value,
                Err(_) => {
                    counters::record_frame_error();
                    return;
                }
            };
            pending.payload_prefix.truncate(available);
            dispatch_authenticated(
                pending,
                &control_sender,
                &evaluation_sender,
                policy_store.as_ref(),
                &authentication_context_lane,
            );
        },
    ));
    let overflow_primary = authentication_sender.clone();
    let (overflow_sender, overflow_receiver) = sync_channel(crate::auth_queue_capacity());
    workers.push(thread::spawn(move || {
        retry_overflow_admissions(overflow_primary, overflow_receiver)
    }));
    ResidentAdmission {
        primary: authentication_sender,
        overflow: overflow_sender,
        workers,
        context_lane,
        policy_store: admission_store,
    }
}

pub(crate) fn admit_connection(
    admission: &ResidentAdmission,
    stream: BoxedResidentStream,
) -> Result<(), String> {
    match admission.primary.try_send(stream) {
        Ok(()) => Ok(()),
        Err(TrySendError::Disconnected(_stream)) => {
            Err("native_resident_worker_pool_stopped".to_owned())
        }
        Err(TrySendError::Full(stream)) => match admission.overflow.try_send(stream) {
            Ok(()) => Ok(()),
            Err(TrySendError::Disconnected(_stream)) => {
                Err("native_resident_worker_pool_stopped".to_owned())
            }
            Err(TrySendError::Full(_stream)) => Ok(()),
        },
    }
}

#[cfg(test)]
#[path = "resident_transport_peer_tests.rs"]
mod peer_tests;

#[cfg(test)]
#[path = "resident_transport_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "resident_transport_continuation_tests.rs"]
mod continuation_tests;

#[cfg(test)]
#[path = "resident_transport_hardening_tests.rs"]
mod hardening_tests;

#[cfg(test)]
#[path = "resident_transport_panic_tests.rs"]
mod panic_tests;
