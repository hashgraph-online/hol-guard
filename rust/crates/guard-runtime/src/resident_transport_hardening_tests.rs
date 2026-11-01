//! Transport hardening: malformed frames, slow clients and an auth flood.
//!
//! Every case here is a connection that never becomes a request. A malformed
//! frame has to be refused before its payload is read, a client that stops
//! sending has to lose its worker on a timeout rather than keep it, and a
//! flood of connections that never authenticate has to leave the accept loop
//! running.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// A peer that sends exactly `input` and then stops, the way a slow client
/// does. It records what the transport wrote back, every read timeout the
/// transport set, and how far the transport read, so a bound can be asserted
/// without waiting for one and a byte the transport must not read can be
/// supplied and then shown to be untouched.
///
/// `chunk` and `pace` turn it into a drip feed: a client that answers every
/// read with one byte, slowly enough that a per-read timeout would be renewed
/// each time.
struct ScriptedStream {
    input: Vec<u8>,
    read_cursor: Arc<AtomicUsize>,
    chunk: usize,
    pace: Duration,
    written: Arc<Mutex<Vec<u8>>>,
    read_timeouts: Arc<Mutex<Vec<Option<Duration>>>>,
}

impl ScriptedStream {
    fn new(input: Vec<u8>) -> Self {
        Self {
            input,
            read_cursor: Arc::new(AtomicUsize::new(0)),
            chunk: usize::MAX,
            pace: Duration::ZERO,
            written: Arc::new(Mutex::new(Vec::new())),
            read_timeouts: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// A client that keeps sending, one `chunk` every `pace`, for as long as
    /// the transport keeps reading.
    fn paced(input: Vec<u8>, chunk: usize, pace: Duration) -> Self {
        Self {
            chunk,
            pace,
            ..Self::new(input)
        }
    }
}

impl Read for ScriptedStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.pace.is_zero() {
            thread::sleep(self.pace);
        }
        let cursor = self.read_cursor.load(Ordering::Acquire);
        let left = &self.input[cursor..];
        if left.is_empty() {
            // The peer is still connected and still silent, which is what the
            // socket reports once the read timeout expires.
            return Err(io::Error::new(io::ErrorKind::TimedOut, "stalled peer"));
        }
        let taken = left.len().min(buf.len()).min(self.chunk);
        buf[..taken].copy_from_slice(&left[..taken]);
        self.read_cursor.store(cursor + taken, Ordering::Release);
        Ok(taken)
    }
}

impl Write for ScriptedStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ResidentStream for ScriptedStream {
    fn set_resident_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.read_timeouts.lock().unwrap().push(timeout);
        Ok(())
    }

    fn set_resident_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_resident_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        Ok(())
    }
}

/// Every read of an exchange is given a timeout of its own, and none of them
/// is given more than the bound the exchange started with: a read that kept
/// the full bound after the deadline had nearly passed would hold its worker
/// for up to twice what the exchange was admitted under.
fn within_bound(recorded: &[Option<Duration>], bound: Duration) -> bool {
    !recorded.is_empty()
        && recorded
            .iter()
            .all(|timeout| matches!(timeout, Some(value) if !value.is_zero() && *value <= bound))
}

fn frame_header(magic: &[u8; 4], body: &[u8], length: u32) -> Vec<u8> {
    let mut header = Vec::with_capacity(crate::FRAME_HEADER_BYTES);
    header.extend_from_slice(magic);
    header.extend_from_slice(&[3u8; crate::FRAME_REQUEST_ID_BYTES]);
    header.extend_from_slice(&Sha256::digest(body));
    header.extend_from_slice(&length.to_be_bytes());
    header
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// `PendingRequest` holds a live stream and has no `Debug`, so a refused header
/// is read out of the `Err` arm rather than through `expect_err`.
fn header_error(stream: ScriptedStream, context: &str) -> String {
    match read_request_header_inner(Box::new(stream)) {
        Ok(_) => panic!("{context}"),
        Err(error) => error,
    }
}

#[test]
fn another_protocols_magic_is_refused_before_its_payload_is_read() {
    let body = br#"{"operation":"pre_tool_decide"}"#;
    let mut frame = frame_header(crate::RESPONSE_MAGIC, body, body.len() as u32);
    frame.extend_from_slice(body);
    let stream = ScriptedStream::new(frame);

    let error = header_error(stream, "magic must not match");

    assert_eq!(error, "native_frame_version_mismatch");
}

#[test]
fn a_truncated_header_never_becomes_a_request() {
    let body = b"{}";
    let mut frame = frame_header(crate::REQUEST_MAGIC, body, body.len() as u32);
    frame.truncate(crate::FRAME_HEADER_BYTES - 1);
    let stream = ScriptedStream::new(frame);

    let error = header_error(stream, "header is short");

    // The last byte never arrives, so the read ends on the header timeout
    // instead of waiting for a peer that has stopped sending.
    assert_eq!(error, "native_frame_header_failed");
}

#[test]
fn a_frame_that_declares_no_payload_is_refused() {
    let stream = ScriptedStream::new(frame_header(crate::REQUEST_MAGIC, b"", 0));

    let error = header_error(stream, "empty frame");

    assert_eq!(error, "native_request_too_large");
}

#[test]
fn a_length_past_the_request_ceiling_is_refused_without_reading_it() {
    let length = u32::try_from(crate::MAX_NATIVE_REQUEST_BYTES + 1).expect("ceiling fits in u32");
    let mut frame = frame_header(crate::REQUEST_MAGIC, b"", length);
    // Payload bytes the transport must not touch. Without them a read past the
    // header would end on the stalled-peer error and look the same.
    frame.extend_from_slice(&[7u8; 64]);
    let stream = ScriptedStream::new(frame);
    let cursor = Arc::clone(&stream.read_cursor);

    let error = header_error(stream, "oversize frame");

    // Nothing is allocated for the declared length and no payload byte is
    // read, so a header claiming more than the ceiling costs the header only.
    assert_eq!(error, "native_request_too_large");
    assert_eq!(cursor.load(Ordering::Acquire), crate::FRAME_HEADER_BYTES);
}

#[test]
fn the_header_read_is_bounded_by_the_header_timeout() {
    let body = br#"{"operation":"pre_tool_decide"}"#;
    let stream = ScriptedStream::new(frame_header(crate::REQUEST_MAGIC, body, body.len() as u32));
    let timeouts = Arc::clone(&stream.read_timeouts);

    read_request_header_inner(Box::new(stream)).expect("header is well formed");

    // A client that sends its header one byte at a time gets the transport's
    // bound, not a worker for as long as it keeps the connection open.
    let timeouts = timeouts.lock().unwrap();
    assert_eq!(timeouts[0], Some(crate::HEADER_TIMEOUT));
    assert!(within_bound(&timeouts, crate::HEADER_TIMEOUT));
}

#[test]
fn a_header_fed_one_byte_at_a_time_still_ends_on_the_header_bound() {
    // A socket read timeout bounds one read. `read_exact` makes as many reads
    // as it needs, so a client that sends a byte before each timeout would
    // renew the bound for as long as it liked and hold an authentication
    // worker the whole time. The header has a deadline of its own, so this
    // client loses its worker having sent part of a header.
    let body = br#"{"operation":"pre_tool_decide"}"#;
    let frame = frame_header(crate::REQUEST_MAGIC, body, body.len() as u32);
    let stream = ScriptedStream::paced(frame, 1, crate::HEADER_TIMEOUT / 8);
    let cursor = Arc::clone(&stream.read_cursor);

    let started = Instant::now();
    let error = header_error(stream, "a drip-fed header must not become a request");

    assert_eq!(error, "native_frame_header_failed");
    assert!(cursor.load(Ordering::Acquire) < crate::FRAME_HEADER_BYTES);
    // Unbounded, this client would have held the worker for 72 reads.
    assert!(started.elapsed() < crate::HEADER_TIMEOUT * 4);
}

fn pending(stream: ScriptedStream, length: usize, prefix: &[u8], digest: &[u8]) -> PendingRequest {
    let mut request_digest = [0u8; crate::FRAME_DIGEST_BYTES];
    request_digest.copy_from_slice(digest);
    PendingRequest {
        peer_identity: None,
        stream: Box::new(stream),
        request_id: [3u8; crate::FRAME_REQUEST_ID_BYTES],
        request_digest,
        length,
        payload_prefix: prefix.to_vec(),
        accepted_at: Instant::now(),
    }
}

#[test]
fn a_payload_that_does_not_match_its_header_digest_is_never_evaluated() {
    let body = br#"{"operation":"pre_tool_decide"}"#;
    let stream = ScriptedStream::new(Vec::new());
    let written = Arc::clone(&stream.written);
    let request = pending(stream, body.len(), body, &Sha256::digest(b"another body"));

    handle_pending_request(request, None, None, None);

    let written = written.lock().unwrap();
    assert!(contains(&written, b"native_request_digest_mismatch"));
    assert!(contains(&written, b"\"retryable\":false"));
}

#[test]
fn a_payload_the_client_stops_sending_ends_on_the_payload_timeout() {
    let body = br#"{"operation":"pre_tool_decide"}"#;
    let stream = ScriptedStream::new(Vec::new());
    let written = Arc::clone(&stream.written);
    let timeouts = Arc::clone(&stream.read_timeouts);
    // The header promised the whole body; only its first ten bytes arrived.
    let request = pending(stream, body.len(), &body[..10], &Sha256::digest(body));

    handle_pending_request(request, None, None, None);

    let recorded = timeouts.lock().unwrap();
    assert_eq!(recorded[0], Some(crate::PAYLOAD_TIMEOUT));
    assert!(within_bound(&recorded, crate::PAYLOAD_TIMEOUT));
    assert!(contains(
        &written.lock().unwrap(),
        b"native_frame_read_failed"
    ));
}

#[test]
fn a_request_that_waited_past_its_budget_is_answered_without_reading_its_payload() {
    let body = br#"{"operation":"pre_tool_decide"}"#;
    let stream = ScriptedStream::new(body.to_vec());
    let written = Arc::clone(&stream.written);
    let cursor = Arc::clone(&stream.read_cursor);
    let mut request = pending(stream, body.len(), b"", &Sha256::digest(body));
    request.accepted_at = Instant::now() - crate::hardening::TOTAL_REQUEST_BUDGET;

    handle_pending_request(request, None, None, None);

    let written = written.lock().unwrap();
    assert!(contains(&written, b"native_request_deadline_exceeded"));
    // Retryable, because the caller may simply have arrived in a burst.
    assert!(contains(&written, b"\"retryable\":true"));
    // The payload was there to be read and the expired request left it alone.
    assert_eq!(cursor.load(Ordering::Acquire), 0);
}

#[test]
fn a_payload_fed_one_byte_at_a_time_ends_on_what_is_left_of_the_budget() {
    // The payload timeout is the larger of the two bounds, so a drip-feeding
    // client is held to whatever remains of the request's total budget: it
    // cannot keep an evaluation worker past the budget it was admitted under.
    let body = vec![b'x'; 4096];
    let stream = ScriptedStream::paced(body.clone(), 1, Duration::from_millis(2));
    let written = Arc::clone(&stream.written);
    let cursor = Arc::clone(&stream.read_cursor);
    let mut request = pending(stream, body.len(), b"", &Sha256::digest(&body));
    let left = Duration::from_millis(200);
    request.accepted_at = Instant::now() - (crate::hardening::TOTAL_REQUEST_BUDGET - left);

    let started = Instant::now();
    handle_pending_request(request, None, None, None);

    assert!(contains(
        &written.lock().unwrap(),
        b"native_frame_read_failed"
    ));
    assert!(cursor.load(Ordering::Acquire) < body.len());
    assert!(started.elapsed() < left * 4);
}

#[test]
fn a_flood_of_connections_that_never_authenticate_leaves_accept_running() {
    // Both queues are full and no worker drains them, which is what an auth
    // flood looks like from the accept loop. Admission has to keep returning
    // instead of blocking the only thread that can accept the next caller.
    let (primary, _primary_rx) = sync_channel(1);
    primary
        .try_send(Box::new(ScriptedStream::new(Vec::new())) as BoxedResidentStream)
        .expect("seed the auth queue");
    let (overflow, _overflow_rx) = sync_channel(1);
    overflow
        .try_send(Box::new(ScriptedStream::new(Vec::new())) as BoxedResidentStream)
        .expect("seed the overflow queue");
    let admission = ResidentAdmission {
        primary,
        overflow,
        workers: Vec::new(),
        context_lane: Arc::new(context::Lane::default()),
        policy_store: None,
    };

    let started = Instant::now();
    for _ in 0..256 {
        admit_connection(&admission, Box::new(ScriptedStream::new(Vec::new())))
            .expect("accept keeps moving");
    }

    assert!(started.elapsed() < Duration::from_secs(1));
    drop(admission);
}

#[cfg(unix)]
const TOKEN: [u8; crate::AUTH_TOKEN_BYTES] = [5u8; crate::AUTH_TOKEN_BYTES];

#[cfg(unix)]
/// Returns the server side of a pair whose client half is scripted by
/// `client`, and the client half so it stays open while the server reads.
fn authenticate_against(
    client: impl FnOnce(&mut UnixStream) + Send + 'static,
) -> (Result<(), String>, Duration, thread::JoinHandle<()>) {
    let (mut server, mut peer) = UnixStream::pair().expect("socket pair");
    let handle = thread::spawn(move || {
        // A peer that waits forever for a proof the server never sends would
        // wedge the test run rather than fail it.
        peer.set_read_timeout(Some(peer_patience()))
            .expect("bound the peer's own reads");
        client(&mut peer);
        // Hold the connection open: a client that disconnects would end
        // the read on EOF rather than on the auth timeout under test.
        thread::sleep(peer_patience());
    });
    let started = Instant::now();
    let result = authenticate_resident_stream(&mut server, &TOKEN);
    (result, started.elapsed(), handle)
}

/// Long enough that an answer arriving inside it cannot have come from the
/// peer closing, and short enough that a wedged exchange fails the test.
#[cfg(unix)]
fn peer_patience() -> Duration {
    crate::AUTH_TIMEOUT * 3
}

#[cfg(unix)]
#[test]
fn a_client_that_never_sends_its_nonce_loses_its_worker_on_the_auth_timeout() {
    let (result, elapsed, handle) = authenticate_against(|_peer| {});

    assert_eq!(
        result.expect_err("a silent client must not authenticate"),
        "native_resident_auth_nonce_failed"
    );
    // The peer is still connected and still holding the socket open, so this
    // answer came from the auth deadline rather than from a closed peer.
    assert!(elapsed < peer_patience());
    handle.join().expect("client thread");
}

#[cfg(unix)]
#[test]
fn a_client_that_stops_after_its_nonce_loses_its_worker_on_the_auth_timeout() {
    let (result, elapsed, handle) = authenticate_against(|peer| {
        peer.write_all(&[1u8; crate::AUTH_NONCE_BYTES])
            .expect("send the nonce");
        let mut proof = [0u8; crate::AUTH_PROOF_BYTES];
        peer.read_exact(&mut proof).expect("read the server proof");
    });

    assert_eq!(
        result.expect_err("half an exchange must not authenticate"),
        "native_resident_auth_client_failed"
    );
    assert!(elapsed < peer_patience());
    handle.join().expect("client thread");
}

#[cfg(unix)]
#[test]
fn a_client_proof_for_another_token_is_rejected() {
    let (result, _elapsed, handle) = authenticate_against(|peer| {
        let nonce = [1u8; crate::AUTH_NONCE_BYTES];
        peer.write_all(&nonce).expect("send the nonce");
        let mut proof = [0u8; crate::AUTH_PROOF_BYTES];
        peer.read_exact(&mut proof).expect("read the server proof");
        assert_eq!(
            proof.to_vec(),
            hmac_sha256(&TOKEN, crate::SERVER_PROOF_LABEL, &nonce).to_vec(),
            "the server proves the token before the client answers"
        );
        let other = [6u8; crate::AUTH_TOKEN_BYTES];
        peer.write_all(&hmac_sha256(&other, crate::CLIENT_PROOF_LABEL, &nonce))
            .expect("send a proof for another token");
    });

    assert_eq!(
        result.expect_err("another token must not authenticate"),
        "native_resident_auth_rejected"
    );
    handle.join().expect("client thread");
}

#[cfg(unix)]
#[test]
fn a_read_waits_only_for_what_is_left_of_the_deadline() {
    // A deadline checked between reads is not enough on a real socket: the
    // read itself blocks for whatever timeout the socket carries, so a client
    // that sends its last byte just before the deadline sends the transport
    // into one more full-length wait. The baseline here is twenty times the
    // deadline, which is the gap that read would have held its worker for.
    let (mut server, _peer) = UnixStream::pair().expect("socket pair");
    let left = Duration::from_millis(100);
    server
        .set_read_timeout(Some(left * 20))
        .expect("a baseline far past the deadline");
    let mut buffer = [0u8; 8];

    let started = Instant::now();
    let error = crate::hardening::read_exact_by(&mut server, &mut buffer, Instant::now() + left)
        .expect_err("a silent peer must not be waited for");

    // The peer is still open, so this ended on the deadline, not on EOF.
    assert!(started.elapsed() < left * 5);
    assert!(matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));
}
