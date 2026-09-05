use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::net::UnixStream;

pub(crate) trait ResidentStream: Read + Write + Send {
    fn set_resident_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_resident_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn try_read_available(&mut self, output: &mut [u8]) -> io::Result<usize>;
    fn configure_low_latency(&self) -> io::Result<()> {
        Ok(())
    }
}

impl ResidentStream for TcpStream {
    fn set_resident_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }

    fn set_resident_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, timeout)
    }

    fn try_read_available(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.set_nonblocking(true)?;
        let result = self.read(output);
        let restore = self.set_nonblocking(false);
        match (result, restore) {
            (Err(error), Ok(())) if error.kind() == io::ErrorKind::WouldBlock => Ok(0),
            (result, Ok(())) => result,
            (_, Err(error)) => Err(error),
        }
    }

    fn configure_low_latency(&self) -> io::Result<()> {
        self.set_nodelay(true)
    }
}

#[cfg(unix)]
impl ResidentStream for UnixStream {
    fn set_resident_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        UnixStream::set_read_timeout(self, timeout)
    }

    fn set_resident_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        UnixStream::set_write_timeout(self, timeout)
    }

    fn try_read_available(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.set_nonblocking(true)?;
        let result = self.read(output);
        let restore = self.set_nonblocking(false);
        match (result, restore) {
            (Err(error), Ok(())) if error.kind() == io::ErrorKind::WouldBlock => Ok(0),
            (result, Ok(())) => result,
            (_, Err(error)) => Err(error),
        }
    }
}

pub(crate) type BoxedResidentStream = Box<dyn ResidentStream>;

pub(crate) struct PendingRequest {
    pub(crate) stream: BoxedResidentStream,
    pub(crate) request_id: [u8; crate::FRAME_REQUEST_ID_BYTES],
    pub(crate) request_digest: [u8; crate::FRAME_DIGEST_BYTES],
    pub(crate) length: usize,
    pub(crate) payload_prefix: Vec<u8>,
    pub(crate) accepted_at: Instant,
}

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left_byte, right_byte) in left.iter().zip(right) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

pub(crate) fn hmac_sha256(key: &[u8], label: &[u8], nonce: &[u8]) -> [u8; crate::AUTH_PROOF_BYTES] {
    const BLOCK_BYTES: usize = 64;
    let mut key_block = [0u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        let digest = Sha256::digest(key);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; BLOCK_BYTES];
    let mut outer_pad = [0x5cu8; BLOCK_BYTES];
    for index in 0..BLOCK_BYTES {
        inner_pad[index] ^= key_block[index];
        outer_pad[index] ^= key_block[index];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(label);
    inner.update(nonce);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    let digest = outer.finalize();
    let mut proof = [0u8; crate::AUTH_PROOF_BYTES];
    proof.copy_from_slice(&digest);
    proof
}

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

    let mut nonce = [0u8; crate::AUTH_NONCE_BYTES];
    stream
        .read_exact(&mut nonce)
        .map_err(|_| "native_resident_auth_nonce_failed".to_owned())?;
    let server_proof = hmac_sha256(token, crate::SERVER_PROOF_LABEL, &nonce);
    stream
        .write_all(&server_proof)
        .map_err(|_| "native_resident_auth_proof_failed".to_owned())?;

    let mut client_proof = [0u8; crate::AUTH_PROOF_BYTES];
    stream
        .read_exact(&mut client_proof)
        .map_err(|_| "native_resident_auth_client_failed".to_owned())?;
    let expected = hmac_sha256(token, crate::CLIENT_PROOF_LABEL, &nonce);
    if !constant_time_eq(&client_proof, &expected) {
        return Err("native_resident_auth_rejected".into());
    }
    Ok(())
}

fn read_request_header(mut stream: BoxedResidentStream) -> Result<PendingRequest, String> {
    stream
        .set_resident_read_timeout(Some(crate::HEADER_TIMEOUT))
        .map_err(|_| "native_frame_timeout_failed".to_owned())?;
    let mut header = [0u8; crate::FRAME_HEADER_BYTES];
    stream
        .read_exact(&mut header)
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
    Ok(PendingRequest {
        stream,
        request_id,
        request_digest,
        length,
        payload_prefix: Vec::new(),
        accepted_at: Instant::now(),
    })
}

fn write_bound_response(
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
    let digest = Sha256::digest(response);
    let mut header = Vec::with_capacity(crate::FRAME_HEADER_BYTES);
    header.extend_from_slice(crate::RESPONSE_MAGIC);
    header.extend_from_slice(request_id);
    header.extend_from_slice(&digest);
    header.extend_from_slice(&(response.len() as u32).to_be_bytes());
    stream
        .write_all(&header)
        .map_err(|error| crate::hardening::write_error(&error, "native_frame_write_failed"))?;
    stream
        .write_all(response)
        .map_err(|error| crate::hardening::write_error(&error, "native_frame_write_failed"))?;
    stream
        .flush()
        .map_err(|error| crate::hardening::write_error(&error, "native_frame_write_failed"))?;
    Ok(())
}

fn write_overload(pending: &mut PendingRequest) {
    let response = crate::resident_protocol::error_response("native_overloaded", true);
    let _ = write_bound_response(&mut *pending.stream, &pending.request_id, &response);
}

fn handle_pending_request(
    mut pending: PendingRequest,
    policy_store: Option<&crate::policy_store::PolicySnapshotStore>,
) {
    if crate::hardening::request_expired(pending.accepted_at) {
        let response =
            crate::resident_protocol::error_response("native_request_deadline_exceeded", true);
        let _ = write_bound_response(&mut *pending.stream, &pending.request_id, &response);
        return;
    }
    let _ = pending
        .stream
        .set_resident_read_timeout(Some(crate::PAYLOAD_TIMEOUT));
    let prefix_length = pending.payload_prefix.len();
    let mut request = vec![0u8; pending.length];
    request[..prefix_length].copy_from_slice(&pending.payload_prefix);
    let response = if pending
        .stream
        .read_exact(&mut request[prefix_length..])
        .is_err()
    {
        crate::resident_protocol::error_response("native_frame_read_failed", false)
    } else {
        let digest = Sha256::digest(&request);
        if !constant_time_eq(&digest, &pending.request_digest) {
            crate::resident_protocol::error_response("native_request_digest_mismatch", false)
        } else {
            match catch_unwind(AssertUnwindSafe(|| {
                crate::resident_protocol::evaluate_resident_bytes(&request, policy_store)
            })) {
                Ok(Ok(response)) => response,
                Ok(Err(reason)) => crate::resident_protocol::safe_error_response(&reason, false),
                Err(_panic) => {
                    crate::resident_protocol::error_response("native_runtime_panicked", false)
                }
            }
        }
    };
    let is_shutdown_request = crate::strict_json_value(&request).is_ok_and(|value| {
        value.get("operation").and_then(serde_json::Value::as_str) == Some("shutdown")
    });
    let _ = write_bound_response(&mut *pending.stream, &pending.request_id, &response);
    if is_shutdown_request {
        crate::managed_resident::shutdown_response_sent();
    }
}

fn spawn_workers<T, F>(count: usize, receiver: Receiver<T>, handler: F)
where
    T: Send + 'static,
    F: Fn(T) + Send + Sync + 'static,
{
    let receiver = Arc::new(Mutex::new(receiver));
    let handler = Arc::new(handler);
    for _ in 0..count {
        let receiver = Arc::clone(&receiver);
        let handler = Arc::clone(&handler);
        thread::spawn(move || loop {
            let next = match receiver.lock() {
                Ok(guard) => guard.recv(),
                Err(_) => return,
            };
            match next {
                Ok(item) => handler(item),
                Err(_) => return,
            }
        });
    }
}

pub(crate) fn start_resident_workers(
    token: Arc<[u8; crate::AUTH_TOKEN_BYTES]>,
    policy_store: Option<Arc<crate::policy_store::PolicySnapshotStore>>,
) -> SyncSender<BoxedResidentStream> {
    let (evaluation_sender, evaluation_receiver) =
        sync_channel::<PendingRequest>(crate::EVALUATION_QUEUE_CAPACITY);
    let evaluation_policy_store = policy_store.clone();
    spawn_workers(
        crate::EVALUATION_WORKERS,
        evaluation_receiver,
        move |pending| {
            handle_pending_request(pending, evaluation_policy_store.as_deref());
        },
    );

    let (authentication_sender, authentication_receiver) =
        sync_channel::<BoxedResidentStream>(crate::AUTH_QUEUE_CAPACITY);
    spawn_workers(
        crate::AUTH_WORKERS,
        authentication_receiver,
        move |mut stream| {
            if authenticate_resident_stream(&mut *stream, &token).is_err() {
                return;
            }
            let mut pending = match read_request_header(stream) {
                Ok(value) => value,
                Err(_) => return,
            };
            pending
                .payload_prefix
                .resize(pending.length.min(crate::AUTHENTICATED_PREFETCH_BYTES), 0);
            let available = match pending
                .stream
                .try_read_available(&mut pending.payload_prefix)
            {
                Ok(value) => value,
                Err(_) => return,
            };
            pending.payload_prefix.truncate(available);
            if available == pending.length {
                handle_pending_request(pending, policy_store.as_deref());
                return;
            }
            match evaluation_sender.try_send(pending) {
                Ok(()) => {}
                Err(TrySendError::Full(returned)) => {
                    let mut pending = returned;
                    write_overload(&mut pending);
                }
                Err(TrySendError::Disconnected(_returned)) => {}
            }
        },
    );
    authentication_sender
}

pub(crate) fn admit_connection(
    sender: &SyncSender<BoxedResidentStream>,
    stream: BoxedResidentStream,
) -> Result<(), String> {
    match sender.try_send(stream) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_stream)) => Ok(()),
        Err(TrySendError::Disconnected(_stream)) => {
            Err("native_resident_worker_pool_stopped".to_owned())
        }
    }
}
