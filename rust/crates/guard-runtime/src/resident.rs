use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::io::{self, BufRead, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use guard_contracts::{MAX_NATIVE_REQUEST_BYTES, MAX_NATIVE_RESPONSE_BYTES};

pub const RESIDENT_PROTOCOL_VERSION: u8 = 2;

const REQUEST_MAGIC: &[u8; 4] = b"HGR2";
const RESPONSE_MAGIC: &[u8; 4] = b"HGS2";
const FRAME_REQUEST_ID_BYTES: usize = 32;
const FRAME_DIGEST_BYTES: usize = 32;
const GENERATION_ID_BYTES: usize = 16;
const REQUEST_HEADER_BYTES: usize = 4 + 1 + 3 + FRAME_REQUEST_ID_BYTES + FRAME_DIGEST_BYTES + 4 + 4;
const RESPONSE_HEADER_BYTES: usize =
    4 + FRAME_REQUEST_ID_BYTES + FRAME_DIGEST_BYTES + GENERATION_ID_BYTES + FRAME_DIGEST_BYTES + 4;
const AUTH_TOKEN_BYTES: usize = 32;
const AUTH_NONCE_BYTES: usize = 32;
const AUTH_PROOF_BYTES: usize = 32;
const AUTH_WORKERS: usize = 4;
const AUTH_QUEUE_CAPACITY: usize = 16;
const LIFECYCLE_WORKERS: usize = 2;
const LIFECYCLE_QUEUE_CAPACITY: usize = 8;
const EVALUATION_WORKERS: usize = 16;
const EVALUATION_QUEUE_CAPACITY: usize = 32;
const MAX_HEALTH_REQUEST_BYTES: usize = 1024;
const MAX_DEADLINE_MILLISECONDS: u64 = 10_000;
const AUTH_TIMEOUT: Duration = Duration::from_millis(250);
const HEADER_TIMEOUT: Duration = Duration::from_millis(250);
const PAYLOAD_TIMEOUT: Duration = Duration::from_secs(2);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(10);
const SERVER_PROOF_LABEL: &[u8] = b"hol-guard-resident-server-v1\0";
const CLIENT_PROOF_LABEL: &[u8] = b"hol-guard-resident-client-v1\0";
const OPERATION_HEALTH: u8 = 1;
const OPERATION_EVALUATE: u8 = 2;

type HmacSha256 = Hmac<Sha256>;
type ResidentEvaluator = fn(&[u8], ResidentOperation) -> Result<Vec<u8>, String>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResidentOperation {
    Health,
    Evaluate,
}

impl ResidentOperation {
    fn from_byte(value: u8) -> Result<Self, String> {
        match value {
            OPERATION_HEALTH => Ok(Self::Health),
            OPERATION_EVALUATE => Ok(Self::Evaluate),
            _ => Err("native_frame_operation_invalid".to_owned()),
        }
    }

    fn request_limit(self) -> usize {
        match self {
            Self::Health => MAX_HEALTH_REQUEST_BYTES,
            Self::Evaluate => MAX_NATIVE_REQUEST_BYTES,
        }
    }
}

trait ResidentStream: Read + Write + Send {
    fn set_resident_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_resident_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;

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

    fn configure_low_latency(&self) -> io::Result<()> {
        self.set_nodelay(true)
    }
}

#[cfg(unix)]
impl ResidentStream for std::os::unix::net::UnixStream {
    fn set_resident_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        std::os::unix::net::UnixStream::set_read_timeout(self, timeout)
    }

    fn set_resident_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        std::os::unix::net::UnixStream::set_write_timeout(self, timeout)
    }
}

type BoxedResidentStream = Box<dyn ResidentStream>;

#[derive(Clone)]
struct ResidentBootstrap {
    auth_token: Arc<[u8; AUTH_TOKEN_BYTES]>,
    generation_id: [u8; GENERATION_ID_BYTES],
}

struct PendingRequest {
    stream: BoxedResidentStream,
    operation: ResidentOperation,
    request_id: [u8; FRAME_REQUEST_ID_BYTES],
    request_digest: [u8; FRAME_DIGEST_BYTES],
    length: usize,
    deadline: Instant,
}

fn hmac_sha256(key: &[u8], label: &[u8], nonce: &[u8]) -> Result<[u8; AUTH_PROOF_BYTES], String> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| "native_resident_auth_key_invalid".to_owned())?;
    mac.update(label);
    mac.update(nonce);
    let bytes = mac.finalize().into_bytes();
    let mut proof = [0u8; AUTH_PROOF_BYTES];
    proof.copy_from_slice(&bytes);
    Ok(proof)
}

fn verify_hmac(key: &[u8], label: &[u8], nonce: &[u8], proof: &[u8]) -> Result<(), String> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| "native_resident_auth_key_invalid".to_owned())?;
    mac.update(label);
    mac.update(nonce);
    mac.verify_slice(proof)
        .map_err(|_| "native_resident_auth_rejected".to_owned())
}

fn authenticate_resident_stream(
    stream: &mut dyn ResidentStream,
    token: &[u8; AUTH_TOKEN_BYTES],
) -> Result<(), String> {
    stream
        .set_resident_read_timeout(Some(AUTH_TIMEOUT))
        .map_err(|_| "native_resident_auth_timeout_failed".to_owned())?;
    stream
        .set_resident_write_timeout(Some(AUTH_TIMEOUT))
        .map_err(|_| "native_resident_auth_timeout_failed".to_owned())?;
    let _ = stream.configure_low_latency();

    let mut nonce = [0u8; AUTH_NONCE_BYTES];
    stream
        .read_exact(&mut nonce)
        .map_err(|_| "native_resident_auth_nonce_failed".to_owned())?;
    let server_proof = hmac_sha256(token, SERVER_PROOF_LABEL, &nonce)?;
    stream
        .write_all(&server_proof)
        .map_err(|_| "native_resident_auth_proof_failed".to_owned())?;

    let mut client_proof = [0u8; AUTH_PROOF_BYTES];
    stream
        .read_exact(&mut client_proof)
        .map_err(|_| "native_resident_auth_client_failed".to_owned())?;
    verify_hmac(token, CLIENT_PROOF_LABEL, &nonce, &client_proof)
}

fn read_request_header(mut stream: BoxedResidentStream) -> Result<PendingRequest, String> {
    stream
        .set_resident_read_timeout(Some(HEADER_TIMEOUT))
        .map_err(|_| "native_frame_timeout_failed".to_owned())?;
    let mut header = [0u8; REQUEST_HEADER_BYTES];
    stream
        .read_exact(&mut header)
        .map_err(|_| "native_frame_header_failed".to_owned())?;
    if header[..4] != REQUEST_MAGIC[..] {
        return Err("native_frame_version_mismatch".to_owned());
    }
    let operation = ResidentOperation::from_byte(header[4])?;
    if header[5..8] != [0, 0, 0] {
        return Err("native_frame_reserved_invalid".to_owned());
    }
    let mut request_id = [0u8; FRAME_REQUEST_ID_BYTES];
    request_id.copy_from_slice(&header[8..8 + FRAME_REQUEST_ID_BYTES]);
    let digest_start = 8 + FRAME_REQUEST_ID_BYTES;
    let mut request_digest = [0u8; FRAME_DIGEST_BYTES];
    request_digest.copy_from_slice(&header[digest_start..digest_start + FRAME_DIGEST_BYTES]);
    let length_start = digest_start + FRAME_DIGEST_BYTES;
    let length = u32::from_be_bytes(
        header[length_start..length_start + 4]
            .try_into()
            .map_err(|_| "native_frame_header_failed".to_owned())?,
    ) as usize;
    if length == 0 || length > operation.request_limit() {
        return Err("native_request_too_large".to_owned());
    }
    let deadline_milliseconds = u32::from_be_bytes(
        header[length_start + 4..length_start + 8]
            .try_into()
            .map_err(|_| "native_frame_header_failed".to_owned())?,
    ) as u64;
    if deadline_milliseconds == 0 || deadline_milliseconds > MAX_DEADLINE_MILLISECONDS {
        return Err("native_deadline_invalid".to_owned());
    }
    Ok(PendingRequest {
        stream,
        operation,
        request_id,
        request_digest,
        length,
        deadline: Instant::now() + Duration::from_millis(deadline_milliseconds),
    })
}

fn remaining(deadline: Instant, cap: Duration) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .map(|value| value.min(cap))
        .filter(|value| !value.is_zero())
}

fn write_bound_response(
    pending: &mut PendingRequest,
    generation_id: &[u8; GENERATION_ID_BYTES],
    response: &[u8],
) -> Result<(), String> {
    if response.is_empty() || response.len() > MAX_NATIVE_RESPONSE_BYTES {
        return Err("native_response_too_large".to_owned());
    }
    let timeout = remaining(pending.deadline, RESPONSE_TIMEOUT)
        .ok_or_else(|| "native_deadline_exceeded".to_owned())?;
    pending
        .stream
        .set_resident_write_timeout(Some(timeout))
        .map_err(|_| "native_frame_timeout_failed".to_owned())?;
    let response_digest = Sha256::digest(response);
    let mut header = Vec::with_capacity(RESPONSE_HEADER_BYTES);
    header.extend_from_slice(RESPONSE_MAGIC);
    header.extend_from_slice(&pending.request_id);
    header.extend_from_slice(&pending.request_digest);
    header.extend_from_slice(generation_id);
    header.extend_from_slice(&response_digest);
    header.extend_from_slice(&(response.len() as u32).to_be_bytes());
    debug_assert_eq!(header.len(), RESPONSE_HEADER_BYTES);
    pending
        .stream
        .write_all(&header)
        .map_err(|_| "native_frame_write_failed".to_owned())?;
    pending
        .stream
        .write_all(response)
        .map_err(|_| "native_frame_write_failed".to_owned())?;
    pending
        .stream
        .flush()
        .map_err(|_| "native_frame_write_failed".to_owned())?;
    Ok(())
}

fn error_response(code: &'static str, retryable: bool) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"error": code, "retryable": retryable})).unwrap_or_else(
        |_| b"{\"error\":\"native_response_encode_failed\",\"retryable\":false}".to_vec(),
    )
}

fn write_overload(pending: &mut PendingRequest, generation_id: &[u8; GENERATION_ID_BYTES]) {
    let response = error_response("native_overloaded", true);
    let _ = write_bound_response(pending, generation_id, &response);
}

fn handle_pending_request(
    mut pending: PendingRequest,
    generation_id: [u8; GENERATION_ID_BYTES],
    evaluator: ResidentEvaluator,
) {
    let Some(timeout) = remaining(pending.deadline, PAYLOAD_TIMEOUT) else {
        return;
    };
    let _ = pending.stream.set_resident_read_timeout(Some(timeout));
    let mut request = vec![0u8; pending.length];
    let response = if pending.stream.read_exact(&mut request).is_err() {
        error_response("native_frame_read_failed", false)
    } else if Sha256::digest(&request).as_slice() != pending.request_digest {
        error_response("native_request_digest_mismatch", false)
    } else if Instant::now() >= pending.deadline {
        error_response("native_deadline_exceeded", true)
    } else {
        match catch_unwind(AssertUnwindSafe(|| evaluator(&request, pending.operation))) {
            Ok(Ok(response)) => response,
            Ok(Err(_reason)) => error_response("native_request_invalid_json", false),
            Err(_panic) => error_response("native_runtime_panicked", false),
        }
    };
    let _ = write_bound_response(&mut pending, &generation_id, &response);
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

fn start_resident_workers(
    bootstrap: ResidentBootstrap,
    evaluator: ResidentEvaluator,
) -> SyncSender<BoxedResidentStream> {
    let (evaluation_sender, evaluation_receiver) =
        sync_channel::<PendingRequest>(EVALUATION_QUEUE_CAPACITY);
    let evaluation_generation = bootstrap.generation_id;
    spawn_workers(EVALUATION_WORKERS, evaluation_receiver, move |pending| {
        handle_pending_request(pending, evaluation_generation, evaluator);
    });

    let (lifecycle_sender, lifecycle_receiver) =
        sync_channel::<PendingRequest>(LIFECYCLE_QUEUE_CAPACITY);
    let lifecycle_generation = bootstrap.generation_id;
    spawn_workers(LIFECYCLE_WORKERS, lifecycle_receiver, move |pending| {
        handle_pending_request(pending, lifecycle_generation, evaluator);
    });

    let (authentication_sender, authentication_receiver) =
        sync_channel::<BoxedResidentStream>(AUTH_QUEUE_CAPACITY);
    let authentication_generation = bootstrap.generation_id;
    spawn_workers(AUTH_WORKERS, authentication_receiver, move |mut stream| {
        if authenticate_resident_stream(&mut *stream, &bootstrap.auth_token).is_err() {
            return;
        }
        let mut pending = match read_request_header(stream) {
            Ok(value) => value,
            Err(_) => return,
        };
        let sender = match pending.operation {
            ResidentOperation::Health => &lifecycle_sender,
            ResidentOperation::Evaluate => &evaluation_sender,
        };
        match sender.try_send(pending) {
            Ok(()) => {}
            Err(TrySendError::Full(returned)) => {
                pending = returned;
                write_overload(&mut pending, &authentication_generation);
            }
            Err(TrySendError::Disconnected(_returned)) => {}
        }
    });
    authentication_sender
}

fn admit_connection(
    sender: &SyncSender<BoxedResidentStream>,
    stream: BoxedResidentStream,
) -> Result<(), String> {
    match sender.try_send(stream) {
        Ok(()) | Err(TrySendError::Full(_)) => Ok(()),
        Err(TrySendError::Disconnected(_)) => Err("native_resident_worker_pool_stopped".to_owned()),
    }
}

#[cfg(unix)]
pub fn serve(socket_path: &str, evaluator: ResidentEvaluator) -> Result<(), String> {
    use std::fs;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    let path = Path::new(socket_path);
    let parent = path
        .parent()
        .ok_or_else(|| "native_socket_parent_missing".to_owned())?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|_| "native_socket_parent_stat_failed".to_owned())?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.permissions().mode() & 0o077 != 0
    {
        return Err("native_socket_parent_not_private".to_owned());
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
                return Err("native_socket_existing_path_rejected".to_owned());
            }
            fs::remove_file(path).map_err(|_| "native_socket_cleanup_failed".to_owned())?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err("native_socket_stat_failed".to_owned()),
    }
    let listener = UnixListener::bind(path).map_err(|_| "native_socket_bind_failed".to_owned())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| "native_socket_permissions_failed".to_owned())?;

    let sender = start_resident_workers(read_resident_bootstrap()?, evaluator);
    loop {
        match listener.accept() {
            Ok((stream, _address)) => admit_connection(&sender, Box::new(stream))?,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::ConnectionAborted
                ) =>
            {
                thread::sleep(ACCEPT_RETRY_DELAY);
            }
            Err(_) => return Err("native_socket_accept_failed".to_owned()),
        }
    }
}

#[cfg(not(unix))]
pub fn serve(_socket_path: &str, _evaluator: ResidentEvaluator) -> Result<(), String> {
    Err("native_unix_socket_not_available".to_owned())
}

pub fn serve_loopback(address: &str, evaluator: ResidentEvaluator) -> Result<(), String> {
    let requested: SocketAddr = address
        .parse()
        .map_err(|_| "native_resident_address_invalid".to_owned())?;
    if requested.ip() != Ipv4Addr::LOCALHOST || requested.port() == 0 {
        return Err("native_resident_address_not_loopback".to_owned());
    }
    let listener = TcpListener::bind(requested)
        .map_err(|_| "native_resident_loopback_bind_failed".to_owned())?;
    let local = listener
        .local_addr()
        .map_err(|_| "native_resident_loopback_addr_failed".to_owned())?;
    if local != requested {
        return Err("native_resident_loopback_addr_changed".to_owned());
    }

    let sender = start_resident_workers(read_resident_bootstrap()?, evaluator);
    loop {
        match listener.accept() {
            Ok((stream, _address)) => admit_connection(&sender, Box::new(stream))?,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::ConnectionAborted
                ) =>
            {
                thread::sleep(ACCEPT_RETRY_DELAY);
            }
            Err(_) => return Err("native_resident_loopback_accept_failed".to_owned()),
        }
    }
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn decode_hex<const N: usize>(encoded: &str) -> Result<[u8; N], String> {
    if encoded.len() != N * 2 {
        return Err("native_resident_bootstrap_invalid".to_owned());
    }
    let mut output = [0u8; N];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high =
            hex_nibble(pair[0]).ok_or_else(|| "native_resident_bootstrap_invalid".to_owned())?;
        let low =
            hex_nibble(pair[1]).ok_or_else(|| "native_resident_bootstrap_invalid".to_owned())?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn read_line_bounded(reader: &mut dyn BufRead, maximum: usize) -> Result<String, String> {
    let mut encoded = String::new();
    reader
        .take((maximum + 2) as u64)
        .read_line(&mut encoded)
        .map_err(|_| "native_resident_bootstrap_read_failed".to_owned())?;
    let value = encoded.trim_end_matches(['\r', '\n']);
    if value.len() > maximum {
        return Err("native_resident_bootstrap_invalid".to_owned());
    }
    Ok(value.to_owned())
}

fn read_resident_bootstrap() -> Result<ResidentBootstrap, String> {
    let stdin = io::stdin();
    let mut reader = io::BufReader::new(stdin.lock());
    let token =
        decode_hex::<AUTH_TOKEN_BYTES>(&read_line_bounded(&mut reader, AUTH_TOKEN_BYTES * 2)?)?;
    let generation_id = decode_hex::<GENERATION_ID_BYTES>(&read_line_bounded(
        &mut reader,
        GENERATION_ID_BYTES * 2,
    )?)?;
    Ok(ResidentBootstrap {
        auth_token: Arc::new(token),
        generation_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct TestStream {
        cursor: Cursor<Vec<u8>>,
    }

    impl TestStream {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                cursor: Cursor::new(bytes),
            }
        }
    }

    impl Read for TestStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.cursor.read(buffer)
        }
    }

    impl Write for TestStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.cursor.write(buffer)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ResidentStream for TestStream {
        fn set_resident_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn set_resident_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
    }

    fn request_header(operation: u8, reserved: [u8; 3], length: u32, deadline: u32) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(REQUEST_MAGIC);
        header.push(operation);
        header.extend_from_slice(&reserved);
        header.extend_from_slice(&[1u8; FRAME_REQUEST_ID_BYTES]);
        header.extend_from_slice(&[2u8; FRAME_DIGEST_BYTES]);
        header.extend_from_slice(&length.to_be_bytes());
        header.extend_from_slice(&deadline.to_be_bytes());
        assert_eq!(header.len(), REQUEST_HEADER_BYTES);
        header
    }

    #[test]
    fn audited_hmac_matches_cross_language_vectors() {
        let token = [7u8; AUTH_TOKEN_BYTES];
        let nonce = [9u8; AUTH_NONCE_BYTES];
        let server = hmac_sha256(&token, SERVER_PROOF_LABEL, &nonce).unwrap();
        let client = hmac_sha256(&token, CLIENT_PROOF_LABEL, &nonce).unwrap();
        assert_eq!(
            hex::encode(server),
            "b819898f11878c1c148423d0361a9de20d9eca3bb86ce1214cee957f95bb06c4"
        );
        assert_eq!(
            hex::encode(client),
            "fef83d9ff5988922ef5c4c7b54d9c666abf42fdfa839448b579f650741d06d97"
        );
        assert_ne!(server, client);
    }

    #[test]
    fn frame_rejects_reserved_bytes_unknown_operations_and_invalid_deadlines() {
        assert!(read_request_header(Box::new(TestStream::new(request_header(
            OPERATION_HEALTH,
            [1, 0, 0],
            1,
            100,
        ))))
        .is_err());
        assert!(read_request_header(Box::new(TestStream::new(request_header(
            99,
            [0, 0, 0],
            1,
            100,
        ))))
        .is_err());
        assert!(read_request_header(Box::new(TestStream::new(request_header(
            OPERATION_EVALUATE,
            [0, 0, 0],
            1,
            0,
        ))))
        .is_err());
    }

    #[test]
    fn health_and_evaluation_have_distinct_allocation_bounds() {
        assert!(read_request_header(Box::new(TestStream::new(request_header(
            OPERATION_HEALTH,
            [0, 0, 0],
            (MAX_HEALTH_REQUEST_BYTES + 1) as u32,
            100,
        ))))
        .is_err());
        assert!(read_request_header(Box::new(TestStream::new(request_header(
            OPERATION_EVALUATE,
            [0, 0, 0],
            (MAX_HEALTH_REQUEST_BYTES + 1) as u32,
            100,
        ))))
        .is_ok());
    }

    #[test]
    fn bootstrap_hex_decoder_is_exact_and_bounded() {
        assert_eq!(decode_hex::<2>("00ff").unwrap(), [0, 255]);
        assert!(decode_hex::<2>("00").is_err());
        assert!(decode_hex::<2>("00xz").is_err());
    }
}
