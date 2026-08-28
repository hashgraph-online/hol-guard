#![forbid(unsafe_code)]

mod hardening;
mod oneshot;

use guard_command::CommandModelRequestV1;
use guard_contracts::{
    NativeHookRequestV1, RuntimeCapabilitiesV1, MAX_NATIVE_REQUEST_BYTES,
    MAX_NATIVE_RESPONSE_BYTES, NATIVE_PROTOCOL_VERSION,
};
use guard_hook_core::review_post_tool;
use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::env;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const BUILD_SHA: &str = match option_env!("HOL_GUARD_BUILD_SHA") {
    Some(value) => value,
    None => "unknown",
};
const PACKAGE_VERSION: &str = match option_env!("HOL_GUARD_PACKAGE_VERSION") {
    Some(value) => value,
    None => env!("CARGO_PKG_VERSION"),
};
const RESIDENT_PROTOCOL_VERSION: u8 = 2;
const REQUEST_MAGIC: &[u8; 4] = b"HGR2";
const RESPONSE_MAGIC: &[u8; 4] = b"HGS2";
const FRAME_REQUEST_ID_BYTES: usize = 32;
const FRAME_DIGEST_BYTES: usize = 32;
const FRAME_HEADER_BYTES: usize = 4 + FRAME_REQUEST_ID_BYTES + FRAME_DIGEST_BYTES + 4;
const AUTH_TOKEN_BYTES: usize = 32;
const AUTH_NONCE_BYTES: usize = 32;
const AUTH_PROOF_BYTES: usize = 32;
const AUTH_WORKERS: usize = 4;
const AUTH_QUEUE_CAPACITY: usize = 16;
const EVALUATION_WORKERS: usize = 16;
const EVALUATION_QUEUE_CAPACITY: usize = 32;
const AUTH_TIMEOUT: Duration = Duration::from_millis(250);
const HEADER_TIMEOUT: Duration = Duration::from_millis(250);
const PAYLOAD_TIMEOUT: Duration = Duration::from_secs(2);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_COLLECTION_ITEMS: usize = 4_096;
const MAX_JSON_STRING_BYTES: usize = 1024 * 1024;
const SERVER_PROOF_LABEL: &[u8] = b"hol-guard-resident-server-v1\0";
const CLIENT_PROOF_LABEL: &[u8] = b"hol-guard-resident-client-v1\0";
#[cfg(unix)]
const PARENT_LIVENESS_FD_ENV: &str = "HOL_GUARD_PARENT_LIVENESS_FD";

#[derive(Debug, Deserialize)]
#[serde(tag = "operation", content = "request", rename_all = "snake_case")]
enum ResidentOperationV1 {
    CommandModel(CommandModelRequestV1),
    PreToolUse(CommandModelRequestV1),
    Health(Value),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ResidentRequestV1 {
    Operation(ResidentOperationV1),
    Hook(NativeHookRequestV1),
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

struct PendingRequest {
    stream: BoxedResidentStream,
    request_id: [u8; FRAME_REQUEST_ID_BYTES],
    request_digest: [u8; FRAME_DIGEST_BYTES],
    length: usize,
    accepted_at: Instant,
}

#[derive(Clone, Copy)]
struct StrictJsonSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictJsonSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.depth > MAX_JSON_DEPTH {
            return Err(serde::de::Error::custom("native_json_depth_exceeded"));
        }
        deserializer.deserialize_any(StrictJsonVisitor { depth: self.depth })
    }
}

struct StrictJsonVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("native_json_number_invalid"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > MAX_JSON_STRING_BYTES {
            return Err(E::custom("native_json_string_too_large"));
        }
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictJsonSeed { depth: self.depth }.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut output = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictJsonSeed {
            depth: self.depth + 1,
        })? {
            if output.len() >= MAX_JSON_COLLECTION_ITEMS {
                return Err(serde::de::Error::custom("native_json_array_too_wide"));
            }
            output.push(value);
        }
        Ok(Value::Array(output))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut output = Map::new();
        let mut seen = HashSet::new();
        while let Some(key) = object.next_key::<String>()? {
            if key.len() > MAX_JSON_STRING_BYTES {
                return Err(serde::de::Error::custom("native_json_key_too_large"));
            }
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom("native_json_duplicate_key"));
            }
            if output.len() >= MAX_JSON_COLLECTION_ITEMS {
                return Err(serde::de::Error::custom("native_json_object_too_wide"));
            }
            let value = object.next_value_seed(StrictJsonSeed {
                depth: self.depth + 1,
            })?;
            output.insert(key, value);
        }
        Ok(Value::Object(output))
    }
}

fn capabilities() -> RuntimeCapabilitiesV1 {
    let mut features = vec![
        "post-tool-inline-v1".into(),
        "post-tool-source-read-v1".into(),
        "oneshot-v1".into(),
        "framed-serve-v1".into(),
        "resident-protocol-v2".into(),
        "bounded-admission-v2".into(),
        "overload-signal-v1".into(),
        "panic-containment-v1".into(),
        "rule-contract-v2".into(),
        "pre-tool-command-model-shadow-v1".into(),
        "resident-command-model-shadow-v1".into(),
        "pre-tool-command-authority-v1".into(),
    ];
    if cfg!(windows) {
        features.push("authenticated-loopback-resident-v1".into());
    }
    if cfg!(unix) {
        features.push("authenticated-unix-resident-v1".into());
    }
    RuntimeCapabilitiesV1 {
        protocol_version: NATIVE_PROTOCOL_VERSION,
        runtime_version: PACKAGE_VERSION.to_owned(),
        rule_digest: guard_rule_contract::rule_digest(),
        build_sha: BUILD_SHA.to_owned(),
        target: format!("{}-{}", env::consts::ARCH, env::consts::OS),
        features,
    }
}

fn read_stdin_bounded() -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX_NATIVE_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| hardening::read_error(&error, "native_request_read_failed"))?;
    if bytes.len() > MAX_NATIVE_REQUEST_BYTES {
        return Err("native_request_too_large".into());
    }
    Ok(bytes)
}

pub(crate) fn strict_json_value(bytes: &[u8]) -> Result<Value, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictJsonSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|_| "native_request_invalid_json".to_owned())?;
    deserializer
        .end()
        .map_err(|_| "native_request_trailing_json".to_owned())?;
    Ok(value)
}

fn evaluate_resident_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = strict_json_value(bytes)?;
    let request: ResidentRequestV1 = serde_json::from_value(value)
        .map_err(|_| "native_resident_request_invalid_json".to_owned())?;
    match request {
        ResidentRequestV1::Operation(ResidentOperationV1::CommandModel(request)) => {
            oneshot::evaluate_command_model_request(&request)
        }
        ResidentRequestV1::Operation(ResidentOperationV1::PreToolUse(request)) => {
            oneshot::evaluate_pre_tool_request(&request)
        }
        ResidentRequestV1::Operation(ResidentOperationV1::Health(_request)) => {
            encode_response(&serde_json::json!({
                "status": "ready",
                "protocol_version": RESIDENT_PROTOCOL_VERSION,
            }))
        }
        ResidentRequestV1::Hook(request) => encode_response(&review_post_tool(&request)),
    }
}

pub(crate) fn encode_response<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let encoded =
        serde_json::to_vec(value).map_err(|_| "native_response_encode_failed".to_owned())?;
    if encoded.len() > MAX_NATIVE_RESPONSE_BYTES {
        return Err("native_response_too_large".to_owned());
    }
    Ok(encoded)
}

fn error_response(code: &'static str, retryable: bool) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"error": code, "retryable": retryable})).unwrap_or_else(
        |_| b"{\"error\":\"native_response_encode_failed\",\"retryable\":false}".to_vec(),
    )
}

fn write_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    serde_json::to_writer(io::stdout().lock(), value)
        .map_err(|_| "native_response_encode_failed".to_owned())?;
    println!();
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left_byte, right_byte) in left.iter().zip(right) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

fn hmac_sha256(key: &[u8], label: &[u8], nonce: &[u8]) -> [u8; AUTH_PROOF_BYTES] {
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
    let mut proof = [0u8; AUTH_PROOF_BYTES];
    proof.copy_from_slice(&digest);
    proof
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
    let server_proof = hmac_sha256(token, SERVER_PROOF_LABEL, &nonce);
    stream
        .write_all(&server_proof)
        .map_err(|_| "native_resident_auth_proof_failed".to_owned())?;

    let mut client_proof = [0u8; AUTH_PROOF_BYTES];
    stream
        .read_exact(&mut client_proof)
        .map_err(|_| "native_resident_auth_client_failed".to_owned())?;
    let expected = hmac_sha256(token, CLIENT_PROOF_LABEL, &nonce);
    if !constant_time_eq(&client_proof, &expected) {
        return Err("native_resident_auth_rejected".into());
    }
    Ok(())
}

fn read_request_header(mut stream: BoxedResidentStream) -> Result<PendingRequest, String> {
    stream
        .set_resident_read_timeout(Some(HEADER_TIMEOUT))
        .map_err(|_| "native_frame_timeout_failed".to_owned())?;
    let mut header = [0u8; FRAME_HEADER_BYTES];
    stream
        .read_exact(&mut header)
        .map_err(|_| "native_frame_header_failed".to_owned())?;
    if !constant_time_eq(&header[..4], REQUEST_MAGIC) {
        return Err("native_frame_version_mismatch".to_owned());
    }
    let mut request_id = [0u8; FRAME_REQUEST_ID_BYTES];
    request_id.copy_from_slice(&header[4..4 + FRAME_REQUEST_ID_BYTES]);
    let digest_start = 4 + FRAME_REQUEST_ID_BYTES;
    let mut request_digest = [0u8; FRAME_DIGEST_BYTES];
    request_digest.copy_from_slice(&header[digest_start..digest_start + FRAME_DIGEST_BYTES]);
    let length = u32::from_be_bytes(
        header[FRAME_HEADER_BYTES - 4..]
            .try_into()
            .map_err(|_| "native_frame_header_failed".to_owned())?,
    ) as usize;
    if length == 0 || length > MAX_NATIVE_REQUEST_BYTES {
        return Err("native_request_too_large".to_owned());
    }
    Ok(PendingRequest {
        stream,
        request_id,
        request_digest,
        length,
        accepted_at: Instant::now(),
    })
}

fn write_bound_response(
    stream: &mut dyn ResidentStream,
    request_id: &[u8; FRAME_REQUEST_ID_BYTES],
    response: &[u8],
) -> Result<(), String> {
    if response.is_empty() || response.len() > MAX_NATIVE_RESPONSE_BYTES {
        return Err("native_response_too_large".to_owned());
    }
    stream
        .set_resident_write_timeout(Some(RESPONSE_TIMEOUT))
        .map_err(|_| "native_frame_timeout_failed".to_owned())?;
    let digest = Sha256::digest(response);
    let mut header = Vec::with_capacity(FRAME_HEADER_BYTES);
    header.extend_from_slice(RESPONSE_MAGIC);
    header.extend_from_slice(request_id);
    header.extend_from_slice(&digest);
    header.extend_from_slice(&(response.len() as u32).to_be_bytes());
    stream
        .write_all(&header)
        .map_err(|error| hardening::write_error(&error, "native_frame_write_failed"))?;
    stream
        .write_all(response)
        .map_err(|error| hardening::write_error(&error, "native_frame_write_failed"))?;
    stream
        .flush()
        .map_err(|error| hardening::write_error(&error, "native_frame_write_failed"))?;
    Ok(())
}

fn write_overload(pending: &mut PendingRequest) {
    let response = error_response("native_overloaded", true);
    let _ = write_bound_response(&mut *pending.stream, &pending.request_id, &response);
}

fn handle_pending_request(mut pending: PendingRequest) {
    if hardening::request_expired(pending.accepted_at) {
        let response = error_response("native_request_deadline_exceeded", true);
        let _ = write_bound_response(&mut *pending.stream, &pending.request_id, &response);
        return;
    }
    let _ = pending
        .stream
        .set_resident_read_timeout(Some(PAYLOAD_TIMEOUT));
    let mut request = vec![0u8; pending.length];
    let response = if pending.stream.read_exact(&mut request).is_err() {
        error_response("native_frame_read_failed", false)
    } else {
        let digest = Sha256::digest(&request);
        if !constant_time_eq(&digest, &pending.request_digest) {
            error_response("native_request_digest_mismatch", false)
        } else {
            match catch_unwind(AssertUnwindSafe(|| evaluate_resident_bytes(&request))) {
                Ok(Ok(response)) => response,
                Ok(Err(_reason)) => error_response("native_request_invalid_json", false),
                Err(_panic) => error_response("native_runtime_panicked", false),
            }
        }
    };
    let _ = write_bound_response(&mut *pending.stream, &pending.request_id, &response);
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

fn start_resident_workers(token: Arc<[u8; AUTH_TOKEN_BYTES]>) -> SyncSender<BoxedResidentStream> {
    let (evaluation_sender, evaluation_receiver) =
        sync_channel::<PendingRequest>(EVALUATION_QUEUE_CAPACITY);
    spawn_workers(
        EVALUATION_WORKERS,
        evaluation_receiver,
        handle_pending_request,
    );

    let (authentication_sender, authentication_receiver) =
        sync_channel::<BoxedResidentStream>(AUTH_QUEUE_CAPACITY);
    spawn_workers(AUTH_WORKERS, authentication_receiver, move |mut stream| {
        if authenticate_resident_stream(&mut *stream, &token).is_err() {
            return;
        }
        let mut pending = match read_request_header(stream) {
            Ok(value) => value,
            Err(_) => return,
        };
        match evaluation_sender.try_send(pending) {
            Ok(()) => {}
            Err(TrySendError::Full(returned)) => {
                pending = returned;
                write_overload(&mut pending);
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
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_stream)) => Ok(()),
        Err(TrySendError::Disconnected(_stream)) => {
            Err("native_resident_worker_pool_stopped".to_owned())
        }
    }
}

#[cfg(unix)]
fn resident_parent_liveness() -> Result<Arc<std::sync::atomic::AtomicBool>, String> {
    let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let Ok(raw_descriptor) = env::var(PARENT_LIVENESS_FD_ENV) else {
        return Ok(alive);
    };
    let descriptor = raw_descriptor
        .parse::<u32>()
        .map_err(|_| "native_parent_liveness_fd_invalid".to_owned())?;
    let dev_path = format!("/dev/fd/{descriptor}");
    let proc_path = format!("/proc/self/fd/{descriptor}");
    let mut pipe = std::fs::File::open(dev_path)
        .or_else(|_| std::fs::File::open(proc_path))
        .map_err(|_| "native_parent_liveness_fd_unavailable".to_owned())?;
    let watcher_state = Arc::clone(&alive);
    thread::spawn(move || {
        let mut byte = [0u8; 1];
        let _ = pipe.read(&mut byte);
        watcher_state.store(false, std::sync::atomic::Ordering::Release);
    });
    Ok(alive)
}

#[cfg(unix)]
fn serve(socket_path: &str) -> Result<(), String> {
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
    listener
        .set_nonblocking(true)
        .map_err(|_| "native_socket_nonblocking_failed".to_owned())?;

    let token = Arc::new(read_resident_auth_token()?);
    let sender = start_resident_workers(token);
    let parent_alive = resident_parent_liveness()?;
    let mut consecutive_accept_failures = 0;
    while parent_alive.load(std::sync::atomic::Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _address)) => {
                consecutive_accept_failures = 0;
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                admit_connection(&sender, Box::new(stream))?
            }
            Err(error)
                if hardening::classify_io_error(&error) != hardening::IoFailureClass::Other =>
            {
                consecutive_accept_failures += 1;
                thread::sleep(hardening::accept_retry_delay(
                    consecutive_accept_failures,
                    &error,
                ));
            }
            Err(_) => return Err("native_socket_accept_failed".to_owned()),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn serve(_socket_path: &str) -> Result<(), String> {
    Err("native_unix_socket_not_available".into())
}

fn serve_loopback(address: &str) -> Result<(), String> {
    let requested: SocketAddr = address
        .parse()
        .map_err(|_| "native_resident_address_invalid".to_owned())?;
    if requested.ip() != Ipv4Addr::LOCALHOST || requested.port() == 0 {
        return Err("native_resident_address_not_loopback".into());
    }
    let listener = TcpListener::bind(requested)
        .map_err(|_| "native_resident_loopback_bind_failed".to_owned())?;
    let local = listener
        .local_addr()
        .map_err(|_| "native_resident_loopback_addr_failed".to_owned())?;
    if local != requested {
        return Err("native_resident_loopback_addr_changed".into());
    }

    let token = Arc::new(read_resident_auth_token()?);
    let sender = start_resident_workers(token);
    let mut consecutive_accept_failures = 0;
    loop {
        match listener.accept() {
            Ok((stream, _address)) => {
                consecutive_accept_failures = 0;
                admit_connection(&sender, Box::new(stream))?;
            }
            Err(error)
                if hardening::classify_io_error(&error) != hardening::IoFailureClass::Other =>
            {
                consecutive_accept_failures += 1;
                thread::sleep(hardening::accept_retry_delay(
                    consecutive_accept_failures,
                    &error,
                ));
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

fn read_resident_auth_token() -> Result<[u8; AUTH_TOKEN_BYTES], String> {
    let mut encoded = String::new();
    io::stdin()
        .take((AUTH_TOKEN_BYTES * 2 + 2) as u64)
        .read_to_string(&mut encoded)
        .map_err(|error| hardening::read_error(&error, "native_resident_auth_read_failed"))?;
    let encoded = encoded.trim();
    if encoded.len() != AUTH_TOKEN_BYTES * 2 {
        return Err("native_resident_auth_invalid".into());
    }
    let mut token = [0u8; AUTH_TOKEN_BYTES];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or_else(|| "native_resident_auth_invalid".to_owned())?;
        let low = hex_nibble(pair[1]).ok_or_else(|| "native_resident_auth_invalid".to_owned())?;
        token[index] = (high << 4) | low;
    }
    Ok(token)
}

fn write_bytes_response(response: &[u8]) -> Result<(), String> {
    io::stdout()
        .write_all(response)
        .map_err(|error| hardening::write_error(&error, "native_response_write_failed"))?;
    io::stdout()
        .write_all(b"\n")
        .map_err(|error| hardening::write_error(&error, "native_response_write_failed"))?;
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [command] if command == "capabilities" => write_json(&capabilities()),
        [command, flag] if command == "capabilities" && flag == "--json" => {
            write_json(&capabilities())
        }
        [command] if command == "rule-contract" => write_json(&guard_rule_contract::rule_contract()),
        [command, flag] if command == "rule-contract" && flag == "--json" => {
            write_json(&guard_rule_contract::rule_contract())
        }
        [command] if command == "self-test" => {
            write_json(&serde_json::json!({"ok": true, "capabilities": capabilities()}))
        }
        [command, flag] if command == "self-test" && flag == "--json" => {
            write_json(&serde_json::json!({"ok": true, "capabilities": capabilities()}))
        }
        [command, flag] if command == "hook" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            let response = oneshot::evaluate_hook_bytes(&bytes)?;
            write_bytes_response(&response)
        }
        [command, flag] if command == "command-model" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            let response = oneshot::evaluate_command_model_bytes(&bytes)?;
            write_bytes_response(&response)
        }
        [command, flag] if command == "pre-tool" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            let response = oneshot::evaluate_pre_tool_bytes(&bytes)?;
            write_bytes_response(&response)
        }
        [command, flag, path] if command == "serve" && flag == "--socket" => serve(path),
        [command, flag, address] if command == "serve" && flag == "--tcp-loopback" => {
            serve_loopback(address)
        }
        _ => Err(
            "usage: hol-guard-runtime capabilities --json | rule-contract --json | self-test --json | hook --stdin | command-model --stdin | pre-tool --stdin | serve --socket PATH | serve --tcp-loopback 127.0.0.1:PORT"
                .into(),
        ),
    }
}

fn main() {
    std::panic::set_hook(Box::new(|_| eprintln!("native_runtime_panicked")));
    if let Err(code) = run() {
        eprintln!("{code}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resident_hmac_matches_cross_language_vectors() {
        let token = [7u8; AUTH_TOKEN_BYTES];
        let nonce = [9u8; AUTH_NONCE_BYTES];
        let server = hmac_sha256(&token, SERVER_PROOF_LABEL, &nonce);
        let client = hmac_sha256(&token, CLIENT_PROOF_LABEL, &nonce);
        assert_eq!(
            server,
            [
                0xb8, 0x19, 0x89, 0x8f, 0x11, 0x87, 0x8c, 0x1c, 0x14, 0x84, 0x23, 0xd0, 0x36, 0x1a,
                0x9d, 0xe2, 0x0d, 0x9e, 0xca, 0x3b, 0xb8, 0x6c, 0xe1, 0x21, 0x4c, 0xee, 0x95, 0x7f,
                0x95, 0xbb, 0x06, 0xc4,
            ]
        );
        assert_eq!(
            client,
            [
                0xfe, 0xf8, 0x3d, 0x9f, 0xf5, 0x98, 0x89, 0x22, 0xef, 0x5c, 0x4c, 0x7b, 0x54, 0xd9,
                0xc6, 0x66, 0xab, 0xf4, 0x2f, 0xdf, 0xa8, 0x39, 0x44, 0x8b, 0x57, 0x9f, 0x65, 0x07,
                0x41, 0xd0, 0x6d, 0x97,
            ]
        );
        assert_ne!(server, client);
        assert!(constant_time_eq(&server, &server));
        assert!(!constant_time_eq(&server, &client));
    }

    #[test]
    fn strict_json_rejects_duplicate_keys_and_trailing_values() {
        assert!(strict_json_value(br#"{"a":1,"a":2}"#).is_err());
        assert!(strict_json_value(br#"{"a":1} {}"#).is_err());
    }

    #[test]
    fn strict_json_rejects_deep_and_wide_values() {
        let deep = format!(
            "{}0{}",
            "[".repeat(MAX_JSON_DEPTH + 2),
            "]".repeat(MAX_JSON_DEPTH + 2)
        );
        assert!(strict_json_value(deep.as_bytes()).is_err());
        let wide = format!(
            "[{}]",
            std::iter::repeat_n("0", MAX_JSON_COLLECTION_ITEMS + 1)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(strict_json_value(wide.as_bytes()).is_err());
    }

    #[test]
    fn overload_response_is_constant_and_retryable() {
        assert_eq!(
            error_response("native_overloaded", true),
            b"{\"error\":\"native_overloaded\",\"retryable\":true}".to_vec()
        );
    }

    #[test]
    fn resident_hmac_changes_with_nonce() {
        let token = [3u8; AUTH_TOKEN_BYTES];
        let mut first_nonce = [1u8; AUTH_NONCE_BYTES];
        let second_nonce = [2u8; AUTH_NONCE_BYTES];
        let first = hmac_sha256(&token, SERVER_PROOF_LABEL, &first_nonce);
        let second = hmac_sha256(&token, SERVER_PROOF_LABEL, &second_nonce);
        assert_ne!(first, second);
        first_nonce[0] ^= 1;
        assert_ne!(first, hmac_sha256(&token, SERVER_PROOF_LABEL, &first_nonce));
    }
}
