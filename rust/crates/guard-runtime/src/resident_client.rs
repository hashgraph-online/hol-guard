#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
#[cfg(unix)]
use std::path::Path;
use std::time::Duration;

use crate::{
    constant_time_eq, hmac_sha256, BoxedResidentStream, AUTH_NONCE_BYTES, AUTH_PROOF_BYTES,
    AUTH_TIMEOUT, CLIENT_PROOF_LABEL, FRAME_DIGEST_BYTES, FRAME_HEADER_BYTES,
    FRAME_REQUEST_ID_BYTES, MAX_NATIVE_RESPONSE_BYTES, REQUEST_MAGIC, RESPONSE_MAGIC,
    SERVER_PROOF_LABEL,
};

use crate::resident_diagnostics::{observe, Phase};

pub(crate) struct ExpectedProcessIdentity<'a> {
    pub(crate) process_id: u32,
    pub(crate) start_marker: &'a str,
    pub(crate) runtime: ExpectedRuntime<'a>,
}

/// How a client proves the peer runs the runtime it expects.
pub(crate) enum ExpectedRuntime<'a> {
    /// The peer shares this executable's path, or its bytes hash to this
    /// runtime's digest. A onefile launcher extracts identical runtimes into
    /// distinct directories, so this reads the peer's runtime when the paths
    /// differ.
    Package,
    /// The peer's runtime hashes to this digest.
    Digest(&'a str),
    /// The peer shares this executable's path, or its state records the digest
    /// that this executable's own durable copy is published under. A caller on
    /// the hook path takes this because it can afford no runtime hash.
    DurableCopy {
        recorded: &'a str,
        published: &'a str,
    },
}

impl<'a> ExpectedRuntime<'a> {
    /// What a direct-lane client requires of the resident it connects to.
    ///
    /// A durable copy knows its own digest from the directory it was published
    /// under, so it can accept the resident its state records without reading a
    /// runtime. Any other launcher keeps the package expectation it had before.
    pub(crate) fn for_direct_lane(recorded: &'a str, durable_digest: Option<&'a str>) -> Self {
        match durable_digest {
            Some(published) => Self::DurableCopy {
                recorded,
                published,
            },
            None => Self::Package,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ResidentClientError {
    pub(crate) code: String,
    pub(crate) retryable_teardown: bool,
}

impl ResidentClientError {
    fn fatal(code: String) -> Self {
        Self {
            code,
            retryable_teardown: false,
        }
    }
}

impl From<String> for ResidentClientError {
    fn from(code: String) -> Self {
        Self::fatal(code)
    }
}

fn is_retryable_teardown_io_error(error: &io::Error) -> bool {
    matches!(
        crate::hardening::classify_io_error(error),
        crate::hardening::IoFailureClass::ClientAbort
            | crate::hardening::IoFailureClass::NetworkChange
    )
}

fn read_exact(
    stream: &mut dyn crate::ResidentStream,
    output: &mut [u8],
) -> Result<(), ResidentClientError> {
    stream
        .read_exact(output)
        .map_err(|_| ResidentClientError::fatal("native_client_frame_read_failed".to_owned()))
}

/// Longest the client waits for the connect and authentication handshake.
const AUTH_WINDOW_MAX: Duration = Duration::from_secs(2);

/// Handshake window for a request with the given total budget.
///
/// Short budgets, such as hook decisions, keep the fixed 250 ms window.  A
/// request that was granted a long budget (lifecycle and approval-gate calls)
/// gets a proportionally longer handshake so a briefly slow resident does not
/// turn into a permanent failure.  It never exceeds the request budget, and an
/// expired window still fails closed.
fn auth_window(timeout: Duration) -> Duration {
    (timeout / 4)
        .clamp(AUTH_TIMEOUT, AUTH_WINDOW_MAX)
        .min(timeout)
}

/// Read the server proof, bounding the whole read (not each read call) by `deadline`.
///
/// A socket timeout restarts on every read, so a peer that drips the proof a few
/// bytes at a time could otherwise hold the handshake open past its window.
fn read_proof_within(
    stream: &mut dyn crate::ResidentStream,
    output: &mut [u8],
    deadline: std::time::Instant,
) -> Result<(), ResidentClientError> {
    let mut filled = 0;
    while filled < output.len() {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(ResidentClientError::fatal(
                "native_client_frame_read_failed".to_owned(),
            ));
        }
        stream
            .set_resident_read_timeout(Some(remaining))
            .map_err(|_| "native_client_auth_timeout_failed".to_owned())?;
        match stream.read(&mut output[filled..]) {
            Ok(0) => {
                return Err(ResidentClientError::fatal(
                    "native_client_frame_read_failed".to_owned(),
                ))
            }
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                return Err(ResidentClientError::fatal(
                    "native_client_frame_read_failed".to_owned(),
                ))
            }
        }
    }
    Ok(())
}

fn authenticate(
    stream: &mut dyn crate::ResidentStream,
    token: &[u8],
    timeout: Duration,
) -> Result<[u8; AUTH_NONCE_BYTES], ResidentClientError> {
    let started = std::time::Instant::now();
    let window = auth_window(timeout);
    stream
        .set_resident_read_timeout(Some(window))
        .map_err(|_| "native_client_auth_timeout_failed".to_owned())?;
    stream
        .set_resident_write_timeout(Some(window))
        .map_err(|_| "native_client_auth_timeout_failed".to_owned())?;
    let _ = stream.configure_low_latency();
    let mut nonce = [0u8; AUTH_NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| "native_client_random_failed".to_owned())?;
    stream
        .write_all(&nonce)
        .map_err(|error| ResidentClientError {
            code: "native_client_auth_nonce_failed".to_owned(),
            retryable_teardown: is_retryable_teardown_io_error(&error),
        })?;
    let mut server_proof = [0u8; AUTH_PROOF_BYTES];
    // A server-proof read happens after the client has sent its nonce.  Even
    // an EOF that looks like a transport teardown at this phase is not safe
    // to replay: the peer has not completed authentication.
    read_proof_within(stream, &mut server_proof, started + window).map_err(|error| {
        ResidentClientError {
            code: error.code,
            retryable_teardown: false,
        }
    })?;
    let expected = hmac_sha256(token, SERVER_PROOF_LABEL, &nonce);
    if !constant_time_eq(&server_proof, &expected) {
        return Err("native_client_auth_rejected".to_owned().into());
    }
    Ok(nonce)
}

fn validate_runtime_owner(identity: &ExpectedProcessIdentity<'_>) -> Result<(), String> {
    match identity.runtime {
        ExpectedRuntime::Digest(digest) => {
            crate::resident_state::validate_runtime_process_identity(
                identity.process_id,
                identity.start_marker,
                digest,
            )
        }
        ExpectedRuntime::Package => crate::resident_state::validate_package_process_identity(
            identity.process_id,
            identity.start_marker,
        ),
        ExpectedRuntime::DurableCopy {
            recorded,
            published,
        } => crate::resident_state::validate_direct_lane_process_identity(
            identity.process_id,
            identity.start_marker,
            recorded,
            Some(published),
        ),
    }
}

/// Confirm the peer validated before connecting is still the same process.
///
/// A matching start marker rules out PID reuse, and a running process cannot
/// change its image, so hashing the runtime again would only add latency.
/// On Windows that second hash can outlast the resident's 250 ms
/// authentication window and make every request fail.
fn revalidate_runtime_owner(identity: &ExpectedProcessIdentity<'_>) -> Result<(), String> {
    crate::resident_state::validate_process_start_marker(identity.process_id, identity.start_marker)
}

fn connect_loopback_with_digest(
    endpoint: &str,
    timeout: Duration,
    identity: &ExpectedProcessIdentity<'_>,
) -> Result<BoxedResidentStream, String> {
    let address: SocketAddr = endpoint
        .parse()
        .map_err(|_| "native_client_endpoint_invalid".to_owned())?;
    if address.ip() != Ipv4Addr::LOCALHOST || address.port() == 0 {
        return Err("native_client_endpoint_invalid".to_owned());
    }
    validate_runtime_owner(identity)?;
    let stream = TcpStream::connect_timeout(&address, auth_window(timeout))
        .map_err(|_| "native_client_connect_failed".to_owned())?;
    revalidate_runtime_owner(identity)?;
    Ok(Box::new(stream))
}

#[cfg(unix)]
fn connect_unix_with_digest(
    endpoint: &str,
    timeout: Duration,
    identity: &ExpectedProcessIdentity<'_>,
) -> Result<BoxedResidentStream, String> {
    use nix::errno::Errno;
    use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use nix::sys::socket::{
        connect, getsockopt, socket, sockopt, AddressFamily, SockFlag, SockType, UnixAddr,
    };
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::net::UnixStream;
    let address = UnixAddr::new(Path::new(endpoint))
        .map_err(|_| "native_client_endpoint_invalid".to_owned())?;
    // Hash the runtime before connecting; after connect only the cheap
    // peer-PID and start-marker checks run inside the auth window.
    validate_runtime_owner(identity)?;
    let descriptor = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|_| "native_client_connect_failed".to_owned())?;
    fcntl(&descriptor, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
        .map_err(|_| "native_client_connect_failed".to_owned())?;
    fcntl(&descriptor, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
        .map_err(|_| "native_client_connect_failed".to_owned())?;
    match connect(descriptor.as_raw_fd(), &address) {
        Ok(()) | Err(Errno::EISCONN) => {}
        Err(Errno::EINPROGRESS) => {
            let poll_timeout = PollTimeout::try_from(timeout)
                .map_err(|_| "native_client_deadline_invalid".to_owned())?;
            let mut descriptors = [PollFd::new(descriptor.as_fd(), PollFlags::POLLOUT)];
            if poll(&mut descriptors, poll_timeout)
                .map_err(|_| "native_client_connect_failed".to_owned())?
                == 0
            {
                return Err("native_client_deadline_exceeded".to_owned());
            }
            let socket_error = getsockopt(&descriptor, sockopt::SocketError)
                .map_err(|_| "native_client_connect_failed".to_owned())?;
            if socket_error != 0 {
                return Err("native_client_connect_failed".to_owned());
            }
        }
        Err(_) => return Err("native_client_connect_failed".to_owned()),
    }
    let stream = UnixStream::from(descriptor);
    stream
        .set_nonblocking(false)
        .map_err(|_| "native_client_connect_failed".to_owned())?;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let peer_process_id =
        nix::sys::socket::getsockopt(&stream, nix::sys::socket::sockopt::LocalPeerPid)
            .map_err(|_| "native_client_peer_identity_failed".to_owned())? as u32;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let peer_process_id = crate::resident_peer_identity::read_linux_credentials(&stream)
        .map_err(|_| "native_client_peer_identity_failed".to_owned())?
        .pid() as u32;
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "android"
    )))]
    let peer_process_id = identity.process_id;
    if peer_process_id != identity.process_id {
        return Err("native_client_peer_identity_mismatch".to_owned());
    }
    revalidate_runtime_owner(identity)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| "native_client_timeout_failed".to_owned())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_| "native_client_timeout_failed".to_owned())?;
    Ok(Box::new(stream))
}

#[cfg(not(unix))]
fn connect_unix_with_digest(
    endpoint: &str,
    timeout: Duration,
    identity: &ExpectedProcessIdentity<'_>,
) -> Result<BoxedResidentStream, String> {
    let _ = (endpoint, timeout, identity);
    Err("native_client_unix_unavailable".to_owned())
}

fn connect(
    transport: &str,
    endpoint: &str,
    timeout: Duration,
    identity: &ExpectedProcessIdentity<'_>,
) -> Result<BoxedResidentStream, String> {
    match transport {
        "unix" => connect_unix_with_digest(endpoint, timeout, identity),
        "loopback" => connect_loopback_with_digest(endpoint, timeout, identity),
        _ => Err("native_client_transport_invalid".to_owned()),
    }
}

fn write_request(
    stream: &mut dyn crate::ResidentStream,
    token: &[u8],
    nonce: &[u8; AUTH_NONCE_BYTES],
    payload: &[u8],
) -> Result<[u8; FRAME_REQUEST_ID_BYTES], ResidentClientError> {
    if payload.is_empty() || payload.len() > crate::MAX_NATIVE_REQUEST_BYTES {
        return Err("native_client_request_too_large".to_owned().into());
    }
    let mut request_id = [0u8; FRAME_REQUEST_ID_BYTES];
    getrandom::fill(&mut request_id).map_err(|_| "native_client_random_failed".to_owned())?;
    let digest = Sha256::digest(payload);
    let mut frame = Vec::with_capacity(AUTH_PROOF_BYTES + FRAME_HEADER_BYTES + payload.len());
    frame.extend_from_slice(&hmac_sha256(token, CLIENT_PROOF_LABEL, nonce));
    frame.extend_from_slice(REQUEST_MAGIC);
    frame.extend_from_slice(&request_id);
    frame.extend_from_slice(&digest);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    stream
        .write_all(&frame)
        .and_then(|()| stream.flush())
        .map_err(|_| ResidentClientError::fatal("native_client_frame_write_failed".to_owned()))?;
    Ok(request_id)
}

fn read_response(
    stream: &mut dyn crate::ResidentStream,
    request_id: &[u8; FRAME_REQUEST_ID_BYTES],
) -> Result<Vec<u8>, ResidentClientError> {
    let mut header = [0u8; FRAME_HEADER_BYTES];
    read_exact(stream, &mut header)?;
    if !constant_time_eq(&header[..4], RESPONSE_MAGIC)
        || !constant_time_eq(&header[4..4 + FRAME_REQUEST_ID_BYTES], request_id)
    {
        return Err("native_client_response_binding_failed".to_owned().into());
    }
    let digest_start = 4 + FRAME_REQUEST_ID_BYTES;
    let digest = &header[digest_start..digest_start + FRAME_DIGEST_BYTES];
    let length = u32::from_be_bytes(
        header[FRAME_HEADER_BYTES - 4..]
            .try_into()
            .map_err(|_| "native_client_frame_invalid".to_owned())?,
    ) as usize;
    if length == 0 || length > MAX_NATIVE_RESPONSE_BYTES {
        return Err("native_client_response_too_large".to_owned().into());
    }
    let mut response = vec![0u8; length];
    read_exact(stream, &mut response)?;
    if !constant_time_eq(&Sha256::digest(&response), digest) {
        return Err("native_client_response_digest_mismatch".to_owned().into());
    }
    Ok(response)
}

// Once a request has been fully written and flushed, the peer may have
// already applied it. Response-side teardown is therefore never replay-safe.
fn read_committed_response(
    stream: &mut dyn crate::ResidentStream,
    request_id: &[u8; FRAME_REQUEST_ID_BYTES],
) -> Result<Vec<u8>, ResidentClientError> {
    read_response(stream, request_id).map_err(|error| ResidentClientError {
        code: error.code,
        retryable_teardown: false,
    })
}

pub(crate) fn send_request_for_digest_detailed(
    transport: &str,
    endpoint: &str,
    token: &[u8],
    payload: &[u8],
    timeout: Duration,
    identity: &ExpectedProcessIdentity<'_>,
) -> Result<Vec<u8>, ResidentClientError> {
    let started = std::time::Instant::now();
    let mut stream = observe(Phase::ClientConnect, || {
        connect(transport, endpoint, timeout, identity)
    })
    .map_err(ResidentClientError::fatal)?;
    let remaining = timeout.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Err("native_client_deadline_exceeded".to_owned().into());
    }
    let nonce = observe(Phase::ClientAuthenticate, || {
        authenticate(&mut *stream, token, remaining)
    })?;
    let remaining = timeout.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Err("native_client_deadline_exceeded".to_owned().into());
    }
    stream
        .set_resident_read_timeout(Some(remaining))
        .map_err(|_| "native_client_timeout_failed".to_owned())?;
    stream
        .set_resident_write_timeout(Some(remaining))
        .map_err(|_| "native_client_timeout_failed".to_owned())?;
    let request_id = observe(Phase::ClientRequestWrite, || {
        write_request(&mut *stream, token, &nonce, payload)
    })?;
    if started.elapsed() >= timeout {
        return Err("native_client_deadline_exceeded".to_owned().into());
    }
    observe(Phase::ClientResponseRead, || {
        read_committed_response(&mut *stream, &request_id)
    })
}

pub(crate) fn send_request_for_digest(
    transport: &str,
    endpoint: &str,
    token: &[u8],
    payload: &[u8],
    timeout: Duration,
    identity: &ExpectedProcessIdentity<'_>,
) -> Result<Vec<u8>, String> {
    send_request_for_digest_detailed(transport, endpoint, token, payload, timeout, identity)
        .map_err(|error| error.code)
}

#[cfg(test)]
#[path = "resident_client_tests.rs"]
mod tests;
