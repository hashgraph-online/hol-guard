#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
#[cfg(unix)]
use std::path::Path;
use std::time::{Duration, Instant};

#[path = "resident_client_deadline.rs"]
mod deadline;
use deadline::DeadlineStream;

use crate::{
    constant_time_eq, hmac_sha256, BoxedResidentStream, ResidentStream, AUTH_NONCE_BYTES,
    AUTH_PROOF_BYTES, AUTH_TIMEOUT, CLIENT_PROOF_LABEL, FRAME_DIGEST_BYTES, FRAME_HEADER_BYTES,
    FRAME_REQUEST_ID_BYTES, MAX_NATIVE_RESPONSE_BYTES, REQUEST_MAGIC, RESPONSE_MAGIC,
    SERVER_PROOF_LABEL,
};

pub(crate) struct ExpectedProcessIdentity<'a> {
    pub(crate) process_id: u32,
    pub(crate) start_marker: &'a str,
    pub(crate) digest: Option<&'a str>,
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

fn authenticate(
    stream: &mut dyn crate::ResidentStream,
    token: &[u8],
    timeout: Duration,
) -> Result<[u8; AUTH_NONCE_BYTES], ResidentClientError> {
    stream
        .set_resident_read_timeout(Some(timeout.min(AUTH_TIMEOUT)))
        .map_err(|_| "native_client_auth_timeout_failed".to_owned())?;
    stream
        .set_resident_write_timeout(Some(timeout.min(AUTH_TIMEOUT)))
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
    read_exact(stream, &mut server_proof).map_err(|error| ResidentClientError {
        code: error.code,
        retryable_teardown: false,
    })?;
    let expected = hmac_sha256(token, SERVER_PROOF_LABEL, &nonce);
    if !constant_time_eq(&server_proof, &expected) {
        return Err("native_client_auth_rejected".to_owned().into());
    }
    Ok(nonce)
}

fn validate_runtime_owner(identity: &ExpectedProcessIdentity<'_>) -> Result<(), String> {
    match identity.digest {
        Some(digest) => crate::resident_state::validate_runtime_process_identity(
            identity.process_id,
            identity.start_marker,
            digest,
        ),
        None => crate::resident_state::validate_package_process_identity(
            identity.process_id,
            identity.start_marker,
        ),
    }
}

fn connect_remaining(deadline: Instant) -> Result<Duration, String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("native_client_deadline_exceeded".to_owned());
    }
    Ok(remaining)
}

fn connect_loopback_with_digest(
    endpoint: &str,
    deadline: Instant,
    identity: &ExpectedProcessIdentity<'_>,
) -> Result<BoxedResidentStream, String> {
    let address: SocketAddr = endpoint
        .parse()
        .map_err(|_| "native_client_endpoint_invalid".to_owned())?;
    if address.ip() != Ipv4Addr::LOCALHOST || address.port() == 0 {
        return Err("native_client_endpoint_invalid".to_owned());
    }
    validate_runtime_owner(identity)?;
    let connect_timeout = connect_remaining(deadline)?.min(AUTH_TIMEOUT);
    let stream = crate::observe_native_phase!(
        LoopbackConnectHandle,
        TcpStream::connect_timeout(&address, connect_timeout)
    )
    .map_err(|_| "native_client_connect_failed".to_owned())?;
    validate_runtime_owner(identity)?;
    let _ = connect_remaining(deadline)?;
    Ok(Box::new(stream))
}

#[cfg(unix)]
fn connect_unix_with_digest(
    endpoint: &str,
    deadline: Instant,
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
    let _ = connect_remaining(deadline)?;
    let address = UnixAddr::new(Path::new(endpoint))
        .map_err(|_| "native_client_endpoint_invalid".to_owned())?;
    let descriptor = crate::observe_native_phase!(
        UnixSocketCreation,
        socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
    )
    .map_err(|_| "native_client_connect_failed".to_owned())?;
    fcntl(&descriptor, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
        .map_err(|_| "native_client_connect_failed".to_owned())?;
    fcntl(&descriptor, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
        .map_err(|_| "native_client_connect_failed".to_owned())?;
    #[cfg(test)]
    connect_deadline_tests::checkpoint();
    let _ = connect_remaining(deadline)?;
    match connect(descriptor.as_raw_fd(), &address) {
        Ok(()) | Err(Errno::EISCONN) => {}
        Err(Errno::EINPROGRESS) => {
            let poll_timeout = PollTimeout::try_from(connect_remaining(deadline)?)
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
    let peer_process_id =
        nix::sys::socket::getsockopt(&stream, nix::sys::socket::sockopt::PeerCredentials)
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
    validate_runtime_owner(identity)?;
    stream
        .set_read_timeout(Some(connect_remaining(deadline)?))
        .map_err(|_| "native_client_timeout_failed".to_owned())?;
    stream
        .set_write_timeout(Some(connect_remaining(deadline)?))
        .map_err(|_| "native_client_timeout_failed".to_owned())?;
    Ok(Box::new(stream))
}

#[cfg(not(unix))]
fn connect_unix_with_digest(
    endpoint: &str,
    deadline: Instant,
    identity: &ExpectedProcessIdentity<'_>,
) -> Result<BoxedResidentStream, String> {
    let _ = (endpoint, deadline, identity);
    Err("native_client_unix_unavailable".to_owned())
}

fn connect(
    transport: &str,
    endpoint: &str,
    deadline: Instant,
    identity: &ExpectedProcessIdentity<'_>,
) -> Result<BoxedResidentStream, String> {
    match transport {
        "unix" => connect_unix_with_digest(endpoint, deadline, identity),
        "loopback" => connect_loopback_with_digest(endpoint, deadline, identity),
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
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| ResidentClientError::fatal("native_client_deadline_invalid".to_owned()))?;
    send_request_for_digest_at_deadline_detailed(
        transport, endpoint, token, payload, deadline, identity,
    )
}

pub(crate) fn send_request_for_digest_at_deadline_detailed(
    transport: &str,
    endpoint: &str,
    token: &[u8],
    payload: &[u8],
    deadline: Instant,
    identity: &ExpectedProcessIdentity<'_>,
) -> Result<Vec<u8>, ResidentClientError> {
    let _ = connect_remaining(deadline).map_err(ResidentClientError::fatal)?;
    let mut stream = crate::observe_native_phase!(
        ClientConnect,
        connect(transport, endpoint, deadline, identity)
    )
    .map_err(ResidentClientError::fatal)?;
    exchange_request(&mut *stream, token, payload, deadline)
}

fn exchange_request(
    stream: &mut dyn crate::ResidentStream,
    token: &[u8],
    payload: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, ResidentClientError> {
    let result = (|| {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("native_client_deadline_exceeded".to_owned().into());
        }
        // read_exact/write_all perform multiple syscalls. Their per-socket
        // timeout alone is an inactivity timeout, not an overall deadline.
        let mut stream = DeadlineStream::new(stream, deadline);
        let nonce = crate::observe_native_phase!(
            ClientAuthenticate,
            authenticate(&mut stream, token, remaining)
        )?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("native_client_deadline_exceeded".to_owned().into());
        }
        stream
            .set_resident_read_timeout(Some(remaining))
            .map_err(|_| "native_client_timeout_failed".to_owned())?;
        stream
            .set_resident_write_timeout(Some(remaining))
            .map_err(|_| "native_client_timeout_failed".to_owned())?;
        let request_id = crate::observe_native_phase!(
            ClientRequestWriteFlush,
            write_request(&mut stream, token, &nonce, payload)
        )?;
        crate::observe_native_phase!(
            ClientCommittedResponseRead,
            read_committed_response(&mut stream, &request_id)
        )
    })();
    if Instant::now() >= deadline {
        // A timed-out write or response can follow a committed request.
        // Never reclassify it as replay-safe transport teardown.
        return Err("native_client_deadline_exceeded".to_owned().into());
    }
    result
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

#[cfg(test)]
#[path = "resident_client_deadline_tests.rs"]
mod deadline_tests;

#[cfg(all(test, unix))]
#[path = "resident_client_connect_deadline_tests.rs"]
mod connect_deadline_tests;
