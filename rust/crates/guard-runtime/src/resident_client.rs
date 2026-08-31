#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
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

fn read_exact(stream: &mut dyn crate::ResidentStream, output: &mut [u8]) -> Result<(), String> {
    stream
        .read_exact(output)
        .map_err(|_| "native_client_frame_read_failed".to_owned())
}

fn authenticate(
    stream: &mut dyn crate::ResidentStream,
    token: &[u8],
    timeout: Duration,
) -> Result<[u8; AUTH_NONCE_BYTES], String> {
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
        .map_err(|_| "native_client_auth_nonce_failed".to_owned())?;
    let mut server_proof = [0u8; AUTH_PROOF_BYTES];
    read_exact(stream, &mut server_proof)?;
    let expected = hmac_sha256(token, SERVER_PROOF_LABEL, &nonce);
    if !constant_time_eq(&server_proof, &expected) {
        return Err("native_client_auth_rejected".to_owned());
    }
    Ok(nonce)
}

#[cfg(windows)]
fn validate_loopback_owner(_address: &SocketAddr, expected_process_id: u32) -> Result<(), String> {
    crate::resident_state::validate_package_process_identity(expected_process_id)
}

#[cfg(not(windows))]
fn validate_loopback_owner(_address: &SocketAddr, _expected_process_id: u32) -> Result<(), String> {
    Ok(())
}

fn connect_loopback(
    endpoint: &str,
    timeout: Duration,
    expected_process_id: u32,
) -> Result<BoxedResidentStream, String> {
    let address: SocketAddr = endpoint
        .parse()
        .map_err(|_| "native_client_endpoint_invalid".to_owned())?;
    if address.ip() != Ipv4Addr::LOCALHOST || address.port() == 0 {
        return Err("native_client_endpoint_invalid".to_owned());
    }
    validate_loopback_owner(&address, expected_process_id)?;
    let stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|_| "native_client_connect_failed".to_owned())?;
    Ok(Box::new(stream))
}

#[cfg(unix)]
fn connect_unix(
    endpoint: &str,
    timeout: Duration,
    expected_process_id: u32,
) -> Result<BoxedResidentStream, String> {
    use std::os::unix::net::UnixStream;
    let stream = UnixStream::connect(Path::new(endpoint))
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
    let peer_process_id = expected_process_id;
    if peer_process_id != expected_process_id {
        return Err("native_client_peer_identity_mismatch".to_owned());
    }
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| "native_client_timeout_failed".to_owned())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_| "native_client_timeout_failed".to_owned())?;
    Ok(Box::new(stream))
}

#[cfg(not(unix))]
fn connect_unix(
    _endpoint: &str,
    _timeout: Duration,
    _expected_process_id: u32,
) -> Result<BoxedResidentStream, String> {
    Err("native_client_unix_unavailable".to_owned())
}

fn connect(
    transport: &str,
    endpoint: &str,
    timeout: Duration,
    expected_process_id: u32,
) -> Result<BoxedResidentStream, String> {
    match transport {
        "unix" => connect_unix(endpoint, timeout, expected_process_id),
        "loopback" => connect_loopback(endpoint, timeout, expected_process_id),
        _ => Err("native_client_transport_invalid".to_owned()),
    }
}

fn write_request(
    stream: &mut dyn crate::ResidentStream,
    token: &[u8],
    nonce: &[u8; AUTH_NONCE_BYTES],
    payload: &[u8],
) -> Result<[u8; FRAME_REQUEST_ID_BYTES], String> {
    if payload.is_empty() || payload.len() > crate::MAX_NATIVE_REQUEST_BYTES {
        return Err("native_client_request_too_large".to_owned());
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
        .map_err(|_| "native_client_frame_write_failed".to_owned())?;
    Ok(request_id)
}

fn read_response(
    stream: &mut dyn crate::ResidentStream,
    request_id: &[u8; FRAME_REQUEST_ID_BYTES],
) -> Result<Vec<u8>, String> {
    let mut header = [0u8; FRAME_HEADER_BYTES];
    read_exact(stream, &mut header)?;
    if !constant_time_eq(&header[..4], RESPONSE_MAGIC)
        || !constant_time_eq(&header[4..4 + FRAME_REQUEST_ID_BYTES], request_id)
    {
        return Err("native_client_response_binding_failed".to_owned());
    }
    let digest_start = 4 + FRAME_REQUEST_ID_BYTES;
    let digest = &header[digest_start..digest_start + FRAME_DIGEST_BYTES];
    let length = u32::from_be_bytes(
        header[FRAME_HEADER_BYTES - 4..]
            .try_into()
            .map_err(|_| "native_client_frame_invalid".to_owned())?,
    ) as usize;
    if length == 0 || length > MAX_NATIVE_RESPONSE_BYTES {
        return Err("native_client_response_too_large".to_owned());
    }
    let mut response = vec![0u8; length];
    read_exact(stream, &mut response)?;
    if !constant_time_eq(&Sha256::digest(&response), digest) {
        return Err("native_client_response_digest_mismatch".to_owned());
    }
    Ok(response)
}

pub(crate) fn send_request(
    transport: &str,
    endpoint: &str,
    token: &[u8],
    payload: &[u8],
    timeout: Duration,
    expected_process_id: u32,
) -> Result<Vec<u8>, String> {
    let started = std::time::Instant::now();
    let mut stream = connect(transport, endpoint, timeout, expected_process_id)?;
    let remaining = timeout.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Err("native_client_deadline_exceeded".to_owned());
    }
    let nonce = authenticate(&mut *stream, token, remaining)?;
    let remaining = timeout.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Err("native_client_deadline_exceeded".to_owned());
    }
    stream
        .set_resident_read_timeout(Some(remaining))
        .map_err(|_| "native_client_timeout_failed".to_owned())?;
    stream
        .set_resident_write_timeout(Some(remaining))
        .map_err(|_| "native_client_timeout_failed".to_owned())?;
    let request_id = write_request(&mut *stream, token, &nonce, payload)?;
    if started.elapsed() >= timeout {
        return Err("native_client_deadline_exceeded".to_owned());
    }
    read_response(&mut *stream, &request_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_loopback_tcp_endpoint() {
        let error = match connect_loopback("192.0.2.1:80", Duration::from_millis(1), 1) {
            Ok(_) => panic!("non-loopback endpoint was accepted"),
            Err(error) => error,
        };
        assert_eq!(error, "native_client_endpoint_invalid");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_response_bound_to_another_request() {
        use std::io::Write as _;
        use std::os::unix::net::UnixStream;
        use std::thread;

        let (mut client, mut server) = UnixStream::pair().unwrap();
        let expected_request_id = [1u8; FRAME_REQUEST_ID_BYTES];
        thread::spawn(move || {
            let response = b"{}";
            let mut header = Vec::new();
            header.extend_from_slice(RESPONSE_MAGIC);
            header.extend_from_slice(&[2u8; FRAME_REQUEST_ID_BYTES]);
            header.extend_from_slice(&Sha256::digest(response));
            header.extend_from_slice(&(response.len() as u32).to_be_bytes());
            server.write_all(&header).unwrap();
            server.write_all(response).unwrap();
        });
        let error = read_response(&mut client, &expected_request_id).unwrap_err();
        assert_eq!(error, "native_client_response_binding_failed");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_response_digest_mismatch() {
        use std::io::Write as _;
        use std::os::unix::net::UnixStream;
        use std::thread;

        let (mut client, mut server) = UnixStream::pair().unwrap();
        let request_id = [3u8; FRAME_REQUEST_ID_BYTES];
        thread::spawn(move || {
            let response = b"{}";
            let mut header = Vec::new();
            header.extend_from_slice(RESPONSE_MAGIC);
            header.extend_from_slice(&request_id);
            header.extend_from_slice(&[0u8; FRAME_DIGEST_BYTES]);
            header.extend_from_slice(&(response.len() as u32).to_be_bytes());
            server.write_all(&header).unwrap();
            server.write_all(response).unwrap();
        });
        let error = read_response(&mut client, &request_id).unwrap_err();
        assert_eq!(error, "native_client_response_digest_mismatch");
    }
}
