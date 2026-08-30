#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{
    constant_time_eq, hex_nibble, hmac_sha256, AUTH_NONCE_BYTES, AUTH_PROOF_BYTES,
    AUTH_TOKEN_BYTES, CLIENT_PROOF_LABEL, FRAME_DIGEST_BYTES, FRAME_HEADER_BYTES,
    FRAME_REQUEST_ID_BYTES, MAX_NATIVE_REQUEST_BYTES, MAX_NATIVE_RESPONSE_BYTES, REQUEST_MAGIC,
    RESPONSE_MAGIC, SERVER_PROOF_LABEL,
};

const CLIENT_TIMEOUT: Duration = Duration::from_secs(2);
static CLIENT_COUNTER: AtomicU64 = AtomicU64::new(1);

fn unique_bytes(label: &[u8], payload: &[u8]) -> [u8; 32] {
    let counter = CLIENT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(std::process::id().to_be_bytes());
    hasher.update(counter.to_be_bytes());
    hasher.update(now.to_be_bytes());
    hasher.update(Sha256::digest(payload));
    hasher.finalize().into()
}

fn parse_input(bytes: &[u8]) -> Result<([u8; AUTH_TOKEN_BYTES], &[u8]), String> {
    if bytes.len() > MAX_NATIVE_REQUEST_BYTES + AUTH_TOKEN_BYTES * 2 + 2 {
        return Err("native_resident_client_input_too_large".to_owned());
    }
    let newline = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or_else(|| "native_resident_client_auth_missing".to_owned())?;
    let encoded = &bytes[..newline];
    if encoded.len() != AUTH_TOKEN_BYTES * 2 {
        return Err("native_resident_client_auth_invalid".to_owned());
    }
    let payload = &bytes[newline + 1..];
    if payload.is_empty() || payload.len() > MAX_NATIVE_REQUEST_BYTES {
        return Err("native_resident_client_payload_invalid".to_owned());
    }
    let mut token = [0u8; AUTH_TOKEN_BYTES];
    for (index, pair) in encoded.chunks_exact(2).enumerate() {
        let high =
            hex_nibble(pair[0]).ok_or_else(|| "native_resident_client_auth_invalid".to_owned())?;
        let low =
            hex_nibble(pair[1]).ok_or_else(|| "native_resident_client_auth_invalid".to_owned())?;
        token[index] = (high << 4) | low;
    }
    Ok((token, payload))
}

fn read_exact_bounded(stream: &mut dyn Read, length: usize) -> Result<Vec<u8>, String> {
    if length > MAX_NATIVE_RESPONSE_BYTES {
        return Err("native_resident_client_response_too_large".to_owned());
    }
    let mut bytes = vec![0u8; length];
    stream
        .read_exact(&mut bytes)
        .map_err(|_| "native_resident_client_read_failed".to_owned())?;
    Ok(bytes)
}

fn authenticate(
    stream: &mut (impl Read + Write),
    token: &[u8; AUTH_TOKEN_BYTES],
    payload: &[u8],
) -> Result<(), String> {
    let nonce = unique_bytes(b"hol-guard-resident-client-nonce-v1\0", payload);
    stream
        .write_all(&nonce[..AUTH_NONCE_BYTES])
        .map_err(|_| "native_resident_client_auth_write_failed".to_owned())?;
    let mut server_proof = [0u8; AUTH_PROOF_BYTES];
    stream
        .read_exact(&mut server_proof)
        .map_err(|_| "native_resident_client_auth_read_failed".to_owned())?;
    let expected = hmac_sha256(token, SERVER_PROOF_LABEL, &nonce[..AUTH_NONCE_BYTES]);
    if !constant_time_eq(&server_proof, &expected) {
        return Err("native_resident_client_auth_rejected".to_owned());
    }
    let client_proof = hmac_sha256(token, CLIENT_PROOF_LABEL, &nonce[..AUTH_NONCE_BYTES]);
    stream
        .write_all(&client_proof)
        .map_err(|_| "native_resident_client_auth_write_failed".to_owned())?;
    Ok(())
}

fn exchange(
    stream: &mut (impl Read + Write),
    token: &[u8; AUTH_TOKEN_BYTES],
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    authenticate(stream, token, payload)?;
    let request_id = unique_bytes(b"hol-guard-resident-client-request-v1\0", payload);
    let request_digest = Sha256::digest(payload);
    let mut header = Vec::with_capacity(FRAME_HEADER_BYTES);
    header.extend_from_slice(REQUEST_MAGIC);
    header.extend_from_slice(&request_id[..FRAME_REQUEST_ID_BYTES]);
    header.extend_from_slice(&request_digest[..FRAME_DIGEST_BYTES]);
    header.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    stream
        .write_all(&header)
        .and_then(|_| stream.write_all(payload))
        .and_then(|_| stream.flush())
        .map_err(|_| "native_resident_client_write_failed".to_owned())?;

    let mut response_header = [0u8; FRAME_HEADER_BYTES];
    stream
        .read_exact(&mut response_header)
        .map_err(|_| "native_resident_client_response_header_failed".to_owned())?;
    if !constant_time_eq(&response_header[..4], RESPONSE_MAGIC) {
        return Err("native_resident_client_response_version_mismatch".to_owned());
    }
    if !constant_time_eq(
        &response_header[4..4 + FRAME_REQUEST_ID_BYTES],
        &request_id[..FRAME_REQUEST_ID_BYTES],
    ) {
        return Err("native_resident_client_response_id_mismatch".to_owned());
    }
    let digest_start = 4 + FRAME_REQUEST_ID_BYTES;
    let response_digest = &response_header[digest_start..digest_start + FRAME_DIGEST_BYTES];
    let length = u32::from_be_bytes(
        response_header[FRAME_HEADER_BYTES - 4..]
            .try_into()
            .map_err(|_| "native_resident_client_response_header_failed".to_owned())?,
    ) as usize;
    if length == 0 || length > MAX_NATIVE_RESPONSE_BYTES {
        return Err("native_resident_client_response_too_large".to_owned());
    }
    let response = read_exact_bounded(stream, length)?;
    if !constant_time_eq(&Sha256::digest(&response), response_digest) {
        return Err("native_resident_client_response_digest_mismatch".to_owned());
    }
    Ok(response)
}

#[cfg(unix)]
pub(crate) fn request_unix(path: &str, input: &[u8]) -> Result<Vec<u8>, String> {
    use std::os::unix::net::UnixStream;

    let (token, payload) = parse_input(input)?;
    let mut stream = UnixStream::connect(path)
        .map_err(|_| "native_resident_client_connect_failed".to_owned())?;
    stream
        .set_read_timeout(Some(CLIENT_TIMEOUT))
        .map_err(|_| "native_resident_client_timeout_failed".to_owned())?;
    stream
        .set_write_timeout(Some(CLIENT_TIMEOUT))
        .map_err(|_| "native_resident_client_timeout_failed".to_owned())?;
    exchange(&mut stream, &token, payload)
}

#[cfg(not(unix))]
pub(crate) fn request_unix(_path: &str, _input: &[u8]) -> Result<Vec<u8>, String> {
    Err("native_unix_socket_not_available".to_owned())
}

pub(crate) fn request_loopback(address: &str, input: &[u8]) -> Result<Vec<u8>, String> {
    let (token, payload) = parse_input(input)?;
    let requested: SocketAddr = address
        .parse()
        .map_err(|_| "native_resident_client_address_invalid".to_owned())?;
    if requested.ip() != Ipv4Addr::LOCALHOST || requested.port() == 0 {
        return Err("native_resident_client_address_not_loopback".to_owned());
    }
    let mut stream = TcpStream::connect_timeout(&requested, CLIENT_TIMEOUT)
        .map_err(|_| "native_resident_client_connect_failed".to_owned())?;
    stream
        .set_nodelay(true)
        .map_err(|_| "native_resident_client_socket_failed".to_owned())?;
    stream
        .set_read_timeout(Some(CLIENT_TIMEOUT))
        .map_err(|_| "native_resident_client_timeout_failed".to_owned())?;
    stream
        .set_write_timeout(Some(CLIENT_TIMEOUT))
        .map_err(|_| "native_resident_client_timeout_failed".to_owned())?;
    exchange(&mut stream, &token, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_or_malformed_auth_prefix() {
        assert!(parse_input(b"{}").is_err());
        assert!(parse_input(b"aa\n{}").is_err());
    }

    #[test]
    fn request_identity_changes_across_calls() {
        let payload = br#"{"operation":"health","request":{}}"#;
        assert_ne!(
            unique_bytes(b"request", payload),
            unique_bytes(b"request", payload)
        );
    }
}
