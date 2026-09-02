#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::path::Path;

const FRAME_HEADER_BYTES: usize = 4;

pub(super) fn read_frame(input: &mut impl Read) -> Result<Option<Vec<u8>>, String> {
    let mut header = [0u8; FRAME_HEADER_BYTES];
    match input.read(&mut header[..1]) {
        Ok(0) => return Ok(None),
        Ok(_) => {}
        Err(_) => return Ok(None),
    }
    input
        .read_exact(&mut header[1..])
        .map_err(|_| "native_client_stream_frame_truncated".to_owned())?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > crate::MAX_NATIVE_REQUEST_BYTES {
        return Err("native_client_stream_request_too_large".to_owned());
    }
    let mut payload = vec![0u8; length];
    input
        .read_exact(&mut payload)
        .map_err(|_| "native_client_stream_frame_truncated".to_owned())?;
    Ok(Some(payload))
}

pub(super) fn write_frame(output: &mut impl Write, response: &[u8]) -> Result<(), String> {
    if response.is_empty() || response.len() > crate::MAX_NATIVE_RESPONSE_BYTES {
        return Err("native_client_stream_response_too_large".to_owned());
    }
    output
        .write_all(&(response.len() as u32).to_be_bytes())
        .and_then(|()| output.write_all(response))
        .and_then(|()| output.flush())
        .map_err(|_| "native_client_stream_write_failed".to_owned())
}

fn lease_for_request<'a>(
    state_base: &Path,
    client_lease: &'a mut Option<super::lease::ClientLease>,
) -> Result<&'a super::lease::ClientLease, String> {
    if client_lease.is_none() {
        *client_lease = Some(super::lease::acquire(state_base)?);
    }
    client_lease
        .as_ref()
        .ok_or_else(|| "native_resident_lease_lock_failed".to_owned())
}

pub(super) fn run(state_base: &Path) -> Result<(), String> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    let mut client_lease = None;
    loop {
        let Some(payload) = read_frame(&mut input)? else {
            return Ok(());
        };
        let timeout = super::client_timeout(&payload);
        let response = match lease_for_request(state_base, &mut client_lease) {
            Ok(lease) => {
                match super::client_request_with_lease(state_base, &payload, timeout, lease) {
                    Ok(response) => response,
                    Err(error) => crate::resident_protocol::safe_error_response(&error, false),
                }
            }
            Err(error) => crate::resident_protocol::safe_error_response(&error, false),
        };
        write_frame(&mut output, &response)?;
    }
}
