//! Bounded private raw-frame pipe between an eventual UID-10001 data-plane
//! child and the Root observer. The parent reparses raw frames independently.

use crate::sdk_wire_tap::{
    SdkWireFrameObserver, SdkWireObservation, MAX_FRAMES, MAX_FRAME_BYTES, MAX_TOTAL_BYTES,
};
use std::io::{Read, Write};

const HEADER_BYTES: usize = 5;
const DIRECTION_CLIENT: u8 = 1;
const DIRECTION_SERVICE: u8 = 2;

pub struct SdkTapFramePipeWriter<W: Write> {
    output: W,
    frames: usize,
    bytes: usize,
    poisoned: bool,
}

impl<W: Write> SdkTapFramePipeWriter<W> {
    pub fn new(output: W) -> Self {
        Self {
            output,
            frames: 0,
            bytes: 0,
            poisoned: false,
        }
    }

    pub fn write_frame(&mut self, direction: &'static str, frame: &[u8]) -> Result<(), String> {
        let direction_code = match direction {
            "client-to-service" => DIRECTION_CLIENT,
            "service-to-client" => DIRECTION_SERVICE,
            _ => {
                self.poisoned = true;
                return Err("invalid SDK tap pipe direction".to_owned());
            }
        };
        if self.poisoned
            || frame.len() < 2
            || frame.len() > MAX_FRAME_BYTES + 1
            || self.frames >= MAX_FRAMES
            || self
                .bytes
                .checked_add(frame.len())
                .is_none_or(|size| size > MAX_TOTAL_BYTES)
        {
            self.poisoned = true;
            return Err("SDK tap pipe frame or aggregate bound exceeded".to_owned());
        }
        let length = u32::try_from(frame.len()).map_err(|error| error.to_string())?;
        let mut header = [0_u8; HEADER_BYTES];
        header[0] = direction_code;
        header[1..].copy_from_slice(&length.to_be_bytes());
        if let Err(error) = self
            .output
            .write_all(&header)
            .and_then(|_| self.output.write_all(frame))
        {
            self.poisoned = true;
            return Err(format!("SDK tap pipe write failed: {error}"));
        }
        self.frames += 1;
        self.bytes += frame.len();
        Ok(())
    }

    /// The zero header terminates the child report. The Root reader still
    /// requires EOF and a closed request/response ledger.
    pub fn finish(mut self) -> Result<W, String> {
        if self.poisoned || self.frames == 0 {
            return Err("SDK tap pipe cannot finish incomplete report".to_owned());
        }
        self.output
            .write_all(&[0_u8; HEADER_BYTES])
            .and_then(|_| self.output.flush())
            .map_err(|error| format!("SDK tap pipe terminal write failed: {error}"))?;
        Ok(self.output)
    }
}

/// Recompute strict JSON-RPC digests and request/response matching from every
/// raw byte the child reported. The caller must supply a bounded/deadlined
/// private reader and independently authenticate the child process.
pub fn read_sdk_tap_frame_pipe_ineligible<R: Read>(
    input: R,
    family: &str,
) -> Result<SdkWireObservation, String> {
    read_sdk_tap_frame_pipe_checked_ineligible(input, family, |_, _| Ok(()))
}

/// Let the Root owner recheck its held SDK and Native process identities at
/// each child-reported frame, before the frame enters the retained observer.
/// The callback must fail closed when either peer has disappeared or changed.
pub(crate) fn read_sdk_tap_frame_pipe_checked_ineligible<R: Read, F>(
    mut input: R,
    family: &str,
    mut check_peers: F,
) -> Result<SdkWireObservation, String>
where
    F: FnMut(&'static str, &[u8]) -> Result<(), String>,
{
    let mut observer = SdkWireFrameObserver::new(family)?;
    let mut frames = 0_usize;
    let mut bytes = 0_usize;
    loop {
        let mut header = [0_u8; HEADER_BYTES];
        input
            .read_exact(&mut header)
            .map_err(|error| format!("SDK tap pipe header missing: {error}"))?;
        let direction = match header[0] {
            0 if header[1..] == [0_u8; 4] => {
                let mut trailing = [0_u8; 1];
                if input
                    .read(&mut trailing)
                    .map_err(|error| error.to_string())?
                    != 0
                {
                    return Err("SDK tap pipe has trailing bytes".to_owned());
                }
                return observer.finish();
            }
            DIRECTION_CLIENT => "client-to-service",
            DIRECTION_SERVICE => "service-to-client",
            _ => return Err("invalid SDK tap pipe direction or terminal".to_owned()),
        };
        let length =
            u32::from_be_bytes(header[1..].try_into().map_err(|_| "invalid pipe length")?) as usize;
        if !(2..=MAX_FRAME_BYTES + 1).contains(&length)
            || frames >= MAX_FRAMES
            || bytes
                .checked_add(length)
                .is_none_or(|size| size > MAX_TOTAL_BYTES)
        {
            return Err("SDK tap pipe frame or aggregate bound exceeded".to_owned());
        }
        let mut raw = vec![0_u8; length];
        input
            .read_exact(&mut raw)
            .map_err(|error| format!("SDK tap pipe raw frame missing: {error}"))?;
        check_peers(direction, &raw)?;
        observer.observe(direction, &raw)?;
        frames += 1;
        bytes += length;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk_wire_tap::relay_bounded_sdk_mcp_pair_with_frame_sink_ineligible;
    use gauntlet_contracts::canonicalize;
    use sha2::{Digest, Sha256};
    use std::io::Cursor;
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::AtomicBool;
    use std::sync::Mutex;

    #[test]
    fn raw_pipe_recomputes_two_frame_tool_exchange() {
        let request = b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\"}\n";
        let response = b"{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{}}\n";
        let mut writer = SdkTapFramePipeWriter::new(Vec::new());
        writer.write_frame("client-to-service", request).unwrap();
        writer.write_frame("service-to-client", response).unwrap();
        let raw = writer.finish().unwrap();
        let observation = read_sdk_tap_frame_pipe_ineligible(Cursor::new(&raw), "docs").unwrap();
        assert_eq!(observation.completed_tool_calls, 1);
        assert_eq!(
            observation.events[0].frame_sha256,
            format!("{:x}", Sha256::digest(request))
        );
        assert_eq!(
            observation.events[1].frame_sha256,
            format!("{:x}", Sha256::digest(response))
        );
        let mut checked = 0;
        let observation =
            read_sdk_tap_frame_pipe_checked_ineligible(Cursor::new(&raw), "docs", |_, _| {
                checked += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(checked, 2);
        assert_eq!(observation.completed_tool_calls, 1);
        let mut checked = 0;
        assert!(
            read_sdk_tap_frame_pipe_checked_ineligible(Cursor::new(&raw), "docs", |_, _| {
                checked += 1;
                if checked == 2 {
                    Err("peer identity changed".to_owned())
                } else {
                    Ok(())
                }
            },)
            .is_err()
        );
        assert_eq!(checked, 2);
    }

    #[test]
    fn incomplete_or_forged_pipe_refuses() {
        let request = b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\"}\n";
        let mut writer = SdkTapFramePipeWriter::new(Vec::new());
        writer.write_frame("client-to-service", request).unwrap();
        let mut raw = writer.finish().unwrap();
        assert!(read_sdk_tap_frame_pipe_ineligible(Cursor::new(&raw), "docs").is_err());
        raw.push(b'x');
        assert!(read_sdk_tap_frame_pipe_ineligible(Cursor::new(&raw), "docs").is_err());
        let mut truncated = raw.clone();
        truncated.truncate(HEADER_BYTES + request.len() - 1);
        assert!(read_sdk_tap_frame_pipe_ineligible(Cursor::new(truncated), "docs").is_err());
        let mut malformed = SdkTapFramePipeWriter::new(Vec::new());
        malformed
            .write_frame(
                "client-to-service",
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"id\":2}\n",
            )
            .unwrap();
        let raw = malformed.finish().unwrap();
        assert!(read_sdk_tap_frame_pipe_ineligible(Cursor::new(raw), "docs").is_err());
    }

    #[test]
    fn actual_relay_reports_raw_bytes_for_independent_root_reparse() {
        let request = b"{ \"jsonrpc\":\"2.0\",\"id\":\"r1\",\"method\":\"tools/call\"}\n";
        let response = b"{\"jsonrpc\":\"2.0\",\"id\":\"r1\",\"result\":{}}\n";
        let (mut sdk, tap_client) = UnixStream::pair().unwrap();
        let (mut native, tap_frontdoor) = UnixStream::pair().unwrap();
        let (pipe_child, pipe_parent) = UnixStream::pair().unwrap();
        pipe_parent
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let parent_reader =
            std::thread::spawn(move || read_sdk_tap_frame_pipe_ineligible(pipe_parent, "docs"));
        let mut writer = SdkTapFramePipeWriter::new(pipe_child);
        {
            let sink = Mutex::new(|direction, frame: &[u8]| writer.write_frame(direction, frame));
            std::thread::scope(|scope| {
                let relay = scope.spawn(|| {
                    relay_bounded_sdk_mcp_pair_with_frame_sink_ineligible(
                        tap_client,
                        tap_frontdoor,
                        "docs",
                        &AtomicBool::new(false),
                        &sink,
                    )
                });
                let server = scope.spawn(|| {
                    let mut observed = vec![0; request.len()];
                    native.read_exact(&mut observed).unwrap();
                    assert_eq!(observed, request);
                    native.write_all(response).unwrap();
                    native.shutdown(Shutdown::Write).unwrap();
                });
                sdk.write_all(request).unwrap();
                sdk.shutdown(Shutdown::Write).unwrap();
                let mut observed = vec![0; response.len()];
                sdk.read_exact(&mut observed).unwrap();
                assert_eq!(observed, response);
                server.join().unwrap();
                assert_eq!(relay.join().unwrap().unwrap().completed_tool_calls, 1);
            });
        }
        let pipe_child = writer.finish().unwrap();
        drop(pipe_child);
        let parent = parent_reader.join().unwrap().unwrap();
        assert_eq!(parent.completed_tool_calls, 1);
        assert_eq!(
            parent.events[0].frame_sha256,
            format!("{:x}", Sha256::digest(request))
        );
        assert_eq!(
            parent.events[0].canonical_message_sha256,
            format!(
                "{:x}",
                Sha256::digest(canonicalize(&request[..request.len() - 1]).unwrap())
            )
        );
        assert_ne!(
            parent.events[0].canonical_message_sha256,
            parent.events[0].frame_sha256
        );
        assert_eq!(
            parent.events[1].frame_sha256,
            format!("{:x}", Sha256::digest(response))
        );
    }
}
