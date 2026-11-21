//! Exact compiled-image invocations requested by the frozen Bash child.

use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use guard_contained_process::{Isolation, PinnedCommand, ResourceLimits};

const HELPER_INPUT_CAP: usize = 256 * 1024;
const HELPER_OUTPUT_CAP: usize = 256 * 1024;
const HELPER_INPUT_ENCODED_CAP: usize = HELPER_INPUT_CAP.div_ceil(3) * 4 + 8192;

pub(super) fn pair() -> io::Result<(std::fs::File, UnixStream)> {
    let (child, owner) = UnixStream::pair()?;
    let child = std::fs::File::from(OwnedFd::from(child));
    Ok((child, owner))
}

pub(super) fn serve(
    stream: UnixStream,
    expected: Vec<(u16, bool)>,
    commands: Vec<PinnedCommand>,
    deadline: Instant,
    cancel: &AtomicBool,
) -> io::Result<()> {
    if expected.len() != commands.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compiled-image broker plan mismatch",
        ));
    }
    stream.set_read_timeout(Some(Duration::from_millis(25)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    for ((id, pipeline_input), command) in expected.into_iter().zip(commands) {
        let request = read_request(&mut reader, deadline, cancel)?;
        if request != id.to_string() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "compiled-image broker sequence mismatch",
            ));
        }
        let input = if pipeline_input {
            read_input(&mut reader, deadline, cancel)?
        } else {
            Vec::new()
        };
        let profile = profile(&command)?;
        let output = command.capture_hardened_image(
            &input,
            HELPER_OUTPUT_CAP,
            deadline,
            cancel,
            Isolation {
                seatbelt: Some(profile),
                resources: Some(ResourceLimits {
                    cpu_seconds: 2,
                    memory_bytes: libc::RLIM_INFINITY,
                    file_bytes: libc::RLIM_INFINITY,
                    open_files: libc::RLIM_INFINITY,
                    processes: 16,
                }),
                ..Isolation::default()
            },
        )?;
        let status = output.exit_code.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "compiled-image broker launch incomplete",
            )
        })?;
        let status = if status < 0 {
            128i32.saturating_add(status.saturating_abs()).min(255)
        } else {
            status.min(255)
        };
        writeln!(writer, "{status}")?;
        writeln!(writer, "{}", octal(&output.stdout))?;
        writeln!(writer, "{}", octal(&output.stderr))?;
        writer.flush()?;
    }
    Ok(())
}

fn read_input(
    reader: &mut BufReader<UnixStream>,
    deadline: Instant,
    cancel: &AtomicBool,
) -> io::Result<Vec<u8>> {
    let mut encoded = String::new();
    loop {
        let line = read_line(reader, HELPER_INPUT_ENCODED_CAP, deadline, cancel)?;
        if line == "." {
            break;
        }
        if !line
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
            || encoded.len().saturating_add(line.len()) > HELPER_INPUT_ENCODED_CAP
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        encoded.push_str(&line);
    }
    decode_input(encoded)
}

fn decode_input(encoded: String) -> io::Result<Vec<u8>> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| io::ErrorKind::InvalidData)?;
    if decoded.len() > HELPER_INPUT_CAP {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(decoded)
}

fn read_request(
    reader: &mut BufReader<UnixStream>,
    deadline: Instant,
    cancel: &AtomicBool,
) -> io::Result<String> {
    let request = read_line(reader, 6, deadline, cancel)?;
    if request.len() > 5 || !request.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(request)
}

fn read_line(
    reader: &mut BufReader<UnixStream>,
    cap: usize,
    deadline: Instant,
    cancel: &AtomicBool,
) -> io::Result<String> {
    let mut line = String::new();
    loop {
        if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match reader.read_line(&mut line) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(_) if line.ends_with('\n') => {
                line.pop();
                if line.len() > cap || line.ends_with('\r') {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                return Ok(line);
            }
            Ok(_) if line.len() <= cap => {}
            Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
    }
}

fn octal(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(4));
    for byte in bytes {
        write!(encoded, "\\{byte:03o}").expect("writing to String cannot fail");
    }
    encoded
}

fn profile(command: &PinnedCommand) -> io::Result<String> {
    // An opaque image cannot borrow modeled network authority from a sibling
    // curl invocation. The deny-default profile intentionally has no network
    // rule until compiled helpers have their own effect proof.
    let literal = |path: &std::path::Path| {
        serde_json::to_string(path.to_str().ok_or(io::ErrorKind::InvalidData)?)
            .map_err(io::Error::other)
    };
    let image = literal(command.effective_executable_path())?;
    let cwd = literal(command.cwd())?;
    Ok(format!(
        r#"(version 1)
(deny default)
(import "system.sb")
(allow process-fork)
(allow process-exec (literal {image}))
(allow file-read* (subpath "/System") (subpath "/usr/lib") (subpath "/dev") (literal {image}))
(allow file-read-metadata)
(allow file-read-data (literal {cwd}))
(allow file-map-executable (subpath "/System") (subpath "/usr/lib") (literal {image}))
(allow file-write* (literal "/dev/null"))
(allow sysctl-read)
(allow signal)"#
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_helper_input_cap_is_enforced_after_decoding() {
        let at_cap = vec![0xa5; HELPER_INPUT_CAP];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&at_cap);
        assert_eq!(decode_input(encoded).unwrap(), at_cap);

        let over_cap = vec![0xa5; HELPER_INPUT_CAP + 1];
        let encoded = base64::engine::general_purpose::STANDARD.encode(over_cap);
        assert_eq!(
            decode_input(encoded).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            decode_input("not-base64!".into()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
