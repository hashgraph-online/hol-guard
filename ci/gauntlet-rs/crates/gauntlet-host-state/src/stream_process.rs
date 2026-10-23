//! Bounded stdin/stdout transport for one large fixed Lima request. A failed
//! child may leave guest work uncertain; callers must never auto-replay it.

use std::io;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamProcessError {
    Unavailable,
    Failed,
    TimedOut,
    TooLarge,
}

fn nonblocking(fd: i32) -> Result<(), StreamProcessError> {
    // SAFETY: `fd` belongs to a live child pipe held by this process.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(StreamProcessError::Unavailable);
    }
    Ok(())
}

fn read_bounded(fd: i32, kept: &mut Vec<u8>, limit: usize) -> Result<bool, StreamProcessError> {
    let mut buffer = [0_u8; 4096];
    // SAFETY: `buffer` is writable and `fd` is a live child pipe.
    let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
    if count == 0 {
        return Ok(false);
    }
    if count < 0 {
        return match io::Error::last_os_error().kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(true),
            _ => Err(StreamProcessError::Unavailable),
        };
    }
    let count = count as usize;
    if kept.len().saturating_add(count) > limit {
        return Err(StreamProcessError::TooLarge);
    }
    kept.extend_from_slice(&buffer[..count]);
    Ok(true)
}

fn wait_bounded(
    child: &mut Child,
    input: &[u8],
    timeout: Duration,
    stdout_limit: usize,
) -> Result<Vec<u8>, StreamProcessError> {
    let stdin = child.stdin.take().ok_or(StreamProcessError::Unavailable)?;
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let stdout_fd = stdout
        .as_ref()
        .ok_or(StreamProcessError::Unavailable)?
        .as_raw_fd();
    let stderr_fd = stderr
        .as_ref()
        .ok_or(StreamProcessError::Unavailable)?
        .as_raw_fd();
    nonblocking(stdin.as_raw_fd())?;
    nonblocking(stdout_fd)?;
    nonblocking(stderr_fd)?;
    let started = Instant::now();
    let mut offset = 0_usize;
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();
    let mut status: Option<ExitStatus> = None;
    loop {
        if status.is_none() {
            status = child
                .try_wait()
                .map_err(|_| StreamProcessError::Unavailable)?;
        }
        if status.is_some() && offset < input.len() {
            return Err(StreamProcessError::Failed);
        }
        if offset == input.len() {
            // Closing stdin tells the remote receiver that its byte stream is complete.
            drop(stdin);
            break;
        }
        if started.elapsed() >= timeout {
            return Err(StreamProcessError::TimedOut);
        }
        let mut fds = [
            libc::pollfd {
                fd: stdin.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            },
            libc::pollfd {
                fd: stdout.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stderr.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: `fds` is a valid in-process array of live child descriptors.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 50) };
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(StreamProcessError::Unavailable);
        }
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
            && !read_bounded(stdout_fd, &mut output, stdout_limit)?
        {
            stdout = None;
        }
        if fds[2].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
            && !read_bounded(stderr_fd, &mut diagnostics, 1024)?
        {
            stderr = None;
        }
        if fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(StreamProcessError::Failed);
        }
        if fds[0].revents & libc::POLLOUT != 0 {
            let end = (offset + 64 * 1024).min(input.len());
            // SAFETY: input slice is valid and `stdin` is a live child pipe.
            let wrote = unsafe {
                libc::write(
                    stdin.as_raw_fd(),
                    input[offset..end].as_ptr().cast(),
                    end - offset,
                )
            };
            if wrote < 0 {
                match io::Error::last_os_error().kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => {}
                    _ => return Err(StreamProcessError::Failed),
                }
            } else if wrote == 0 {
                return Err(StreamProcessError::Failed);
            } else {
                offset += wrote as usize;
            }
        }
    }
    loop {
        if status.is_none() {
            status = child
                .try_wait()
                .map_err(|_| StreamProcessError::Unavailable)?;
        }
        if status.is_some() && stdout.is_none() && stderr.is_none() {
            return if status.is_some_and(|result| result.success()) {
                Ok(output)
            } else {
                Err(StreamProcessError::Failed)
            };
        }
        if started.elapsed() >= timeout {
            return Err(StreamProcessError::TimedOut);
        }
        let mut fds = [
            libc::pollfd {
                fd: stdout.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stderr.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: `fds` is a valid in-process array of live child descriptors.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 50) };
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(StreamProcessError::Unavailable);
        }
        if stdout.is_some()
            && fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
            && !read_bounded(stdout_fd, &mut output, stdout_limit)?
        {
            stdout = None;
        }
        if stderr.is_some()
            && fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
            && !read_bounded(stderr_fd, &mut diagnostics, 1024)?
        {
            stderr = None;
        }
    }
}

pub(crate) fn run_streamed(
    argv: &[String],
    input: &[u8],
    timeout: Duration,
    stdout_limit: usize,
) -> Result<Vec<u8>, StreamProcessError> {
    if input.is_empty() || input.len() > 256 * 1024 * 1024 {
        return Err(StreamProcessError::TooLarge);
    }
    let executable = argv.first().ok_or(StreamProcessError::Unavailable)?;
    if !Path::new(executable).is_absolute() {
        return Err(StreamProcessError::Unavailable);
    }
    let mut child = Command::new(executable)
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| StreamProcessError::Unavailable)?;
    let result = wait_bounded(&mut child, input, timeout, stdout_limit);
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn python(script: &str) -> Vec<String> {
        vec![
            "/usr/bin/python3".to_owned(),
            "-I".to_owned(),
            "-B".to_owned(),
            "-c".to_owned(),
            script.to_owned(),
        ]
    }

    #[test]
    fn multi_megabyte_stream_completes_and_early_exit_refuses() {
        let input = vec![0x5a; 2 * 1024 * 1024];
        let output = run_streamed(
            &python("import sys; b=sys.stdin.buffer.read(); print(len(b))"),
            &input,
            Duration::from_secs(10),
            128,
        )
        .unwrap();
        assert_eq!(output, b"2097152\n");
        assert_eq!(
            run_streamed(
                &python("import sys; sys.exit(7)"),
                &input,
                Duration::from_secs(10),
                128,
            ),
            Err(StreamProcessError::Failed)
        );
    }

    #[test]
    fn blocked_receiver_is_killed_at_deadline() {
        let input = vec![0x5a; 2 * 1024 * 1024];
        assert_eq!(
            run_streamed(
                &python("import time; time.sleep(3)"),
                &input,
                Duration::from_millis(200),
                128,
            ),
            Err(StreamProcessError::TimedOut)
        );
    }
}
