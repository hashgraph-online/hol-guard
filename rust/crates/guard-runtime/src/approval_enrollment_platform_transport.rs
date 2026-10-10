use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;

const IO_BUFFER_BYTES: usize = 8 * 1024;
const MAX_HELPER_STDERR_BYTES: usize = 16 * 1024;
pub(super) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub(super) struct Completed {
    pub(super) status: ExitStatus,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr_seen: bool,
}

#[derive(Clone, Copy)]
enum Channel {
    Stdin,
    Stdout,
    Stderr,
}

enum ReadResult {
    Data(usize),
    Eof,
    WouldBlock,
}

struct ChildGuard {
    child: Child,
    process_group: Option<Pid>,
    reaped: bool,
}

impl ChildGuard {
    fn spawn(mut command: Command) -> Result<Self, String> {
        command.process_group(0);
        let child = command
            .spawn()
            .map_err(|_| super::SECURE_STATE_UNAVAILABLE.to_owned())?;
        let process_group = i32::try_from(child.id()).ok().map(Pid::from_raw);
        Ok(Self {
            child,
            process_group,
            reaped: false,
        })
    }

    fn try_wait(&mut self) -> Result<Option<ExitStatus>, String> {
        let status = self
            .child
            .try_wait()
            .map_err(|_| super::SECURE_STATE_UNAVAILABLE.to_owned())?;
        if status.is_some() {
            self.reaped = true;
        }
        Ok(status)
    }

    fn cleanup(&mut self) {
        if self.reaped {
            return;
        }
        if let Some(process_group) = self.process_group {
            let _ = killpg(process_group, Signal::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.reaped = true;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn set_nonblocking<Fd: AsFd>(fd: &Fd) -> Result<(), String> {
    let flags =
        fcntl(fd, FcntlArg::F_GETFL).map_err(|_| super::SECURE_STATE_UNAVAILABLE.to_owned())?;
    let flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
    fcntl(fd, FcntlArg::F_SETFL(flags)).map_err(|_| super::SECURE_STATE_UNAVAILABLE.to_owned())?;
    Ok(())
}

fn read_once<R: Read>(stream: &mut R, buffer: &mut [u8]) -> Result<ReadResult, String> {
    match stream.read(buffer) {
        Ok(0) => Ok(ReadResult::Eof),
        Ok(bytes) => Ok(ReadResult::Data(bytes)),
        Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(ReadResult::WouldBlock),
        Err(error) if error.kind() == ErrorKind::Interrupted => Ok(ReadResult::WouldBlock),
        Err(_) => Err(super::SECURE_STATE_UNAVAILABLE.to_owned()),
    }
}

fn poll_timeout(deadline: Instant) -> PollTimeout {
    PollTimeout::try_from(deadline.saturating_duration_since(Instant::now()))
        .unwrap_or(PollTimeout::MAX)
}

fn sleep_until_next_poll(deadline: Instant) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    std::thread::sleep(remaining.min(Duration::from_millis(10)));
}

pub(super) fn run_helper(
    command_path: &Path,
    args: &[&str],
    input: Option<&[u8]>,
    stdout_limit: usize,
    timeout: Duration,
) -> Result<Completed, String> {
    let mut command = Command::new(command_path);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = ChildGuard::spawn(command)?;
    let mut stdin = child.child.stdin.take();
    let mut stdout = Some(
        child
            .child
            .stdout
            .take()
            .ok_or_else(|| super::SECURE_STATE_UNAVAILABLE.to_owned())?,
    );
    let mut stderr = Some(
        child
            .child
            .stderr
            .take()
            .ok_or_else(|| super::SECURE_STATE_UNAVAILABLE.to_owned())?,
    );
    if let Some(stream) = stdin.as_ref() {
        set_nonblocking(stream)?;
    }
    if let Some(stream) = stdout.as_ref() {
        set_nonblocking(stream)?;
    }
    if let Some(stream) = stderr.as_ref() {
        set_nonblocking(stream)?;
    }

    let input = input.unwrap_or_default();
    let mut input_offset = 0;
    if input.is_empty() {
        stdin = None;
    }
    let mut stdout_data = Vec::new();
    let mut stderr_seen = false;
    let mut stderr_bytes: usize = 0;
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let status = loop {
        if Instant::now() >= deadline {
            return Err(super::SECURE_STATE_UNAVAILABLE.to_owned());
        }

        if stdin.is_none() && stdout.is_none() && stderr.is_none() {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            sleep_until_next_poll(deadline);
            continue;
        }

        let mut poll_fds = Vec::with_capacity(3);
        let mut channels = Vec::with_capacity(3);
        if let Some(stream) = stdin.as_ref() {
            poll_fds.push(PollFd::new(stream.as_fd(), PollFlags::POLLOUT));
            channels.push(Channel::Stdin);
        }
        if let Some(stream) = stdout.as_ref() {
            poll_fds.push(PollFd::new(stream.as_fd(), PollFlags::POLLIN));
            channels.push(Channel::Stdout);
        }
        if let Some(stream) = stderr.as_ref() {
            poll_fds.push(PollFd::new(stream.as_fd(), PollFlags::POLLIN));
            channels.push(Channel::Stderr);
        }

        let poll_result = poll(&mut poll_fds, poll_timeout(deadline));
        let ready = match poll_result {
            Ok(_) => poll_fds
                .iter()
                .zip(channels.iter().copied())
                .map(|(poll_fd, channel)| {
                    (channel, poll_fd.revents().unwrap_or(PollFlags::POLLNVAL))
                })
                .collect::<Vec<_>>(),
            Err(nix::errno::Errno::EINTR) => Vec::new(),
            Err(_) => return Err(super::SECURE_STATE_UNAVAILABLE.to_owned()),
        };
        drop(poll_fds);

        for (channel, events) in ready {
            if events.intersects(PollFlags::POLLNVAL) {
                return Err(super::SECURE_STATE_UNAVAILABLE.to_owned());
            }
            match channel {
                Channel::Stdin => {
                    if !events
                        .intersects(PollFlags::POLLOUT | PollFlags::POLLERR | PollFlags::POLLHUP)
                    {
                        continue;
                    }
                    let Some(stream) = stdin.as_mut() else {
                        continue;
                    };
                    match stream.write(&input[input_offset..]) {
                        Ok(0) => return Err(super::SECURE_STATE_UNAVAILABLE.to_owned()),
                        Ok(bytes) => {
                            input_offset += bytes;
                            if input_offset == input.len() {
                                stdin = None;
                            }
                        }
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                        Err(error) if error.kind() == ErrorKind::Interrupted => {}
                        Err(_) => return Err(super::SECURE_STATE_UNAVAILABLE.to_owned()),
                    }
                }
                Channel::Stdout => {
                    if !events
                        .intersects(PollFlags::POLLIN | PollFlags::POLLERR | PollFlags::POLLHUP)
                    {
                        continue;
                    }
                    let Some(stream) = stdout.as_mut() else {
                        continue;
                    };
                    let mut buffer = [0; IO_BUFFER_BYTES];
                    match read_once(stream, &mut buffer)? {
                        ReadResult::Data(bytes) => {
                            if stdout_data.len().saturating_add(bytes) > stdout_limit {
                                return Err(super::SECURE_STATE_INVALID.to_owned());
                            }
                            stdout_data.extend_from_slice(&buffer[..bytes]);
                        }
                        ReadResult::Eof => stdout = None,
                        ReadResult::WouldBlock => {}
                    }
                }
                Channel::Stderr => {
                    if !events
                        .intersects(PollFlags::POLLIN | PollFlags::POLLERR | PollFlags::POLLHUP)
                    {
                        continue;
                    }
                    let Some(stream) = stderr.as_mut() else {
                        continue;
                    };
                    let mut buffer = [0; IO_BUFFER_BYTES];
                    match read_once(stream, &mut buffer)? {
                        ReadResult::Data(bytes) => {
                            stderr_seen = true;
                            stderr_bytes = stderr_bytes.saturating_add(bytes);
                            if stderr_bytes > MAX_HELPER_STDERR_BYTES {
                                return Err(super::SECURE_STATE_UNAVAILABLE.to_owned());
                            }
                        }
                        ReadResult::Eof => stderr = None,
                        ReadResult::WouldBlock => {}
                    }
                }
            }
        }
    };

    Ok(Completed {
        status,
        stdout: stdout_data,
        stderr_seen,
    })
}

pub(super) fn classify_lookup(
    completed: Completed,
    max_bytes: usize,
) -> Result<Option<String>, String> {
    if !completed.status.success() {
        // secret-tool uses status 1 with no output for a missing item. Any
        // diagnostic or other status is a helper/service failure.
        if completed.status.code() == Some(1)
            && completed.stdout.is_empty()
            && !completed.stderr_seen
        {
            return Ok(None);
        }
        return Err(super::SECURE_STATE_UNAVAILABLE.to_owned());
    }
    if completed.stderr_seen {
        return Err(super::SECURE_STATE_UNAVAILABLE.to_owned());
    }
    let value =
        String::from_utf8(completed.stdout).map_err(|_| super::SECURE_STATE_INVALID.to_owned())?;
    let value = value.trim();
    if value.len() > max_bytes {
        return Err(super::SECURE_STATE_INVALID.to_owned());
    }
    Ok(Some(value.to_owned()))
}
