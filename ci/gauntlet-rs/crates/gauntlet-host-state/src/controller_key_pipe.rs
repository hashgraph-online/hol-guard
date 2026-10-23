//! Bounded local pipe adapter for the host half of the prelaunch exchange.
//! A future Lima runner must attest its executable/VM and own both pipe ends.

use super::{
    HostControllerKeyPinJournal, HostKeyPinError, HostKeyPinRecord, HostPrelaunchIdentity,
};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

const MAX_FRAME_BYTES: usize = 1024;
const MAX_HANDOFF_TIME: Duration = Duration::from_secs(60);

fn ready(fd: libc::c_int, events: libc::c_short, deadline: Instant) -> Result<(), HostKeyPinError> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HostKeyPinError::TransportTimedOut);
        }
        let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: poll receives one initialized descriptor and never owns it.
        let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
        if result < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(HostKeyPinError::TransportFailed);
        }
        if result == 0 {
            continue;
        }
        if descriptor.revents & (libc::POLLNVAL | libc::POLLERR) != 0 {
            return Err(HostKeyPinError::TransportFailed);
        }
        if descriptor.revents & events != 0
            || events == libc::POLLIN && descriptor.revents & libc::POLLHUP != 0
        {
            return Ok(());
        }
        if descriptor.revents & libc::POLLHUP != 0 {
            return Err(HostKeyPinError::TransportFailed);
        }
    }
}

fn read_frame(fd: libc::c_int, deadline: Instant) -> Result<Vec<u8>, HostKeyPinError> {
    let mut bytes = Vec::new();
    loop {
        ready(fd, libc::POLLIN, deadline)?;
        let mut byte = 0u8;
        // SAFETY: read writes at most one byte into this initialized local.
        let count = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
        if count == 0 {
            return Err(HostKeyPinError::TransportFailed);
        }
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(HostKeyPinError::TransportFailed);
        }
        if byte == b'\n' {
            if bytes.is_empty() {
                return Err(HostKeyPinError::TransportFailed);
            }
            return Ok(bytes);
        }
        bytes.push(byte);
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(HostKeyPinError::FrameTooLarge);
        }
    }
}

pub(super) fn write_frame(
    fd: libc::c_int,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), HostKeyPinError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(HostKeyPinError::FrameTooLarge);
    }
    for byte in bytes.iter().copied().chain(std::iter::once(b'\n')) {
        loop {
            ready(fd, libc::POLLOUT, deadline)?;
            // One-byte writes cannot block after exclusive POLLOUT readiness.
            // SAFETY: write reads exactly one initialized local byte.
            let count = unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) };
            if count == 1 {
                break;
            }
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) {
                    continue;
                }
            }
            return Err(HostKeyPinError::TransportFailed);
        }
    }
    Ok(())
}

impl HostControllerKeyPinJournal {
    /// Read one newline-delimited prepared frame, persist it against the
    /// planned job and send one ack on caller-owned local pipes. The caller
    /// must provide a reviewed, bounded Lima process and retain uncertainty
    /// if this returns after the record was created but before ack delivery.
    pub fn accept_prepared_pipe(
        &self,
        prepared_reader: &impl AsRawFd,
        ack_writer: &impl AsRawFd,
        expected: &HostPrelaunchIdentity,
        timeout: Duration,
    ) -> Result<HostKeyPinRecord, HostKeyPinError> {
        if timeout.is_zero() || timeout > MAX_HANDOFF_TIME {
            return Err(HostKeyPinError::TransportTimedOut);
        }
        let deadline = Instant::now() + timeout;
        let frame = read_frame(prepared_reader.as_raw_fd(), deadline)?;
        let (record, ack) = self.accept_prepared(&frame, expected)?;
        write_frame(ack_writer.as_raw_fd(), &ack, deadline)?;
        Ok(record)
    }
}
