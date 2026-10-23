//! Owned, bounded management I/O above Gauntlet's Python-compatible HMAC
//! frame codec. The caller must independently authenticate each descriptor
//! and deliver a fresh private key; this transport never grants a verdict.

use gauntlet_evidence::FrameCodec;
use serde_json::Value;
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

mod rpc;
pub use rpc::{serve_one, BridgeClient, BridgeOperation, OperationResult};
mod bootstrap;
pub use bootstrap::{read_private_bootstrap, Bootstrap, BootstrapKind, OutboundBootstrap};

const MAX_POLL: Duration = Duration::from_millis(100);
const IO_CHUNK: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum BridgeIoError {
    Invalid(&'static str),
    Deadline,
    Cancelled,
    Eof,
    Io(String),
    Frame(String),
    RemoteFailure(&'static str),
}

impl fmt::Display for BridgeIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => f.write_str(message),
            Self::Deadline => f.write_str("bridge management I/O deadline exceeded"),
            Self::Cancelled => f.write_str("bridge management I/O cancelled"),
            Self::Eof => {
                f.write_str("bridge management stream ended before terminal acknowledgement")
            }
            Self::Io(message) => write!(f, "bridge management I/O unavailable: {message}"),
            Self::Frame(message) => write!(f, "bridge frame refused: {message}"),
            Self::RemoteFailure(code) => write!(f, "bridge operation failed: {code}"),
        }
    }
}

impl std::error::Error for BridgeIoError {}

type Result<T> = std::result::Result<T, BridgeIoError>;

fn operating_error() -> BridgeIoError {
    BridgeIoError::Io(io::Error::last_os_error().to_string())
}

fn validate_management_fd(fd: RawFd) -> Result<()> {
    // SAFETY: fstat writes one initialized local stat and borrows the owned FD.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(operating_error());
    }
    let kind = stat.st_mode & libc::S_IFMT;
    if kind == libc::S_IFIFO {
        return Ok(());
    }
    if kind != libc::S_IFSOCK {
        return Err(BridgeIoError::Invalid(
            "management channel requires pipes or stream sockets",
        ));
    }
    let mut socket_type = 0_i32;
    let mut type_len = std::mem::size_of_val(&socket_type) as libc::socklen_t;
    // SAFETY: getsockopt writes at most the provided integer and length.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut i32).cast(),
            &mut type_len,
        )
    } != 0
    {
        return Err(operating_error());
    }
    let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_storage>() };
    let mut address_len = std::mem::size_of_val(&address) as libc::socklen_t;
    // SAFETY: getsockname writes at most the sockaddr_storage byte budget.
    if unsafe {
        libc::getsockname(
            fd,
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut address_len,
        )
    } != 0
    {
        return Err(operating_error());
    }
    if socket_type != libc::SOCK_STREAM
        || type_len as usize != std::mem::size_of_val(&socket_type)
        || address_len < std::mem::size_of::<libc::sa_family_t>() as libc::socklen_t
        || address.ss_family as libc::c_int != libc::AF_UNIX
    {
        return Err(BridgeIoError::Invalid(
            "only private Unix stream sockets are supported",
        ));
    }
    Ok(())
}

fn nonblocking(fd: RawFd) -> Result<()> {
    // SAFETY: fcntl reads and changes flags only on the owned management FD.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(operating_error());
    }
    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if descriptor_flags < 0
        || unsafe { libc::fcntl(fd, libc::F_SETFD, descriptor_flags | libc::FD_CLOEXEC) } < 0
    {
        return Err(operating_error());
    }
    Ok(())
}

fn ready(
    fd: RawFd,
    events: libc::c_short,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<()> {
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(BridgeIoError::Cancelled);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(BridgeIoError::Deadline);
        }
        let timeout = remaining
            .min(MAX_POLL)
            .as_millis()
            .clamp(1, i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: poll borrows one initialized descriptor without owning it.
        let count = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if count < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(operating_error());
        }
        if count == 0 {
            continue;
        }
        if descriptor.revents & (libc::POLLNVAL | libc::POLLERR) != 0 {
            return Err(BridgeIoError::Invalid(
                "management descriptor became invalid",
            ));
        }
        if descriptor.revents & events != 0
            || events == libc::POLLIN && descriptor.revents & libc::POLLHUP != 0
        {
            return Ok(());
        }
        if descriptor.revents & libc::POLLHUP != 0 {
            return Err(BridgeIoError::Eof);
        }
    }
}

fn read_exact(
    fd: RawFd,
    output: &mut [u8],
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<()> {
    let mut offset = 0;
    while offset < output.len() {
        ready(fd, libc::POLLIN, deadline, cancelled)?;
        // SAFETY: read writes at most the remaining initialized slice length.
        let count = unsafe {
            libc::read(
                fd,
                output[offset..].as_mut_ptr().cast(),
                (output.len() - offset).min(IO_CHUNK),
            )
        };
        if count == 0 {
            return Err(BridgeIoError::Eof);
        }
        if count < 0 {
            if matches!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(operating_error());
        }
        offset += count as usize;
    }
    Ok(())
}

fn write_all(fd: RawFd, raw: &[u8], deadline: Instant, cancelled: &AtomicBool) -> Result<()> {
    let mut offset = 0;
    while offset < raw.len() {
        ready(fd, libc::POLLOUT, deadline, cancelled)?;
        // SAFETY: write reads at most the bounded initialized input slice.
        let count = unsafe {
            libc::write(
                fd,
                raw[offset..].as_ptr().cast(),
                (raw.len() - offset).min(IO_CHUNK),
            )
        };
        if count < 0 {
            if matches!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(operating_error());
        }
        if count == 0 {
            return Err(BridgeIoError::Invalid(
                "bridge frame write made no progress",
            ));
        }
        offset += count as usize;
    }
    Ok(())
}

pub struct BridgeChannel {
    reader: OwnedFd,
    writer: OwnedFd,
    codec: FrameCodec,
}

impl BridgeChannel {
    pub fn new(reader: OwnedFd, writer: OwnedFd, codec: FrameCodec) -> Result<Self> {
        if reader.as_raw_fd() == writer.as_raw_fd() {
            return Err(BridgeIoError::Invalid(
                "distinct dedicated management descriptors required",
            ));
        }
        validate_management_fd(reader.as_raw_fd())?;
        validate_management_fd(writer.as_raw_fd())?;
        nonblocking(reader.as_raw_fd())?;
        nonblocking(writer.as_raw_fd())?;
        Ok(Self {
            reader,
            writer,
            codec,
        })
    }

    pub fn poisoned(&self) -> bool {
        self.codec.poisoned()
    }

    pub fn invalidate(&mut self) {
        self.codec.invalidate();
    }

    pub fn send(
        &mut self,
        kind: &str,
        body: &Value,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<()> {
        let outcome = (|| {
            if deadline <= Instant::now() {
                return Err(BridgeIoError::Deadline);
            }
            let frame = self
                .codec
                .encode(kind, body)
                .map_err(|error| BridgeIoError::Frame(error.to_string()))?;
            write_all(self.writer.as_raw_fd(), &frame, deadline, cancelled)
        })();
        if outcome.is_err() {
            self.codec.invalidate();
        }
        outcome
    }

    pub fn receive(
        &mut self,
        kind: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Value> {
        let outcome = (|| {
            let mut header = [0_u8; 4];
            read_exact(self.reader.as_raw_fd(), &mut header, deadline, cancelled)?;
            let length = u32::from_be_bytes(header) as usize;
            self.codec
                .validate_length(length)
                .map_err(|error| BridgeIoError::Frame(error.to_string()))?;
            let mut body = vec![0_u8; length];
            read_exact(self.reader.as_raw_fd(), &mut body, deadline, cancelled)?;
            self.codec
                .decode(&body, kind)
                .map_err(|error| BridgeIoError::Frame(error.to_string()))
        })();
        if outcome.is_err() {
            self.codec.invalidate();
        }
        outcome
    }
}
