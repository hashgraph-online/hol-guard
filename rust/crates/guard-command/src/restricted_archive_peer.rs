//! TCP transport with explicit peer verification before rustls performs TLS.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Instant;
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, LazyBuffers, NextTimeout, Transport,
};

#[derive(Debug)]
pub(super) struct PinnedConnector {
    pub peer: SocketAddr,
    pub deadline: Instant,
}

impl Connector for PinnedConnector {
    type Out = PinnedTcp;

    fn connect(
        &self,
        _: &ConnectionDetails,
        _: Option<()>,
    ) -> Result<Option<PinnedTcp>, ureq::Error> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ureq::Error::Timeout(ureq::Timeout::Global));
        }
        let stream = TcpStream::connect_timeout(&self.peer, remaining)?;
        verify_peer(&stream, self.peer)?;
        stream.set_nodelay(true)?;
        Ok(Some(PinnedTcp {
            stream,
            buffers: LazyBuffers::new(16 * 1024, 16 * 1024),
            deadline: self.deadline,
        }))
    }
}

fn verify_peer(stream: &TcpStream, expected: SocketAddr) -> Result<(), ureq::Error> {
    if stream.peer_addr()? != expected {
        return Err(
            io::Error::new(io::ErrorKind::PermissionDenied, "archive peer mismatch").into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_peer_mismatch_is_refused_before_tls() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stream = TcpStream::connect(address).unwrap();
        let (_server, _) = listener.accept().unwrap();
        verify_peer(&stream, address).unwrap();
        let wrong = SocketAddr::new("8.8.8.8".parse().unwrap(), address.port());
        assert!(
            matches!(verify_peer(&stream, wrong), Err(ureq::Error::Io(error))
            if error.kind() == io::ErrorKind::PermissionDenied)
        );
    }
}

#[derive(Debug)]
pub(super) struct PinnedTcp {
    stream: TcpStream,
    buffers: LazyBuffers,
    deadline: Instant,
}

impl PinnedTcp {
    fn remaining(&self, timeout: NextTimeout) -> Result<std::time::Duration, ureq::Error> {
        let remaining = self
            .deadline
            .saturating_duration_since(Instant::now())
            .min(*timeout.after);
        if remaining.is_zero() {
            Err(ureq::Error::Timeout(ureq::Timeout::Global))
        } else {
            Ok(remaining)
        }
    }
}

fn map_io(error: io::Error, timeout: NextTimeout) -> ureq::Error {
    if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        ureq::Error::Timeout(timeout.reason)
    } else {
        error.into()
    }
}

impl Transport for PinnedTcp {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }
    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.stream
            .set_write_timeout(Some(self.remaining(timeout)?))?;
        self.stream
            .write_all(&self.buffers.output()[..amount])
            .map_err(|error| map_io(error, timeout))
    }
    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.stream
            .set_read_timeout(Some(self.remaining(timeout)?))?;
        let size = self
            .stream
            .read(self.buffers.input_append_buf())
            .map_err(|error| map_io(error, timeout))?;
        self.buffers.input_appended(size);
        Ok(size > 0)
    }
    fn is_open(&mut self) -> bool {
        // Requests explicitly close connections; never offer one for reuse.
        false
    }
}
