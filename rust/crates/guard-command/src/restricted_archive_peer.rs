//! TCP transport with explicit peer verification before rustls performs TLS.
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, LazyBuffers, NextTimeout, Transport,
};

#[derive(Debug)]
pub(super) struct PinnedConnector {
    pub peer: SocketAddr,
    pub deadline: Instant,
    pub cancel: Option<Arc<AtomicBool>>,
}
impl Connector for PinnedConnector {
    type Out = PinnedTcp;
    fn connect(
        &self,
        _: &ConnectionDetails,
        _: Option<()>,
    ) -> Result<Option<PinnedTcp>, ureq::Error> {
        check_cancel(&self.cancel)?;
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ureq::Error::Timeout(ureq::Timeout::Global));
        }
        // Cooperative transfers bound a pending TCP connect as well as reads.
        let connect = if self.cancel.is_some() {
            remaining.min(Duration::from_secs(5))
        } else {
            remaining
        };
        let stream = TcpStream::connect_timeout(&self.peer, connect)?;
        check_cancel(&self.cancel)?;
        verify_peer(&stream, self.peer)?;
        stream.set_nodelay(true)?;
        Ok(Some(PinnedTcp {
            stream,
            buffers: LazyBuffers::new(16 * 1024, 16 * 1024),
            deadline: self.deadline,
            cancel: self.cancel.clone(),
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
fn check_cancel(cancel: &Option<Arc<AtomicBool>>) -> Result<(), ureq::Error> {
    if cancel
        .as_ref()
        .is_some_and(|cancel| cancel.load(Ordering::Acquire))
    {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "archive transfer cancelled",
        )
        .into());
    }
    Ok(())
}

#[derive(Debug)]
pub(super) struct PinnedTcp {
    stream: TcpStream,
    buffers: LazyBuffers,
    deadline: Instant,
    cancel: Option<Arc<AtomicBool>>,
}
impl PinnedTcp {
    fn remaining(&self, timeout: NextTimeout) -> Result<Duration, ureq::Error> {
        check_cancel(&self.cancel)?;
        let remaining = self
            .deadline
            .saturating_duration_since(Instant::now())
            .min(*timeout.after);
        if remaining.is_zero() {
            Err(ureq::Error::Timeout(timeout.reason))
        } else {
            Ok(remaining)
        }
    }
    fn slice(&self, timeout: NextTimeout) -> Result<Duration, ureq::Error> {
        let remaining = self.remaining(timeout)?;
        Ok(if self.cancel.is_some() {
            remaining.min(Duration::from_millis(100))
        } else {
            remaining
        })
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
        if self.cancel.is_none() {
            self.stream
                .set_write_timeout(Some(self.remaining(timeout)?))?;
            return self
                .stream
                .write_all(&self.buffers.output()[..amount])
                .map_err(|error| map_io(error, timeout));
        }
        let local_deadline = Instant::now() + self.remaining(timeout)?;
        let mut written = 0;
        while written < amount {
            let remaining = local_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ureq::Error::Timeout(timeout.reason));
            }
            self.stream
                .set_write_timeout(Some(self.slice(timeout)?.min(remaining)))?;
            match self.stream.write(&self.buffers.output()[written..amount]) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ok(n) => written += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(map_io(e, timeout)),
            }
        }
        check_cancel(&self.cancel)
    }
    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        let local_deadline = Instant::now() + self.remaining(timeout)?;
        loop {
            let remaining = local_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ureq::Error::Timeout(timeout.reason));
            }
            self.stream
                .set_read_timeout(Some(self.slice(timeout)?.min(remaining)))?;
            match self.stream.read(self.buffers.input_append_buf()) {
                Ok(size) => {
                    check_cancel(&self.cancel)?;
                    self.buffers.input_appended(size);
                    return Ok(size > 0);
                }
                Err(e)
                    if self.cancel.is_some()
                        && matches!(
                            e.kind(),
                            io::ErrorKind::TimedOut
                                | io::ErrorKind::WouldBlock
                                | io::ErrorKind::Interrupted
                        ) => {}
                Err(e) => return Err(map_io(e, timeout)),
            }
        }
    }
    fn is_open(&mut self) -> bool {
        false
    }
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
            matches!(verify_peer(&stream,wrong),Err(ureq::Error::Io(error)) if error.kind()==io::ErrorKind::PermissionDenied)
        );
    }
    #[test]
    fn cancelled_transfer_does_not_wait_for_a_stalled_http_body_deadline() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut transport = PinnedTcp {
            stream,
            buffers: LazyBuffers::new(4096, 4096),
            deadline: Instant::now() + Duration::from_secs(10),
            cancel: Some(Arc::clone(&cancel)),
        };
        let signal = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            cancel.store(true, Ordering::Release);
        });
        let start = Instant::now();
        let result = transport.await_input(NextTimeout {
            after: Duration::from_secs(10).into(),
            reason: ureq::Timeout::Global,
        });
        assert!(
            matches!(result,Err(ureq::Error::Io(error)) if error.kind()==io::ErrorKind::ConnectionAborted)
        );
        assert!(start.elapsed() < Duration::from_millis(750));
        signal.join().unwrap();
    }
}
