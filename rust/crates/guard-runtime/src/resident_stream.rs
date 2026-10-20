//! One authenticated, full-duplex request/response connection.
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub(crate) struct DisconnectInput {
    pub(crate) reader: Box<dyn Read + Send>,
    pub(crate) interrupt: Box<dyn Fn() + Send>,
}

pub(crate) trait ResidentStream: Read + Write + Send {
    fn kernel_peer_identity(
        &self,
    ) -> Result<Option<crate::resident_peer_identity::UnixPeerIdentity>, String> {
        Ok(None)
    }
    fn set_resident_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_resident_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_resident_nonblocking(&self, nonblocking: bool) -> io::Result<()>;
    fn try_read_available(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.set_resident_nonblocking(true)?;
        let result = self.read(output);
        let restore = self.set_resident_nonblocking(false);
        match (result, restore) {
            (Err(error), Ok(())) if error.kind() == io::ErrorKind::WouldBlock => Ok(0),
            (result, Ok(())) => result,
            (_, Err(error)) => Err(error),
        }
    }
    fn configure_low_latency(&self) -> io::Result<()> {
        Ok(())
    }
    fn disconnect_input(&self) -> io::Result<DisconnectInput> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

impl ResidentStream for TcpStream {
    fn set_resident_read_timeout(&self, value: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(value)
    }
    fn set_resident_write_timeout(&self, value: Option<Duration>) -> io::Result<()> {
        self.set_write_timeout(value)
    }
    fn set_resident_nonblocking(&self, value: bool) -> io::Result<()> {
        self.set_nonblocking(value)
    }
    fn configure_low_latency(&self) -> io::Result<()> {
        self.set_nodelay(true)
    }
    fn disconnect_input(&self) -> io::Result<DisconnectInput> {
        let reader = self.try_clone()?;
        let interrupt = self.try_clone()?;
        reader.set_read_timeout(Some(Duration::from_millis(20)))?;
        Ok(DisconnectInput {
            reader: Box::new(reader),
            interrupt: Box::new(move || {
                let _ = interrupt.shutdown(Shutdown::Read);
            }),
        })
    }
}

#[cfg(unix)]
impl ResidentStream for UnixStream {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn kernel_peer_identity(
        &self,
    ) -> Result<Option<crate::resident_peer_identity::UnixPeerIdentity>, String> {
        crate::resident_peer_identity::UnixPeerIdentity::read(self).map(Some)
    }
    fn set_resident_read_timeout(&self, value: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(value)
    }
    fn set_resident_write_timeout(&self, value: Option<Duration>) -> io::Result<()> {
        self.set_write_timeout(value)
    }
    fn set_resident_nonblocking(&self, value: bool) -> io::Result<()> {
        self.set_nonblocking(value)
    }
    fn disconnect_input(&self) -> io::Result<DisconnectInput> {
        let reader = self.try_clone()?;
        let interrupt = self.try_clone()?;
        reader.set_read_timeout(Some(Duration::from_millis(20)))?;
        Ok(DisconnectInput {
            reader: Box::new(reader),
            interrupt: Box::new(move || {
                let _ = interrupt.shutdown(Shutdown::Read);
            }),
        })
    }
}
