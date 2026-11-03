//! Nonblocking source delivery. Only a committed gate can release the marker.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use super::launch::RequestWindow;
use super::process_io::write_without_sigpipe;
use crate::source_launch::SourceGate;

pub(super) struct Input<'input, 'gate> {
    bytes: &'input [u8],
    offset: usize,
    gate: Option<SourceGate<'gate>>,
    framed: bool,
    committed: bool,
    released: bool,
    effects_prepared: bool,
}

impl<'input, 'gate> Input<'input, 'gate> {
    pub(super) fn new(bytes: &'input [u8], gate: Option<SourceGate<'gate>>) -> Self {
        Self {
            bytes,
            offset: 0,
            gate,
            framed: false,
            committed: false,
            released: false,
            effects_prepared: false,
        }
    }

    pub(super) fn prepare_effects(&mut self, window: &RequestWindow<'_>) -> io::Result<()> {
        window.require_launch()?;
        if !self.effects_prepared {
            let gate = self.gate.as_mut().ok_or(io::ErrorKind::PermissionDenied)?;
            gate.gate.prepare_effects()?;
            self.effects_prepared = true;
        }
        window.require_launch()
    }

    pub(super) fn write_body(&mut self, stdin: &mut Option<OwnedFd>) -> io::Result<()> {
        if self.offset == self.bytes.len() {
            if self
                .gate
                .as_ref()
                .is_some_and(|gate| gate.frame_before_commit)
                && !self.framed
            {
                let Some(fd) = stdin.as_ref() else {
                    return Ok(());
                };
                match write_without_sigpipe(fd.as_raw_fd(), &[0]) {
                    Ok(1) => self.framed = true,
                    Ok(_) => return Err(io::ErrorKind::WriteZero.into()),
                    Err(error) if retry(&error) => (),
                    Err(error) => return Err(error),
                }
            }
            if self.gate.is_none() {
                stdin.take();
            }
            return Ok(());
        }
        let Some(fd) = stdin.as_ref() else {
            return Ok(());
        };
        match write_without_sigpipe(fd.as_raw_fd(), &self.bytes[self.offset..]) {
            Ok(length) => self.offset += length,
            Err(error) if error.raw_os_error() == Some(libc::EPIPE) => {
                stdin.take();
                if self.gate.is_some() {
                    return Err(error);
                }
            }
            Err(error) if retry(&error) => (),
            Err(error) => return Err(error),
        }
        Ok(())
    }

    pub(super) fn release(
        &mut self,
        stdin: &mut Option<OwnedFd>,
        started: bool,
        window: &RequestWindow<'_>,
    ) -> io::Result<()> {
        if !started || self.offset != self.bytes.len() || self.released {
            return Ok(());
        }
        let (Some(gate), Some(fd)) = (self.gate.as_mut(), stdin.as_ref()) else {
            return Ok(());
        };
        if gate.frame_before_commit && !self.framed {
            return Ok(());
        }
        window.require_launch()?;
        if !self.committed {
            gate.gate.commit()?;
            self.committed = true;
        }
        window.require_launch()?;
        match write_without_sigpipe(fd.as_raw_fd(), &[0]) {
            Ok(1) => {
                self.released = true;
                stdin.take();
                gate.gate.released()?;
            }
            Ok(_) => return Err(io::ErrorKind::WriteZero.into()),
            Err(error) if retry(&error) => (),
            Err(error) => return Err(error),
        }
        Ok(())
    }
}

fn retry(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}
