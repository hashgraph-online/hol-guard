//! A native-owned readiness/dispatch channel, separate from user output.

use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::SourceLaunchGate;

pub(super) struct Gate<'a> {
    pub authority: &'a mut dyn SourceLaunchGate,
    pub channel: std::fs::File,
    pub deadline: Instant,
    pub cancel: &'a AtomicBool,
    pub outputs: Vec<crate::deferred_output::DeferredOutput>,
    pub output_base: u32,
}

impl Gate<'_> {
    fn read_frame(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            if self.cancel.load(Ordering::Acquire) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .ok_or(io::ErrorKind::TimedOut)?;
            let mut poll = libc::pollfd {
                fd: self.channel.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // Poll returns immediately on readiness. Bound only the cancellation
            // observation interval; the caller's deadline remains authoritative.
            let milliseconds = remaining.as_millis().clamp(1, 10) as i32;
            let result = unsafe { libc::poll(&mut poll, 1, milliseconds) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if result == 0 {
                continue;
            }
            match self.channel.read(&mut bytes[offset..]) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(length) => offset += length,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        if self.cancel.load(Ordering::Acquire) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if Instant::now() >= self.deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(())
    }

    fn receive(&mut self, expected: u8) -> io::Result<()> {
        let mut byte = [0];
        self.read_frame(&mut byte)?;
        if byte[0] != expected {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
}

impl SourceLaunchGate for Gate<'_> {
    fn prepare_effects(&mut self) -> io::Result<()> {
        self.authority.prepare_effects()
    }

    fn commit(&mut self) -> io::Result<()> {
        for index in 0..self.outputs.len() {
            let mut frame = [0u8; 21];
            self.read_frame(&mut frame)?;
            if frame[0] != b'O'
                || u32::from_le_bytes(frame[1..5].try_into().unwrap())
                    != self.output_base + index as u32
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let device = u64::from_le_bytes(frame[5..13].try_into().unwrap());
            let inode = u64::from_le_bytes(frame[13..21].try_into().unwrap());
            self.outputs[index].verify_opened(device, inode)?;
        }
        self.receive(b'R')?;
        self.authority.commit()
    }

    fn released(&mut self) -> io::Result<()> {
        self.receive(b'S')?;
        self.authority.released()
    }
}
