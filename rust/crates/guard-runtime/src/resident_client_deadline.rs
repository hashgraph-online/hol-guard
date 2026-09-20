//! Keep each client phase inside its original monotonic deadline.
use std::cell::Cell;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use crate::ResidentStream;

pub(super) struct DeadlineStream<'a> {
    stream: &'a mut dyn ResidentStream,
    deadline: Instant,
    read_deadline: Cell<Instant>,
    write_deadline: Cell<Instant>,
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
}

impl<'a> DeadlineStream<'a> {
    pub(super) fn new(stream: &'a mut dyn ResidentStream, deadline: Instant) -> Self {
        Self {
            stream,
            deadline,
            read_deadline: Cell::new(deadline),
            write_deadline: Cell::new(deadline),
        }
    }

    fn phase_deadline(&self, timeout: Option<Duration>) -> io::Result<Instant> {
        if timeout.is_some_and(|timeout| timeout.is_zero()) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        // Callers can narrow the current phase (authentication), but no
        // timeout reset or None can extend the original request deadline.
        Ok(timeout
            .and_then(|timeout| Instant::now().checked_add(timeout))
            .map_or(self.deadline, |deadline| deadline.min(self.deadline)))
    }
}

impl Read for DeadlineStream<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let deadline = self.read_deadline.get();
        let result = match self
            .stream
            .set_resident_read_timeout(Some(remaining(deadline)?))
        {
            Ok(()) => self.stream.read(output),
            Err(error) => match self
                .stream
                .read_buffered_after_timeout_error(output, &error, deadline)
            {
                Some(result) => result,
                None => return Err(error),
            },
        };
        // Socket timeout granularity can allow a successful final read past
        // the deadline. Such a response must not be accepted as timely.
        remaining(deadline)?;
        result
    }
}

impl Write for DeadlineStream<'_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let deadline = self.write_deadline.get();
        self.stream
            .set_resident_write_timeout(Some(remaining(deadline)?))?;
        let result = self.stream.write(input);
        remaining(deadline)?;
        result
    }

    fn flush(&mut self) -> io::Result<()> {
        let deadline = self.write_deadline.get();
        let result = match self
            .stream
            .set_resident_write_timeout(Some(remaining(deadline)?))
        {
            Ok(()) => self.stream.flush(),
            Err(error) => match self.stream.flush_after_timeout_error(&error, deadline) {
                Some(result) => result,
                None => return Err(error),
            },
        };
        remaining(deadline)?;
        result
    }
}

impl ResidentStream for DeadlineStream<'_> {
    fn set_resident_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        let deadline = self.phase_deadline(timeout)?;
        self.stream
            .set_resident_read_timeout(Some(remaining(deadline)?))?;
        self.read_deadline.set(deadline);
        Ok(())
    }

    fn set_resident_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        let deadline = self.phase_deadline(timeout)?;
        self.stream
            .set_resident_write_timeout(Some(remaining(deadline)?))?;
        self.write_deadline.set(deadline);
        Ok(())
    }

    fn set_resident_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.stream.set_resident_nonblocking(nonblocking)
    }

    fn configure_low_latency(&self) -> io::Result<()> {
        self.stream.configure_low_latency()
    }
}
