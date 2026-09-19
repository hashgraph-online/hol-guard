use std::io;
use std::os::windows::io::OwnedHandle;
use std::time::{Duration, Instant};

use super::process_lifecycle;

const JOB_POLL_INTERVAL: Duration = Duration::from_millis(10);
pub(super) const NATURAL_EXIT_GRACE: Duration = Duration::from_millis(250);

pub(super) struct CleanupBudget {
    started: Instant,
    timeout: Duration,
}

impl CleanupBudget {
    pub(super) fn new(timeout: Duration) -> Self {
        Self {
            started: Instant::now(),
            timeout,
        }
    }

    pub(super) fn remaining(&self) -> Duration {
        self.timeout.saturating_sub(self.started.elapsed())
    }
}

pub(super) fn wait_for_empty_job(job: &OwnedHandle, budget: &CleanupBudget) -> io::Result<()> {
    poll_empty_job(
        || process_lifecycle::job_active_processes(job),
        || budget.remaining(),
        std::thread::sleep,
    )
}

pub(super) fn wait_for_empty_job_during_grace(
    job: &OwnedHandle,
    parent: &CleanupBudget,
    grace: &CleanupBudget,
) -> io::Result<()> {
    poll_empty_job_with_parent(
        || process_lifecycle::job_active_processes(job),
        || parent.remaining(),
        || grace.remaining(),
        std::thread::sleep,
    )
}

fn poll_empty_job_with_parent(
    active_processes: impl FnMut() -> io::Result<u32>,
    mut parent_remaining: impl FnMut() -> Duration,
    mut grace_remaining: impl FnMut() -> Duration,
    pause: impl FnMut(Duration),
) -> io::Result<()> {
    poll_empty_job(
        active_processes,
        || parent_remaining().min(grace_remaining()),
        pause,
    )
}

fn poll_empty_job(
    mut active_processes: impl FnMut() -> io::Result<u32>,
    mut remaining: impl FnMut() -> Duration,
    mut pause: impl FnMut(Duration),
) -> io::Result<()> {
    loop {
        if remaining().is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owned Job observation timed out",
            ));
        }
        let active = active_processes()?;
        let remaining = remaining();
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owned Job observation timed out",
            ));
        }
        if active == 0 {
            return Ok(());
        }
        pause(remaining.min(JOB_POLL_INTERVAL));
    }
}

#[cfg(test)]
#[path = "job_retirement_tests.rs"]
mod tests;
