//! Linux-only active-run deadline. CLOCK_BOOTTIME advances during guest suspend;
//! wall-clock changes cannot extend a run. This primitive never starts or kills
//! a process; a dispatcher must contain and reap all descendants on expiry.

use rustix::time::{clock_gettime, ClockId};
use std::fmt;
use std::time::Duration;

const NANOS_PER_SECOND: u128 = 1_000_000_000;
const MAX_POLL: Duration = Duration::from_millis(200);
pub const MAX_ACTIVE_SECONDS: u64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineError {
    InvalidTimeout,
    InvalidClock,
    ClockRegressed,
}

impl fmt::Display for DeadlineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTimeout => f.write_str("active-run timeout must be 1..=86400 seconds"),
            Self::InvalidClock => f.write_str("Linux boottime clock is unavailable"),
            Self::ClockRegressed => f.write_str("Linux boottime clock moved backwards"),
        }
    }
}

impl std::error::Error for DeadlineError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoottimeDeadline {
    started_ns: u128,
    expires_ns: u128,
}

fn boottime_ns() -> Result<u128, DeadlineError> {
    let now = clock_gettime(ClockId::Boottime);
    if now.tv_sec < 0 || !(0..1_000_000_000).contains(&now.tv_nsec) {
        return Err(DeadlineError::InvalidClock);
    }
    Ok(now.tv_sec as u128 * NANOS_PER_SECOND + now.tv_nsec as u128)
}

impl BoottimeDeadline {
    /// `seconds` must come from reviewed worker configuration, never the
    /// untrusted run request. The default Python host timeout is 3600 seconds.
    pub fn start(seconds: u64) -> Result<Self, DeadlineError> {
        Self::at_ticks(boottime_ns()?, seconds)
    }

    fn at_ticks(started_ns: u128, seconds: u64) -> Result<Self, DeadlineError> {
        if !(1..=MAX_ACTIVE_SECONDS).contains(&seconds) {
            return Err(DeadlineError::InvalidTimeout);
        }
        let expires_ns = started_ns
            .checked_add(u128::from(seconds) * NANOS_PER_SECOND)
            .ok_or(DeadlineError::InvalidClock)?;
        Ok(Self {
            started_ns,
            expires_ns,
        })
    }

    /// A backward or malformed clock sample is an error, never extra time.
    pub fn remaining(&self) -> Result<Duration, DeadlineError> {
        self.remaining_at_ticks(boottime_ns()?)
    }

    fn remaining_at_ticks(&self, now_ns: u128) -> Result<Duration, DeadlineError> {
        if now_ns < self.started_ns {
            return Err(DeadlineError::ClockRegressed);
        }
        let remaining = self.expires_ns.saturating_sub(now_ns);
        Ok(Duration::new(
            (remaining / NANOS_PER_SECOND) as u64,
            (remaining % NANOS_PER_SECOND) as u32,
        ))
    }

    /// Limit polling jitter without sleeping beyond the remaining budget.
    pub fn next_poll(&self) -> Result<Duration, DeadlineError> {
        Ok(self.remaining()?.min(MAX_POLL))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unbounded_or_zero_timeouts() {
        assert_eq!(
            BoottimeDeadline::at_ticks(0, 0),
            Err(DeadlineError::InvalidTimeout)
        );
        assert_eq!(
            BoottimeDeadline::at_ticks(0, MAX_ACTIVE_SECONDS + 1),
            Err(DeadlineError::InvalidTimeout)
        );
        assert_eq!(
            BoottimeDeadline::at_ticks(u128::MAX, 1),
            Err(DeadlineError::InvalidClock)
        );
    }

    #[test]
    fn expires_at_exact_monotone_tick_and_never_grants_time_after_expiry() {
        let started = 1_000 * NANOS_PER_SECOND;
        let deadline = BoottimeDeadline::at_ticks(started, 3_600).unwrap();
        assert_eq!(
            deadline.remaining_at_ticks(started).unwrap(),
            Duration::from_secs(3_600)
        );
        assert_eq!(
            deadline
                .remaining_at_ticks(started + 3_599 * NANOS_PER_SECOND + 999_999_999)
                .unwrap(),
            Duration::from_nanos(1)
        );
        assert_eq!(
            deadline
                .remaining_at_ticks(started + 3_600 * NANOS_PER_SECOND)
                .unwrap(),
            Duration::ZERO
        );
        assert_eq!(
            deadline
                .remaining_at_ticks(started + 4_000 * NANOS_PER_SECOND)
                .unwrap(),
            Duration::ZERO
        );
        assert_eq!(
            deadline.remaining_at_ticks(started - 1),
            Err(DeadlineError::ClockRegressed)
        );
    }

    #[test]
    fn host_clock_yields_a_bounded_nonnegative_poll_window() {
        let deadline = BoottimeDeadline::start(3_600).unwrap();
        let interval = deadline.next_poll().unwrap();
        assert!(interval > Duration::ZERO);
        assert!(interval <= MAX_POLL);
    }
}
