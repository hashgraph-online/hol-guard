#![forbid(unsafe_code)]

use std::io;
use std::time::{Duration, Instant};

pub const TOTAL_REQUEST_BUDGET: Duration = Duration::from_secs(4);
const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(5);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoFailureClass {
    ClientAbort,
    Timeout,
    Interrupted,
    ResourcePressure,
    NetworkChange,
    Other,
}

pub fn request_expired(accepted_at: Instant) -> bool {
    accepted_at.elapsed() >= TOTAL_REQUEST_BUDGET
}

pub fn classify_io_error(error: &io::Error) -> IoFailureClass {
    match error.kind() {
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::UnexpectedEof => IoFailureClass::ClientAbort,
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => IoFailureClass::Timeout,
        io::ErrorKind::Interrupted => IoFailureClass::Interrupted,
        io::ErrorKind::OutOfMemory => IoFailureClass::ResourcePressure,
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkDown
        | io::ErrorKind::NetworkUnreachable => IoFailureClass::NetworkChange,
        _ if matches!(error.raw_os_error(), Some(23 | 24 | 55 | 10024 | 10055)) => {
            IoFailureClass::ResourcePressure
        }
        _ if matches!(
            error.raw_os_error(),
            Some(50 | 51 | 52 | 53 | 54 | 64 | 65 | 10050 | 10051 | 10052 | 10053 | 10054 | 10060 | 10064 | 10065)
        ) => IoFailureClass::NetworkChange,
        _ => IoFailureClass::Other,
    }
}

pub fn accept_retry_delay(consecutive_failures: u32, error: &io::Error) -> Duration {
    match classify_io_error(error) {
        IoFailureClass::Interrupted | IoFailureClass::ClientAbort => Duration::ZERO,
        IoFailureClass::Timeout => ACCEPT_BACKOFF_MIN,
        IoFailureClass::ResourcePressure => {
            let shift = consecutive_failures.min(7);
            ACCEPT_BACKOFF_MIN
                .saturating_mul(1u32 << shift)
                .min(ACCEPT_BACKOFF_MAX)
        }
        IoFailureClass::NetworkChange => Duration::from_millis(100)
            .saturating_mul(1u32 << consecutive_failures.min(3))
            .min(ACCEPT_BACKOFF_MAX),
        IoFailureClass::Other => Duration::from_millis(25)
            .saturating_mul(1u32 << consecutive_failures.min(5))
            .min(ACCEPT_BACKOFF_MAX),
    }
}

pub fn read_error(error: &io::Error, fallback: &'static str) -> String {
    match classify_io_error(error) {
        IoFailureClass::ClientAbort => "native_client_disconnected".to_owned(),
        IoFailureClass::Timeout => "native_request_read_timeout".to_owned(),
        IoFailureClass::Interrupted => "native_request_read_interrupted".to_owned(),
        IoFailureClass::ResourcePressure => "native_resource_pressure".to_owned(),
        IoFailureClass::NetworkChange => "native_local_transport_changed".to_owned(),
        IoFailureClass::Other => fallback.to_owned(),
    }
}

pub fn write_error(error: &io::Error, fallback: &'static str) -> String {
    match classify_io_error(error) {
        IoFailureClass::ClientAbort => "native_client_disconnected".to_owned(),
        IoFailureClass::Timeout => "native_response_write_timeout".to_owned(),
        IoFailureClass::Interrupted => "native_response_write_interrupted".to_owned(),
        IoFailureClass::ResourcePressure => "native_resource_pressure".to_owned(),
        IoFailureClass::NetworkChange => "native_local_transport_changed".to_owned(),
        IoFailureClass::Other => fallback.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_budget_expires_stale_queued_work() {
        assert!(!request_expired(Instant::now()));
        assert!(request_expired(Instant::now() - TOTAL_REQUEST_BUDGET));
    }

    #[test]
    fn client_disconnects_are_not_runtime_integrity_failures() {
        let error = io::Error::new(io::ErrorKind::BrokenPipe, "fixture");
        assert_eq!(classify_io_error(&error), IoFailureClass::ClientAbort);
        assert_eq!(write_error(&error, "fallback"), "native_client_disconnected");
    }

    #[test]
    fn descriptor_pressure_uses_bounded_exponential_backoff() {
        let error = io::Error::from_raw_os_error(24);
        assert_eq!(classify_io_error(&error), IoFailureClass::ResourcePressure);
        assert!(accept_retry_delay(0, &error) >= ACCEPT_BACKOFF_MIN);
        assert!(accept_retry_delay(100, &error) <= ACCEPT_BACKOFF_MAX);
        assert!(accept_retry_delay(5, &error) >= accept_retry_delay(1, &error));
    }

    #[test]
    fn interrupted_accept_is_retried_without_sleep() {
        let error = io::Error::new(io::ErrorKind::Interrupted, "fixture");
        assert_eq!(accept_retry_delay(10, &error), Duration::ZERO);
    }

    #[test]
    fn network_change_backoff_is_bounded() {
        let error = io::Error::new(io::ErrorKind::NetworkDown, "fixture");
        assert_eq!(classify_io_error(&error), IoFailureClass::NetworkChange);
        assert!(accept_retry_delay(100, &error) <= ACCEPT_BACKOFF_MAX);
    }
}
