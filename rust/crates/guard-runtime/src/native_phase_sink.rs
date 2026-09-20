//! Bounded best-effort export outside all native request threads.
//!
//! The original run result is returned unchanged. Request threads update fixed
//! counters only; the exporter never joins, retries a send, or changes shutdown.
//! A killed process or exhausted exporter leaves an explicitly partial snapshot.

#[path = "native_phase_endpoint.rs"]
mod endpoint;

use crate::native_phase_observation::{self, Report};
use nix::sys::socket::{send, MsgFlags};
use serde::Serialize;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub(crate) const MAX_DATAGRAM_BYTES: usize = 8192;
const MAX_EXPORT_ATTEMPTS: u16 = 256;
const EXPORT_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    ResidentClient,
    PersistentClient,
    Resident,
    ManagedResident,
}

impl Role {
    fn from_command(command: &str) -> Option<Self> {
        match command {
            "hook-client" | "resident-client" => Some(Self::ResidentClient),
            "resident-client-stream" => Some(Self::PersistentClient),
            "serve" => Some(Self::Resident),
            "serve-managed" => Some(Self::ManagedResident),
            _ => None,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum RunState {
    Running,
    ReturnedOk,
    ReturnedErr,
}

impl RunState {
    fn from_code(code: u8) -> Self {
        match code {
            1 => Self::ReturnedOk,
            2 => Self::ReturnedErr,
            _ => Self::Running,
        }
    }
}

#[derive(Serialize)]
struct Frame {
    schema: &'static str,
    sender_pid: u32,
    sender_start_ticks: u64,
    role: Role,
    ordinal: u16,
    max_export_attempts: u16,
    export_interval_ms: u64,
    max_datagram_bytes: usize,
    diagnostic_socket_opens: u8,
    diagnostic_socket_in_request_counts: bool,
    prior_export_loss_observed: bool,
    last_allowed_attempt: bool,
    run_state_when_sampled: RunState,
    complete_run: bool,
    headline_timing_eligible: bool,
    snapshot: Option<Report>,
}

pub(crate) struct Exporter {
    run_state: Arc<AtomicU8>,
}

impl Exporter {
    pub(crate) fn finished(self, returned_ok: bool) {
        // Memory only. The original process is neither held open nor joined.
        self.run_state
            .store(if returned_ok { 1 } else { 2 }, Ordering::Relaxed);
    }
}

fn send_frame(socket: &UnixDatagram, frame: &Frame) -> bool {
    let Ok(bytes) = serde_json::to_vec(frame) else {
        return false;
    };
    if bytes.len() > MAX_DATAGRAM_BYTES {
        return false;
    }
    // One datagram, with explicit per-call nonblocking and no-SIGPIPE flags.
    // Partial results, interruptions and closed/full receivers are never retried.
    matches!(
        send(socket.as_raw_fd(), &bytes, MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL),
        Ok(length) if length == bytes.len()
    )
}

fn export_loop(
    socket: UnixDatagram,
    role: Role,
    sender_start_ticks: u64,
    run_state: Arc<AtomicU8>,
) {
    let sender_pid = std::process::id();
    let mut loss_observed = false;
    for ordinal in 1..=MAX_EXPORT_ATTEMPTS {
        let run_code = run_state.load(Ordering::Relaxed);
        let frame = Frame {
            schema: "hol-guard-native-phase-frame.v1",
            sender_pid,
            sender_start_ticks,
            role,
            ordinal,
            max_export_attempts: MAX_EXPORT_ATTEMPTS,
            export_interval_ms: 50,
            max_datagram_bytes: MAX_DATAGRAM_BYTES,
            diagnostic_socket_opens: 1,
            diagnostic_socket_in_request_counts: false,
            prior_export_loss_observed: loss_observed,
            last_allowed_attempt: ordinal == MAX_EXPORT_ATTEMPTS,
            run_state_when_sampled: RunState::from_code(run_code),
            complete_run: false,
            headline_timing_eligible: false,
            snapshot: native_phase_observation::snapshot(),
        };
        loss_observed |= !send_frame(&socket, &frame);
        if run_code != 0 || ordinal == MAX_EXPORT_ATTEMPTS {
            return;
        }
        thread::sleep(EXPORT_INTERVAL);
    }
}

pub(crate) fn start() -> Option<Exporter> {
    let role = Role::from_command(&std::env::args().nth(1)?)?;
    let sender_start_ticks = endpoint::self_start_ticks()?;
    let socket = endpoint::from_environment()?;
    let run_state = Arc::new(AtomicU8::new(0));
    let thread_state = Arc::clone(&run_state);
    // Dropping the handle detaches the bounded diagnostic worker. No original
    // process thread waits for it, including on a failed or timed-out request.
    let handle = thread::Builder::new()
        .name("guard-phase-export".into())
        .spawn(move || export_loop(socket, role, sender_start_ticks, thread_state))
        .ok()?;
    drop(handle);
    native_phase_observation::enable();
    Some(Exporter { run_state })
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("native_phase_sink_tests.rs");
}
