//! Client liveness for native-owned Bash launches. The request body has
//! already passed framing/authentication/digest checks. This protocol carries
//! one request per full-duplex connection; EOF or extra input cancels ownership.
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use super::{DisconnectInput, PendingRequest};
use crate::policy_store::PolicySnapshotStore;

struct Watch {
    cancelled: Arc<AtomicBool>,
    stopped: Arc<AtomicBool>,
    interrupt: Box<dyn Fn() + Send>,
    worker: Option<JoinHandle<()>>,
}

struct CancelOnUnexpectedExit<'a> {
    cancelled: &'a AtomicBool,
    stopped: &'a AtomicBool,
}

impl Drop for CancelOnUnexpectedExit<'_> {
    fn drop(&mut self) {
        if !self.stopped.load(Ordering::Acquire) {
            self.cancelled.store(true, Ordering::Release);
        }
    }
}

impl Watch {
    fn start(input: DisconnectInput) -> io::Result<Self> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let stopped = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancelled);
        let stop = Arc::clone(&stopped);
        let mut reader = input.reader;
        let worker = thread::Builder::new()
            .name("guard-bash-client-watch".into())
            .spawn(move || {
                let _failure = CancelOnUnexpectedExit {
                    cancelled: &flag,
                    stopped: &stop,
                };
                let mut byte = [0u8; 1];
                while !stop.load(Ordering::Acquire) {
                    match reader.read(&mut byte) {
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock
                                    | io::ErrorKind::TimedOut
                                    | io::ErrorKind::Interrupted
                            ) => {}
                        // The full body was consumed. EOF, unexpected data and
                        // permanent socket errors all stop this attempt.
                        _ => {
                            return;
                        }
                    }
                }
            })?;
        Ok(Self {
            cancelled,
            stopped,
            interrupt: input.interrupt,
            worker: Some(worker),
        })
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        // Wake the reader immediately. Only the completed request's READ
        // half is shut down; the response can still be written normally.
        (self.interrupt)();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub(super) fn evaluate(
    pending: &mut PendingRequest,
    request: &[u8],
    store: Option<&PolicySnapshotStore>,
) -> Result<Vec<u8>, String> {
    guard_command::native_command_program::work_stats::begin_request();
    let response = evaluate_request(pending, request, store);
    crate::resident_diagnostics::note_command_work();
    response
}

fn evaluate_request(
    pending: &mut PendingRequest,
    request: &[u8],
    store: Option<&PolicySnapshotStore>,
) -> Result<Vec<u8>, String> {
    let owns_launch = crate::strict_json_value(request).is_ok_and(|value| {
        value.get("operation").and_then(serde_json::Value::as_str) == Some("native_bash_execute")
    });
    if !owns_launch {
        return crate::resident_protocol::evaluate_resident_bytes(request, store);
    }
    let input = pending
        .stream
        .disconnect_input()
        .map_err(|_| "native_bash_disconnect_monitor_unavailable")?;
    let watch = Watch::start(input).map_err(|_| "native_bash_disconnect_monitor_unavailable")?;
    crate::resident_ops::evaluate_resident_bytes_with_cancellation(
        request,
        store,
        Some(Arc::clone(&watch.cancelled)),
    )
}

#[cfg(test)]
#[path = "resident_request_cancellation_tests.rs"]
mod tests;
