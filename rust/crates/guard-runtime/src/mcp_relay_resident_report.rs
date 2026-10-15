//! The catalog report a native relay session sends the resident.
//!
//! `_report_relay_server` sends its report from a background thread, so a
//! slow or cold resident never delays a host message. The relay does the
//! same: each attempt runs on a detached thread with its own resident
//! connection, and the relay loop only reads the answer after it has sent
//! the host a response (`settle`), without waiting for it. A report the
//! resident did not record, say because the daemon that starts it was still
//! cold, is sent again on a later message: at most `MAX_ATTEMPTS` times and
//! no sooner than `RETRY_INTERVAL` after the last attempt, so the server is
//! known to its later sessions even when this one started before the
//! resident did. A newer catalog replaces a report still pending, and the
//! session's exit gives an attempt in flight up to `REPORT_TIMEOUT`, as
//! `_finish_relay_report` does.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::{discover, send, STATE_DIRECTORY};
use crate::mcp_relay_servers::REPORT_SCHEMA;

/// How long one attempt waits for the resident to take the report.
const REPORT_TIMEOUT: Duration = Duration::from_millis(500);
/// Attempts at one catalog before the session stops reporting it.
const MAX_ATTEMPTS: u32 = 8;
/// The least time between two attempts at one catalog.
const RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// Starts one attempt; the receiver yields whether the resident recorded
/// the catalog, and disconnects when the attempt could not finish.
pub(super) type Deliver = fn(&Path, &[u8]) -> Receiver<bool>;

/// Where a report stands after `poll`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Progress {
    /// An attempt is in flight, or another is due on a later message.
    Pending,
    /// The resident recorded the catalog.
    Recorded,
    /// Every attempt failed: the server stays unknown, as it does when a
    /// proxy session's report is lost.
    Abandoned,
}

/// A catalog report the resident has not confirmed yet.
pub(super) struct CatalogReport {
    guard_home: PathBuf,
    payload: Vec<u8>,
    deliver: Deliver,
    attempts: u32,
    last: Option<Instant>,
    answer: Option<Receiver<bool>>,
}

impl CatalogReport {
    pub(super) fn new(guard_home: PathBuf, payload: Vec<u8>, deliver: Deliver) -> Self {
        Self {
            guard_home,
            payload,
            deliver,
            attempts: 0,
            last: None,
            answer: None,
        }
    }

    /// Read the attempt in flight, and start another when the last one was
    /// not recorded and the retry interval has passed. Never blocks.
    pub(super) fn poll(&mut self, now: Instant) -> Progress {
        if let Some(answer) = &self.answer {
            match answer.try_recv() {
                Ok(true) => {
                    self.answer = None;
                    return Progress::Recorded;
                }
                Err(TryRecvError::Empty) => return Progress::Pending,
                Ok(false) | Err(TryRecvError::Disconnected) => self.answer = None,
            }
        }
        if self.attempts >= MAX_ATTEMPTS {
            return Progress::Abandoned;
        }
        if self
            .last
            .is_some_and(|last| now.saturating_duration_since(last) < RETRY_INTERVAL)
        {
            return Progress::Pending;
        }
        self.attempts += 1;
        self.last = Some(now);
        self.answer = Some((self.deliver)(&self.guard_home, &self.payload));
        Progress::Pending
    }

    /// Drop a report a newer catalog replaces, without waiting for it.
    pub(super) fn supersede(mut self) {
        self.answer = None;
    }
}

impl Drop for CatalogReport {
    /// `_finish_relay_report`: give an attempt in flight a moment to land
    /// before the session exits.
    fn drop(&mut self) {
        if let Some(answer) = self.answer.take() {
            let _ = answer.recv_timeout(REPORT_TIMEOUT);
        }
    }
}

/// Send `payload` on a detached thread with its own resident connection.
pub(super) fn deliver(guard_home: &Path, payload: &[u8]) -> Receiver<bool> {
    let (sender, answer) = mpsc::channel();
    let state_base = guard_home.join(STATE_DIRECTORY);
    let payload = payload.to_vec();
    // A thread that cannot start drops the sender, which reads as an attempt
    // that failed.
    let _ = std::thread::Builder::new()
        .name("mcp-relay-report".to_owned())
        .spawn(move || {
            let deadline = Instant::now() + REPORT_TIMEOUT;
            let recorded = discover(&state_base)
                .and_then(|resident| send(&resident, &payload, deadline).ok())
                .is_some_and(|output| recorded(&output));
            let _ = sender.send(recorded);
        });
    answer
}

/// Whether the resident's answer says it recorded the catalog.
fn recorded(output: &[u8]) -> bool {
    serde_json::from_slice::<Value>(output).is_ok_and(|answer| {
        answer.get("schema").and_then(Value::as_str) == Some(REPORT_SCHEMA)
            && answer.get("recorded").and_then(Value::as_bool) == Some(true)
    })
}

#[cfg(test)]
#[path = "mcp_relay_resident_report_tests.rs"]
mod tests;
