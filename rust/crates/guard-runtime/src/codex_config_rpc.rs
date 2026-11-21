//! Bounded, task-owned access to Codex's supported configuration RPCs: the
//! retired Python `CodexConfigRpc` of `runtime/codex_config_rpc.py`.
//!
//! A session starts `codex app-server --listen stdio://` and talks to it over
//! pipes. It never creates a thread, invokes a tool or starts an inference
//! turn: only `config/read` and `config/batchWrite` are sent, and a write
//! always carries the host's version. Host diagnostics can hold private
//! configuration, so the child's stderr is discarded and a failure is only
//! ever one of the reason codes below.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

pub(crate) type Reason = &'static str;

pub(crate) const UNAVAILABLE: Reason = "codex_config_rpc_unavailable";
pub(crate) const CHANGED: Reason = "codex_config_changed";
pub(crate) const READONLY: Reason = "codex_config_readonly";
const INVALID: Reason = "codex_config_rpc_invalid";
const LIMIT: Reason = "codex_config_rpc_limit";
const TIMEOUT: Reason = "codex_config_rpc_timeout";
const REJECTED: Reason = "codex_config_rpc_rejected";
const VERSION_REQUIRED: Reason = "codex_config_version_required";
const UNSUPPORTED: Reason = "unsupported_codex_config_operation";

const MAX_MESSAGE_BYTES: usize = 1_048_576;
const MAX_JSON_DEPTH: usize = 64;
/// Bound on unsolicited notifications while waiting for one response.
const MAX_RECEIVED_MESSAGES: usize = 64;
const QUEUE_SIZE: usize = 8;
pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(8);
/// How long one session may last in all. The caller that runs the native op
/// bounds it with a SIGKILL deadline (Python's 75 s), and a SIGKILL cannot run
/// `Drop`, so the host would be left running. The session ends itself, and ends
/// the host, well before that: this is the bound the caller's deadline sits above.
pub(crate) const SESSION_LIMIT: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_millis(5);

/// Where the setup flow reads and writes Codex's configuration.
pub(crate) trait ConfigHost {
    /// One `config/read` or `config/batchWrite`; the `result` object of the reply.
    fn request(&mut self, method: &str, params: &Value) -> Result<Map<String, Value>, Reason>;
}

enum Incoming {
    Message(Value),
    Failure(Reason),
}

/// One running host and the pipes to it. Closing it, or dropping it, ends the host.
pub(crate) struct ConfigRpc {
    child: Child,
    stdin: Arc<Mutex<Option<ChildStdin>>>,
    messages: Receiver<Incoming>,
    closed: Arc<AtomicBool>,
    writer: Option<JoinHandle<()>>,
    timeout: Duration,
    session_deadline: Instant,
    sequence: i64,
}

impl ConfigRpc {
    /// Starts the host and finishes its `initialize` handshake. Every failure
    /// to get that far is `codex_config_rpc_unavailable`.
    pub(crate) fn open(
        executable: &str,
        cwd: Option<&Path>,
        environment: &[(String, String)],
        timeout: Duration,
    ) -> Result<Self, Reason> {
        Self::open_within(executable, cwd, environment, timeout, SESSION_LIMIT)
    }

    /// `open`, with the whole session (handshake included) bounded to `limit`.
    pub(crate) fn open_within(
        executable: &str,
        cwd: Option<&Path>,
        environment: &[(String, String)],
        timeout: Duration,
        limit: Duration,
    ) -> Result<Self, Reason> {
        let session_deadline = Instant::now() + limit;
        let mut command = Command::new(executable);
        command
            .args(["app-server", "--listen", "stdio://"])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Host diagnostics can contain private configuration.
            .stderr(Stdio::null());
        // The host leads its own process group, so stopping it also stops
        // anything it started.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        for (name, value) in environment {
            command.env(name, value);
        }
        if let Some(cwd) = cwd {
            command.current_dir(cwd);
        }
        let mut child = command.spawn().map_err(|_| UNAVAILABLE)?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(UNAVAILABLE);
        };
        let (sender, messages) = mpsc::sync_channel(QUEUE_SIZE);
        let closed = Arc::new(AtomicBool::new(false));
        let reader_closed = Arc::clone(&closed);
        thread::spawn(move || read_messages(stdout, &sender, &reader_closed));
        let mut rpc = Self {
            child,
            stdin: Arc::new(Mutex::new(Some(stdin))),
            messages,
            closed,
            writer: None,
            timeout,
            session_deadline,
            sequence: 0,
        };
        if rpc.handshake().is_err() {
            rpc.close();
            return Err(UNAVAILABLE);
        }
        Ok(rpc)
    }

    /// What one wait may take: the per-request timeout, cut to what the
    /// session has left. Zero when the session is over.
    fn allowance(&self) -> Duration {
        self.timeout.min(
            self.session_deadline
                .saturating_duration_since(Instant::now()),
        )
    }

    fn handshake(&mut self) -> Result<(), Reason> {
        let hello = json!({
            "clientInfo": {"name": "hol_guard_setup", "title": "HOL Guard setup", "version": "1"},
        });
        self.exchange("initialize", &hello)?;
        self.send(&json!({"method": "initialized"}))
    }

    fn send(&mut self, message: &Value) -> Result<(), Reason> {
        if !matches!(self.child.try_wait(), Ok(None)) {
            return Err(UNAVAILABLE);
        }
        let mut encoded = serde_json::to_vec(message).map_err(|_| UNAVAILABLE)?;
        encoded.push(b'\n');
        if encoded.len() > MAX_MESSAGE_BYTES {
            return Err(LIMIT);
        }
        let allowance = self.allowance();
        if allowance.is_zero() {
            return Err(TIMEOUT);
        }
        // The write happens on its own thread: a host that stops reading
        // must not hold the caller past its timeout.
        let (done, outcome) = mpsc::sync_channel(1);
        let stdin = Arc::clone(&self.stdin);
        self.writer = Some(thread::spawn(move || {
            let written = match stdin.lock() {
                Ok(mut guard) => guard.as_mut().is_some_and(|pipe| {
                    pipe.write_all(&encoded).and_then(|()| pipe.flush()).is_ok()
                }),
                Err(_) => false,
            };
            let _ = done.send(written);
        }));
        match outcome.recv_timeout(allowance) {
            Ok(true) => Ok(()),
            Ok(false) | Err(RecvTimeoutError::Disconnected) => Err(UNAVAILABLE),
            Err(RecvTimeoutError::Timeout) => Err(TIMEOUT),
        }
    }

    /// `_request`: one request, then the reply that carries its id.
    fn exchange(&mut self, method: &str, params: &Value) -> Result<Map<String, Value>, Reason> {
        self.sequence += 1;
        let request_id = self.sequence;
        self.send(&json!({"id": request_id, "method": method, "params": params}))?;
        let deadline = Instant::now() + self.allowance();
        for _ in 0..MAX_RECEIVED_MESSAGES {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(TIMEOUT);
            }
            let message = match self.messages.recv_timeout(remaining) {
                Ok(Incoming::Message(message)) => message,
                Ok(Incoming::Failure(reason)) => return Err(reason),
                Err(RecvTimeoutError::Timeout) => return Err(TIMEOUT),
                Err(RecvTimeoutError::Disconnected) => return Err(UNAVAILABLE),
            };
            let Value::Object(mut message) = message else {
                return Err(INVALID);
            };
            let Some(id) = message.get("id") else {
                continue;
            };
            if id.as_i64() != Some(request_id) {
                return Err(INVALID);
            }
            if let Some(error) = message.get("error") {
                return Err(error_reason(error));
            }
            return match message.remove("result") {
                Some(Value::Object(result)) => Ok(result),
                _ => Err(INVALID),
            };
        }
        Err(LIMIT)
    }

    /// Ends the host: a blocked write is cut off first, then its input is
    /// closed so it can finish, and it is stopped if it does not.
    pub(crate) fn close(&mut self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let writing = self
            .writer
            .as_ref()
            .is_some_and(|writer| !writer.is_finished());
        if writing && matches!(self.child.try_wait(), Ok(None)) {
            stop(&mut self.child, Duration::from_secs(1));
        }
        if let Some(writer) = self.writer.take() {
            join_within(writer, Duration::from_secs(1));
        }
        if let Ok(mut pipe) = self.stdin.try_lock() {
            drop(pipe.take());
        }
        if !wait_for(&mut self.child, Duration::from_millis(500)) {
            stop(&mut self.child, Duration::from_secs(1));
        }
    }

    #[cfg(all(test, unix))]
    pub(crate) fn exit_code(&mut self) -> Option<Option<i32>> {
        self.child
            .try_wait()
            .ok()
            .flatten()
            .map(|status| status.code())
    }
}

impl ConfigHost for ConfigRpc {
    fn request(&mut self, method: &str, params: &Value) -> Result<Map<String, Value>, Reason> {
        if !matches!(method, "config/read" | "config/batchWrite") {
            return Err(UNSUPPORTED);
        }
        if method == "config/batchWrite" {
            let version = params.get("expectedVersion").and_then(Value::as_str);
            if !version.is_some_and(|version| (1..=256).contains(&version.chars().count())) {
                return Err(VERSION_REQUIRED);
            }
        }
        self.exchange(method, params)
    }
}

impl Drop for ConfigRpc {
    fn drop(&mut self) {
        self.close();
    }
}

/// How a host's `error` reply reads: a version conflict and a read-only layer
/// get their own reasons, everything else is rejected without its payload.
fn error_reason(error: &Value) -> Reason {
    let data = error.as_object().and_then(|error| error.get("data"));
    let code = match data {
        Some(Value::Object(details)) => details
            .get("configWriteErrorCode")
            .or_else(|| details.get("code")),
        other => other,
    };
    match code.and_then(Value::as_str) {
        Some("configVersionConflict") => CHANGED,
        Some("configLayerReadonly" | "configRequirementReadonly") => READONLY,
        _ => REJECTED,
    }
}

/// `check_json_depth`: brackets outside strings nest at most `MAX_JSON_DEPTH`.
fn depth_within_limit(message: &[u8]) -> bool {
    let (mut depth, mut quoted, mut escaped) = (0_usize, false, false);
    for &byte in message {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else if byte == b'"' {
            quoted = true;
        } else if matches!(byte, b'[' | b'{') {
            depth += 1;
            if depth > MAX_JSON_DEPTH {
                return false;
            }
        } else if matches!(byte, b']' | b'}') {
            let Some(rest) = depth.checked_sub(1) else {
                return false;
            };
            depth = rest;
        }
    }
    true
}

/// One host line as JSON: a repeated key, a bare constant or too much nesting is refused.
fn parse(line: &[u8]) -> Option<Value> {
    if !depth_within_limit(line) {
        return None;
    }
    crate::strict_json::parse_with_limits(line, usize::MAX, MAX_JSON_DEPTH).ok()
}

fn read_messages(stdout: ChildStdout, queue: &SyncSender<Incoming>, closed: &AtomicBool) {
    let mut reader = BufReader::new(stdout);
    while !closed.load(Ordering::SeqCst) {
        let mut line = Vec::new();
        let read = reader
            .by_ref()
            .take(MAX_MESSAGE_BYTES as u64 + 1)
            .read_until(b'\n', &mut line);
        let incoming = match read {
            Ok(0) => Incoming::Failure(UNAVAILABLE),
            Ok(_) if line.len() > MAX_MESSAGE_BYTES => Incoming::Failure(LIMIT),
            Ok(_) => match parse(&line) {
                Some(message) => Incoming::Message(message),
                None => Incoming::Failure(INVALID),
            },
            Err(_) => Incoming::Failure(INVALID),
        };
        let last = matches!(incoming, Incoming::Failure(_));
        if !deliver(queue, incoming, closed) || last {
            return;
        }
    }
}

/// Puts one message on the queue, waiting while it is full. False once the
/// session is closed or nobody is reading.
fn deliver(queue: &SyncSender<Incoming>, mut incoming: Incoming, closed: &AtomicBool) -> bool {
    loop {
        if closed.load(Ordering::SeqCst) {
            return false;
        }
        match queue.try_send(incoming) {
            Ok(()) => return true,
            Err(TrySendError::Full(back)) => {
                incoming = back;
                thread::sleep(Duration::from_millis(10));
            }
            Err(TrySendError::Disconnected(_)) => return false,
        }
    }
}

/// Whether the child exited within `limit`.
fn wait_for(child: &mut Child, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        if !matches!(child.try_wait(), Ok(None)) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(POLL);
    }
}

/// Asks the child to end, and kills it when it has not within `grace`.
fn stop(child: &mut Child, grace: Duration) {
    terminate(child);
    if !wait_for(child, grace) {
        kill_group(child);
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// SIGKILL to the host's whole process group. The group exists for as long as
/// the host does, and the host is not yet reaped when this is called.
#[cfg(unix)]
fn kill_group(child: &Child) {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    if let Ok(pid) = i32::try_from(child.id()) {
        let _ = kill(Pid::from_raw(-pid), Signal::SIGKILL);
    }
}

#[cfg(not(unix))]
fn kill_group(_child: &Child) {}

#[cfg(unix)]
fn terminate(child: &mut Child) {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    if let Ok(pid) = i32::try_from(child.id()) {
        let _ = kill(Pid::from_raw(-pid), Signal::SIGTERM);
    }
}

#[cfg(not(unix))]
fn terminate(child: &mut Child) {
    let _ = child.kill();
}

fn join_within(handle: JoinHandle<()>, limit: Duration) {
    let deadline = Instant::now() + limit;
    while !handle.is_finished() && Instant::now() < deadline {
        thread::sleep(POLL);
    }
    if handle.is_finished() {
        let _ = handle.join();
    }
}

#[cfg(all(test, unix))]
#[path = "codex_config_rpc_tests.rs"]
mod tests;
