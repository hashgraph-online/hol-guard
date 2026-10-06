//! Persistent bounded MCP stdio session owner (RTM-022/023 data plane).
//!
//! Byte-parity port of the live transport in
//! `src/codex_plugin_scanner/guard/proxy/runtime_mcp.py` `serve()`: spawn a
//! scrubbed child, pump its stdout on a dedicated drain thread, and expose a
//! bidirectional JSON-RPC mediation surface to the resident.
//!
//! Unlike the one-shot `RpcSession` used by the catalog probe, this session is
//! retained across resident ops (`open` → `send`/`recv` → `close`) and adds the
//! correlation layer `runtime_mcp.py` implements per-id: response-key
//! normalization, buffered cross-correlated queues, request/notification
//! classification, and timeout-driven quarantine. Policy authority stays in
//! Python: each `tools/call` frame is surfaced to the control plane as an
//! opaque authority request and the verdict is applied here — this module
//! never decides allow/deny itself.
//!
//! `#[cfg(unix)]`: launch attributes and process-group teardown are unix-only,
//! matching `local_mcp_stdio.rs`.

use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Read;

#[path = "mcp_stdio_writer.rs"]
mod writer;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use writer::SessionWriter;

use crate::local_mcp_stdio::{
    is_rpc_message, kill_process_group, pop_json_message, probe_search_path,
};

/// Per-frame JSON cap for the persistent pump: a single frame may not exceed
/// this; oversized/undecodable bytes are discarded without killing the pump.
/// Mirrors the probe `MCP_PROBE_OUTPUT_LIMIT` byte ceiling but applies
/// per-frame rather than lifetime (a live session legitimately exceeds 1 MB
/// of cumulative output).
const SESSION_FRAME_LIMIT: usize = 1_000_000;

/// Bound on queued child→guard frames; `sync_channel` applies backpressure so
/// a fast child blocks the reader instead of the pump dying at a fixed count.
const SESSION_QUEUE: usize = 256;

/// Maximum cross-correlated buffered responses held per response key.
const MAX_BUFFERED_PER_KEY: usize = 8;

/// Why a `next_event` drain ended without a usable frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionReadError {
    /// The drain pump hung up: child stdout closed or the pump thread died.
    Eof,
}

/// Persistent stdout pump for the session data plane. Unlike the probe
/// `drain_stream`, a live session may stream arbitrarily many frames over its
/// lifetime — the bound is per-frame size plus a bounded `sync_channel` for
/// backpressure, not a cumulative byte/frame quota. Runs on a dedicated
/// thread and exits on EOF, cancel, or a dead receiver.
fn session_pump(
    mut stdout: std::process::ChildStdout,
    tx: mpsc::SyncSender<Value>,
    cancel: Arc<AtomicBool>,
) {
    let mut buffer: Vec<u8> = Vec::new();
    loop {
        if cancel.load(Ordering::Acquire) {
            return;
        }
        let mut chunk = [0u8; 8192];
        let n = match stdout.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buffer.extend_from_slice(&chunk[..n]);
        // A single in-flight frame may not exceed the cap; drop undecodable
        // head bytes so one malformed frame cannot wedge the session.
        while let Some((message, consumed)) = pop_json_message(&buffer) {
            if consumed == 0 {
                break;
            }
            buffer.drain(..consumed);
            if let Some(msg) = message {
                if is_rpc_message(&msg) && tx.send(msg).is_err() {
                    return;
                }
            }
        }
        if buffer.len() > SESSION_FRAME_LIMIT {
            buffer.clear();
        }
    }
}

/// npm/package-cache dir the Python probe env guarantees so a child resolving
/// itself retains shim resolution: honor a caller-provided `NPM_CONFIG_CACHE`
/// (either casing), else derive `<home>/.npm` when a home dir is given.
fn npm_cache_dir(env: &BTreeMap<String, String>, home_dir: Option<&Path>) -> Option<String> {
    for key in ["NPM_CONFIG_CACHE", "npm_config_cache"] {
        if let Some(value) = env.get(key) {
            if !value.is_empty() {
                return Some(value.clone());
            }
        }
    }
    home_dir.map(|home| home.join(".npm").to_string_lossy().into_owned())
}

// ---------------------------------------------------------------------------
// JSON-RPC frame classification (`runtime_mcp.py` helpers).
// ---------------------------------------------------------------------------

/// `_is_request` — `{"method", "id"}` both present.
fn is_request(message: &Value) -> bool {
    match message {
        Value::Object(m) => m.contains_key("method") && m.contains_key("id"),
        _ => false,
    }
}

/// `_is_response` — an `id` and no `method`.
fn is_response(message: &Value) -> bool {
    match message {
        Value::Object(m) => m.contains_key("id") && !m.contains_key("method"),
        _ => false,
    }
}

/// `_is_notification` — a `method` and no `id`.
fn is_notification(message: &Value) -> bool {
    match message {
        Value::Object(m) => m.contains_key("method") && !m.contains_key("id"),
        _ => false,
    }
}

/// `_response_key` — `json.dumps(value, sort_keys=True, separators=(",",":"))`
/// canonical key used to correlate a response to its request id. `None` →
/// `None` (a non-object/id-less message is not correlated).
fn response_key(value: Option<&Value>) -> Option<String> {
    let value = value?;
    // serde_json serializes map keys in insertion order; canonicalize to match
    // Python's sort_keys compact dump for correlation keys.
    fn canon(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut sorted: BTreeMap<String, Value> = BTreeMap::new();
                for (k, v) in m {
                    sorted.insert(k.clone(), canon(v));
                }
                // Rebuild preserving sort order via a Map keyed insert.
                let mut out = serde_json::Map::new();
                for (k, v) in sorted {
                    out.insert(k, v);
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(canon).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_string(&canon(value)).ok()
}

/// The direction a drained frame is bound, and the message to surface.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionEvent {
    /// A child→client response correlated to a client request id.
    ChildResponse(Value),
    /// A child→client request that must be proxied upstream (reverse request).
    ChildRequest(Value),
    /// A child→client notification to forward verbatim.
    ChildNotification(Value),
}

/// `LiveMcpSession` — a spawned, scrubbed MCP child whose stdio is owned by
/// the native runtime. The caller (resident op) drives `write`/`next_event`
/// while Python supplies policy verdicts out-of-band.
pub struct LiveMcpSession {
    writer: SessionWriter,
    child_pid: i32,
    inbox: mpsc::Receiver<Value>,
    cancellation: Arc<AtomicBool>,
    _drain: Option<thread::JoinHandle<()>>,
    /// Buffered child responses keyed by `response_key(id)` that arrived while
    /// servicing a different request (out-of-order / interleaved).
    buffered_child: ResponseBuffers,
    /// Buffered client→server responses keyed by `response_key(id)` that
    /// arrived while awaiting a different correlation.
    buffered_client: ResponseBuffers,
    peeked: Option<Value>,
    closed: bool,
}

/// Cross-correlated response buffer (`runtime_mcp.py`
/// `_buffered_child_responses`/`_buffered_client_responses`): a FIFO queue of
/// payloads per `response_key(id)`, capped per key.
#[derive(Default)]
struct ResponseBuffers {
    map: BTreeMap<String, Vec<Value>>,
}

impl ResponseBuffers {
    fn buffer(&mut self, payload: Value) {
        if let Some(key) = response_key(payload.get("id")) {
            let bucket = self.map.entry(key).or_default();
            if bucket.len() < MAX_BUFFERED_PER_KEY {
                bucket.push(payload);
            }
        }
    }

    fn pop(&mut self, request_id: &Value) -> Option<Value> {
        let key = response_key(Some(request_id))?;
        let pending = self.map.get_mut(&key)?;
        if pending.is_empty() {
            self.map.remove(&key);
            return None;
        }
        let payload = pending.remove(0);
        if pending.is_empty() {
            self.map.remove(&key);
        }
        Some(payload)
    }
}

impl LiveMcpSession {
    /// Spawn the child with the caller's launch environment and a live drain
    /// pump. `argv` is a resolved launch vector; `child_env` is the complete
    /// environment already selected by the native `mcp_launch_environment`
    /// authority (the same mapping the Python `Popen(env=...)` path installs
    /// verbatim), so it is applied as-is rather than re-filtered through the
    /// probe env. `cwd` is the workspace the launch identity bound; `stderr`
    /// is inherited like the Python path so a chatty server cannot block on a
    /// discarded pipe. Empty/NUL-bearing argv fails closed.
    pub fn spawn(
        argv: &[String],
        child_env: Option<&BTreeMap<String, String>>,
        home_dir: Option<&Path>,
        cwd: Option<&Path>,
        cancellation: Arc<AtomicBool>,
    ) -> Result<(Self, Child), String> {
        if argv.is_empty() || argv.iter().any(|p| p.is_empty() || p.contains('\0')) {
            return Err("invalid_launch".to_owned());
        }
        if cancellation.load(Ordering::Acquire) {
            return Err("cancelled".to_owned());
        }
        let mut env = child_env.cloned().unwrap_or_default();
        // Fallbacks the probe env guarantees even when the caller's mapping
        // omitted them: a sane PATH plus npm/package-cache dirs so a child
        // resolving itself does not lose shim resolution.
        if env.get("PATH").is_none_or(|p| p.is_empty()) {
            env.insert("PATH".to_owned(), probe_search_path());
        }
        if env.get("PYTHONUNBUFFERED").is_none_or(|v| v.is_empty()) {
            env.insert("PYTHONUNBUFFERED".to_owned(), "1".to_owned());
        }
        if let Some(dir) = npm_cache_dir(&env, home_dir) {
            env.entry("npm_config_cache".to_owned())
                .or_insert_with(|| dir.clone());
            env.entry("NPM_CONFIG_CACHE".to_owned()).or_insert(dir);
        }
        let working_dir = cwd.map(Path::to_path_buf).unwrap_or_else(|| {
            std::env::temp_dir()
                .canonicalize()
                .unwrap_or_else(|_| std::env::temp_dir())
        });
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .current_dir(working_dir)
            .env_clear()
            .envs(&env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd
            .process_group(0)
            .spawn()
            .map_err(|_| "transport_failed".to_owned())?;
        let stdin = child.stdin.take().ok_or("transport_failed")?;
        let stdout = child.stdout.take().ok_or("transport_failed")?;
        let writer = match SessionWriter::spawn(stdin) {
            Ok(writer) => writer,
            Err(code) => {
                kill_process_group(child.id() as i32);
                let _ = child.kill();
                let _ = child.wait();
                return Err(code);
            }
        };
        let child_pid = child.id() as i32;
        let (tx, rx) = mpsc::sync_channel::<Value>(SESSION_QUEUE);
        let cancel_tx = Arc::clone(&cancellation);
        let drain = thread::spawn(move || session_pump(stdout, tx, cancel_tx));
        Ok((
            LiveMcpSession {
                writer,
                child_pid,
                inbox: rx,
                cancellation,
                _drain: Some(drain),
                buffered_child: ResponseBuffers::default(),
                buffered_client: ResponseBuffers::default(),
                peeked: None,
                closed: false,
            },
            child,
        ))
    }

    /// Write a raw JSON-RPC frame (client→child), newline-framed. Bounded by
    /// the caller's serialized size checks upstream.
    pub fn write(&mut self, message: &Value) -> Result<(), String> {
        if self.closed {
            return Err("session_closed".to_owned());
        }
        let mut framed =
            serde_json::to_vec(message).map_err(|_| "child_frame_invalid".to_owned())?;
        if framed.len() > SESSION_FRAME_LIMIT {
            return Err("child_frame_too_large".to_owned());
        }
        framed.push(b'\n');
        let result = self
            .writer
            .write(framed, &self.cancellation, Duration::from_secs(5));
        if result.is_err() {
            // A timed-out write may have delivered part of a frame. Retire the
            // transport rather than retrying and corrupting JSON-RPC framing.
            self.cancel();
            kill_process_group(self.child_pid);
        }
        result
    }

    /// Drain the next inbound child frame within `timeout`, classifying it.
    /// Non-RPC noise is skipped by the drain pump; here we distinguish
    /// response / reverse-request / notification so the control plane applies
    /// the right routing. `Ok(None)` = timeout; `Err(Eof)` = pump EOF.
    pub fn next_event(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<SessionEvent>, SessionReadError> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.cancellation.load(Ordering::Acquire) {
                return Err(SessionReadError::Eof);
            }
            let msg = if let Some(msg) = self.peeked.take() {
                msg
            } else {
                let now = Instant::now();
                if now >= deadline {
                    match self.inbox.try_recv() {
                        Ok(msg) => msg,
                        Err(mpsc::TryRecvError::Empty) => return Ok(None),
                        Err(mpsc::TryRecvError::Disconnected) => {
                            return Err(SessionReadError::Eof);
                        }
                    }
                } else {
                    match self
                        .inbox
                        .recv_timeout((deadline - now).min(Duration::from_millis(25)))
                    {
                        Ok(msg) => msg,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            return Err(SessionReadError::Eof);
                        }
                    }
                }
            };
            if !is_rpc_message(&msg) {
                continue;
            }
            if is_response(&msg) {
                return Ok(Some(SessionEvent::ChildResponse(msg)));
            }
            if is_request(&msg) {
                return Ok(Some(SessionEvent::ChildRequest(msg)));
            }
            if is_notification(&msg) {
                return Ok(Some(SessionEvent::ChildNotification(msg)));
            }

            // Unclassified object: treat as a notification-shaped frame
            // and let the control plane decide.
            return Ok(Some(SessionEvent::ChildNotification(msg)));
        }
    }

    /// `_buffer_child_response` — stash a child response under its correlation
    /// key while servicing an interleaved request.
    pub fn buffer_child_response(&mut self, payload: Value) {
        self.buffered_child.buffer(payload);
    }

    /// `_pop_buffered_child_response` — remove the oldest buffered response for
    /// `request_id`'s correlation key.
    pub fn pop_buffered_child_response(&mut self, request_id: &Value) -> Option<Value> {
        self.buffered_child.pop(request_id)
    }

    /// `_buffer_client_response` — stash a client→server response while a
    /// different correlation is in flight.
    pub fn buffer_client_response(&mut self, payload: Value) {
        self.buffered_client.buffer(payload);
    }

    /// `_pop_buffered_client_response`.
    pub fn pop_buffered_client_response(&mut self, request_id: &Value) -> Option<Value> {
        self.buffered_client.pop(request_id)
    }

    /// Signal cooperative cancellation to the drain pump.
    pub fn cancel(&self) {
        self.cancellation.store(true, Ordering::Release);
    }

    /// `stop_child` — kill the process group then reap the child. Idempotent.
    pub fn close(&mut self, child: &mut Child) {
        if self.closed {
            return;
        }
        self.cancel();
        let pid = child.id() as i32;
        if pid > 0 {
            kill_process_group(pid);
        }
        let _ = child.kill();
        let _ = child.wait();
        self.closed = true;
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// True once the drain pump has exited and the inbox is empty —
    /// `try_recv` reports `Disconnected`, not merely `Empty`. Used to reap a
    /// dead session without discarding undelivered frames still in flight.
    pub fn is_drained_and_idle(&mut self) -> bool {
        if self.closed
            || self.peeked.is_some()
            || !self.buffered_child.map.is_empty()
            || !self.buffered_client.map.is_empty()
        {
            return false;
        }
        match self.inbox.try_recv() {
            Ok(msg) => {
                self.peeked = Some(msg);
                false
            }
            Err(mpsc::TryRecvError::Empty) => false,
            Err(mpsc::TryRecvError::Disconnected) => true,
        }
    }
}

#[cfg(test)]
#[path = "mcp_stdio_session_tests.rs"]
mod tests;
