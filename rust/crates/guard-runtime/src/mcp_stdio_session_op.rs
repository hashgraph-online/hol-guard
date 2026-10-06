//! `McpStdioSession*` resident ops — persistent bounded MCP stdio data plane
//! (RTM-022/023). Owns the live child via
//! `guard_command::mcp_stdio_session::LiveMcpSession` (scrubbed spawn, drain
//! pump, process-group teardown) plus the cross-correlation buffers the Python
//! proxy implements in `_drain_child_messages`/`_buffer_*_response`.
//!
//! Policy authority stays in Python: a `tools/call` (or reverse request) is
//! surfaced to the control plane as `event_kind:"child_request"`; the verdict
//! is relayed back as a `send` op. These ops never decide allow/deny.
//!
//! `#[cfg(unix)]`: the session owner is unix-only.

use guard_contracts::{
    McpStdioSessionCloseRequestV1, McpStdioSessionOpenRequestV1, McpStdioSessionRecvRequestV1,
    McpStdioSessionResultV1, McpStdioSessionSendRequestV1,
};
use serde_json::Value;
#[cfg(unix)]
use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::process::Child;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use guard_command::mcp_stdio_session::{LiveMcpSession, SessionEvent};

#[cfg(unix)]
const MAX_SESSIONS: usize = 64;
#[cfg(unix)]
const MAX_SESSION_ID: usize = 128;

/// A live session: the framing owner plus the spawned child for teardown.
#[cfg(unix)]
struct SessionEntry {
    session: LiveMcpSession,
    child: Child,
}

#[cfg(unix)]
impl Drop for SessionEntry {
    fn drop(&mut self) {
        self.session.close(&mut self.child);
    }
}

/// Cancellation is reachable without taking the I/O mutex.
#[cfg(unix)]
struct SessionHandle {
    state: Mutex<SessionEntry>,
    cancellation: Arc<AtomicBool>,
    owner_pid: u32,
    owner_start: String,
}

#[cfg(unix)]
type SessionRegistryGuard<'a> = std::sync::MutexGuard<'a, HashMap<String, Arc<SessionHandle>>>;

#[cfg(unix)]
static SESSIONS: OnceLock<Mutex<HashMap<String, Arc<SessionHandle>>>> = OnceLock::new();

#[cfg(unix)]
fn sessions() -> Result<SessionRegistryGuard<'static>, String> {
    SESSIONS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| "mcp_session_registry_unavailable".to_owned())
}

/// Look up a session's `Arc` under the registry lock, then drop the guard so a
/// blocking `recv` doesn't serialize ops across other sessions.
#[cfg(unix)]
fn lookup(session_id: &str) -> Result<Arc<SessionHandle>, String> {
    validate_session_id(session_id)?;
    sessions()?
        .get(session_id)
        .cloned()
        .ok_or_else(|| "mcp_session_not_found".to_owned())
}

#[cfg(unix)]
fn validate_session_id(session_id: &str) -> Result<(), String> {
    if session_id.is_empty() || session_id.len() > MAX_SESSION_ID {
        return Err("invalid_mcp_session_id".to_owned());
    }
    Ok(())
}

fn encode(result: McpStdioSessionResultV1) -> Result<Vec<u8>, String> {
    crate::encode_response(&result)
}

fn err_result(code: &str) -> Result<Vec<u8>, String> {
    let mut r = McpStdioSessionResultV1::status("error");
    r.payload = Some(Value::String(code.to_owned()));
    encode(r)
}

#[cfg(unix)]
fn child_exit_code(child: &mut Child) -> Result<Option<i32>, String> {
    child
        .try_wait()
        .map(|status| {
            status.map(|status| {
                status
                    .code()
                    .or_else(|| status.signal().map(|signal| -signal))
                    .unwrap_or(-1)
            })
        })
        .map_err(|_| "mcp_child_status_unavailable".to_owned())
}

#[cfg(unix)]
fn exited_result(exit_code: i32) -> Result<Vec<u8>, String> {
    let mut r = McpStdioSessionResultV1::status("exited");
    r.exit_code = Some(exit_code);
    encode(r)
}

#[cfg(unix)]
fn close_handle(handle: Arc<SessionHandle>) {
    handle.cancellation.store(true, Ordering::Release);
    // A poisoned entry still owns a child and must be torn down.
    let mut guard = handle.state.lock().unwrap_or_else(|e| e.into_inner());
    let SessionEntry { session, child } = &mut *guard;
    session.close(child);
}

#[cfg(unix)]
fn owner_gone(handle: &SessionHandle) -> bool {
    use crate::resident_process_identity::{process_is_definitively_gone, process_start_marker};
    if process_is_definitively_gone(handle.owner_pid).unwrap_or(false) {
        return true;
    }
    process_start_marker(handle.owner_pid).is_ok_and(|start| start != handle.owner_start)
}

/// Only dead owners may lose queued output. A live owner's exited child retains
/// its final frames until recv/close, even if another proxy opens a session.
#[cfg(unix)]
fn reap_orphaned_sessions() {
    let snapshot: Vec<_> = match sessions() {
        Ok(registry) => registry
            .iter()
            .map(|(id, h)| (id.clone(), Arc::clone(h)))
            .collect(),
        Err(_) => return,
    };
    for (id, handle) in snapshot {
        if !owner_gone(&handle) {
            continue;
        }
        let removed = match sessions() {
            Ok(mut registry) => {
                if registry
                    .get(&id)
                    .is_some_and(|current| Arc::ptr_eq(current, &handle))
                {
                    registry.remove(&id)
                } else {
                    None
                }
            }
            Err(_) => None,
        };
        if let Some(handle) = removed {
            close_handle(handle);
        }
    }
}

#[cfg(unix)]
fn start_reaper() -> Result<(), String> {
    static STARTED: OnceLock<Result<(), String>> = OnceLock::new();
    STARTED
        .get_or_init(|| {
            std::thread::Builder::new()
                .name("guard-mcp-reaper".to_owned())
                .spawn(|| loop {
                    std::thread::sleep(Duration::from_secs(1));
                    reap_orphaned_sessions();
                })
                .map(|_| ())
                .map_err(|_| "mcp_session_reaper_unavailable".to_owned())
        })
        .clone()
}

pub(crate) fn close_all_sessions() {
    #[cfg(unix)]
    if let Ok(mut registry) = sessions() {
        let handles: Vec<_> = registry.drain().map(|(_, handle)| handle).collect();
        drop(registry);
        for handle in handles {
            close_handle(handle);
        }
    }
}

/// `mcp_stdio_session_open` — spawn + register a live session.
#[cfg(unix)]
pub(crate) fn session_open(request: &McpStdioSessionOpenRequestV1) -> Result<Vec<u8>, String> {
    if validate_session_id(&request.session_id).is_err() {
        return err_result("invalid_mcp_session_id");
    }
    if request.owner_pid == 0 || request.owner_pid > i32::MAX as u32 {
        return err_result("invalid_mcp_session_owner");
    }
    let owner_start =
        match crate::resident_process_identity::process_start_marker(request.owner_pid) {
            Ok(marker) => marker,
            Err(_) => return err_result("mcp_session_owner_unavailable"),
        };
    if let Err(code) = start_reaper() {
        return err_result(&code);
    }
    reap_orphaned_sessions();
    let cancellation = Arc::new(AtomicBool::new(false));
    let home_dir = request
        .home_dir
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let cwd = request
        .cwd
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let spawned = LiveMcpSession::spawn(
        &request.argv,
        request.extra_env.as_ref(),
        home_dir.as_deref(),
        cwd.as_deref(),
        Arc::clone(&cancellation),
    );
    let (session, child) = match spawned {
        Ok(v) => v,
        Err(code) => return err_result(&code),
    };
    let mut registry = match sessions() {
        Ok(g) => g,
        Err(code) => {
            let mut s = session;
            let mut c = child;
            s.close(&mut c);
            return err_result(&code);
        }
    };
    if registry.contains_key(&request.session_id) {
        drop(registry);
        let mut s = session;
        let mut c = child;
        s.close(&mut c);
        return err_result("mcp_session_exists");
    }
    if registry.len() >= MAX_SESSIONS {
        drop(registry);
        let mut s = session;
        let mut c = child;
        s.close(&mut c);
        return err_result("mcp_session_registry_full");
    }
    registry.insert(
        request.session_id.clone(),
        Arc::new(SessionHandle {
            state: Mutex::new(SessionEntry { session, child }),
            cancellation,
            owner_pid: request.owner_pid,
            owner_start,
        }),
    );
    drop(registry);
    let mut r = McpStdioSessionResultV1::status("opened");
    r.payload = Some(Value::String(request.session_id.clone()));
    encode(r)
}

/// `mcp_stdio_session_send` — frame a client→child message onto stdin.
#[cfg(unix)]
pub(crate) fn session_send(request: &McpStdioSessionSendRequestV1) -> Result<Vec<u8>, String> {
    let entry = match lookup(&request.session_id) {
        Ok(e) => e,
        Err(code) => return err_result(&code),
    };
    let mut guard = match entry.state.lock() {
        Ok(g) => g,
        Err(_) => return err_result("mcp_session_unavailable"),
    };
    match guard.session.write(&request.message) {
        Ok(()) => encode(McpStdioSessionResultV1::status("sent")),
        Err(code) => err_result(&code),
    }
}

/// `mcp_stdio_session_recv` — drain the next inbound child frame, optionally
/// correlated to `await_request_id` (out-of-order frames are buffered).
#[cfg(unix)]
pub(crate) fn session_recv(request: &McpStdioSessionRecvRequestV1) -> Result<Vec<u8>, String> {
    let entry = match lookup(&request.session_id) {
        Ok(e) => e,
        Err(code) => return err_result(&code),
    };
    let mut guard = match entry.state.lock() {
        Ok(g) => g,
        Err(_) => return err_result("mcp_session_unavailable"),
    };
    let entry = &mut *guard;
    if request.poll_only {
        return match child_exit_code(&mut entry.child) {
            Ok(Some(exit_code)) => exited_result(exit_code),
            Ok(None) => encode(McpStdioSessionResultV1::status("running")),
            Err(code) => err_result(&code),
        };
    }
    let timeout = Duration::from_millis(request.timeout_ms.unwrap_or(30_000).min(120_000));

    // Awaited correlation: return a buffered match first.
    if let Some(await_id) = request.await_request_id.as_ref() {
        if let Some(payload) = entry.session.pop_buffered_child_response(await_id) {
            let mut r = McpStdioSessionResultV1::status("event");
            r.event_kind = Some("child_response".to_owned());
            r.payload = Some(payload);
            return encode(r);
        }
    }

    let deadline = std::time::Instant::now() + timeout;
    loop {
        let now = std::time::Instant::now();
        let remaining = deadline.saturating_duration_since(now);
        match entry.session.next_event(remaining) {
            Ok(None) => {
                let mut r = McpStdioSessionResultV1::status("timeout");
                r.timed_out = Some(true);
                return encode(r);
            }
            Err(guard_command::mcp_stdio_session::SessionReadError::Eof) => {
                match child_exit_code(&mut entry.child) {
                    Ok(Some(exit_code)) => return exited_result(exit_code),
                    Ok(None) => return encode(McpStdioSessionResultV1::status("eof")),
                    Err(code) => return err_result(&code),
                }
            }
            Ok(Some(SessionEvent::ChildResponse(payload))) => {
                // If awaiting a specific id and this is not it, buffer + keep
                // draining (out-of-order responses are valid).
                if let Some(await_id) = request.await_request_id.as_ref() {
                    let matches = payload.get("id") == Some(await_id);
                    if !matches {
                        entry.session.buffer_child_response(payload);
                        continue;
                    }
                }
                let mut r = McpStdioSessionResultV1::status("event");
                r.event_kind = Some("child_response".to_owned());
                r.payload = Some(payload);
                return encode(r);
            }
            Ok(Some(SessionEvent::ChildRequest(payload))) => {
                let mut r = McpStdioSessionResultV1::status("event");
                r.event_kind = Some("child_request".to_owned());
                r.payload = Some(payload);
                return encode(r);
            }
            Ok(Some(SessionEvent::ChildNotification(payload))) => {
                let mut r = McpStdioSessionResultV1::status("event");
                r.event_kind = Some("child_notification".to_owned());
                r.payload = Some(payload);
                return encode(r);
            }
        }
    }
}

/// `mcp_stdio_session_close` — cancel + teardown + deregister.
#[cfg(unix)]
pub(crate) fn session_close(request: &McpStdioSessionCloseRequestV1) -> Result<Vec<u8>, String> {
    if validate_session_id(&request.session_id).is_err() {
        return err_result("invalid_mcp_session_id");
    }
    let arc = {
        let mut registry = match sessions() {
            Ok(g) => g,
            Err(code) => return err_result(&code),
        };
        // Remove under the registry lock, then drop it before locking the
        // session — the per-session mutex may block on a live recv and must
        // not serialize other sessions' ops on the global registry.
        registry.remove(&request.session_id)
    };
    match arc {
        Some(arc) => {
            close_handle(arc);
            encode(McpStdioSessionResultV1::status("closed"))
        }
        None => encode(McpStdioSessionResultV1::status("closed")),
    }
}

// Non-unix: the data plane is unsupported — fail closed with an explicit error
// rather than silently degrading (ADR 0006).
#[cfg(not(unix))]
pub(crate) fn session_open(_r: &McpStdioSessionOpenRequestV1) -> Result<Vec<u8>, String> {
    err_result("native_mcp_stdio_session_unsupported")
}
#[cfg(not(unix))]
pub(crate) fn session_send(_r: &McpStdioSessionSendRequestV1) -> Result<Vec<u8>, String> {
    err_result("native_mcp_stdio_session_unsupported")
}
#[cfg(not(unix))]
pub(crate) fn session_recv(_r: &McpStdioSessionRecvRequestV1) -> Result<Vec<u8>, String> {
    err_result("native_mcp_stdio_session_unsupported")
}
#[cfg(not(unix))]
pub(crate) fn session_close(_r: &McpStdioSessionCloseRequestV1) -> Result<Vec<u8>, String> {
    err_result("native_mcp_stdio_session_unsupported")
}

#[cfg(all(test, unix))]
#[path = "mcp_stdio_session_op_tests.rs"]
mod tests;
