//! How Guard's CIGAR clients (the dashboard routes, `hol-guard context` and
//! the MCP context tools) reach the resident: one framed, time-limited request
//! per call, with the reply bound back to it.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

#[path = "context_assistance_client_calls.rs"]
mod calls;
pub(crate) use calls::{agent, runner_authority, state_dir};

pub(crate) const CODE_PREFIX: &str = "native_context_assistance_";
pub(crate) const UNAVAILABLE: &str = "native_context_assistance_unavailable";
pub(crate) const REQUEST_SCHEMA: &str = "guard-context-assistance-request.v1";
pub(crate) const RESULT_SCHEMA: &str = "guard-context-assistance-result.v1";
const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Engine control answers from state the resident already holds.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
/// Workspace, folder and version requests may read the disk or start a job.
const SLOW_TIMEOUT: Duration = Duration::from_secs(8);
/// At most this many slow requests wait on the resident at once.
const SLOW_SLOTS: usize = 2;

static REQUEST_IDS: AtomicU64 = AtomicU64::new(1);
static SLOW_BUSY: Mutex<usize> = Mutex::new(0);
static SLOW_FREED: Condvar = Condvar::new();

/// One resident request: the `ok` payload bound to it, or the refusal code.
pub(crate) fn ask(
    guard_home: &str,
    query: &Value,
    slow: bool,
) -> Result<Map<String, Value>, String> {
    let timeout = if slow { SLOW_TIMEOUT } else { CONTROL_TIMEOUT };
    let deadline = Instant::now() + timeout;
    let _slot = if slow {
        Some(SlowSlot::acquire(deadline).ok_or_else(|| UNAVAILABLE.to_owned())?)
    } else {
        None
    };
    let mut query = query.clone();
    query["guard_home"] = Value::from(guard_home);
    let request = json!({
        "schema": REQUEST_SCHEMA,
        "request_id": next_request_id(),
        "query": query,
    });
    let digest =
        crate::package_authority_op::request_digest_with_limit(&request, MAX_REQUEST_BYTES)
            .map_err(|_| format!("{CODE_PREFIX}request_invalid"))?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(UNAVAILABLE.to_owned());
    }
    let encoded = serde_json::to_vec(&json!({
        "operation": "context_assistance",
        "deadline_budget_ms": u64::try_from(remaining.as_millis()).unwrap_or(1).max(1),
        "request": request,
    }))
    .map_err(|_| format!("{CODE_PREFIX}request_invalid"))?;
    if encoded.len() > MAX_REQUEST_BYTES {
        return Err(UNAVAILABLE.to_owned());
    }
    let state_dir = std::fs::canonicalize(Path::new(guard_home))
        .map_err(|_| format!("{CODE_PREFIX}home_unbound"))?
        .join("native-runtime");
    let output = crate::managed_resident::client_request(&state_dir, &encoded, remaining)
        .map_err(|_| UNAVAILABLE.to_owned())?;
    let envelope: Value = serde_json::from_slice(&output).map_err(|_| UNAVAILABLE.to_owned())?;
    bound(envelope, &request, &digest)
}

/// The `ok` payload of a reply bound to `request`, or the refusal code. A
/// reply for another request, or with a code outside the engine's, is the
/// engine being unavailable.
pub(crate) fn bound(
    envelope: Value,
    request: &Value,
    digest: &str,
) -> Result<Map<String, Value>, String> {
    let unavailable = || UNAVAILABLE.to_owned();
    let Value::Object(mut envelope) = envelope else {
        return Err(unavailable());
    };
    if envelope.get("schema").and_then(Value::as_str) != Some(RESULT_SCHEMA)
        || envelope.get("request_id") != request.get("request_id")
        || envelope.get("request_sha256").and_then(Value::as_str) != Some(digest)
    {
        return Err(unavailable());
    }
    let status = envelope.get("status").and_then(Value::as_str);
    let code = envelope.get("code").and_then(Value::as_str);
    if status == Some("error") {
        return Err(code
            .filter(|code| engine_code(code))
            .map_or_else(unavailable, str::to_owned));
    }
    let answered = status == Some("ok") && code == Some("ok");
    let kind = request.pointer("/query/kind");
    match envelope.remove("payload") {
        Some(Value::Object(payload)) if answered && payload.get("kind") == kind => Ok(payload),
        _ => Err(unavailable()),
    }
}

/// `^native_context_assistance_[a-z_]{1,64}$`.
fn engine_code(code: &str) -> bool {
    code.strip_prefix(CODE_PREFIX).is_some_and(|rest| {
        (1..=64).contains(&rest.len())
            && rest
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    })
}

fn next_request_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    format!(
        "context-assistance-edge-{}-{nanos:x}-{}",
        std::process::id(),
        REQUEST_IDS.fetch_add(1, Ordering::Relaxed)
    )
}

/// One of the [`SLOW_SLOTS`] places for a slow request, held until dropped.
pub(crate) struct SlowSlot;

impl SlowSlot {
    pub(crate) fn acquire(deadline: Instant) -> Option<Self> {
        let mut busy = SLOW_BUSY.lock().ok()?;
        while *busy >= SLOW_SLOTS {
            let wait = deadline.checked_duration_since(Instant::now())?;
            let (next, timeout) = SLOW_FREED.wait_timeout(busy, wait).ok()?;
            busy = next;
            if timeout.timed_out() && *busy >= SLOW_SLOTS {
                return None;
            }
        }
        *busy += 1;
        Some(Self)
    }
}

impl Drop for SlowSlot {
    fn drop(&mut self) {
        if let Ok(mut busy) = SLOW_BUSY.lock() {
            *busy = busy.saturating_sub(1);
        }
        SLOW_FREED.notify_one();
    }
}
