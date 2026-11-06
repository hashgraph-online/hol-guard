//! Rust port of `codex_resume.py` — Codex browser approval resume
//! orchestration and diagnostics.
//!
//! TODO(deps): Python lazily resolves `.codex_app_server`
//! (`default_codex_app_server_socket_available`, `resume_codex_thread_for_request`),
//! `.live_process_identity` (`process_identity_matches`), and
//! `.codex_live_hook_target` (`codex_live_hook_wait_deadline`) inside function
//! bodies, and `.store.GuardStore` is the module-level store. Until those ports
//! land, the surfaces stay behind seams (`CodexAppServerApi`,
//! `ProcessIdentityApi`, `LiveHookTargetApi`, `ResumeStore`) injected through
//! `CodexResumeDeps`. `_parse_timestamp` maps onto
//! `local_supply_chain::parse_timestamp` (naive inputs treated as UTC, `Z`
//! handled — same contract).
//!
//! Python `str()`/`bool()` truthiness is approximated by `py_str`/`truthy`;
//! `dict`/`list` `str()` reprs are not reproduced (store payloads for these
//! fields are strings/integers/null in practice).

use serde_json::{json, Map, Value};

use crate::local_supply_chain::{parse_timestamp, Timestamp};

/// `ResumeNotSupportedError` / `ValueError` surface (:16-22).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeError {
    /// `ValueError` — carries the machine-readable code verbatim
    /// ("not_found", "not_resolved").
    Validation(String),
    /// `ResumeNotSupportedError` — `ValueError("resume_not_supported")`.
    NotSupported,
}

impl std::fmt::Display for ResumeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(m) => f.write_str(m),
            Self::NotSupported => f.write_str("resume_not_supported"),
        }
    }
}

impl std::error::Error for ResumeError {}

pub type ResumeResult<T> = Result<T, ResumeError>;

/// `_THREAD_ID_KEYS` (:25-33) — ordered as in source.
const THREAD_ID_KEYS: &[&str] = &[
    "codex_thread_id",
    "thread_id",
    "threadId",
    "conversation_id",
    "conversationId",
    "session_id",
    "sessionId",
];

/// `.store.GuardStore` seam — the request-resume table methods plus the
/// approval-request / operation lookups this module performs.
pub trait ResumeStore {
    /// `store.get_approval_request(request_id) -> dict | None`
    fn get_approval_request(&self, request_id: &str) -> Option<Map<String, Value>>;
    /// `store.get_guard_operation_for_approval_request(request_id) -> dict | None`
    fn get_guard_operation_for_approval_request(
        &self,
        request_id: &str,
    ) -> Option<Map<String, Value>>;
    /// `store.seed_request_resume(...)` (store_resume.py :93).
    #[allow(clippy::too_many_arguments)]
    fn seed_request_resume(
        &self,
        request_id: &str,
        operation_id: Option<&str>,
        harness: &str,
        strategy: &str,
        supported: bool,
        thread_id: Option<&str>,
        now: &str,
    );
    /// `store.get_request_resume(request_id) -> dict | None` (store_resume.py :132).
    fn get_request_resume(&self, request_id: &str) -> Option<Map<String, Value>>;
    /// `store.get_latest_request_resume(harness=) -> dict | None` (store_resume.py :150).
    fn get_latest_request_resume(&self, harness: Option<&str>) -> Option<Map<String, Value>>;
    /// `store.update_request_resume(...)` (store_resume.py :174). The Python
    /// `continuation_*` kwargs are not modeled — this module never sets them.
    fn update_request_resume(&self, update: &RequestResumeUpdate<'_>);
}

/// Keyword bundle for `ResumeStore::update_request_resume` — mirrors the
/// non-continuation kwargs of `store_resume.update_request_resume` (:174).
#[derive(Debug, Clone)]
pub struct RequestResumeUpdate<'a> {
    pub request_id: &'a str,
    pub resolution_action: &'a str,
    pub strategy: Option<&'a str>,
    pub supported: Option<bool>,
    pub status: &'a str,
    pub reason: Option<&'a str>,
    pub message: Option<&'a str>,
    pub last_error: Option<&'a str>,
    pub attempt_count: i64,
    pub last_attempt_at: Option<&'a str>,
    pub sent_at: Option<&'a str>,
    pub now: &'a str,
}

/// `.codex_app_server` seam.
pub trait CodexAppServerApi {
    /// `default_codex_app_server_socket_available()` (codex_app_server.py :64).
    fn default_codex_app_server_socket_available(&self) -> bool;
    /// `resume_codex_thread_for_request(store=, request_id=, action=, timeout_seconds=)`
    /// (codex_app_server.py :114) -> dict | None.
    fn resume_codex_thread_for_request(
        &self,
        store: &dyn ResumeStore,
        request_id: &str,
        action: &str,
        timeout_seconds: Option<f64>,
    ) -> Option<Map<String, Value>>;
}

/// `.live_process_identity` seam.
pub trait ProcessIdentityApi {
    /// `process_identity_matches(value)` (live_process_identity.py :44).
    fn process_identity_matches(&self, value: Option<&Value>) -> bool;
}

/// `.codex_live_hook_target` seam.
pub trait LiveHookTargetApi {
    /// `codex_live_hook_wait_deadline(store, operation=, metadata=)`
    /// (codex_live_hook_target.py :22) -> datetime | None.
    fn codex_live_hook_wait_deadline(
        &self,
        store: &dyn ResumeStore,
        operation: &Map<String, Value>,
        metadata: &Map<String, Value>,
    ) -> Option<Timestamp>;
}

/// Lazily-resolved Python dependencies bundled for the public entry points.
pub struct CodexResumeDeps<'a> {
    pub app_server: &'a dyn CodexAppServerApi,
    pub process_identity: &'a dyn ProcessIdentityApi,
    pub live_hook_target: &'a dyn LiveHookTargetApi,
}

// --- Python scalar helpers ---------------------------------------------------

/// Python truthiness (`bool(x)`).
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Python `str(x)` for JSON scalars; containers fall back to compact JSON
/// (never reached for the string/int fields these call sites read).
fn py_str(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// `str(mapping.get(key) or fallback)` — truthiness-gated fallback.
fn py_str_or(value: Option<&Value>, fallback: &str) -> String {
    value
        .filter(|v| truthy(v))
        .map(py_str)
        .unwrap_or_else(|| fallback.to_string())
}

/// `int(str)` accepting Python's whitespace/sign/underscore digit grammar.
fn py_int_str(text: &str) -> Option<i64> {
    let trimmed = text.trim();
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    if digits.is_empty() {
        return None;
    }
    let bytes = digits.as_bytes();
    let mut acc: i64 = 0;
    let mut prev_digit = false;
    for (index, &byte) in bytes.iter().enumerate() {
        if byte == b'_' {
            // Underscores only between digits.
            if !prev_digit || index + 1 == bytes.len() {
                return None;
            }
            prev_digit = false;
            continue;
        }
        if !byte.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((byte - b'0') as i64)?;
        prev_digit = true;
    }
    if !prev_digit {
        return None;
    }
    Some(if negative { -acc } else { acc })
}

/// `_int_value` (:30-42).
fn int_value(value: Option<&Value>, default: i64) -> i64 {
    match value {
        // `isinstance(value, bool)` first — bool is an int subclass in Python.
        Some(Value::Bool(b)) => i64::from(*b),
        // `isinstance(value, int)` — JSON floats are not ints.
        Some(Value::Number(n)) => n.as_i64().unwrap_or(default),
        Some(Value::String(s)) => py_int_str(s).unwrap_or(default),
        _ => default,
    }
}

/// `_first_string` (:464-469).
fn first_string(mapping: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(Value::String(s)) = mapping.get(*key) {
            if !s.trim().is_empty() {
                return Some(s.clone());
            }
        }
    }
    None
}

/// `_parse_timestamp` (:249-258) — `datetime.fromisoformat` subset; naive
/// inputs treated as UTC, `Z` handled by the shared parser.
fn _parse_timestamp(value: &str) -> Option<Timestamp> {
    parse_timestamp(value)
}

// --- message templates --------------------------------------------------------

/// `_manual_resume_message` (:443-449).
fn manual_resume_message(_action: &str) -> String {
    "Decision recorded for the original request. HOL Guard could not find the original Codex chat to resume. \
     Return to that chat and retry; a new tool call may require fresh approval."
        .to_string()
}

/// `_failed_resume_message` (:450-456).
fn failed_resume_message(_action: &str) -> String {
    "Decision recorded for the original request. HOL Guard could not send a continuation to the original \
     Codex chat. Return to that chat and retry; a new tool call may require fresh approval."
        .to_string()
}

/// `_blocked_resume_message` (:457-463).
fn blocked_resume_message() -> String {
    "Decision saved. HOL Guard blocked this Codex request and will not resume or retry it. \
     Do not retry that action in Codex. Ask for a safe alternative instead."
        .to_string()
}

// --- ported functions ---------------------------------------------------------

/// `seed_request_resume_record` (:43-64).
pub fn seed_request_resume_record(
    store: &dyn ResumeStore,
    request_id: &str,
    now: &str,
) -> Option<Map<String, Value>> {
    let request = store.get_approval_request(request_id)?;
    if request.get("harness").and_then(Value::as_str) != Some("codex") {
        return None;
    }
    let operation = store.get_guard_operation_for_approval_request(request_id);
    let metadata = operation
        .as_ref()
        .and_then(|op| op.get("metadata"))
        .and_then(Value::as_object);
    let thread_id = metadata.and_then(|m| first_string(m, THREAD_ID_KEYS));
    let strategy = if thread_id.is_some() {
        "codex-app-server-thread"
    } else {
        "manual-only"
    };
    store.seed_request_resume(
        request_id,
        operation
            .as_ref()
            .and_then(|op| op.get("operation_id"))
            .map(py_str)
            .as_deref(),
        "codex",
        strategy,
        thread_id.is_some(),
        thread_id.as_deref(),
        now,
    );
    store.get_request_resume(request_id)
}

/// `get_request_resume_status` (:65-71).
pub fn get_request_resume_status(
    store: &dyn ResumeStore,
    request_id: &str,
    now: &str,
) -> Option<Map<String, Value>> {
    if let Some(resume) = store.get_request_resume(request_id) {
        return Some(resume);
    }
    seed_request_resume_record(store, request_id, now)
}

/// `retry_request_resume` (:72-136).
pub fn retry_request_resume(
    store: &dyn ResumeStore,
    deps: &CodexResumeDeps<'_>,
    request_id: &str,
    now: &str,
    force: bool,
    timeout_seconds: Option<f64>,
) -> ResumeResult<Map<String, Value>> {
    let request = store
        .get_approval_request(request_id)
        .ok_or_else(|| ResumeError::Validation("not_found".to_string()))?;
    if request.get("harness").and_then(Value::as_str) != Some("codex") {
        return Err(ResumeError::NotSupported);
    }
    let action = match request.get("resolution_action") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return Err(ResumeError::Validation("not_resolved".to_string())),
    };
    let resume =
        get_request_resume_status(store, request_id, now).ok_or(ResumeError::NotSupported)?;
    if action == "block" {
        let attempt_count = int_value(resume.get("attempt_count"), 0) + 1;
        return skip_blocked_resume(store, request_id, &resume, attempt_count, now);
    }
    if resume.get("status").and_then(Value::as_str) == Some("sent") && !force {
        let mut out = resume.clone();
        out.insert("status".to_string(), json!("already_sent"));
        out.insert(
            "message".to_string(),
            json!("HOL Guard already sent Codex a continuation message for this request."),
        );
        return Ok(out);
    }
    if resume.get("status").and_then(Value::as_str) == Some("in_progress") {
        return Ok(resume);
    }
    let attempt_count = int_value(resume.get("attempt_count"), 0) + 1;
    store.update_request_resume(&RequestResumeUpdate {
        request_id,
        resolution_action: &action,
        strategy: resume.get("strategy").and_then(Value::as_str),
        supported: resume.get("supported").filter(|v| !v.is_null()).map(truthy),
        status: "in_progress",
        reason: Some("attempting_resume"),
        message: Some("Sending Codex a continuation message..."),
        last_error: None,
        attempt_count,
        last_attempt_at: Some(now),
        sent_at: resume.get("sent_at").and_then(Value::as_str),
        now,
    });
    let refreshed = store
        .get_request_resume(request_id)
        .ok_or(ResumeError::NotSupported)?;
    finalize_resume_attempt(
        store,
        deps,
        request_id,
        &action,
        &refreshed,
        now,
        timeout_seconds,
    )
}

/// `defer_request_resume_to_live_hook` (:137-191).
pub fn defer_request_resume_to_live_hook(
    store: &dyn ResumeStore,
    deps: &CodexResumeDeps<'_>,
    request_id: &str,
    action: &str,
    now: &str,
) -> ResumeResult<Option<Map<String, Value>>> {
    let Some(operation) = store.get_guard_operation_for_approval_request(request_id) else {
        return Ok(None);
    };
    if operation.get("harness").and_then(Value::as_str) != Some("codex") {
        return Ok(None);
    }
    if operation.get("status").and_then(Value::as_str) != Some("waiting_on_approval") {
        return Ok(None);
    }
    let Some(metadata) = operation.get("metadata").and_then(Value::as_object) else {
        return Ok(None);
    };
    let event_name = metadata
        .get("hook_event_name")
        .filter(|v| truthy(v))
        .or_else(|| metadata.get("event").filter(|v| truthy(v)))
        .map(py_str)
        .unwrap_or_default();
    if !(live_hook_wait_is_active(metadata, now, deps)
        || event_name == "PreToolUse"
            && pretool_bridge_wait_is_active(store, &operation, now, deps))
    {
        return Ok(None);
    }
    let Some(resume) = get_request_resume_status(store, request_id, now) else {
        return Ok(None);
    };
    let attempt_count = int_value(resume.get("attempt_count"), 0);
    if action == "block" {
        return skip_blocked_resume(store, request_id, &resume, attempt_count, now).map(Some);
    }
    let message = "Decision saved. Codex is still waiting for this browser decision, \
        so HOL Guard will let the original Codex action continue without starting a second headless run.";
    store.update_request_resume(&RequestResumeUpdate {
        request_id,
        resolution_action: action,
        strategy: resume.get("strategy").and_then(Value::as_str),
        supported: resume.get("supported").filter(|v| !v.is_null()).map(truthy),
        status: "pending",
        reason: Some("live_hook_waiting"),
        message: Some(message),
        last_error: None,
        attempt_count,
        last_attempt_at: Some(now),
        sent_at: resume.get("sent_at").and_then(Value::as_str),
        now,
    });
    Ok(store.get_request_resume(request_id))
}

/// `inspect_codex_resume_capabilities` (:192-211).
pub fn inspect_codex_resume_capabilities(
    store: &dyn ResumeStore,
    deps: &CodexResumeDeps<'_>,
) -> Map<String, Value> {
    let socket_available = deps.app_server.default_codex_app_server_socket_available();
    let latest_attempt = store.get_latest_request_resume(Some("codex"));
    let mut out = Map::new();
    out.insert("codex_binary_found".to_string(), json!(false));
    out.insert("app_server_support".to_string(), json!(socket_available));
    out.insert(
        "app_server_support_reason".to_string(),
        json!("Same-chat continuation requires the Codex app-server remote-control socket. \
             When the socket is missing, HOL Guard cannot visibly continue the open Codex App chat."),
    );
    out.insert(
        "app_server_socket_available".to_string(),
        json!(socket_available),
    );
    out.insert("headless_resume_support".to_string(), json!(false));
    out.insert(
        "headless_resume_support_reason".to_string(),
        json!("Disabled by design. `codex exec resume` starts a separate background run and does not continue \
             the visible Codex App chat. HOL Guard only auto-continues Codex through the app-server socket."),
    );
    out.insert(
        "latest_attempt".to_string(),
        latest_attempt.map(Value::Object).unwrap_or(Value::Null),
    );
    out
}

/// `_live_hook_wait_is_active` (:212-228).
fn live_hook_wait_is_active(
    metadata: &Map<String, Value>,
    now: &str,
    deps: &CodexResumeDeps<'_>,
) -> bool {
    if metadata.get("codex_hook_waits_for_browser_approval") != Some(&Value::Bool(true)) {
        return false;
    }
    if !deps
        .process_identity
        .process_identity_matches(metadata.get("codex_browser_wait_process"))
    {
        return false;
    }
    let Some(deadline) = first_string(
        metadata,
        &["codex_browser_wait_deadline_at", "browser_wait_deadline_at"],
    ) else {
        return false;
    };
    let deadline_at = _parse_timestamp(&deadline);
    let now_at = _parse_timestamp(now);
    matches!((deadline_at, now_at), (Some(d), Some(n)) if n <= d)
}

/// `_pretool_bridge_wait_is_active` (:229-248).
fn pretool_bridge_wait_is_active(
    store: &dyn ResumeStore,
    operation: &Map<String, Value>,
    now: &str,
    deps: &CodexResumeDeps<'_>,
) -> bool {
    let Some(metadata) = operation.get("metadata").and_then(Value::as_object) else {
        return false;
    };
    let mut bridged_operation = operation.clone();
    bridged_operation.insert(
        "status".to_string(),
        operation
            .get("status")
            .filter(|v| truthy(v))
            .cloned()
            .unwrap_or_else(|| json!("waiting_on_approval")),
    );
    let mut bridged_metadata = metadata.clone();
    bridged_metadata.insert(
        "hook_event_name".to_string(),
        metadata
            .get("hook_event_name")
            .filter(|v| truthy(v))
            .cloned()
            .unwrap_or_else(|| json!("PreToolUse")),
    );
    let deadline = deps.live_hook_target.codex_live_hook_wait_deadline(
        store,
        &bridged_operation,
        &bridged_metadata,
    );
    let now_at = _parse_timestamp(now);
    matches!((deadline, now_at), (Some(d), Some(n)) if n <= d)
}

/// `_finalize_resume_attempt` (:259-327).
fn finalize_resume_attempt(
    store: &dyn ResumeStore,
    deps: &CodexResumeDeps<'_>,
    request_id: &str,
    action: &str,
    resume: &Map<String, Value>,
    now: &str,
    timeout_seconds: Option<f64>,
) -> ResumeResult<Map<String, Value>> {
    // Python `str(resume["strategy"])`/`bool(resume["supported"])` — missing
    // keys would KeyError; missing here falls back to ""/false.
    let strategy = resume.get("strategy").map(py_str).unwrap_or_default();
    let supported = resume.get("supported").map(truthy).unwrap_or(false);
    let thread_id = resume.get("thread_id").filter(|v| !v.is_null()).map(py_str);
    let attempt_count = int_value(resume.get("attempt_count"), 0);
    if strategy == "manual-only" || !supported {
        let message = manual_resume_message(action);
        store.update_request_resume(&RequestResumeUpdate {
            request_id,
            resolution_action: action,
            strategy: resume.get("strategy").and_then(Value::as_str),
            supported: resume.get("supported").filter(|v| !v.is_null()).map(truthy),
            status: "skipped",
            reason: Some("session_not_found"),
            message: Some(&message),
            last_error: None,
            attempt_count,
            last_attempt_at: Some(now),
            sent_at: None,
            now,
        });
        return store
            .get_request_resume(request_id)
            .ok_or(ResumeError::NotSupported);
    }

    let raw_result = dispatch_resume_attempt(
        store,
        deps,
        request_id,
        action,
        &strategy,
        thread_id.as_deref(),
        timeout_seconds,
    );
    let normalized =
        normalize_dispatch_result(action, &strategy, thread_id.as_deref(), raw_result.as_ref());
    // `now if normalized["status"] == "sent" else str(sent_at) if sent_at else None`
    // — the else branch is truthiness-gated, not `is not None`.
    let sent_at: Option<String> =
        if normalized.get("status").and_then(Value::as_str) == Some("sent") {
            Some(now.to_string())
        } else {
            resume.get("sent_at").filter(|v| truthy(v)).map(py_str)
        };
    store.update_request_resume(&RequestResumeUpdate {
        request_id,
        resolution_action: action,
        strategy: normalized.get("strategy").and_then(Value::as_str),
        supported: normalized.get("supported").map(truthy),
        status: normalized
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or(""),
        reason: normalized
            .get("reason")
            .filter(|v| !v.is_null())
            .map(py_str)
            .as_deref(),
        message: normalized
            .get("message")
            .filter(|v| !v.is_null())
            .map(py_str)
            .as_deref(),
        last_error: normalized
            .get("last_error")
            .filter(|v| !v.is_null())
            .map(py_str)
            .as_deref(),
        attempt_count,
        last_attempt_at: Some(now),
        sent_at: sent_at.as_deref(),
        now,
    });
    store
        .get_request_resume(request_id)
        .ok_or(ResumeError::NotSupported)
}

/// `_skip_blocked_resume` (:328-355).
fn skip_blocked_resume(
    store: &dyn ResumeStore,
    request_id: &str,
    resume: &Map<String, Value>,
    attempt_count: i64,
    now: &str,
) -> ResumeResult<Map<String, Value>> {
    let message = blocked_resume_message();
    store.update_request_resume(&RequestResumeUpdate {
        request_id,
        resolution_action: "block",
        strategy: resume.get("strategy").and_then(Value::as_str),
        supported: Some(false),
        status: "skipped",
        reason: Some("blocked_not_resumed"),
        message: Some(&message),
        last_error: None,
        attempt_count,
        last_attempt_at: Some(now),
        sent_at: None,
        now,
    });
    store
        .get_request_resume(request_id)
        .ok_or(ResumeError::NotSupported)
}

/// `_dispatch_resume_attempt` (:356-384).
fn dispatch_resume_attempt(
    store: &dyn ResumeStore,
    deps: &CodexResumeDeps<'_>,
    request_id: &str,
    action: &str,
    strategy: &str,
    thread_id: Option<&str>,
    timeout_seconds: Option<f64>,
) -> Option<Map<String, Value>> {
    let thread_id = thread_id?;
    let app_server_result =
        deps.app_server
            .resume_codex_thread_for_request(store, request_id, action, timeout_seconds);
    app_server_result.or_else(|| {
        let mut out = Map::new();
        out.insert("status".to_string(), json!("skipped"));
        out.insert("reason".to_string(), json!("session_not_found"));
        out.insert("thread_id".to_string(), json!(thread_id));
        out.insert("strategy".to_string(), json!(strategy));
        out.insert("supported".to_string(), json!(false));
        Some(out)
    })
}

/// `_normalize_dispatch_result` (:385-442).
fn normalize_dispatch_result(
    action: &str,
    strategy: &str,
    thread_id: Option<&str>,
    raw_result: Option<&Map<String, Value>>,
) -> Map<String, Value> {
    let Some(raw) = raw_result else {
        let mut out = Map::new();
        out.insert("status".to_string(), json!("skipped"));
        out.insert("reason".to_string(), json!("session_not_found"));
        out.insert("message".to_string(), json!(manual_resume_message(action)));
        out.insert("last_error".to_string(), Value::Null);
        out.insert(
            "thread_id".to_string(),
            thread_id.map(|t| json!(t)).unwrap_or(Value::Null),
        );
        out.insert("strategy".to_string(), json!(strategy));
        out.insert("supported".to_string(), json!(false));
        return out;
    };
    let effective_strategy = py_str_or(raw.get("strategy"), strategy);
    let raw_status = py_str_or(raw.get("status"), "");
    let raw_reason = py_str_or(raw.get("reason"), "unknown");
    let raw_thread_id = match raw.get("thread_id") {
        Some(v) if !v.is_null() => Some(py_str(v)),
        _ => thread_id.map(str::to_string),
    };
    let raw_last_error = raw.get("last_error").filter(|v| !v.is_null()).map(py_str);
    let supported = match raw.get("supported") {
        Some(Value::Bool(b)) => *b,
        _ => raw_status != "skipped",
    };
    if raw_status == "sent" {
        let mut out = Map::new();
        out.insert("status".to_string(), json!("sent"));
        out.insert("reason".to_string(), json!(raw_reason));
        out.insert(
            "message".to_string(),
            json!("HOL Guard sent Codex a continuation message in the original chat."),
        );
        out.insert("last_error".to_string(), Value::Null);
        out.insert(
            "thread_id".to_string(),
            raw_thread_id.map(Value::String).unwrap_or(Value::Null),
        );
        out.insert("strategy".to_string(), json!(effective_strategy));
        out.insert("supported".to_string(), json!(true));
        return out;
    }
    // `raw_last_error or str(message or raw_reason)` — `or` treats "" as falsy.
    let last_error_or_message = |raw: &Map<String, Value>| -> String {
        match raw_last_error.as_ref() {
            Some(s) if !s.is_empty() => s.clone(),
            _ => py_str_or(raw.get("message"), &raw_reason),
        }
    };
    if matches!(
        raw_reason.as_str(),
        "socket_not_available" | "unsafe_socket_path" | "turn_start_timeout" | "turn_start_error"
    ) {
        let mut out = Map::new();
        out.insert("status".to_string(), json!("failed"));
        out.insert("reason".to_string(), json!(raw_reason));
        out.insert("message".to_string(), json!(failed_resume_message(action)));
        out.insert("last_error".to_string(), json!(last_error_or_message(raw)));
        out.insert(
            "thread_id".to_string(),
            raw_thread_id.map(Value::String).unwrap_or(Value::Null),
        );
        out.insert("strategy".to_string(), json!(effective_strategy));
        out.insert("supported".to_string(), json!(true));
        return out;
    }
    let failed = raw_status == "failed";
    let mut out = Map::new();
    out.insert(
        "status".to_string(),
        json!(if failed { "failed" } else { "skipped" }),
    );
    out.insert("reason".to_string(), json!(raw_reason));
    out.insert(
        "message".to_string(),
        json!(if failed {
            failed_resume_message(action)
        } else {
            manual_resume_message(action)
        }),
    );
    out.insert(
        "last_error".to_string(),
        if failed {
            json!(last_error_or_message(raw))
        } else {
            Value::Null
        },
    );
    out.insert(
        "thread_id".to_string(),
        raw_thread_id.map(Value::String).unwrap_or(Value::Null),
    );
    out.insert("strategy".to_string(), json!(effective_strategy));
    out.insert("supported".to_string(), json!(supported));
    out
}
