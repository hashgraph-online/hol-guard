//! `CodexRequestResume` - resident op that owns the Codex browser-approval
//! resume record.
//!
//! `seed` writes the record from the queued Codex operation and `status`
//! seeds it only when it is missing. `retry` checks the approval is a resolved Codex one, marks the
//! record in progress, sends the continuation to the original thread and
//! records how it went. `defer` records that a Codex hook still waiting on the
//! browser decision will continue the action itself; the caller has already
//! confirmed that hook is live. Every timestamp comes from the caller.

use guard_contracts::{
    CodexRequestResumeRequestV1, CodexRequestResumeResultV1,
    CODEX_REQUEST_RESUME_MAX_BUSY_TIMEOUT_MS, CODEX_REQUEST_RESUME_MAX_BYTES,
    CODEX_REQUEST_RESUME_MAX_TIMEOUT_MS, CODEX_REQUEST_RESUME_REQUEST_SCHEMA,
    CODEX_REQUEST_RESUME_RESULT_SCHEMA,
};
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Map, Value};

use crate::codex_request_resume_store::{self as store, ResumeSeed, ResumeUpdate};
use crate::codex_thread_continue_op::{continue_thread, ContinueRequest};
use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_json::py_str;
use crate::package_authority_op::request_digest_with_limit;

const THREAD_ID_KEYS: [&str; 7] = [
    "codex_thread_id",
    "thread_id",
    "threadId",
    "conversation_id",
    "conversationId",
    "session_id",
    "sessionId",
];
const STRATEGY_THREAD: &str = "codex-app-server-thread";
const STRATEGY_MANUAL: &str = "manual-only";
const CONTINUE_FAILURE_REASONS: [&str; 4] = [
    "socket_not_available",
    "unsafe_socket_path",
    "turn_start_timeout",
    "turn_start_error",
];
const ALREADY_SENT_MESSAGE: &str =
    "HOL Guard already sent Codex a continuation message for this request.";
const ATTEMPTING_MESSAGE: &str = "Sending Codex a continuation message...";
const SENT_MESSAGE: &str = "HOL Guard sent Codex a continuation message in the original chat.";
const LIVE_HOOK_MESSAGE: &str = "Decision saved. Codex is still waiting for this browser decision, so HOL Guard will let the original Codex action continue without starting a second headless run.";
const MANUAL_MESSAGE: &str = "Decision recorded for the original request. HOL Guard could not find the original Codex chat to resume. Return to that chat and retry; a new tool call may require fresh approval.";
const FAILED_MESSAGE: &str = "Decision recorded for the original request. HOL Guard could not send a continuation to the original Codex chat. Return to that chat and retry; a new tool call may require fresh approval.";
const BLOCKED_MESSAGE: &str = "Decision saved. HOL Guard blocked this Codex request and will not resume or retry it. Do not retry that action in Codex. Ask for a safe alternative instead.";
const INVALID: &str = "native_codex_request_resume_invalid";

/// What a call reports: the resume record, or why a retry cannot run.
#[derive(Debug, PartialEq)]
pub(crate) enum Outcome {
    Resume(Option<Value>),
    Refused(&'static str),
}

pub(crate) fn evaluate_codex_request_resume_request(
    request: &CodexRequestResumeRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, CODEX_REQUEST_RESUME_MAX_BYTES)
        .map_err(|_| "native_codex_request_resume_too_large".to_owned())?;
    let (status, code, payload) = match evaluate(request) {
        Ok(Outcome::Resume(resume)) => ("ok", "ok", Some(json!({ "resume": resume }))),
        Ok(Outcome::Refused(error)) => ("ok", "ok", Some(json!({ "error": error }))),
        Err(code) => ("error", code, None),
    };
    crate::encode_response(&CodexRequestResumeResultV1 {
        schema: CODEX_REQUEST_RESUME_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

fn evaluate(request: &CodexRequestResumeRequestV1) -> Result<Outcome, &'static str> {
    if request.schema != CODEX_REQUEST_RESUME_REQUEST_SCHEMA
        || request.approval_request_id.is_empty()
        || request.now.is_empty()
        || !(1..=CODEX_REQUEST_RESUME_MAX_TIMEOUT_MS).contains(&request.timeout_ms)
        || !(1..=CODEX_REQUEST_RESUME_MAX_BUSY_TIMEOUT_MS).contains(&request.busy_timeout_ms)
    {
        return Err(INVALID);
    }
    let path =
        crate::local_store_read::require_store_path(&request.store_path, &request.guard_home)
            .map_err(|_| "native_codex_request_resume_path_invalid")?;
    let connection = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| "native_codex_request_resume_store_unavailable")?;
    crate::codex_request_resume_busy::arm(&connection, request.busy_timeout_ms)
        .map_err(|_| "native_codex_request_resume_store_unavailable")?;
    let call = Call {
        request_id: &request.approval_request_id,
        now: &request.now,
    };
    let send = |action: &str, metadata: &Map<String, Value>| {
        let continuation = ContinueRequest {
            approval_request_id: &request.approval_request_id,
            action,
            home_dir: request.home_dir.as_deref(),
            temp_dir: request.temp_dir.as_deref(),
            cwd: request.cwd.as_deref(),
            timeout_ms: request.timeout_ms,
        };
        continue_thread(&continuation, metadata)
    };
    let outcome = match (request.call.as_str(), request.action.as_deref()) {
        ("seed", _) => seed(&connection, &call).map(Outcome::Resume),
        ("status", _) => status(&connection, &call).map(Outcome::Resume),
        ("retry", _) => retry(&connection, &call, request.force, &send),
        ("defer", Some(action)) => defer(&connection, &call, action).map(Outcome::Resume),
        _ => return Err(INVALID),
    };
    outcome.map_err(|error| match error {
        StoreError::Invalid(code) => code,
        StoreError::Sqlite(error) if is_busy(&error) => "native_codex_request_resume_store_busy",
        _ => "native_codex_request_resume_store_failed",
    })
}

fn is_busy(error: &rusqlite::Error) -> bool {
    matches!(
        error.sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    )
}

pub(crate) struct Call<'a> {
    pub(crate) request_id: &'a str,
    pub(crate) now: &'a str,
}

/// Sends one continuation: `(action, operation metadata) -> result or null`.
pub(crate) type Send<'a> = dyn Fn(&str, &Map<String, Value>) -> Value + 'a;

/// `get_request_resume_status`.
pub(crate) fn status(connection: &Connection, call: &Call<'_>) -> StoreResult<Option<Value>> {
    if let Some(resume) = store::resume(connection, call.request_id)? {
        return Ok(Some(resume));
    }
    seed(connection, call)
}

/// `seed_request_resume_record`: writes the record even when one exists.
pub(crate) fn seed(connection: &Connection, call: &Call<'_>) -> StoreResult<Option<Value>> {
    match store::approval(connection, call.request_id)? {
        Some(approval) if approval.harness == "codex" => {}
        _ => return Ok(None),
    }
    let operation = store::operation(connection, call.request_id)?;
    let thread_id = operation
        .as_ref()
        .and_then(|operation| operation["metadata"].as_object())
        .and_then(|metadata| first_string(metadata, &THREAD_ID_KEYS));
    let seed = ResumeSeed {
        operation_id: operation
            .as_ref()
            .and_then(|operation| operation["operation_id"].as_str()),
        strategy: if thread_id.is_some() {
            STRATEGY_THREAD
        } else {
            STRATEGY_MANUAL
        },
        thread_id,
    };
    store::seed(connection, call.request_id, &seed, call.now)?;
    store::resume(connection, call.request_id)
}

/// `retry_request_resume`.
pub(crate) fn retry(
    connection: &Connection,
    call: &Call<'_>,
    force: bool,
    send: &Send<'_>,
) -> StoreResult<Outcome> {
    let Some(approval) = store::approval(connection, call.request_id)? else {
        return Ok(Outcome::Refused("not_found"));
    };
    if approval.harness != "codex" {
        return Ok(Outcome::Refused("resume_not_supported"));
    }
    let Some(action) = approval.resolution_action else {
        return Ok(Outcome::Refused("not_resolved"));
    };
    let Some(resume) = status(connection, call)? else {
        return Ok(Outcome::Refused("resume_not_supported"));
    };
    let attempt_count = int_field(&resume, "attempt_count") + 1;
    if action == "block" {
        return skip_blocked(connection, call, &resume, attempt_count).map(Outcome::Resume);
    }
    match resume["status"].as_str() {
        Some("sent") if !force => {
            let mut resume = resume;
            resume["status"] = Value::from("already_sent");
            resume["message"] = Value::from(ALREADY_SENT_MESSAGE);
            return Ok(Outcome::Resume(Some(resume)));
        }
        Some("in_progress") => return Ok(Outcome::Resume(Some(resume))),
        _ => {}
    }
    let update = ResumeUpdate {
        resolution_action: &action,
        strategy: resume["strategy"].as_str(),
        supported: resume["supported"].as_bool(),
        status: "in_progress",
        reason: Some("attempting_resume"),
        message: Some(ATTEMPTING_MESSAGE),
        last_error: None,
        attempt_count,
        sent_at: resume["sent_at"].as_str(),
    };
    store::update(connection, call.request_id, &update, call.now)?;
    let Some(refreshed) = store::resume(connection, call.request_id)? else {
        return Ok(Outcome::Refused("resume_not_supported"));
    };
    finalize(connection, call, &action, &refreshed, send)
}

/// `_finalize_resume_attempt`.
fn finalize(
    connection: &Connection,
    call: &Call<'_>,
    action: &str,
    resume: &Value,
    send: &Send<'_>,
) -> StoreResult<Outcome> {
    let strategy = resume["strategy"].as_str().unwrap_or_default();
    let thread_id = resume["thread_id"].as_str();
    let attempt_count = int_field(resume, "attempt_count");
    if strategy == STRATEGY_MANUAL || resume["supported"] != Value::Bool(true) {
        let update = ResumeUpdate {
            resolution_action: action,
            strategy: Some(strategy),
            supported: resume["supported"].as_bool(),
            status: "skipped",
            reason: Some("session_not_found"),
            message: Some(MANUAL_MESSAGE),
            last_error: None,
            attempt_count,
            sent_at: None,
        };
        store::update(connection, call.request_id, &update, call.now)?;
        return finished(connection, call);
    }
    let raw = match thread_id {
        None => None,
        Some(thread_id) => Some(dispatch(
            connection, call, action, strategy, thread_id, send,
        )?),
    };
    let normalized = normalize(strategy, raw.as_ref());
    let sent_at = if normalized.status == "sent" {
        Some(call.now)
    } else {
        resume["sent_at"].as_str().filter(|text| !text.is_empty())
    };
    let update = ResumeUpdate {
        resolution_action: action,
        strategy: Some(&normalized.strategy),
        supported: Some(normalized.supported),
        status: normalized.status,
        reason: normalized.reason.as_deref(),
        message: Some(normalized.message),
        last_error: normalized.last_error.as_deref(),
        attempt_count,
        sent_at,
    };
    store::update(connection, call.request_id, &update, call.now)?;
    finished(connection, call)
}

fn finished(connection: &Connection, call: &Call<'_>) -> StoreResult<Outcome> {
    Ok(match store::resume(connection, call.request_id)? {
        Some(resume) => Outcome::Resume(Some(resume)),
        None => Outcome::Refused("resume_not_supported"),
    })
}

/// `_dispatch_resume_attempt`: sends to the Codex operation's thread, or
/// reports the session as not found when there is no such operation.
fn dispatch(
    connection: &Connection,
    call: &Call<'_>,
    action: &str,
    strategy: &str,
    thread_id: &str,
    send: &Send<'_>,
) -> StoreResult<Value> {
    let operation = store::codex_operation(connection, call.request_id)?;
    let result = match operation.as_ref().and_then(|op| op["metadata"].as_object()) {
        Some(metadata) => send(action, metadata),
        None => Value::Null,
    };
    if result.is_object() {
        return Ok(result);
    }
    Ok(json!({
        "status": "skipped",
        "reason": "session_not_found",
        "thread_id": thread_id,
        "strategy": strategy,
        "supported": false,
    }))
}

struct Normalized {
    status: &'static str,
    reason: Option<String>,
    message: &'static str,
    last_error: Option<String>,
    strategy: String,
    supported: bool,
}

/// `_normalize_dispatch_result`, minus the thread id the record never stores.
fn normalize(strategy: &str, raw: Option<&Value>) -> Normalized {
    let Some(raw) = raw else {
        return Normalized {
            status: "skipped",
            reason: Some("session_not_found".to_owned()),
            message: MANUAL_MESSAGE,
            last_error: None,
            strategy: strategy.to_owned(),
            supported: false,
        };
    };
    let text_or =
        |key: &str, default: &str| truthy_str(&raw[key]).unwrap_or_else(|| default.to_owned());
    let strategy = text_or("strategy", strategy);
    let raw_status = text_or("status", "");
    let raw_reason = text_or("reason", "unknown");
    let raw_last_error = (!raw["last_error"].is_null())
        .then(|| py_str(&raw["last_error"]))
        .flatten()
        .filter(|text| !text.is_empty());
    let last_error = || {
        raw_last_error
            .clone()
            .unwrap_or_else(|| text_or("message", &raw_reason))
    };
    let supported = raw["supported"]
        .as_bool()
        .unwrap_or(raw_status != "skipped");
    if raw_status == "sent" {
        return Normalized {
            status: "sent",
            reason: Some(raw_reason),
            message: SENT_MESSAGE,
            last_error: None,
            strategy,
            supported: true,
        };
    }
    if CONTINUE_FAILURE_REASONS.contains(&raw_reason.as_str()) {
        return Normalized {
            status: "failed",
            last_error: Some(last_error()),
            reason: Some(raw_reason),
            message: FAILED_MESSAGE,
            strategy,
            supported: true,
        };
    }
    let failed = raw_status == "failed";
    Normalized {
        status: if failed { "failed" } else { "skipped" },
        last_error: failed.then(last_error),
        reason: Some(raw_reason),
        message: if failed {
            FAILED_MESSAGE
        } else {
            MANUAL_MESSAGE
        },
        strategy,
        supported,
    }
}

/// `defer_request_resume_to_live_hook` once the caller has found the
/// waiting hook.
pub(crate) fn defer(
    connection: &Connection,
    call: &Call<'_>,
    action: &str,
) -> StoreResult<Option<Value>> {
    let Some(resume) = status(connection, call)? else {
        return Ok(None);
    };
    let attempt_count = int_field(&resume, "attempt_count");
    if action == "block" {
        return skip_blocked(connection, call, &resume, attempt_count);
    }
    let update = ResumeUpdate {
        resolution_action: action,
        strategy: resume["strategy"].as_str(),
        supported: resume["supported"].as_bool(),
        status: "pending",
        reason: Some("live_hook_waiting"),
        message: Some(LIVE_HOOK_MESSAGE),
        last_error: None,
        attempt_count,
        sent_at: resume["sent_at"].as_str(),
    };
    store::update(connection, call.request_id, &update, call.now)?;
    store::resume(connection, call.request_id)
}

/// `_skip_blocked_resume`.
fn skip_blocked(
    connection: &Connection,
    call: &Call<'_>,
    resume: &Value,
    attempt_count: i64,
) -> StoreResult<Option<Value>> {
    let update = ResumeUpdate {
        resolution_action: "block",
        strategy: resume["strategy"].as_str(),
        supported: Some(false),
        status: "skipped",
        reason: Some("blocked_not_resumed"),
        message: Some(BLOCKED_MESSAGE),
        last_error: None,
        attempt_count,
        sent_at: None,
    };
    store::update(connection, call.request_id, &update, call.now)?;
    store::resume(connection, call.request_id)
}

fn int_field(resume: &Value, key: &str) -> i64 {
    resume[key].as_i64().unwrap_or_default()
}

/// `str(value)` when `value` is truthy, as `str(raw.get(key) or default)`.
fn truthy_str(value: &Value) -> Option<String> {
    crate::cloud_request_text::py_truthy(value)
        .then(|| py_str(value))
        .flatten()
}

/// `_first_string`: the first non-blank string, unstripped.
fn first_string<'a>(mapping: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| {
        mapping
            .get(*key)
            .and_then(Value::as_str)
            .filter(|text| !crate::guard_store_json::py_strip(text).is_empty())
    })
}

#[cfg(test)]
#[path = "codex_request_resume_vectors_tests.rs"]
mod vectors_tests;
