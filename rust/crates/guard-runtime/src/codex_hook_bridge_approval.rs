//! The native Codex bridge's browser approval wait: a port of
//! `apply_browser_approval_wait` in `codex_daemon_hook_resume.py`.
//!
//! A `PreToolUse` deny that names a pending approval request is held while
//! the bridge opens the signed approval link, polls the daemon until the
//! request is resolved, and asks the daemon to record the live decision for
//! this hook. Only a completed allow replaces the deny; every other outcome
//! keeps it.
//!
//! A request id the daemon could never resolve is refused before waiting:
//! one with a character outside `[A-Za-z0-9_-]` (Python accepts any
//! character `str.isalnum` admits, which no daemon request id contains).
//! The bridge then answers with the original deny, as Python does once its
//! wait runs out.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::claude_hook_bridge_http::remaining;
use crate::codex_hook_bridge_transport::{approval_request, ApprovalFailure};
use crate::codex_hook_response::{codex_hook_response, PRE_TOOL_USE};
use crate::hook_env_stamp::{dumps, json_string};
use crate::pyjson::PyVal;

/// `GUARD_APPROVAL_REQUEST_ID_KEY` in `codex_daemon_hook_resume.py`.
const APPROVAL_REQUEST_ID_KEY: &str = "guardApprovalRequestId";
/// `GUARD_APPROVAL_URL_KEY`.
const APPROVAL_URL_KEY: &str = "guardApprovalUrl";
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const GET_TIMEOUT_CAP: Duration = Duration::from_millis(1500);
const FINALIZE_TIMEOUT_CAP: Duration = Duration::from_secs(5);
const FINALIZE_MAX_ATTEMPTS: usize = 3;
/// `/requests/`, the fixed segment of `_REQUEST_URL_RE`.
const REQUEST_SEGMENT: [char; 10] = ['/', 'r', 'e', 'q', 'u', 'e', 's', 't', 's', '/'];
const MIN_ID_CHARS: usize = 8;
const MAX_ID_CHARS: usize = 128;

/// A deny that names a pending approval request.
#[derive(Debug, PartialEq)]
pub(crate) struct Pending {
    pub(crate) request_id: String,
    pub(crate) approval_url: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Action {
    Allow,
    Block,
}

impl Action {
    fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Block => "block",
        }
    }
}

/// `str.isspace()`, which `str.strip()` and `\s` use.
fn py_space(character: char) -> bool {
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

fn py_strip(text: &str) -> &str {
    text.trim_matches(py_space)
}

/// Whether `character` matches the letter `lower` under `re.IGNORECASE`:
/// its ASCII capital, and for `s` the long s (`U+017F`) as well.
fn folds_to(character: char, lower: char) -> bool {
    character.to_ascii_lowercase() == lower || (lower == 's' && character == '\u{017f}')
}

/// `[A-Za-z0-9_-]` under `re.IGNORECASE`, which also admits the four
/// non-ASCII letters whose simple case mapping is an ASCII letter.
fn id_char(character: char) -> bool {
    character.is_ascii_alphanumeric()
        || matches!(
            character,
            '_' | '-' | '\u{0130}' | '\u{0131}' | '\u{017f}' | '\u{212a}'
        )
}

/// `_optional_safe_request_id(value)` for a request id the daemon can
/// resolve: `None` for every value Python refuses, and for an id with a
/// character outside ASCII.
fn safe_request_id(value: &str) -> Option<String> {
    let id = py_strip(value);
    let safe = id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    (safe && (MIN_ID_CHARS..=MAX_ID_CHARS).contains(&id.len())).then(|| id.to_owned())
}

/// `_optional_http_url(value)`.
fn http_url(value: &str) -> Option<String> {
    let url = py_strip(value);
    let scheme = url.starts_with("http://") || url.starts_with("https://");
    (scheme && !url.chars().any(py_space)).then(|| url.to_owned())
}

/// Where `https?://` matched at `start` ends, as `re.IGNORECASE` matches it.
fn scheme_end(text: &[char], start: usize) -> Option<usize> {
    let letters = text.get(start..start + 4)?;
    if !letters
        .iter()
        .zip("http".chars())
        .all(|(c, l)| folds_to(*c, l))
    {
        return None;
    }
    let separator = |at: usize| text.get(at..at + 3) == Some(&[':', '/', '/'][..]);
    match text.get(start + 4) {
        Some(&s) if folds_to(s, 's') && separator(start + 5) => Some(start + 8),
        _ if separator(start + 4) => Some(start + 7),
        _ => None,
    }
}

/// The last `/requests/` in `text[from..end]` followed by at least eight id
/// characters, with how many follow it (at most 128): where a greedy
/// `[^\s]+` gives way to `/requests/([A-Za-z0-9_-]{8,128})`.
fn last_request_segment(text: &[char], from: usize, end: usize) -> Option<(usize, usize)> {
    (from..end).rev().find_map(|segment| {
        let id_start = segment + REQUEST_SEGMENT.len();
        let literal = text.get(segment..id_start)?;
        if !literal
            .iter()
            .zip(REQUEST_SEGMENT)
            .all(|(c, l)| folds_to(*c, l))
        {
            return None;
        }
        let limit = end.min(id_start + MAX_ID_CHARS);
        let count = text[id_start..limit]
            .iter()
            .take_while(|c| id_char(**c))
            .count();
        (count >= MIN_ID_CHARS).then_some((segment, count))
    })
}

/// `_REQUEST_URL_RE.search(reason)`: groups 1 (the link) and 2 (the id).
fn request_link(reason: &str) -> Option<(String, String)> {
    let text: Vec<char> = reason.chars().collect();
    // The non-whitespace run the last scheme matched in, and its last
    // request segment: every later scheme in the run has the same one.
    let mut run: Option<(usize, Option<(usize, usize)>)> = None;
    for start in 0..text.len() {
        let Some(after) = scheme_end(&text, start) else {
            continue;
        };
        let last = match run {
            Some((end, last)) if start < end => last,
            _ => {
                let end = (start..text.len())
                    .find(|&index| py_space(text[index]))
                    .unwrap_or(text.len());
                let last = last_request_segment(&text, start, end);
                run = Some((end, last));
                last
            }
        };
        // `[^\s]+` takes at least one character before the segment.
        if let Some((segment, count)) = last.filter(|(segment, _)| *segment > after) {
            let id_start = segment + REQUEST_SEGMENT.len();
            let link = text[start..id_start + count].iter().collect();
            let id = text[id_start..id_start + count].iter().collect();
            return Some((link, id));
        }
    }
    None
}

/// `pending_pretool_approval(response, event_name=...)`, for a request id
/// the daemon can resolve.
pub(crate) fn pending_pretool_approval(response: &PyVal, event_name: &str) -> Option<Pending> {
    if event_name != PRE_TOOL_USE {
        return None;
    }
    let output = response.get("hookSpecificOutput")?;
    if !matches!(output, PyVal::Dict(_)) {
        return None;
    }
    if !matches!(output.get("permissionDecision"), Some(PyVal::Str(text)) if text == "deny") {
        return None;
    }
    let mut request_id = None;
    if let Some(PyVal::Str(value)) = response.get(APPROVAL_REQUEST_ID_KEY) {
        // An id Python could accept but the daemon never resolves keeps
        // the deny; so does one Python refuses but this port cannot tell
        // from one it accepts.
        if !py_strip(value).is_ascii() {
            return None;
        }
        request_id = safe_request_id(value);
    }
    let mut approval_url = match response.get(APPROVAL_URL_KEY) {
        Some(PyVal::Str(value)) => http_url(value),
        _ => None,
    };
    if request_id.is_none() || approval_url.is_none() {
        let reason = match output.get("permissionDecisionReason") {
            Some(PyVal::Str(reason)) => request_link(reason),
            _ => None,
        };
        if let Some((link, id)) = reason {
            // The link ends in an id character, so `.rstrip(".,);")` keeps
            // it whole.
            approval_url = approval_url.or_else(|| http_url(&link));
            if request_id.is_none() {
                if !id.is_ascii() {
                    return None;
                }
                request_id = safe_request_id(&id);
            }
        }
    }
    Some(Pending {
        request_id: request_id?,
        approval_url,
    })
}

fn now_micros() -> Option<i64> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_micros();
    i64::try_from(micros).ok()
}

/// `Path(state_path).parent`.
fn guard_home(state_path: &Path) -> &Path {
    match state_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// `_open_pending_approval(approval_url, state_path=...)`. A link this port
/// cannot sign byte for byte is reported as unavailable, never opened.
fn open_pending(approval_url: Option<&str>, state_path: &Path) {
    let Some(url) = approval_url else {
        return;
    };
    let home = guard_home(state_path);
    let browser_url = now_micros().and_then(|now| {
        crate::native_review_link::approval_browser_url(
            url,
            || {
                crate::daemon_policy_authority::load_guard_daemon_auth_token(home)
                    .filter(|token| !token.is_empty())
            },
            crate::native_review_link::APPROVAL_CENTER_SURFACE,
            now,
        )
    });
    let Some(browser_url) = browser_url else {
        eprintln!("{}", crate::native_review_link::SIGNED_LINK_UNAVAILABLE);
        return;
    };
    eprintln!("HOL Guard is waiting for approval in your browser: {browser_url}");
    crate::browser_open::open_browser_url(&browser_url);
}

/// `_resolution_action(payload)`.
fn resolution_action(payload: &PyVal) -> Option<Action> {
    if !matches!(payload.get("status"), Some(PyVal::Str(status)) if status == "resolved") {
        return None;
    }
    let Some(PyVal::Str(action)) = payload.get("resolution_action") else {
        return None;
    };
    if matches!(action.as_str(), "block" | "deny" | "denied" | "blocked") {
        return Some(Action::Block);
    }
    if action != "allow" {
        return None;
    }
    let reviewed = matches!(
        payload.get("policy_action"),
        Some(PyVal::Str(policy)) if policy == "review" || policy == "require-reapproval"
    );
    Some(if reviewed {
        Action::Allow
    } else {
        Action::Block
    })
}

/// The deadline for one request: at most `cap` from now.
fn capped(deadline: Instant, cap: Duration) -> Instant {
    Instant::now() + remaining(deadline).min(cap)
}

fn pause(deadline: Instant) {
    std::thread::sleep(POLL_INTERVAL.min(remaining(deadline)));
}

/// `_poll_resolution(request_id=..., state_path=..., deadline=...)`. The
/// id is `[A-Za-z0-9_-]`, which `quote(request_id, safe='')` keeps as is.
fn poll_resolution(state_path: &Path, request_id: &str, deadline: Instant) -> Option<Action> {
    let path = format!("/v1/requests/{request_id}");
    loop {
        if remaining(deadline) < POLL_INTERVAL {
            return None;
        }
        let payload = approval_request(state_path, &path, None, capped(deadline, GET_TIMEOUT_CAP));
        if let Ok(Some(payload)) = payload {
            if let Some(action) = resolution_action(&payload) {
                return Some(action);
            }
        }
        pause(deadline);
    }
}

/// `_complete_resolution(...)`: the action the daemon recorded for this
/// hook, when it is the one the browser chose.
fn complete_resolution(
    state_path: &Path,
    request_id: &str,
    action: Action,
    hook_input: &str,
    deadline: Instant,
) -> Option<Action> {
    let path = format!("/v1/requests/{request_id}/live-decision");
    let body = format!(
        "{{\"hook_input\":{}}}",
        json_string(hook_input, true, false)
    );
    for attempt in 0..FINALIZE_MAX_ATTEMPTS {
        if remaining(deadline) < POLL_INTERVAL {
            return None;
        }
        let sent = approval_request(
            state_path,
            &path,
            Some(body.as_bytes()),
            capped(deadline, FINALIZE_TIMEOUT_CAP),
        );
        let payload = match sent {
            Ok(payload) => payload?,
            Err(ApprovalFailure::Refused) => return None,
            Err(ApprovalFailure::Retry) => {
                // Completion may already be committed. Replaying this exact
                // request still requires daemon authentication and fresh
                // policy validation.
                if attempt + 1 < FINALIZE_MAX_ATTEMPTS {
                    pause(deadline);
                }
                continue;
            }
        };
        if !matches!(payload.get("completed"), Some(PyVal::Bool(true))) {
            return None;
        }
        let recorded = matches!(
            payload.get("action"),
            Some(PyVal::Str(recorded)) if recorded == action.as_str()
        );
        return recorded.then_some(action);
    }
    None
}

/// Wait for the browser's decision on `pending`: whether the daemon
/// recorded an allow for this hook before `deadline`.
pub(crate) fn approved(
    state_path: &Path,
    pending: &Pending,
    hook_input: &str,
    deadline: Instant,
) -> bool {
    open_pending(pending.approval_url.as_deref(), state_path);
    let Some(action) = poll_resolution(state_path, &pending.request_id, deadline) else {
        return false;
    };
    complete_resolution(
        state_path,
        &pending.request_id,
        action,
        hook_input,
        deadline,
    ) == Some(Action::Allow)
}

/// `allow_pretool_response()` as the bridge writes it.
pub(crate) fn allow_rendered() -> String {
    let allow = [(
        "hookSpecificOutput".to_owned(),
        PyVal::Dict(vec![(
            "hookEventName".to_owned(),
            PyVal::Str(PRE_TOOL_USE.to_owned()),
        )]),
    )];
    let mut rendered = String::new();
    dumps(
        &codex_hook_response(&allow, PRE_TOOL_USE),
        true,
        false,
        &mut rendered,
    );
    rendered
}

#[cfg(all(test, unix))]
#[path = "codex_hook_bridge_approval_tests.rs"]
mod tests;
