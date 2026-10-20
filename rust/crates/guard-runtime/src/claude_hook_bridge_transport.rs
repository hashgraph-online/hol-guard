//! Authenticated same-connection transport for the native Claude hook
//! bridge: a port of `authenticated_claude_hook_response` in
//! `claude_daemon_hook_transport.py`. The bridge proves the daemon's
//! identity with a signed challenge on one loopback connection, then posts
//! the hook with the proof, all inside one absolute deadline.

use std::fmt;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::claude_hook_bridge_auth::{authenticated_state, verify_challenge_response};
use crate::claude_hook_bridge_http::{
    remaining, LoopbackConnection, MAX_DAEMON_RESPONSE_BYTES, MINIMUM_OPERATION,
};
use crate::claude_hook_bridge_render::py_strip;
use crate::hook_env_stamp::{json_string, with_remaining_hint};
use crate::pyjson::{self, in_surrogate_plane, JsonFailure, PyVal};

const DEFAULT_EVENT: &str = "PreToolUse";
const CHALLENGE_PATH: &str = "/v1/daemon/identity-challenge";
const CHALLENGE_LABEL: &str = "daemon identity challenge";
const HOOK_DEADLINE: &str = "daemon hook response exceeded the hook deadline";
const INTEGER_LIMIT: &str = "Exceeds the limit (4300 digits) for integer string conversion";
const RECURSION_LIMIT: &str = "maximum recursion depth exceeded while decoding a JSON document";
pub(crate) const OVERLOAD_MARKERS: [&str; 5] =
    ["capacity", "overload", "too_many", "too many", "busy"];

/// A daemon exchange failure, in the three shapes the Python bridge
/// classifies: an HTTP status, a `ValueError` (the daemon or its state
/// failed authentication, or the request was refused before sending), and
/// any other error, which is a transport failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BridgeError {
    Http { status: u16, detail: String },
    Value(String),
    Transport(String),
}

impl fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BridgeError::Http { status, .. } => write!(formatter, "daemon returned HTTP {status}"),
            BridgeError::Value(message) | BridgeError::Transport(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl BridgeError {
    fn is_overload(&self) -> bool {
        match self {
            BridgeError::Http { status, detail } => {
                let detail = detail.to_lowercase();
                *status == 429
                    || OVERLOAD_MARKERS
                        .iter()
                        .any(|marker| detail.contains(marker))
            }
            _ => false,
        }
    }

    /// `_daemon_failure_kind`.
    pub(crate) fn failure_kind(&self) -> &'static str {
        match self {
            _ if self.is_overload() => "overload",
            BridgeError::Http {
                status: 401 | 403, ..
            }
            | BridgeError::Value(_) => "authenticated-control-plane-failure",
            _ => "transport-failure",
        }
    }

    /// `_daemon_failure_is_recoverable`.
    pub(crate) fn is_recoverable(&self) -> bool {
        match self {
            BridgeError::Value(_) => false,
            BridgeError::Http { status, .. } => {
                !self.is_overload() && matches!(status, 408 | 500 | 502 | 503 | 504)
            }
            BridgeError::Transport(_) => true,
        }
    }

    /// `_daemon_failure_reason`.
    pub(crate) fn reason(&self) -> String {
        match self {
            BridgeError::Http { detail, .. } if !detail.is_empty() => format!("{self}: {detail}"),
            _ => self.to_string(),
        }
    }
}

/// `\xNN`, `\uNNNN` or `\UNNNNNNNN`, as CPython escapes a code point.
pub(crate) fn escape_code_point(character: char) -> String {
    let code = u32::from(character);
    if code < 0x100 {
        format!("\\x{code:02x}")
    } else if code < 0x1_0000 {
        format!("\\u{code:04x}")
    } else {
        format!("\\U{code:08x}")
    }
}

/// Characters `str.isprintable()` rejects outside ASCII: controls,
/// separators, format characters, private use and noncharacters.
fn py_unprintable(character: char) -> bool {
    let code = u32::from(character);
    character.is_control()
        || character.is_whitespace()
        || matches!(
            code,
            0xAD | 0x600..=0x605
                | 0x61C
                | 0x6DD
                | 0x70F
                | 0x180E
                | 0x200B..=0x200F
                | 0x202A..=0x202E
                | 0x2060..=0x2064
                | 0x2066..=0x206F
                | 0xE000..=0xF8FF
                | 0xFDD0..=0xFDEF
                | 0xFEFF
                | 0xFFF9..=0xFFFB
                | 0x110BD
                | 0x1D173..=0x1D17A
                | 0xE0001
                | 0xE0020..=0xE007F
                | 0xF0000..=0x10FFFF
        )
        || code & 0xFFFE == 0xFFFE
}

/// CPython `repr(str)`.
pub(crate) fn py_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ if character == quote => {
                out.push('\\');
                out.push(character);
            }
            '\u{0}'..='\u{1f}' | '\u{7f}' => out.push_str(&escape_code_point(character)),
            _ if !character.is_ascii() && py_unprintable(character) => {
                out.push_str(&escape_code_point(character));
            }
            _ => out.push(character),
        }
    }
    out.push(quote);
    out
}

pub(crate) fn json_failure(failure: JsonFailure) -> BridgeError {
    match failure {
        JsonFailure::IntegerLimit => BridgeError::Value(INTEGER_LIMIT.to_owned()),
        _ => BridgeError::Transport(RECURSION_LIMIT.to_owned()),
    }
}

/// The transport's `_event_name`: `hook_event_name` when the key is
/// present (whatever its value), else `event`, stripped.
pub(crate) fn hook_event_name(data: &str) -> Result<String, BridgeError> {
    let parsed = match pyjson::parse_mapping_lone_surrogates(data) {
        Ok(parsed) => parsed,
        Err(JsonFailure::Syntax | JsonFailure::Duplicate) => return Ok(DEFAULT_EVENT.to_owned()),
        Err(failure) => return Err(json_failure(failure)),
    };
    let PyVal::Dict(entries) = &parsed.value else {
        return Ok(DEFAULT_EVENT.to_owned());
    };
    let member = |key: &str| entries.iter().find(|(name, _)| name == key);
    let chosen = member("hook_event_name").or_else(|| member("event"));
    let Some((_, PyVal::Str(name))) = chosen else {
        return Ok(DEFAULT_EVENT.to_owned());
    };
    let name = py_strip(name);
    if name.is_empty() {
        return Ok(DEFAULT_EVENT.to_owned());
    }
    // CPython would carry the lone surrogate through the challenge; the
    // daemon's echo of it is not valid JSON here, so refuse it up front.
    if parsed.mapped && name.chars().any(in_surrogate_plane) {
        return Err(BridgeError::Transport(
            "hook event name holds an unpaired surrogate".to_owned(),
        ));
    }
    Ok(name.to_owned())
}

/// Whether the daemon `state_path` names is up and proves its identity,
/// without sending it a hook: what the bridge waits on after starting the
/// daemon, so a hook is still delivered at most once to the new daemon.
pub(crate) fn daemon_proves_identity(
    state_path: &Path,
    data: &str,
    timeout: Duration,
) -> Result<(), BridgeError> {
    let deadline = Instant::now() + timeout;
    let state = authenticated_state(state_path).map_err(BridgeError::Transport)?;
    let hook_event = hook_event_name(data)?;
    let nonce = new_nonce()?;
    let mut connection = LoopbackConnection::new(state.text("host"), state.port());
    let challenge = request_identity_challenge(
        &mut connection,
        state.text("state_id"),
        &nonce,
        &hook_event,
        deadline,
    )?;
    verify_challenge_response(&challenge, &state, &nonce, &hook_event)
        .map(|_| ())
        .map_err(BridgeError::Value)
}

pub(crate) fn new_nonce() -> Result<String, BridgeError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| BridgeError::Transport(error.to_string()))?;
    Ok(hex::encode(bytes))
}

/// POST the identity challenge and read its JSON object.
pub(crate) fn request_identity_challenge(
    connection: &mut LoopbackConnection,
    state_id: &str,
    nonce: &str,
    hook_event: &str,
    deadline: Instant,
) -> Result<serde_json::Map<String, serde_json::Value>, BridgeError> {
    let body = format!(
        "{{\"protocol_version\":1,\"nonce\":\"{nonce}\",\"state_id\":{},\"hook_event\":{}}}",
        json_string(state_id, true, false),
        json_string(hook_event, true, false),
    );
    let head = connection.post(
        CHALLENGE_PATH,
        &[
            ("Content-Type", "application/json"),
            ("Connection", "keep-alive"),
        ],
        body.as_bytes(),
        deadline,
    )?;
    let body = connection.read_body(
        &head,
        deadline,
        &format!("{CHALLENGE_LABEL} exceeded the hook deadline"),
        "timed out",
    )?;
    if body.len() > MAX_DAEMON_RESPONSE_BYTES {
        return Err(BridgeError::Value(format!(
            "{CHALLENGE_LABEL} response is too large"
        )));
    }
    let text = String::from_utf8_lossy(&body);
    if head.status != 200 {
        return Err(BridgeError::Http {
            status: head.status,
            detail: py_strip(&text).to_owned(),
        });
    }
    match serde_json::from_str(py_strip(&text)) {
        Ok(serde_json::Value::Object(payload)) => Ok(payload),
        _ => Err(BridgeError::Value(format!(
            "{CHALLENGE_LABEL} returned malformed JSON"
        ))),
    }
}

/// `authenticated_claude_hook_response`: the daemon's hook response text.
pub(crate) fn authenticated_claude_hook_response(
    state_path: &Path,
    query: &str,
    data: &str,
    timeout: Duration,
) -> Result<String, BridgeError> {
    let deadline = Instant::now() + timeout;
    let state = authenticated_state(state_path).map_err(BridgeError::Transport)?;
    let hook_path = format!("/v1/hooks/claude-code?{query}");
    let hook_event = hook_event_name(data)?;
    let nonce = new_nonce()?;
    let mut connection = LoopbackConnection::new(state.text("host"), state.port());
    let challenge = request_identity_challenge(
        &mut connection,
        state.text("state_id"),
        &nonce,
        &hook_event,
        deadline,
    )?;
    let proof = verify_challenge_response(&challenge, &state, &nonce, &hook_event)
        .map_err(BridgeError::Value)?;
    let current = authenticated_state(state_path).map_err(BridgeError::Value)?;
    if !current.same_generation(&state) {
        return Err(BridgeError::Value(
            "daemon state changed during identity verification".to_owned(),
        ));
    }
    let left = remaining(deadline);
    if left < MINIMUM_OPERATION {
        return Err(BridgeError::Transport(
            "daemon identity challenge exhausted the hook deadline".to_owned(),
        ));
    }
    // The daemon times the hook from its own arrival, so tell it how long
    // this client will still wait; it must answer before that.
    let hinted =
        with_remaining_hint(data, remaining(deadline).as_millis()).map_err(json_failure)?;
    let head = connection.post(
        &hook_path,
        &[
            ("Content-Type", "application/json"),
            ("Connection", "close"),
            ("X-Guard-Daemon-Nonce", &nonce),
            ("X-Guard-Daemon-Proof", &proof),
        ],
        hinted.as_bytes(),
        deadline,
    )?;
    let body = connection.read_body(&head, deadline, HOOK_DEADLINE, HOOK_DEADLINE)?;
    if body.len() > MAX_DAEMON_RESPONSE_BYTES {
        return Err(BridgeError::Value(
            "daemon hook response is too large".to_owned(),
        ));
    }
    let text = String::from_utf8_lossy(&body).into_owned();
    if head.status != 200 {
        return Err(BridgeError::Http {
            status: head.status,
            detail: py_strip(&text).to_owned(),
        });
    }
    Ok(text)
}

#[cfg(all(test, unix))]
#[path = "claude_hook_bridge_transport_tests.rs"]
mod tests;
