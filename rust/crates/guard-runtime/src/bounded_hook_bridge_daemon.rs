//! The loopback daemon transport the native hook bridges share: the
//! private daemon state and auth token `try_daemon_hook` reads, the
//! transport deadline it leaves the rest of the hook, and the authenticated
//! `POST` of one hook. Every failure is the calling bridge's to settle, by
//! the kind of failure where it asks; nothing here decides a verdict.

use std::path::Path;
use std::time::{Duration, Instant};

use super::{HOOK_DEADLINE, MAX_STATE_BYTES, MAX_TOKEN_BYTES, STATE_FILE, TOKEN_FILE};
use crate::claude_hook_bridge_auth::{private_file_text, LOOPBACK_HOSTS};
use crate::claude_hook_bridge_http::{LoopbackConnection, ResponseHead, MAX_DAEMON_RESPONSE_BYTES};
use crate::claude_hook_bridge_transport::OVERLOAD_MARKERS;
use crate::claude_hook_bridge_url::assert_loopback_http_url;
use crate::pyjson::{self, PyVal, SurrogateMapped};

/// The loopback daemon and the token a hook is sent with.
pub(crate) struct DaemonTarget {
    host: String,
    port: u16,
    token: String,
    /// The state text the target was read from, which names its generation.
    state: String,
}

impl DaemonTarget {
    /// Whether `other` was read from the same daemon state and token.
    pub(crate) fn same_daemon(&self, other: &DaemonTarget) -> bool {
        self.state == other.state && self.token == other.token
    }
}

/// `_daemon_hook_endpoint`: the loopback host and port the daemon state
/// names, after the URL check `try_daemon_hook` applies, and that state.
fn daemon_endpoint(guard_home: &Path, harness: &str) -> Option<(String, u16, String)> {
    let path = guard_home.join(STATE_FILE);
    if std::fs::symlink_metadata(&path).ok()?.len() > MAX_STATE_BYTES {
        return None;
    }
    let text = private_file_text(&path, "Guard daemon state").ok()?;
    let parsed = pyjson::parse_mapping_lone_surrogates(&text).ok()?;
    if parsed.mapped {
        return None;
    }
    let host = parsed.value.get("host")?.as_str()?;
    let Some(PyVal::Int(digits)) = parsed.value.get("port") else {
        return None;
    };
    let port = digits.parse::<u16>().ok().filter(|port| *port >= 1)?;
    if !LOOPBACK_HOSTS.contains(&host) {
        return None;
    }
    let rendered_host = if host == "::1" {
        "[::1]".to_owned()
    } else {
        host.to_owned()
    };
    assert_loopback_http_url(&format!("http://{rendered_host}:{port}/v1/hooks/{harness}")).ok()?;
    Some((host.to_owned(), port, text))
}

/// `load_guard_daemon_auth_token`, limited to tokens urllib sends as is.
fn daemon_auth_token(guard_home: &Path) -> Option<String> {
    let path = guard_home.join(TOKEN_FILE);
    if std::fs::symlink_metadata(&path).ok()?.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let token = private_file_text(&path, "Guard daemon auth token").ok()?;
    let sendable = token
        .bytes()
        .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte));
    (!token.is_empty() && sendable).then_some(token)
}

/// The daemon a `harness` hook is sent to, or `None` when its state or
/// token is missing, unreadable or not one the bridge sends to.
pub(crate) fn daemon_target(guard_home: &Path, harness: &str) -> Option<DaemonTarget> {
    let (host, port, state) = daemon_endpoint(guard_home, harness)?;
    let token = daemon_auth_token(guard_home)?;
    Some(DaemonTarget {
        host,
        port,
        token,
        state,
    })
}

/// The deadline for one daemon request: at most `budget` and half of the
/// `left` the hook had, so the rest of the hook keeps the other half. `None`
/// when no time is left for the request.
pub(crate) fn transport_deadline(
    deadline: Instant,
    left: Duration,
    budget: Duration,
) -> Option<Instant> {
    let now = Instant::now();
    let transport = deadline.min(now + (left / 2).min(budget));
    (transport > now).then_some(transport)
}

/// Why a posted hook got no `200` body the bridge accepts, in the kinds
/// the Cursor client's `_daemon_hook_result` names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PostFailure {
    /// The connection failed or the answer did not arrive in time.
    Transport,
    /// The daemon refused the hook because it is at capacity.
    Overload,
    /// The daemon refused the hook otherwise, or answered with a body the
    /// client does not read.
    ControlPlane,
}

impl PostFailure {
    /// The `HOL_GUARD_HOOK_FAILURE_KIND` the daemon start is told.
    pub(crate) fn failure_kind(self) -> &'static str {
        match self {
            Self::Transport => "transport-failure",
            Self::Overload => "overload",
            Self::ControlPlane => "authenticated-control-plane-failure",
        }
    }
}

/// The daemon's `200` body for a hook posted to `path`, as UTF-8 text
/// without a BOM, or why there is none.
pub(crate) fn post_hook_reply(
    target: &DaemonTarget,
    path: &str,
    data: &str,
    deadline: Instant,
) -> Result<String, PostFailure> {
    let mut connection = LoopbackConnection::new(&target.host, target.port);
    let head = connection
        .post(
            path,
            &[
                ("Content-Type", "application/json"),
                ("Connection", "close"),
                ("X-Guard-Token", target.token.as_str()),
            ],
            data.as_bytes(),
            deadline,
        )
        .map_err(|_| PostFailure::Transport)?;
    if head.status != 200 {
        return Err(refusal(&mut connection, &head, deadline));
    }
    let body = connection
        .read_body(&head, deadline, HOOK_DEADLINE, HOOK_DEADLINE)
        .map_err(|_| PostFailure::Transport)?;
    if Instant::now() >= deadline {
        return Err(PostFailure::Transport);
    }
    if body.len() > MAX_DAEMON_RESPONSE_BYTES || body.starts_with(b"\xef\xbb\xbf") {
        return Err(PostFailure::ControlPlane);
    }
    String::from_utf8(body).map_err(|_| PostFailure::ControlPlane)
}

/// A refused hook's kind, as the Cursor client reads an `HTTPError`: `429`,
/// `503` or a body that names the daemon's capacity is an overload. A body
/// that cannot be read, or is too large, names nothing.
fn refusal(
    connection: &mut LoopbackConnection,
    head: &ResponseHead,
    deadline: Instant,
) -> PostFailure {
    if matches!(head.status, 429 | 503) {
        return PostFailure::Overload;
    }
    let detail = connection
        .read_body(head, deadline, HOOK_DEADLINE, HOOK_DEADLINE)
        .ok()
        .filter(|detail| detail.len() <= MAX_DAEMON_RESPONSE_BYTES)
        .map(|detail| String::from_utf8_lossy(&detail).to_lowercase())
        .unwrap_or_default();
    if OVERLOAD_MARKERS
        .iter()
        .any(|marker| detail.contains(marker))
    {
        PostFailure::Overload
    } else {
        PostFailure::ControlPlane
    }
}

/// `post_hook_json`: the daemon's JSON object, lone surrogates mapped as
/// `json.loads` keeps them, or `None` for any failure.
pub(crate) fn post_hook(
    target: &DaemonTarget,
    harness: &str,
    data: &str,
    deadline: Instant,
) -> Option<SurrogateMapped> {
    let text = post_hook_reply(target, &format!("/v1/hooks/{harness}"), data, deadline).ok()?;
    let parsed = pyjson::parse_mapping_lone_surrogates(&text).ok()?;
    parsed.value.as_dict().is_some().then_some(parsed)
}
