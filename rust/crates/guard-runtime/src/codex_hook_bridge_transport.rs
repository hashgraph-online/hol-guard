//! Authenticated same-connection transport for the native Codex hook
//! bridge: a port of `_daemon_response_once` in
//! `codex_daemon_hook_transport.py`. The bridge proves the daemon's identity
//! with a signed challenge, checks that the daemon auth token belongs to the
//! same signed state, then posts the hook with the token and the proof on
//! one loopback connection inside one absolute deadline.
//!
//! Any failure is returned as an error that says whether the daemon looked
//! not yet up before the hook was sent, so the bridge knows when asking a
//! starting daemon again cannot deliver the hook twice.

use std::path::Path;
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::claude_hook_bridge_auth::{
    authenticated_state, private_file_text, verify_challenge_response, AuthenticatedState,
};
use crate::claude_hook_bridge_http::{
    remaining, LoopbackConnection, MAX_DAEMON_RESPONSE_BYTES, MINIMUM_OPERATION,
};
use crate::claude_hook_bridge_render::py_strip;
use crate::claude_hook_bridge_transport::{
    hook_event_name, json_failure, new_nonce, request_identity_challenge, BridgeError,
};
use crate::claude_hook_bridge_url::assert_loopback_http_url;
use crate::hook_env_stamp::with_remaining_hint;
use crate::resident_transport::constant_time_eq;

const AUTH_TOKEN_FILE: &str = "daemon-auth-token";
const HOOK_DEADLINE: &str = "daemon hook exceeded the hook deadline";

/// A failed Codex hook exchange.
#[derive(Debug)]
pub(crate) struct HookFailure {
    pub(crate) error: BridgeError,
    /// The hook was not sent and the daemon looked not yet up: no signed
    /// state, nothing answering the challenge, or a new generation.
    pub(crate) not_up: bool,
}

/// A failure before the hook was sent.
fn unsent(error: BridgeError, not_up: bool) -> HookFailure {
    HookFailure { error, not_up }
}

/// A failure once the hook may have reached the daemon.
fn sent(error: BridgeError) -> HookFailure {
    HookFailure {
        error,
        not_up: false,
    }
}

fn generation_changed(message: &str) -> BridgeError {
    BridgeError::Value(message.to_owned())
}

/// The signed state must still name the same daemon generation.
fn require_same_generation(
    state_path: &Path,
    state: &AuthenticatedState,
    message: &str,
) -> Result<(), BridgeError> {
    let current = authenticated_state(state_path).map_err(BridgeError::Value)?;
    if current.same_generation(state) {
        Ok(())
    } else {
        Err(generation_changed(message))
    }
}

/// `_daemon_auth_token(state_path, state)`: the private token whose SHA-256
/// the signed state names.
fn daemon_auth_token(state_path: &Path, state: &AuthenticatedState) -> Result<String, String> {
    let parent = match state_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let token = private_file_text(&parent.join(AUTH_TOKEN_FILE), "daemon auth token")?;
    let actual = hex::encode(Sha256::digest(token.as_bytes()));
    let expected = state
        .payload
        .get("auth_token_id")
        .and_then(serde_json::Value::as_str);
    match expected {
        Some(expected)
            if !token.is_empty() && constant_time_eq(actual.as_bytes(), expected.as_bytes()) =>
        {
            Ok(token)
        }
        _ => Err("daemon auth token does not match authenticated state".to_owned()),
    }
}

/// `http://{host}:{port}`, bracketing an IPv6 host.
fn daemon_url(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("http://[{host}]:{port}")
    } else {
        format!("http://{host}:{port}")
    }
}

/// `http://{host}:{port}/v1/hooks/codex?{query}`.
fn hook_endpoint(host: &str, port: u16, query: &str) -> String {
    format!("{}/v1/hooks/codex?{query}", daemon_url(host, port))
}

/// One authenticated Codex hook exchange: the daemon's stripped response
/// text on HTTP 200.
pub(crate) fn authenticated_codex_hook_response(
    state_path: &Path,
    query: &str,
    data: &str,
    deadline: Instant,
) -> Result<String, HookFailure> {
    let state = authenticated_state(state_path)
        .map_err(|message| unsent(BridgeError::Transport(message), true))?;
    assert_loopback_http_url(&hook_endpoint(state.text("host"), state.port(), query))
        .map_err(|message| unsent(BridgeError::Value(message), false))?;
    let hook_event = hook_event_name(data).map_err(|error| unsent(error, false))?;
    let nonce = new_nonce().map_err(|error| unsent(error, false))?;
    let mut connection = LoopbackConnection::new(state.text("host"), state.port());
    let challenge = request_identity_challenge(
        &mut connection,
        state.text("state_id"),
        &nonce,
        &hook_event,
        deadline,
    )
    .map_err(|error| {
        // Nothing listening answers with a transport failure; any status
        // came from a daemon that is up.
        let not_up = matches!(error, BridgeError::Transport(_));
        unsent(error, not_up)
    })?;
    let proof = verify_challenge_response(&challenge, &state, &nonce, &hook_event)
        .map_err(|message| unsent(BridgeError::Value(message), false))?;
    require_same_generation(
        state_path,
        &state,
        "daemon state changed during identity verification",
    )
    .map_err(|error| unsent(error, true))?;
    let token = daemon_auth_token(state_path, &state)
        .map_err(|message| unsent(BridgeError::Value(message), false))?;
    if remaining(deadline) < MINIMUM_OPERATION {
        return Err(unsent(
            BridgeError::Transport(
                "daemon identity challenge exhausted the hook deadline".to_owned(),
            ),
            false,
        ));
    }
    let hinted = with_remaining_hint(data, remaining(deadline).as_millis())
        .map_err(|error| unsent(json_failure(error), false))?;
    let head = connection
        .post(
            &format!("/v1/hooks/codex?{query}"),
            &[
                ("Content-Type", "application/json"),
                ("Connection", "close"),
                ("X-Guard-Token", &token),
                ("X-Guard-Daemon-Nonce", &nonce),
                ("X-Guard-Daemon-Proof", &proof),
            ],
            hinted.as_bytes(),
            deadline,
        )
        .map_err(sent)?;
    let body = connection
        .read_body(&head, deadline, HOOK_DEADLINE, HOOK_DEADLINE)
        .map_err(sent)?;
    if body.len() > MAX_DAEMON_RESPONSE_BYTES {
        return Err(sent(BridgeError::Value(
            "daemon hook response is too large".to_owned(),
        )));
    }
    let text = String::from_utf8_lossy(&body);
    if head.status != 200 {
        return Err(sent(BridgeError::Http {
            status: head.status,
            detail: py_strip(&text).to_owned(),
        }));
    }
    Ok(py_strip(&text).to_owned())
}

/// Why an approval request to the daemon gave no answer: `Retry` where
/// Python's call raised `OSError` or `HTTPException` (nothing was settled,
/// the same request may be sent again), `Refused` where it raised
/// `ValueError` (a status other than 200, an oversized or malformed body).
#[derive(Debug, PartialEq)]
pub(crate) enum ApprovalFailure {
    Retry,
    Refused,
}

const APPROVAL_DEADLINE: &str = "daemon request exceeded the hook deadline";

/// `_daemon_json_get` (`path` is `None`) or `_daemon_json_post` with
/// `body`, authenticated with the daemon token the signed state names. A
/// 404 answers `None` to a GET, as it does in Python; so does a request
/// with less than the minimum operation time left.
pub(crate) fn approval_request(
    state_path: &Path,
    path: &str,
    body: Option<&[u8]>,
    deadline: Instant,
) -> Result<Option<crate::pyjson::PyVal>, ApprovalFailure> {
    if remaining(deadline) < MINIMUM_OPERATION {
        return Ok(None);
    }
    // A daemon whose state cannot be read is not up, which `OSError`
    // reports in Python.
    let state = authenticated_state(state_path).map_err(|_| ApprovalFailure::Retry)?;
    let endpoint = format!("{}{path}", daemon_url(state.text("host"), state.port()));
    assert_loopback_http_url(&endpoint).map_err(|_| ApprovalFailure::Refused)?;
    let token = daemon_auth_token(state_path, &state).map_err(|_| ApprovalFailure::Refused)?;
    let mut connection = LoopbackConnection::new(state.text("host"), state.port());
    let sent = match body {
        Some(body) => connection.post(
            path,
            &[
                ("Connection", "close"),
                ("Content-Type", "application/json"),
                ("X-Guard-Token", &token),
            ],
            body,
            deadline,
        ),
        None => connection.get(
            path,
            &[("Connection", "close"), ("X-Guard-Token", &token)],
            deadline,
        ),
    };
    let failure = |error: BridgeError| match error {
        BridgeError::Transport(_) => ApprovalFailure::Retry,
        BridgeError::Value(_) | BridgeError::Http { .. } => ApprovalFailure::Refused,
    };
    let head = sent.map_err(failure)?;
    let text = connection
        .read_body(&head, deadline, APPROVAL_DEADLINE, APPROVAL_DEADLINE)
        .map_err(failure)?;
    if text.len() > MAX_DAEMON_RESPONSE_BYTES {
        return Err(ApprovalFailure::Refused);
    }
    if head.status != 200 {
        return if head.status == 404 && body.is_none() {
            Ok(None)
        } else {
            Err(ApprovalFailure::Refused)
        };
    }
    match crate::pyjson::parse_mapping_lone_surrogates(py_strip(&String::from_utf8_lossy(&text))) {
        Ok(parsed) if matches!(parsed.value, crate::pyjson::PyVal::Dict(_)) => {
            Ok(Some(parsed.value))
        }
        _ => Err(ApprovalFailure::Refused),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::hook_endpoint;

    #[test]
    fn endpoint_brackets_ipv6_hosts() {
        assert_eq!(
            hook_endpoint("::1", 8080, "home=%2Fh"),
            "http://[::1]:8080/v1/hooks/codex?home=%2Fh"
        );
        assert_eq!(
            hook_endpoint("127.0.0.1", 1, "a=b"),
            "http://127.0.0.1:1/v1/hooks/codex?a=b"
        );
    }
}
