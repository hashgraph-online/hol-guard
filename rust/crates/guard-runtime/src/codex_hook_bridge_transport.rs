//! Authenticated same-connection transport for the native Codex hook
//! bridge: a port of `_daemon_response_once` in
//! `codex_daemon_hook_transport.py`. The bridge proves the daemon's identity
//! with a signed challenge, checks that the daemon auth token belongs to the
//! same signed state, then posts the hook with the token and the proof on
//! one loopback connection inside one absolute deadline.
//!
//! Any failure is returned as an error. The native bridge never recovers or
//! retries on its own: it hands the hook to the Python bridge, which owns
//! every recovery path.

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

/// `http://{host}:{port}/v1/hooks/codex?{query}`, bracketing an IPv6 host.
fn hook_endpoint(host: &str, port: u16, query: &str) -> String {
    let rendered = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    format!("http://{rendered}:{port}/v1/hooks/codex?{query}")
}

/// One authenticated Codex hook exchange: the daemon's stripped response
/// text on HTTP 200.
pub(crate) fn authenticated_codex_hook_response(
    state_path: &Path,
    query: &str,
    data: &str,
    deadline: Instant,
) -> Result<String, BridgeError> {
    let state = authenticated_state(state_path).map_err(BridgeError::Transport)?;
    assert_loopback_http_url(&hook_endpoint(state.text("host"), state.port(), query))
        .map_err(BridgeError::Value)?;
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
    require_same_generation(
        state_path,
        &state,
        "daemon state changed during identity verification",
    )?;
    let token = daemon_auth_token(state_path, &state).map_err(BridgeError::Value)?;
    if remaining(deadline) < MINIMUM_OPERATION {
        return Err(BridgeError::Transport(
            "daemon identity challenge exhausted the hook deadline".to_owned(),
        ));
    }
    let hinted =
        with_remaining_hint(data, remaining(deadline).as_millis()).map_err(json_failure)?;
    let head = connection.post(
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
    )?;
    let body = connection.read_body(&head, deadline, HOOK_DEADLINE, HOOK_DEADLINE)?;
    if body.len() > MAX_DAEMON_RESPONSE_BYTES {
        return Err(BridgeError::Value(
            "daemon hook response is too large".to_owned(),
        ));
    }
    let text = String::from_utf8_lossy(&body);
    if head.status != 200 {
        return Err(BridgeError::Http {
            status: head.status,
            detail: py_strip(&text).to_owned(),
        });
    }
    Ok(py_strip(&text).to_owned())
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
