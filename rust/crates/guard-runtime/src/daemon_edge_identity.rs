//! `POST /v1/daemon/identity-challenge`: the daemon proves who it is to a hook
//! bridge on one loopback connection, then reads the hook that redeems the
//! proof on that same connection (`_handle_daemon_identity_challenge` and
//! `_consume_codex_daemon_challenge`).
//!
//! The proof is bound to the connection, so only the process that holds the
//! socket can redeem it. The hook it redeems is answered by the daemon's own
//! handler through the CLI, told that the proof checked out.

use std::io::Write;
use std::net::{Shutdown, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

use super::super::http::parse_request;
use super::super::replay;
use super::{json_response, write_answer, NativeReads, Outcome, ReadConfig};
use crate::claude_hook_bridge_auth::{authenticated_state, json_int, sign_discovery_payload};
use crate::claude_hook_bridge_render::py_strip;
use crate::resident_transport::constant_time_eq;

pub(in crate::daemon_edge) const CHALLENGE_PATH: &str = "/v1/daemon/identity-challenge";
/// The hook routes a challenge proof can authenticate (`CHALLENGE_HOOK_PATHS`).
const HOOK_PATHS: [&str; 2] = ["/v1/hooks/codex", "/v1/hooks/claude-code"];
const PROTOCOL_VERSION: i64 = 1;
/// `DAEMON_DISCOVERY_CHALLENGE_TTL_SECONDS`.
const CHALLENGE_TTL: Duration = Duration::from_secs(5);
const MAX_HOOK_EVENT_CHARS: usize = 128;
const STATE_FILE: &str = "daemon-state.json";

/// The status and error a challenge is refused with.
type Refusal = (u16, &'static str);

/// One issued challenge, waiting for its hook on the same connection.
struct Issued {
    nonce: String,
    proof: String,
    hook_event: String,
    expires: Instant,
}

/// Answers the challenge on `client`, then serves the request that follows it
/// on the same connection.
pub(in crate::daemon_edge) fn serve(
    client: &TcpStream,
    body: &[u8],
    config: &ReadConfig,
    reads: &NativeReads,
    stalled_write: Duration,
) -> Outcome {
    let issued = match issue(client, body, config, reads) {
        Ok((issued, response)) => {
            if !write_keep_alive(client, &response, stalled_write) {
                let _ = client.shutdown(Shutdown::Both);
                return Outcome::Answered;
            }
            reads.report_activity();
            issued
        }
        Err((status, error)) => {
            let response = json_response(
                status,
                &serde_json::json!({ "error": error }),
                config.dashboard_build.as_deref(),
                None,
                false,
            );
            return write_answer(client, &response, reads, stalled_write);
        }
    };
    let Some(request) = replay::read_request(client, CHALLENGE_TTL) else {
        let _ = client.shutdown(Shutdown::Both);
        return Outcome::Answered;
    };
    let verified = redeems(&request, &issued);
    if verified {
        if let Some(response) = direct_answer(&request, config) {
            return write_answer(client, &response, reads, stalled_write);
        }
    }
    if let Some(response) = reviewed_answer(client, &request, config, reads, verified) {
        return write_answer(client, &response, reads, stalled_write);
    }
    replay::replay_with(
        client,
        config,
        request,
        stalled_write,
        reads.daemon_pid(),
        verified,
    );
    reads.report_activity();
    Outcome::Answered
}

/// The signed challenge answer, or the status and error the daemon refuses
/// the challenge with.
fn issue(
    client: &TcpStream,
    body: &[u8],
    config: &ReadConfig,
    reads: &NativeReads,
) -> Result<(Issued, Map<String, Value>), Refusal> {
    const INVALID: Refusal = (400, "invalid_daemon_identity_challenge");
    let payload: Map<String, Value> = serde_json::from_slice(body).map_err(|_| INVALID)?;
    let text = |field: &str| payload.get(field).and_then(Value::as_str);
    let nonce = text("nonce")
        .filter(|nonce| nonce.len() == 64 && nonce.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or(INVALID)?;
    let hook_event = text("hook_event")
        .filter(|event| event.chars().count() <= MAX_HOOK_EVENT_CHARS)
        .ok_or(INVALID)?;
    let state_id = text("state_id").ok_or(INVALID)?;
    if json_int(payload.get("protocol_version")) != Some(i128::from(PROTOCOL_VERSION))
        || payload
            .get("protocol_version")
            .is_some_and(Value::is_boolean)
    {
        return Err(INVALID);
    }
    let state = authenticated_state(&Path::new(&config.guard_home).join(STATE_FILE))
        .map_err(|_| (503, "daemon_identity_unavailable"))?;
    let local = client
        .local_addr()
        .map_err(|_| (503, "daemon_identity_unavailable"))?;
    let field = |name: &str| state.payload.get(name);
    let matches = field("state_id").and_then(Value::as_str) == Some(state_id)
        && field("host").and_then(Value::as_str) == Some(local.ip().to_string().as_str())
        && json_int(field("port")) == Some(i128::from(local.port()))
        && json_int(field("pid")) == Some(i128::from(reads.daemon_pid()));
    if !matches {
        return Err((409, "daemon_identity_state_mismatch"));
    }
    let issued_at_ms = now_ms();
    let expires_at_ms = issued_at_ms + CHALLENGE_TTL.as_millis() as i64;
    let mut response = Map::new();
    response.insert("protocol_version".into(), PROTOCOL_VERSION.into());
    response.insert("nonce".into(), nonce.into());
    for name in [
        "state_id",
        "host",
        "port",
        "pid",
        "started_at",
        "guard_home",
    ] {
        response.insert(name.into(), field(name).cloned().unwrap_or(Value::Null));
    }
    response.insert("hook_event".into(), hook_event.into());
    response.insert("issued_at_ms".into(), issued_at_ms.into());
    response.insert("expires_at_ms".into(), expires_at_ms.into());
    let proof = sign_discovery_payload(&state.key, &response)
        .map_err(|_| (503, "daemon_identity_unavailable"))?;
    response.insert("proof".into(), proof.clone().into());
    let issued = Issued {
        nonce: nonce.to_owned(),
        proof,
        hook_event: hook_event.to_owned(),
        expires: Instant::now() + CHALLENGE_TTL,
    };
    Ok((issued, response))
}

/// Whether `request` is a hook that presents the proof just issued for its
/// own event, before the proof expired.
fn redeems(request: &[u8], issued: &Issued) -> bool {
    if Instant::now() > issued.expires {
        return false;
    }
    let Some(head_len) = replay::find_head_end(request) else {
        return false;
    };
    let Some(head) = parse_request(&request[..head_len]) else {
        return false;
    };
    if head.method != "POST" || !HOOK_PATHS.contains(&head.path) {
        return false;
    }
    let (Some(nonce), Some(proof)) = (
        head.single_header("X-Guard-Daemon-Nonce"),
        head.single_header("X-Guard-Daemon-Proof"),
    ) else {
        return false;
    };
    if nonce != issued.nonce || !constant_time_eq(proof.as_bytes(), issued.proof.as_bytes()) {
        return false;
    }
    let Ok(Value::Object(body)) = serde_json::from_slice::<Value>(&request[head_len..]) else {
        return false;
    };
    let event = body
        .get("hook_event_name")
        .or_else(|| body.get("event"))
        .and_then(Value::as_str);
    event.is_some_and(|event| py_strip(event) == issued.hook_event)
}

/// The resident's answer to the redeemed hook, or `None` for the daemon's
/// own handler.
fn direct_answer(request: &[u8], config: &ReadConfig) -> Option<Vec<u8>> {
    let head_len = replay::find_head_end(request)?;
    let head = parse_request(&request[..head_len])?;
    super::direct_hook::respond(&head, &request[head_len..], config)
}

/// The daemon's own review of the hook that followed the challenge, told
/// whether it redeemed the proof.
fn reviewed_answer(
    client: &TcpStream,
    request: &[u8],
    config: &ReadConfig,
    reads: &NativeReads,
    verified: bool,
) -> Option<Vec<u8>> {
    let head_len = replay::find_head_end(request)?;
    let head = parse_request(&request[..head_len])?;
    let port = client.local_addr().ok()?.port();
    super::hook_review::respond(&head, &request[head_len..], port, config, reads, verified)
}

/// Writes the challenge answer as an HTTP/1.1 response the client can reuse
/// its connection after, as the daemon does for this one request.
fn write_keep_alive(
    client: &TcpStream,
    body: &Map<String, Value>,
    stalled_write: Duration,
) -> bool {
    let encoded = serde_json::to_vec(&Value::Object(body.clone())).unwrap_or_default();
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\n\r\n",
        encoded.len()
    )
    .into_bytes();
    response.extend_from_slice(&encoded);
    let _ = client.set_write_timeout(Some(stalled_write));
    let mut writer = client;
    writer.write_all(&response).is_ok()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or_default()
}
