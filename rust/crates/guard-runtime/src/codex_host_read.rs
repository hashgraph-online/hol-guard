//! Reading the public app metadata an existing Codex host holds, end to end:
//! the retired Python `read_codex_host_inventory` and cache check of
//! `runtime/codex_host_inventory.py`.
//!
//! Two requests under the `codex_host_inventory` kind:
//!
//! - `{"read": {codex_home, timeout_ms, home_dir, temp_dir}}` connects to the
//!   host's private control socket, authenticates the process on the other
//!   end, asks `app/installed` and `app/read` and answers
//!   `{"snapshot": {connection_id, apps, metadata_complete, host_pid,
//!   managed_pid, source: {target, identity}}}`. No host is listening:
//!   `{"absent": true}`. Anything the host or its identity got wrong:
//!   `{"error": code}`.
//! - `{"check": {codex_home, home_dir, temp_dir, target, identity, pid,
//!   managed_pid}}` answers `{"valid": bool}`: whether the private socket and
//!   marker still describe the host a snapshot came from.
//!
//! No host or MCP process is started, and no tool summary becomes a schema,
//! account evidence or a permission.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::codex_app_server_socket::{connect, Connection, Failure};
use crate::codex_host_inventory::{installed_apps, merge_metadata, Rows};
use crate::codex_host_probe::{
    is_codex_process, optional_managed_pid, peer_identity, socket_target, still_the_host, Pin,
    Probed, Stop, CHANGED, INVALID, UNAVAILABLE, UNTRUSTED,
};
use crate::codex_thread_continue_op::trusted_local_socket;

const LIMIT: &str = "codex_host_limit";
const TIMEOUT: &str = "codex_host_timeout";
const MAX_MESSAGES: usize = 128;
const MAX_JSON_DEPTH: usize = 32;
const MAX_TOOLS: usize = 10_000;
const PAGE: usize = 100;
/// A frame holds at most a megabyte, so no host list is wider than this.
const COLLECTION_LIMIT: usize = 1_000_000;

fn fail<T>(code: &'static str) -> Probed<T> {
    Err(Stop::Code(code))
}

/// A socket failure by the Python exception it stood for: a missing socket is
/// an absent host, a protocol breach is invalid, anything else unavailable.
fn failure_stop(failure: Failure) -> Stop {
    match failure {
        Failure::Error("FileNotFoundError") => Stop::Absent,
        Failure::Error("ValueError") => Stop::Code(INVALID),
        Failure::Timeout | Failure::Error(_) => Stop::Code(UNAVAILABLE),
    }
}

/// `check_json_depth`: brackets outside strings nest at most `MAX_JSON_DEPTH`.
fn check_depth(message: &[u8]) -> Probed<()> {
    let (mut depth, mut quoted, mut escaped) = (0_usize, false, false);
    for byte in message {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else if *byte == b'"' {
            quoted = true;
        } else if matches!(byte, b'[' | b'{') {
            depth += 1;
            if depth > MAX_JSON_DEPTH {
                return fail(LIMIT);
            }
        } else if matches!(byte, b']' | b'}') {
            depth = depth.checked_sub(1).ok_or(Stop::Code(LIMIT))?;
        }
    }
    Ok(())
}

/// One host message: text that is not JSON is unavailable, JSON the strict
/// parser refuses (a repeated key, a bare constant) is invalid.
fn parse_message(payload: &[u8]) -> Probed<Map<String, Value>> {
    let text = std::str::from_utf8(payload).map_err(|_| Stop::Code(UNAVAILABLE))?;
    if serde_json::from_str::<serde::de::IgnoredAny>(text).is_err() {
        return fail(UNAVAILABLE);
    }
    match crate::strict_json::parse_with_collection_limit(text.as_bytes(), COLLECTION_LIMIT) {
        Ok(Value::Object(message)) => Ok(message),
        _ => fail(INVALID),
    }
}

/// `_rpc`: one request and the result of the reply that carries its id.
fn rpc(
    connection: &mut Connection,
    deadline: Instant,
    method: &str,
    params: Value,
) -> Probed<Map<String, Value>> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| Stop::Code(UNAVAILABLE))?;
    let request_id = hex::encode(nonce);
    let request = json!({ "id": request_id, "method": method, "params": params });
    connection
        .send_frame(0x1, request.to_string().as_bytes())
        .map_err(failure_stop)?;
    for _ in 0..MAX_MESSAGES {
        if Instant::now() >= deadline {
            return fail(TIMEOUT);
        }
        let (opcode, payload) = connection.read_frame().map_err(failure_stop)?;
        if opcode == 0x9 {
            connection.send_frame(0xA, &payload).map_err(failure_stop)?;
            continue;
        }
        if opcode != 0x1 {
            return fail(INVALID);
        }
        check_depth(&payload)?;
        let message = parse_message(&payload)?;
        match message.get("id") {
            None if message.contains_key("method") => continue,
            Some(Value::String(id)) if *id == request_id => {}
            _ => return fail(INVALID),
        }
        if message.contains_key("error") {
            return fail(UNAVAILABLE);
        }
        return match message.get("result") {
            Some(Value::Object(result)) => Ok(result.clone()),
            _ => fail(INVALID),
        };
    }
    fail(LIMIT)
}

/// The caller's own view of where a trusted socket may live.
struct Request<'a> {
    codex_home: &'a str,
    home_dir: Option<&'a str>,
    temp_dir: Option<&'a str>,
}

impl<'a> Request<'a> {
    fn parse(request: &'a Map<String, Value>) -> Option<Self> {
        let text = |key: &str| request.get(key).and_then(Value::as_str);
        let codex_home = text("codex_home").filter(|home| Path::new(home).is_absolute())?;
        Some(Self {
            codex_home,
            home_dir: text("home_dir"),
            temp_dir: text("temp_dir"),
        })
    }

    fn socket_path(&self) -> PathBuf {
        Path::new(self.codex_home)
            .join("app-server-control")
            .join("app-server-control.sock")
    }
}

/// `hashlib.sha256` of the host's home, user, process and socket identity.
fn source_id(codex_home: &str, uid: u32, pid: u32, identity: &[u64; 4]) -> String {
    let source = json!([
        codex_home,
        uid,
        pid,
        identity[0],
        identity[1],
        identity[2],
        identity[3]
    ]);
    hex::encode(Sha256::digest(source.to_string().as_bytes()))
}

struct Snapshot {
    connection_id: String,
    apps: Vec<Value>,
    complete: bool,
    host_pid: u32,
    managed_pid: Option<u32>,
    pin: Pin,
}

/// `read_codex_host_inventory`, with the process check the caller supplies.
fn read_snapshot(
    request: &Request<'_>,
    timeout: Duration,
    process_is_codex: &dyn Fn(u32) -> Probed<bool>,
) -> Probed<Snapshot> {
    let socket_path = request.socket_path();
    let trusted = trusted_local_socket(request.home_dir, request.temp_dir);
    let pin = socket_target(&socket_path, &trusted)?;
    let expected_pid = optional_managed_pid(&socket_path)?;
    let deadline =
        Instant::now() + timeout.clamp(Duration::from_millis(100), Duration::from_secs(10));
    let stream = connect(Path::new(&pin.target), deadline).map_err(failure_stop)?;
    let peer = peer_identity(&stream)?;
    if peer.uid != nix::unistd::geteuid().as_raw()
        || expected_pid.is_some_and(|expected| expected != peer.pid)
        || !process_is_codex(peer.pid)?
    {
        return fail(UNTRUSTED);
    }
    if socket_target(&socket_path, &trusted)? != pin {
        return fail(CHANGED);
    }
    let mut connection = Connection::new(stream, deadline);
    connection.handshake().map_err(failure_stop)?;
    rpc(
        &mut connection,
        deadline,
        "initialize",
        json!({
            "clientInfo": { "name": "hol_guard_inventory", "version": "1" },
            "capabilities": { "experimentalApi": true },
        }),
    )?;
    connection
        .send_frame(0x1, br#"{"method":"initialized"}"#)
        .map_err(failure_stop)?;
    let installed = rpc(
        &mut connection,
        deadline,
        "app/installed",
        json!({ "forceRefresh": false }),
    )?;
    let mut apps = installed_apps(&installed).map_err(Stop::Code)?;
    let mut complete = true;
    for start in (0..apps.len()).step_by(PAGE) {
        let end = (start + PAGE).min(apps.len());
        let ids: Vec<Value> = apps[start..end]
            .iter()
            .filter_map(|app| app.get("app_id").cloned())
            .collect();
        let result = rpc(
            &mut connection,
            deadline,
            "app/read",
            json!({ "appIds": ids, "includeTools": true }),
        )?;
        let page: Rows = apps[start..end]
            .iter()
            .filter_map(|app| app.as_object().cloned())
            .collect();
        let (merged, page_complete) = merge_metadata(page, &result, &[]).map_err(Stop::Code)?;
        for (slot, row) in apps[start..end].iter_mut().zip(merged) {
            *slot = Value::Object(row);
        }
        complete = page_complete && complete;
        let tools: usize = apps
            .iter()
            .map(|app| {
                app.get("tools")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len)
            })
            .sum();
        if tools > MAX_TOOLS {
            return fail(LIMIT);
        }
    }
    if !still_the_host(&socket_path, &trusted, &pin, peer.pid, expected_pid)? {
        return fail(CHANGED);
    }
    drop(connection);
    if !still_the_host(&socket_path, &trusted, &pin, peer.pid, expected_pid)? {
        return fail(CHANGED);
    }
    Ok(Snapshot {
        connection_id: source_id(request.codex_home, peer.uid, peer.pid, &pin.identity),
        apps,
        complete,
        host_pid: peer.pid,
        managed_pid: expected_pid,
        pin,
    })
}

fn answer(outcome: Probed<Snapshot>) -> Value {
    match outcome {
        Ok(snapshot) => json!({ "snapshot": {
            "connection_id": snapshot.connection_id,
            "apps": snapshot.apps,
            "metadata_complete": snapshot.complete,
            "host_pid": snapshot.host_pid,
            "managed_pid": snapshot.managed_pid,
            "source": { "target": snapshot.pin.target, "identity": snapshot.pin.identity },
        } }),
        Err(Stop::Absent) => json!({ "absent": true }),
        Err(Stop::Code(code)) => json!({ "error": code }),
    }
}

/// The `read` request.
pub(crate) fn read_op(request: &Map<String, Value>) -> Value {
    let Some(parsed) = Request::parse(request) else {
        return json!({ "error": INVALID });
    };
    let timeout = Duration::from_millis(
        request
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(5000),
    );
    answer(read_snapshot(&parsed, timeout, &is_codex_process))
}

/// The `check` request: a snapshot is only current while this holds.
pub(crate) fn check_op(request: &Map<String, Value>) -> Value {
    json!({ "valid": check(request).unwrap_or(false) })
}

fn check(request: &Map<String, Value>) -> Option<bool> {
    let parsed = Request::parse(request)?;
    let target = request.get("target")?.as_str()?.to_owned();
    let identity: Vec<u64> = request
        .get("identity")?
        .as_array()?
        .iter()
        .map(Value::as_u64)
        .collect::<Option<_>>()?;
    let identity: [u64; 4] = identity.try_into().ok()?;
    let pid = u32::try_from(request.get("pid")?.as_u64()?).ok()?;
    let managed = match request.get("managed_pid")? {
        Value::Null => None,
        value => Some(u32::try_from(value.as_u64()?).ok()?),
    };
    let trusted = trusted_local_socket(parsed.home_dir, parsed.temp_dir);
    still_the_host(
        &parsed.socket_path(),
        &trusted,
        &Pin { target, identity },
        pid,
        managed,
    )
    .ok()
}

#[cfg(test)]
#[path = "codex_host_fake_host.rs"]
mod fake_host;
#[cfg(test)]
#[path = "codex_host_read_tests.rs"]
mod tests;
