//! `cloud-actions-health --stdin`: what Guard Cloud's replies to the live
//! checks behind `hol-guard cloud-actions status` and `cloud-actions doctor`
//! mean. Ported from `cli/cloud_actions_health.py` (`_decode_body`,
//! `check_service`, `check_connection` and `_classify_ping_reply`).
//!
//! A one-shot command rather than a resident kind: `cloud-actions status` is
//! a read and must not start a resident. Python still sends the requests, so
//! the Cloud actions access never reaches this command. It sends the HTTP
//! status (`null` when Guard Cloud could not be reached) and the reply body as
//! base64, read up to one byte past the limit:
//!
//! - `{"op": "service", "status", "body", "resource"}` compares the public
//!   Cloud actions description with the gateway `resource` the pairing
//!   expects;
//! - `{"op": "connection", "status", "body"}` reads the reply to the `ping`
//!   sent with the access.
//!
//! Both answer `{"state", "message"}` with `http_status` when Guard Cloud
//! answered, and the connection check adds `actions` when it accepted the
//! computer. The message never carries the reply body.

use std::io::Read;

use base64::{engine::general_purpose::STANDARD, Engine};
use guard_runtime_pyjson::{parse, PyVal};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::daemon_lifecycle_text::{py_splitlines, py_strip};

/// The reply limit, in bytes; a longer reply is not read as an answer.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// The base64 body plus the request's other members.
const MAX_REQUEST_BYTES: u64 = 128 * 1024;
const RECONNECT_COMMAND: &str = "hol-guard connect";
const PING_ID: &str = "hol-guard-status";
const INVOKE_SCOPE: &str = "gateway:invoke";
/// JSON-RPC "method not found": Guard Cloud accepted the access but serves no actions yet.
const METHOD_NOT_FOUND: &str = "-32601";
const NOT_AVAILABLE_YET: &str =
    "Guard Cloud accepted this computer. Actions are not available on this Guard Cloud yet.";

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Service {
        status: Option<u16>,
        body: String,
        resource: String,
    },
    Connection {
        status: Option<u16>,
        body: String,
    },
}

/// One check's outcome: a stable `state` code and a message safe to print.
struct Check {
    state: &'static str,
    message: String,
    http_status: Option<u16>,
    actions: Option<&'static str>,
}

impl Check {
    fn new(state: &'static str, message: impl Into<String>, http_status: Option<u16>) -> Self {
        Self {
            state,
            message: message.into(),
            http_status,
            actions: None,
        }
    }

    fn connected(status: u16, actions: &'static str) -> Self {
        let message = if actions == "available" {
            "Guard Cloud accepted this computer."
        } else {
            NOT_AVAILABLE_YET
        };
        Self {
            actions: Some(actions),
            ..Self::new("connected", message, Some(status))
        }
    }

    fn into_value(self) -> Value {
        let mut answer = Map::new();
        answer.insert("state".to_owned(), json!(self.state));
        answer.insert("message".to_owned(), json!(self.message));
        if let Some(status) = self.http_status {
            answer.insert("http_status".to_owned(), json!(status));
        }
        if let Some(actions) = self.actions {
            answer.insert("actions".to_owned(), json!(actions));
        }
        Value::Object(answer)
    }
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "cloud-actions-health"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cloud_actions_health_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("cloud_actions_health_request_too_large".to_owned());
    }
    let request: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    serde_json::to_vec(&answer(request)?)
        .map_err(|_| "cloud_actions_health_response_encode_failed".to_owned())
}

fn invalid() -> String {
    "cloud_actions_health_request_invalid".to_owned()
}

fn answer(request: Value) -> Result<Value, String> {
    let request: Request = serde_json::from_value(request).map_err(|_| invalid())?;
    let check = match request {
        Request::Service {
            status,
            body,
            resource,
        } => match status {
            None => offline(),
            Some(status) => service(status, decode_body(&body)?.as_ref(), &resource),
        },
        Request::Connection { status, body } => match status {
            None => offline(),
            Some(status) => connection(status, decode_body(&body)?.as_ref()),
        },
    };
    Ok(check.into_value())
}

fn offline() -> Check {
    Check::new("offline", "Guard Cloud could not be reached.", None)
}

/// `_decode_body`: a JSON reply, or the first JSON event of an event-stream
/// reply. `Ok(None)` when the reply is no usable answer.
fn decode_body(body: &str) -> Result<Option<PyVal>, String> {
    let raw = STANDARD.decode(body).map_err(|_| invalid())?;
    if raw.len() > MAX_RESPONSE_BYTES {
        return Ok(None);
    }
    let Ok(text) = std::str::from_utf8(&raw) else {
        return Ok(None);
    };
    if let Ok(value) = parse(text) {
        return Ok(Some(value));
    }
    let data = py_splitlines(text)
        .into_iter()
        .find_map(|line| line.strip_prefix("data:"));
    Ok(data.and_then(|data| parse(py_strip(data)).ok()))
}

/// `check_service`: Guard Cloud's public Cloud actions description against
/// what the pairing expects.
fn service(status: u16, body: Option<&PyVal>, resource: &str) -> Check {
    if status == 404 {
        return not_turned_on(status);
    }
    let Some(body) = body.filter(|body| status == 200 && body.as_dict().is_some()) else {
        return Check::new(
            "unexpected_answer",
            format!("Guard Cloud answered HTTP {status}."),
            Some(status),
        );
    };
    if body.get("resource").and_then(PyVal::as_str) != Some(resource) {
        return Check::new(
            "changed",
            "Guard Cloud now describes a different Cloud actions address.",
            Some(status),
        );
    }
    let Some(supported) = body.get("scopes_supported").and_then(PyVal::as_list) else {
        return Check::new(
            "unexpected_answer",
            "Guard Cloud did not list the Cloud actions permissions.",
            Some(status),
        );
    };
    if !supported
        .iter()
        .any(|scope| scope.as_str() == Some(INVOKE_SCOPE))
    {
        return Check::new(
            "changed",
            "Guard Cloud no longer offers Cloud actions to AI tools.",
            Some(status),
        );
    }
    Check::new("current", "Guard Cloud offers Cloud actions.", Some(status))
}

/// `check_connection`: the reply to the `ping` sent with Cloud actions access.
fn connection(status: u16, body: Option<&PyVal>) -> Check {
    if (200..300).contains(&status) {
        return ping_reply(status, body);
    }
    if status == 501 && body.is_some_and(method_not_found) {
        return Check::connected(status, "not_available_yet");
    }
    match status {
        401 => Check::new(
            "reconnect",
            format!("Guard Cloud no longer accepts this computer. Run {RECONNECT_COMMAND}."),
            Some(status),
        ),
        403 => Check::new(
            "not_permitted",
            "Guard Cloud accepted this computer, but this member may not use Cloud actions.",
            Some(status),
        ),
        400 => Check::new(
            "workspace_mismatch",
            "Guard Cloud refused the workspace this computer is connected to.",
            Some(status),
        ),
        404 => not_turned_on(status),
        _ => Check::new(
            "unexpected_answer",
            format!("Guard Cloud answered HTTP {status}."),
            Some(status),
        ),
    }
}

fn not_turned_on(status: u16) -> Check {
    Check::new(
        "not_turned_on",
        "Cloud actions are not turned on for this Guard Cloud.",
        Some(status),
    )
}

/// `_classify_ping_reply`: a success status alone proves nothing, since a
/// proxy page or an error inside HTTP 200 is not a ping reply.
fn ping_reply(status: u16, body: Option<&PyVal>) -> Check {
    if let Some(body) =
        body.filter(|body| body.get("jsonrpc").and_then(PyVal::as_str) == Some("2.0"))
    {
        let reply_id = body.get("id").filter(|id| **id != PyVal::Null);
        if body.get("result").is_some() && reply_id.and_then(PyVal::as_str) == Some(PING_ID) {
            return Check::connected(status, "available");
        }
        if method_not_found(body) && reply_id.is_none_or(|id| id.as_str() == Some(PING_ID)) {
            return Check::connected(status, "not_available_yet");
        }
    }
    Check::new(
        "unexpected_answer",
        format!("Guard Cloud answered HTTP {status} without a Cloud actions reply."),
        Some(status),
    )
}

/// `_rpc_error_code(body) == -32601`, where Python's `==` also matches the float.
fn method_not_found(body: &PyVal) -> bool {
    match body.get("error").and_then(|error| error.get("code")) {
        Some(PyVal::Int(digits)) => digits == METHOD_NOT_FOUND,
        Some(PyVal::Float(number)) => *number == -32601.0,
        _ => false,
    }
}

#[cfg(test)]
#[path = "cloud_actions_health_tests.rs"]
mod tests;
