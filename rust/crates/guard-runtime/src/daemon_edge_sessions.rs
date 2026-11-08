//! `POST /v1/initialize`, `/v1/sessions/start`, `/v1/operations/start` and
//! `/v1/operations/<id>/items` and `/status`, written as the daemon's surface
//! runtime writes them: the same store rows, `guard_events` payloads in
//! Python's key order and `json.dumps` text, and the same answers.
//!
//! Every check runs before the first write, so a request the edge cannot
//! finish goes to the daemon untouched. A store failure after a write leaves
//! the connection unanswered, as the daemon's handler does when the same
//! store call raises.

use serde_json::{json, Value};

use super::super::{NativeReads, ReadConfig};
use super::{now_isoformat, DROPPED};
use crate::guard_store_guard_event::dumps;
use crate::pyjson::{self, PyVal};

type Dict = [(String, PyVal)];

/// `_guard_session_row`.
const SESSION: &[(&str, Column)] = &[
    ("session_id", Column::Text),
    ("harness", Column::Text),
    ("surface", Column::Text),
    ("status", Column::Text),
    ("client_name", Column::Text),
    ("client_title", Column::Optional),
    ("client_version", Column::Optional),
    ("workspace", Column::Optional),
    ("capabilities", Column::Json("capabilities_json")),
    ("created_at", Column::Text),
    ("updated_at", Column::Text),
];
/// `_guard_operation_row`.
const OPERATION: &[(&str, Column)] = &[
    ("operation_id", Column::Text),
    ("session_id", Column::Text),
    ("harness", Column::Text),
    ("operation_type", Column::Text),
    ("status", Column::Text),
    (
        "approval_request_ids",
        Column::Json("approval_request_ids_json"),
    ),
    ("resume_token", Column::Optional),
    ("metadata", Column::Json("metadata_json")),
    ("created_at", Column::Text),
    ("updated_at", Column::Text),
];
/// `_guard_item_row`.
const ITEM: &[(&str, Column)] = &[
    ("item_id", Column::Text),
    ("operation_id", Column::Text),
    ("item_type", Column::Text),
    ("lifecycle", Column::Text),
    ("payload", Column::Json("payload_json")),
    ("created_at", Column::Text),
];

enum Column {
    Text,
    Optional,
    Json(&'static str),
}

pub(super) enum Route<'a> {
    Initialize,
    SessionStart,
    OperationStart,
    Item(&'a str),
    Status(&'a str),
}

impl<'a> Route<'a> {
    /// The routes the daemon's `do_POST` sends to these handlers. An
    /// operation path with any other shape goes to the daemon.
    pub(super) fn parse(method: &str, path: &'a str) -> Option<Self> {
        if method != "POST" {
            return None;
        }
        match path {
            "/v1/initialize" => return Some(Self::Initialize),
            "/v1/sessions/start" => return Some(Self::SessionStart),
            "/v1/operations/start" => return Some(Self::OperationStart),
            _ => {}
        }
        let (operation_id, action) = path.strip_prefix("/v1/operations/")?.split_once('/')?;
        if operation_id.is_empty() {
            return None;
        }
        match action {
            "items" => Some(Self::Item(operation_id)),
            "status" => Some(Self::Status(operation_id)),
            _ => None,
        }
    }
}

pub(super) fn respond(
    route: &Route<'_>,
    payload: &Dict,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value)> {
    let writer = Writer { config, reads };
    match route {
        Route::Initialize => initialize::respond(payload, config, reads),
        Route::SessionStart => writer.start_session(payload),
        Route::OperationStart => writer.start_operation(payload),
        Route::Item(operation_id) => writer.add_item(operation_id, payload),
        Route::Status(operation_id) => writer.update_status(operation_id, payload),
    }
}

struct Writer<'a> {
    config: &'a ReadConfig,
    reads: &'a NativeReads,
}

impl Writer<'_> {
    /// `_handle_session_start` and `start_session`.
    fn start_session(&self, payload: &Dict) -> Option<(u16, Value)> {
        let (Some(harness), Some(surface), Some(client_name)) = (
            optional_string(payload, "harness"),
            optional_string(payload, "surface"),
            optional_string(payload, "client_name"),
        ) else {
            return missing_fields();
        };
        let capabilities = match get(payload, "capabilities") {
            Some(PyVal::List(items)) => strings(items),
            _ => PyVal::List(Vec::new()),
        };
        let row = self.call(
            "upsert_guard_session",
            json!({
                "session_id": uuid4_hex()?,
                "harness": harness,
                "surface": surface,
                "status": "active",
                "client_name": client_name,
                "client_title": optional_string(payload, "client_title"),
                "client_version": optional_string(payload, "client_version"),
                "workspace": optional_string(payload, "workspace"),
                "capabilities_json": dumps(&capabilities)?,
                "now": now_isoformat()?,
            }),
        )?;
        written(|| {
            let session = shaped(&row, SESSION)?;
            self.add_event("session/started", "session", &session)?;
            Some((200, session.to_json()?))
        })
    }

    /// `_handle_operation_start` and `start_operation`.
    fn start_operation(&self, payload: &Dict) -> Option<(u16, Value)> {
        let (Some(session_id), Some(operation_type), Some(harness)) = (
            optional_string(payload, "session_id"),
            optional_string(payload, "operation_type"),
            optional_string(payload, "harness"),
        ) else {
            return missing_fields();
        };
        let metadata = match get(payload, "metadata") {
            Some(metadata @ PyVal::Dict(_)) => metadata.clone(),
            _ => PyVal::Dict(Vec::new()),
        };
        if !plain(&metadata) {
            return None;
        }
        if self.session(&session_id)?.is_none() {
            return unknown_session(&session_id);
        }
        let row = self.call(
            "upsert_guard_operation",
            json!({
                "operation_id": uuid4_hex()?,
                "session_id": session_id,
                "harness": harness,
                "operation_type": operation_type,
                "status": "started",
                "approval_request_ids_json": "[]",
                "resume_token": null,
                "metadata_json": dumps(&metadata)?,
                "now": now_isoformat()?,
            }),
        )?;
        written(|| {
            let operation = shaped(&row, OPERATION)?;
            // `_set_session_status(session_id, "active")`.
            let Some(session) = self.session(&session_id)? else {
                return unknown_session(&session_id);
            };
            let capabilities = match session.get("capabilities")? {
                PyVal::List(items) => strings(items),
                _ => PyVal::List(Vec::new()),
            };
            self.call(
                "upsert_guard_session",
                json!({
                    "session_id": session_id,
                    "harness": session.get("harness")?.to_json()?,
                    "surface": session.get("surface")?.to_json()?,
                    "status": "active",
                    "client_name": session.get("client_name")?.to_json()?,
                    "client_title": session.get("client_title")?.to_json()?,
                    "client_version": session.get("client_version")?.to_json()?,
                    "workspace": session.get("workspace")?.to_json()?,
                    "capabilities_json": dumps(&capabilities)?,
                    "now": now_isoformat()?,
                }),
            )?;
            self.add_event("operation/started", "operation", &operation)?;
            Some((200, operation.to_json()?))
        })
    }

    /// `_handle_operation_item` and `add_item`.
    fn add_item(&self, operation_id: &str, payload: &Dict) -> Option<(u16, Value)> {
        let (Some(item_type), Some(item_payload @ PyVal::Dict(_))) = (
            optional_string(payload, "item_type"),
            get(payload, "payload"),
        ) else {
            return missing_fields();
        };
        if !plain(item_payload) {
            return None;
        }
        if self.operation(operation_id)?.is_none() {
            return unknown_operation(operation_id);
        }
        let row = self.call(
            "add_guard_operation_item",
            json!({
                "item_id": uuid4_hex()?,
                "operation_id": operation_id,
                "item_type": item_type,
                "lifecycle": "completed",
                "payload_json": dumps(item_payload)?,
                "now": now_isoformat()?,
            }),
        )?;
        written(|| {
            let item = shaped(&row, ITEM)?;
            self.add_event("item/completed", "item", &item)?;
            Some((200, json!({ "item": item.to_json()? })))
        })
    }

    /// `_handle_operation_status` and `update_operation_status`.
    fn update_status(&self, operation_id: &str, payload: &Dict) -> Option<(u16, Value)> {
        let Some(status) = optional_string(payload, "status") else {
            return missing_fields();
        };
        let Some(current) = self.operation(operation_id)? else {
            return unknown_operation(operation_id);
        };
        let metadata = match current.get("metadata")? {
            metadata @ PyVal::Dict(_) => metadata.clone(),
            _ => PyVal::Dict(Vec::new()),
        };
        let waiting = status == "waiting_on_approval";
        let (request_ids, resume_token, event_name) = if waiting {
            let request_ids = match get(payload, "approval_request_ids") {
                Some(PyVal::List(items)) => strings(items),
                _ => PyVal::List(Vec::new()),
            };
            let resume_token = Value::from(uuid4_hex()?);
            (request_ids, resume_token, "operation/waitingApproval")
        } else {
            let request_ids = match current.get("approval_request_ids")? {
                ids @ PyVal::List(_) => ids.clone(),
                _ => PyVal::List(Vec::new()),
            };
            let resume_token = current.get("resume_token")?.to_json()?;
            let event_name = if matches!(status.as_str(), "completed" | "blocked" | "failed") {
                "operation/completed"
            } else {
                "operation/resumed"
            };
            (request_ids, resume_token, event_name)
        };
        if !plain(&metadata) || !plain(&request_ids) {
            return None;
        }
        let row = self.call(
            "upsert_guard_operation",
            json!({
                "operation_id": operation_id,
                "session_id": current.get("session_id")?.to_json()?,
                "harness": current.get("harness")?.to_json()?,
                "operation_type": current.get("operation_type")?.to_json()?,
                "status": status,
                "approval_request_ids_json": dumps(&request_ids)?,
                "resume_token": resume_token,
                "metadata_json": dumps(&metadata)?,
                "now": now_isoformat()?,
            }),
        )?;
        written(|| {
            let operation = shaped(&row, OPERATION)?;
            self.add_event(event_name, "operation", &operation)?;
            Some((200, json!({ "operation": operation.to_json()? })))
        })
    }

    fn call(&self, method: &str, args: Value) -> Option<Value> {
        self.reads.store_call(self.config, method, args)
    }

    /// `get_guard_session`, shaped; `Some(None)` when there is none.
    fn session(&self, session_id: &str) -> Option<Option<PyVal>> {
        let row = self.call("get_guard_session", json!({ "session_id": session_id }))?;
        optional_row(&row, SESSION)
    }

    /// `get_guard_operation`, shaped; `Some(None)` when there is none.
    fn operation(&self, operation_id: &str) -> Option<Option<PyVal>> {
        let row = self.call(
            "get_guard_operation",
            json!({ "operation_id": operation_id }),
        )?;
        optional_row(&row, OPERATION)
    }

    /// `add_event(event_name, {key: value}, _now())`.
    fn add_event(&self, event_name: &str, key: &str, value: &PyVal) -> Option<()> {
        let payload = PyVal::Dict(vec![(key.to_owned(), value.clone())]);
        self.call(
            "add_event",
            json!({
                "event_name": event_name,
                "payload_json": dumps(&payload)?,
                "occurred_at": now_isoformat()?,
            }),
        )?;
        Some(())
    }
}

/// The answer once a write has landed. A step that fails from here on is one
/// the daemon would raise on, so the connection closes unanswered.
fn written(rest: impl FnOnce() -> Option<(u16, Value)>) -> Option<(u16, Value)> {
    Some(rest().unwrap_or((DROPPED, Value::Null)))
}

fn missing_fields() -> Option<(u16, Value)> {
    Some((400, json!({"error": "missing_required_fields"})))
}

fn unknown_session(session_id: &str) -> Option<(u16, Value)> {
    Some((
        400,
        json!({ "error": format!("Unknown guard session: {session_id}") }),
    ))
}

fn unknown_operation(operation_id: &str) -> Option<(u16, Value)> {
    Some((
        400,
        json!({ "error": format!("Unknown guard operation: {operation_id}") }),
    ))
}

fn get<'p>(payload: &'p Dict, key: &str) -> Option<&'p PyVal> {
    payload
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

/// `_optional_string`: the text stripped as `str.strip()` strips it, or
/// `None` for anything else or nothing left.
fn optional_string(payload: &Dict, key: &str) -> Option<String> {
    let PyVal::Str(text) = get(payload, key)? else {
        return None;
    };
    let stripped =
        text.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c));
    (!stripped.is_empty()).then(|| stripped.to_owned())
}

/// `[str(item) for item in items if isinstance(item, str)]`.
fn strings(items: &[PyVal]) -> PyVal {
    PyVal::List(
        items
            .iter()
            .filter(|item| matches!(item, PyVal::Str(_)))
            .cloned()
            .collect(),
    )
}

/// A value whose wire form the edge writes exactly as the daemon does: no
/// float, whose spelling Python chooses its own way, and no integer past the
/// 64-bit range.
fn plain(value: &PyVal) -> bool {
    match value {
        PyVal::Float(_) => false,
        PyVal::Int(digits) => digits.parse::<i64>().is_ok() || digits.parse::<u64>().is_ok(),
        PyVal::List(items) => items.iter().all(plain),
        PyVal::Dict(entries) => entries.iter().all(|(_, value)| plain(value)),
        _ => true,
    }
}

fn optional_row(row: &Value, columns: &[(&str, Column)]) -> Option<Option<PyVal>> {
    if row.is_null() {
        return Some(None);
    }
    shaped(row, columns).map(Some)
}

/// A store row in the daemon's key order, its JSON columns read as
/// `json.loads` reads them.
fn shaped(row: &Value, columns: &[(&str, Column)]) -> Option<PyVal> {
    let row = row.as_object()?;
    let mut entries = Vec::with_capacity(columns.len());
    for (name, column) in columns {
        let value = match (column, row.get(*name)) {
            (Column::Optional, Some(Value::Null)) => PyVal::Null,
            (Column::Text | Column::Optional, Some(Value::String(text))) => {
                PyVal::Str(text.clone())
            }
            (Column::Json(source), _) => loads(row.get(*source)?.as_str()?)?,
            _ => return None,
        };
        entries.push(((*name).to_owned(), value));
    }
    Some(PyVal::Dict(entries))
}

/// `json.loads`, for text whose Python value the edge holds exactly.
fn loads(text: &str) -> Option<PyVal> {
    let parsed = pyjson::parse_mapping_lone_surrogates(text).ok()?;
    (!parsed.mapped && !parsed.collision).then_some(parsed.value)
}

/// `uuid.uuid4().hex`.
fn uuid4_hex() -> Option<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).ok()?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Some(hex::encode(bytes))
}

#[path = "daemon_edge_initialize.rs"]
mod initialize;

#[cfg(test)]
#[path = "daemon_edge_sessions_tests.rs"]
mod tests;
