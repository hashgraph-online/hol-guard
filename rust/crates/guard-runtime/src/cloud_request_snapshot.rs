//! `local_request_snapshot_payload`: the bounded Cloud-safe list of local
//! approval requests. Python reads the store rows and builds each review
//! claim; every projection, bound and byte-cap decision is made here.

use serde_json::{json, Map, Value};

use super::cloud_request_payload::cloud_safe_local_request_payload;
use super::cloud_request_text::{
    py_json_len, py_truthy, set_dual_key, LOCAL_REQUEST_SNAPSHOT_MAX_LIST_ITEMS,
    LOCAL_REQUEST_SNAPSHOT_MAX_STRING_CHARS,
};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const PENDING_LIMIT: u64 = 125;
const RESOLVED_LIMIT: u64 = 25;
const MAX_BYTES: usize = 900_000;
const REQUESTS_EMPTY_BYTES: usize = 15;
const REDUCED_KEYS: [&str; 26] = [
    "localRequestId",
    "requestKind",
    "requestPayload",
    "localStatus",
    "firstSeenAt",
    "lastSeenAt",
    "resolvedAt",
    "status",
    "harness",
    "artifactId",
    "artifactName",
    "artifactType",
    "policyAction",
    "recommendedScope",
    "local_request_id",
    "rawCommandText",
    "raw_command_text",
    "commandText",
    "command_text",
    "reviewCommand",
    "actionEnvelope",
    "action_envelope_json",
    "envelopeRedacted",
    "envelope_redacted",
    "redactionEnabled",
    "redaction_enabled",
];

/// `str(value)` for the scalar column types a store row carries.
fn py_str(value: &Value) -> Result<String, &'static str> {
    match value {
        Value::String(text) => Ok(text.clone()),
        Value::Number(number) => Ok(number.to_string()),
        Value::Bool(true) => Ok("True".to_owned()),
        Value::Bool(false) => Ok("False".to_owned()),
        _ => Err(ERR_INVALID),
    }
}

fn truthy_or<'a>(value: Option<&'a Value>, fallback: &'a Value) -> &'a Value {
    value
        .filter(|candidate| py_truthy(candidate))
        .unwrap_or(fallback)
}

/// `_local_request_snapshot_routing_base`: the raw identifiers Python read
/// from the OAuth metadata or local credentials become dual-keyed fields.
fn routing_base(inputs: &Map<String, Value>) -> Map<String, Value> {
    let mut metadata = Map::new();
    for (snake, camel) in [
        ("workspace_id", "workspaceId"),
        ("machine_installation_id", "machineInstallationId"),
        ("grant_id", "grantId"),
        ("runtime_id", "runtimeId"),
    ] {
        set_dual_key(
            &mut metadata,
            snake,
            camel,
            inputs.get(snake).unwrap_or(&Value::Null),
        );
    }
    metadata
}

fn routing_metadata(
    item: &Map<String, Value>,
    base: &Map<String, Value>,
    request_id: &str,
    last_seen_at: &str,
) -> Map<String, Value> {
    let mut metadata = base.clone();
    let review = Value::String("guard-review".to_owned());
    set_dual_key(
        &mut metadata,
        "local_request_id",
        "localRequestId",
        &Value::String(request_id.to_owned()),
    );
    set_dual_key(
        &mut metadata,
        "harness_id",
        "harnessId",
        truthy_or(item.get("harness"), &review),
    );
    set_dual_key(
        &mut metadata,
        "request_last_seen_at",
        "requestLastSeenAt",
        &Value::String(last_seen_at.to_owned()),
    );
    metadata
}

fn build_items(
    rows: &[Value],
    status: &str,
    redaction_level: &str,
    base: &Map<String, Value>,
    now: &str,
) -> Result<Vec<Value>, &'static str> {
    let mut items = Vec::new();
    for entry in rows {
        let entry = args_object(entry)?;
        let item = args_object(entry.get("row").ok_or(ERR_INVALID)?)?;
        let Some(request_id) = item
            .get("request_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        else {
            continue;
        };
        let created_at = match item.get("created_at").filter(|value| py_truthy(value)) {
            Some(value) => py_str(value)?,
            None => now.to_owned(),
        };
        let last_seen_at = match item.get("last_seen_at").filter(|value| py_truthy(value)) {
            Some(value) => py_str(value)?,
            None => created_at.clone(),
        };
        let routing = routing_metadata(item, base, request_id, &last_seen_at);
        let payload = cloud_safe_local_request_payload(item, redaction_level, Some(&routing))?;
        let review = Value::String("guard-review".to_owned());
        let status = Value::String(status.to_owned());
        let resolved_at = match item.get("resolved_at") {
            Some(Value::String(text)) if !text.is_empty() => Value::String(text.clone()),
            _ => Value::Null,
        };
        let mut snapshot = Map::new();
        snapshot.insert(
            "claim".to_owned(),
            entry.get("claim").cloned().unwrap_or(Value::Null),
        );
        snapshot.insert(
            "localRequestId".to_owned(),
            Value::String(request_id.to_owned()),
        );
        snapshot.insert(
            "requestKind".to_owned(),
            Value::String(py_str(truthy_or(item.get("harness"), &review))?),
        );
        snapshot.insert("requestPayload".to_owned(), Value::Object(payload));
        snapshot.insert(
            "localStatus".to_owned(),
            Value::String(py_str(truthy_or(item.get("status"), &status))?),
        );
        snapshot.insert("firstSeenAt".to_owned(), Value::String(created_at));
        snapshot.insert("lastSeenAt".to_owned(), Value::String(last_seen_at));
        snapshot.insert("resolvedAt".to_owned(), resolved_at);
        snapshot.extend(routing);
        items.push(Value::Object(snapshot));
    }
    Ok(items)
}

fn compact_value(value: &Value) -> Value {
    match value {
        Value::String(text) if text.chars().count() > LOCAL_REQUEST_SNAPSHOT_MAX_STRING_CHARS => {
            let prefix: String = text
                .chars()
                .take(LOCAL_REQUEST_SNAPSHOT_MAX_STRING_CHARS)
                .collect();
            Value::String(format!("{prefix}...[truncated]"))
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .take(LOCAL_REQUEST_SNAPSHOT_MAX_LIST_ITEMS)
                .map(compact_value)
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), compact_value(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn compact_item(item: &Value) -> Value {
    let compact = compact_value(item);
    if py_json_len(&compact) <= MAX_BYTES {
        return compact;
    }
    let Value::Object(map) = &compact else {
        return compact;
    };
    let reduced: Map<String, Value> = REDUCED_KEYS
        .iter()
        .filter_map(|key| {
            map.get(*key)
                .map(|value| ((*key).to_owned(), value.clone()))
        })
        .collect();
    if reduced.is_empty() {
        compact
    } else {
        Value::Object(reduced)
    }
}

/// Running byte size of `{"requests": [...]}`.
fn requests_bytes(count: usize, item_bytes: usize) -> usize {
    REQUESTS_EMPTY_BYTES + item_bytes + count.saturating_sub(1)
}

struct Selection {
    items: Vec<Value>,
    item_bytes: usize,
}

impl Selection {
    fn size_with(&self, extra: usize) -> usize {
        requests_bytes(self.items.len() + 1, self.item_bytes + extra)
    }

    fn push(&mut self, item: Value, bytes: usize) {
        self.item_bytes += bytes;
        self.items.push(item);
    }
}

/// `_local_request_snapshot_byte_capped_items`; returns completeness.
fn byte_capped_items(selection: &mut Selection, items: Vec<Value>, max_bytes: usize) -> bool {
    let initial = selection.items.len();
    for item in items {
        let bytes = py_json_len(&item);
        if selection.size_with(bytes) > max_bytes {
            if selection.items.len() == initial {
                let compact = compact_item(&item);
                let compact_bytes = py_json_len(&compact);
                if selection.size_with(compact_bytes) <= max_bytes {
                    selection.push(compact, compact_bytes);
                }
            }
            return false;
        }
        selection.push(item, bytes);
    }
    true
}

fn request_max_bytes(pending: usize, resolved: usize) -> usize {
    let envelope = json!({
        "requests": [],
        "pendingComplete": false,
        "resolvedComplete": false,
        "pendingLimit": PENDING_LIMIT,
        "resolvedLimit": RESOLVED_LIMIT,
        "pendingCount": pending,
        "resolvedCount": resolved,
        "maxBytes": MAX_BYTES,
    });
    let metadata = py_json_len(&envelope).saturating_sub(REQUESTS_EMPTY_BYTES);
    MAX_BYTES.saturating_sub(metadata).max(1)
}

/// A page is either raw `rows` (built here) or `items` a caller already built
/// with `local_request_snapshot_items` (used when the raw rows would not fit in
/// one resident request).
fn page_items(
    args: &Map<String, Value>,
    key: &str,
    status: &str,
    redaction_level: &str,
    base: &Map<String, Value>,
    now: &str,
) -> Result<(Vec<Value>, bool), &'static str> {
    let page = args_object(args.get(key).ok_or(ERR_INVALID)?)?;
    let complete = page
        .get("complete")
        .and_then(Value::as_bool)
        .ok_or(ERR_INVALID)?;
    let items = match (page.get("rows"), page.get("items")) {
        (Some(rows), None) => build_items(
            rows.as_array().ok_or(ERR_INVALID)?,
            status,
            redaction_level,
            base,
            now,
        )?,
        (None, Some(items)) => items.as_array().ok_or(ERR_INVALID)?.clone(),
        _ => return Err(ERR_INVALID),
    };
    Ok((items, complete))
}

/// Kind `local_request_snapshot_items`: the pre-cap snapshot items of one chunk
/// of rows.
pub(crate) fn local_request_snapshot_items(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let redaction_level = args
        .get("redaction_level")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let base = routing_base(args_object(args.get("routing_inputs").ok_or(ERR_INVALID)?)?);
    let now = args.get("now").and_then(Value::as_str).ok_or(ERR_INVALID)?;
    let status = match args.get("status").and_then(Value::as_str) {
        Some("pending") => "pending",
        Some("resolved") => "resolved",
        _ => return Err(ERR_INVALID),
    };
    let rows = args
        .get("rows")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    Ok(json!({ "items": build_items(rows, status, redaction_level, &base, now)? }))
}

/// Kind `local_request_snapshot`.
pub(crate) fn local_request_snapshot(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let redaction_level = args
        .get("redaction_level")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let base = routing_base(args_object(args.get("routing_inputs").ok_or(ERR_INVALID)?)?);
    let now = args.get("now").and_then(Value::as_str).ok_or(ERR_INVALID)?;
    let (pending, pending_complete) =
        page_items(args, "pending", "pending", redaction_level, &base, now)?;
    let (resolved, resolved_complete) =
        page_items(args, "resolved", "resolved", redaction_level, &base, now)?;
    let (pending_count, resolved_count) = (pending.len(), resolved.len());
    let max_bytes = request_max_bytes(pending_count, resolved_count);
    let mut selection = Selection {
        items: Vec::new(),
        item_bytes: 0,
    };
    let pending_byte_complete = byte_capped_items(&mut selection, pending, max_bytes);
    let resolved_byte_complete =
        pending_byte_complete && byte_capped_items(&mut selection, resolved, max_bytes);
    Ok(json!({
        "requests": selection.items,
        "pendingComplete": pending_complete && pending_byte_complete,
        "resolvedComplete": resolved_complete && resolved_byte_complete,
        "pendingLimit": PENDING_LIMIT,
        "resolvedLimit": RESOLVED_LIMIT,
        "pendingCount": pending_count,
        "resolvedCount": resolved_count,
        "maxBytes": MAX_BYTES,
    }))
}

/// Kind `cloud_request_payload`.
pub(crate) fn cloud_request_payload(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let item = args_object(args.get("item").ok_or(ERR_INVALID)?)?;
    let level = args
        .get("redaction_level")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let routing = match args.get("routing_metadata") {
        None | Some(Value::Null) => None,
        Some(value) => Some(args_object(value)?),
    };
    cloud_safe_local_request_payload(item, level, routing)
        .map(|payload| json!({ "payload": payload }))
}
