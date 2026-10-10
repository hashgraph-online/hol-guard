//! Appending an immutable request-snapshot event to the Review outbox.

use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_db::{exec, int, query_one, value_error, Row, StoreError, StoreResult};
use crate::guard_store_json::{dumps_sorted, py_strip, Separators};
use crate::guard_store_outbox_binding::load_binding;
use crate::guard_store_outbox_decode::{
    EVENT_SCHEMA_NAME, EVENT_SCHEMA_VERSION, SNAPSHOT_COLUMNS, SNAPSHOT_JSON_FIELDS,
};
use crate::guard_store_outbox_identity::payload_digest;

const UNREPRESENTABLE: StoreError = StoreError::Invalid("native_guard_store_value_unrepresentable");

/// Delivery identity columns as stored (each may be NULL).
pub(crate) type StoredIdentity = [Value; 4];

fn complete(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|text| !py_strip(text).is_empty())
}

/// Binding, status and quarantine reason an appended event must carry.
fn binding_for_append(
    connection: &Connection,
    request_id: &str,
    source: &str,
) -> StoreResult<(StoredIdentity, &'static str, Option<&'static str>)> {
    let current = load_binding(connection, source)?;
    let prior = query_one(
        connection,
        "select oauth_subject_hash, workspace_id, machine_id, machine_installation_id \
         from guard_review_outbox_request_sequences where local_request_id = ?",
        &[Value::from(request_id)],
    )?;
    let from_binding = |binding: &crate::guard_store_outbox_binding::Binding| -> StoredIdentity {
        let values = binding.values();
        [
            values[0].clone(),
            values[1].clone(),
            values[2].clone(),
            values[3].clone(),
        ]
    };
    let Some(prior) = prior else {
        return Ok(match current {
            Some(binding) => (from_binding(&binding), "ready", None),
            None => (
                [Value::Null, Value::Null, Value::Null, Value::Null],
                "quarantined",
                Some("identity_incomplete"),
            ),
        });
    };
    let null = Value::Null;
    let values: StoredIdentity = [
        "oauth_subject_hash",
        "workspace_id",
        "machine_id",
        "machine_installation_id",
    ]
    .map(|name| prior.get(name).unwrap_or(&null).clone());
    if !values.iter().all(complete) {
        return Ok((values, "quarantined", Some("identity_incomplete")));
    }
    match current {
        Some(binding)
            if values[0].as_str() == Some(binding.subject_hash.as_str())
                && values[1].as_str() == Some(binding.workspace_id.as_str()) =>
        {
            Ok((from_binding(&binding), "ready", None))
        }
        _ => Ok((
            values,
            "quarantined",
            Some("identity_changed_requires_confirmation"),
        )),
    }
}

/// Canonical immutable event payload from a complete request row.
fn payload_json(
    request: &Map<String, Value>,
    event_type: &str,
    occurred_at: &str,
    native_replay: bool,
) -> StoreResult<String> {
    let missing: Vec<&str> = SNAPSHOT_COLUMNS
        .iter()
        .copied()
        .filter(|name| !request.contains_key(*name))
        .collect();
    if !missing.is_empty() {
        return value_error(&format!(
            "Review request snapshot is missing columns: {}",
            missing.join(", ")
        ));
    }
    let snapshot: Map<String, Value> = SNAPSHOT_COLUMNS
        .iter()
        .map(|name| ((*name).to_owned(), request[*name].clone()))
        .collect();
    let mut payload = Map::new();
    payload.insert("schema".into(), Value::from(EVENT_SCHEMA_NAME));
    payload.insert("localRequestId".into(), request["request_id"].clone());
    payload.insert("eventType".into(), Value::from(event_type));
    payload.insert("occurredAt".into(), Value::from(occurred_at));
    for (key, column) in [
        ("status", "status"),
        ("resolutionAction", "resolution_action"),
        ("resolutionScope", "resolution_scope"),
        ("reason", "reason"),
        ("oauthSource", "oauth_source"),
    ] {
        payload.insert(key.into(), request[column].clone());
    }
    payload.insert("requestSnapshot".into(), Value::Object(snapshot));
    if event_type == "review.request.snapshot_requeued" {
        payload.insert("nativeReplay".into(), Value::Bool(native_replay));
    }
    dumps_sorted(&Value::Object(payload), Separators::Compact).ok_or(UNREPRESENTABLE)
}

#[cfg(test)]
thread_local! {
    /// Parity vectors freeze `uuid4` to a counter recorded from the Python store.
    pub(crate) static TEST_EVENT_ID_COUNTER: std::cell::Cell<Option<u128>> =
        const { std::cell::Cell::new(None) };
}

fn uuid4_hex() -> StoreResult<String> {
    #[cfg(test)]
    if let Some(next) = TEST_EVENT_ID_COUNTER.with(std::cell::Cell::get) {
        TEST_EVENT_ID_COUNTER.with(|counter| counter.set(Some(next + 1)));
        return Ok(format!("{next:032x}"));
    }
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|_| StoreError::Invalid("native_guard_store_random_failed"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(hex::encode(bytes))
}

/// Append a request snapshot without replacing any unacknowledged event.
/// Returns the number of events appended (0 or 1).
pub(crate) fn append_request_snapshot_event(
    connection: &Connection,
    request_id: &str,
    source: &str,
    event_type: &str,
    occurred_at: &str,
    request_snapshot: Option<&Map<String, Value>>,
    native_replay: bool,
) -> StoreResult<i64> {
    let request: Map<String, Value> = match request_snapshot {
        None => {
            let Some(row) = query_one(
                connection,
                "select * from approval_requests where request_id = ?",
                &[Value::from(request_id)],
            )?
            else {
                return Ok(0);
            };
            row
        }
        Some(snapshot) => {
            let mut request = snapshot.clone();
            if request.get("request_id").and_then(Value::as_str) != Some(request_id) {
                return Ok(0);
            }
            for field in SNAPSHOT_JSON_FIELDS {
                if matches!(request.get(field), Some(Value::Object(_) | Value::Array(_))) {
                    let text = dumps_sorted(&request[field], Separators::Compact)
                        .ok_or(UNREPRESENTABLE)?;
                    request.insert(field.to_owned(), Value::String(text));
                }
            }
            request
        }
    };
    let (values, binding_status, quarantine_reason) =
        binding_for_append(connection, request_id, source)?;
    let payload = payload_json(&request, event_type, occurred_at, native_replay)?;
    let [subject, workspace, machine, installation] = &values;
    exec(
        connection,
        "insert into guard_review_outbox_request_sequences (\
         local_request_id, last_sequence, updated_at, oauth_source, \
         oauth_subject_hash, workspace_id, machine_id, machine_installation_id \
         ) values (?, 1, ?, ?, ?, ?, ?, ?) \
         on conflict(local_request_id) do update set \
         last_sequence = guard_review_outbox_request_sequences.last_sequence + 1, \
         updated_at = excluded.updated_at, \
         oauth_source = coalesce(guard_review_outbox_request_sequences.oauth_source, excluded.oauth_source), \
         oauth_subject_hash = coalesce(guard_review_outbox_request_sequences.oauth_subject_hash, excluded.oauth_subject_hash), \
         workspace_id = coalesce(guard_review_outbox_request_sequences.workspace_id, excluded.workspace_id), \
         machine_id = coalesce(guard_review_outbox_request_sequences.machine_id, excluded.machine_id), \
         machine_installation_id = coalesce(guard_review_outbox_request_sequences.machine_installation_id, excluded.machine_installation_id)",
        &[
            Value::from(request_id),
            Value::from(occurred_at),
            Value::from(source),
            subject.clone(),
            workspace.clone(),
            machine.clone(),
            installation.clone(),
        ],
    )?;
    let sequence: Option<Row> = query_one(
        connection,
        "select last_sequence from guard_review_outbox_request_sequences where local_request_id = ?",
        &[Value::from(request_id)],
    )?;
    let Some(sequence) = sequence else {
        return Err(StoreError::Invalid(
            "native_guard_store_sequence_allocation_failed",
        ));
    };
    let source_value = Value::from(source);
    let digest = payload_digest(
        &payload,
        [&source_value, subject, workspace, machine, installation],
    );
    let inserted = exec(
        connection,
        "insert into guard_review_outbox_events (\
         event_id, local_request_id, request_sequence, event_type, event_schema_version, \
         payload_json, payload_hash, occurred_at, oauth_source, oauth_subject_hash, \
         workspace_id, machine_id, machine_installation_id, binding_status, quarantine_reason \
         ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &[
            Value::from(uuid4_hex()?),
            Value::from(request_id),
            Value::from(int(&sequence, "last_sequence")),
            Value::from(event_type),
            Value::from(EVENT_SCHEMA_VERSION),
            Value::from(payload),
            Value::from(digest),
            Value::from(occurred_at),
            source_value,
            subject.clone(),
            workspace.clone(),
            machine.clone(),
            installation.clone(),
            Value::from(binding_status),
            quarantine_reason.map_or(Value::Null, Value::from),
        ],
    )?;
    Ok(inserted.max(0))
}
