//! Local Review event outbox — sequencing, OAuth binding, requeue, retry, and
//! acknowledgment.
//!
//! Consolidates `store_review_event_outbox.py` (orchestrator),
//! `store_review_event_outbox_binding.py`, `store_review_event_outbox_writes.py`,
//! `store_review_event_sequence_recovery.py` (constants), and
//! `store_review_event_acknowledgment.py`. All durable work runs against an
//! injected `&mut dyn Connection` inside a `BEGIN IMMEDIATE` transaction the
//! host opens; `guard-command` owns no rusqlite dependency.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::review_event_outbox_schema::{
    review_event_payload_digest, review_event_payload_json, Connection, DbRow,
    REVIEW_EVENT_SCHEMA_VERSION,
};
use crate::review_event_outbox_schema::{row_get, row_i64, row_is_null, row_str};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// `store_review_event_sequence_recovery.py` — constants.
// ---------------------------------------------------------------------------

/// `_DEFAULT_SYNC_SOURCES` — OAuth sources that participate in sequencing.
pub const DEFAULT_SYNC_SOURCES: &[&str] = &["default"];
/// `MAX_REVIEW_EVENT_ATTEMPTS`.
pub const MAX_REVIEW_EVENT_ATTEMPTS: i64 = 6;
/// `REVIEW_RETRY_BACKOFF_BASE_SECONDS`.
pub const REVIEW_RETRY_BACKOFF_BASE_SECONDS: f64 = 0.5;
/// `REVIEW_RETRY_BACKOFF_MAX_SECONDS`.
pub const REVIEW_RETRY_BACKOFF_MAX_SECONDS: f64 = 30.0;
/// `REVIEW_REQUEST_SNAPSHOT_REQUIRED_FIELDS` — required request snapshot keys.
pub const REVIEW_REQUEST_SNAPSHOT_REQUIRED_FIELDS: &[&str] = &["request_id", "status"];
/// `REVIEW_EVENT_SEQUENCES_SCHEMA_VERSION`.
pub const REVIEW_EVENT_SEQUENCES_SCHEMA_VERSION: i64 = 1;
/// `_LISTEN_QUEUE_ORDERING_SOURCES`.
pub const LISTEN_QUEUE_ORDERING_SOURCES: &[&str] = &["default"];
/// `SEQUENCE_RECOVERY_VERSION`.
pub const SEQUENCE_RECOVERY_VERSION: i64 = 1;

const BINDING_FIELDS: [&str; 4] = [
    "oauth_subject_hash",
    "workspace_id",
    "machine_id",
    "machine_installation_id",
];

const REQUEST_SNAPSHOT_JSON_FIELDS: [&str; 7] = [
    "action_envelope_json",
    "browser_intent_json",
    "continuation_snapshot_json",
    "changed_fields_json",
    "decision_v2_json",
    "risk_signals_json",
    "scanner_evidence_json",
];

// ---------------------------------------------------------------------------
// Small JSON / row helpers (byte-parity with the Python mapping accessors).
// ---------------------------------------------------------------------------

fn trimmed_str(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

fn row_is_present(row: &DbRow, column: &str) -> bool {
    matches!(row.get(column), Some(Value::String(text)) if !text.trim().is_empty())
        || matches!(row.get(column), Some(Value::Number(_)))
}

fn column_complete(row: &DbRow, column: &str) -> bool {
    match row.get(column) {
        Some(Value::String(text)) => !text.trim().is_empty(),
        Some(Value::Number(_)) => true,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// `review_correlation.py` — uuid5 correlation identifier.
// ---------------------------------------------------------------------------

const CORRELATION_DOMAIN: [u8; 16] = [
    0xe9, 0x27, 0xe1, 0xcf, 0xe2, 0x57, 0x4a, 0xf5, 0xae, 0x66, 0xa8, 0xb6, 0xed, 0xcc, 0x18, 0xf5,
];

fn sha1(data: &[u8]) -> [u8; 20] {
    // Self-contained RFC 3174 SHA-1 — `sha1`/`ring` are not guard-command deps.
    let mut state: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in message.chunks_exact(64) {
        let mut words = [0u32; 80];
        for (index, word) in chunk.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) =
            (state[0], state[1], state[2], state[3], state[4]);
        for (index, word) in words.iter().enumerate() {
            let (f, k) = match index {
                0..=19 => ((b & c) | (!b & d), 0x5a827999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }
    let mut digest = [0u8; 20];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// `cloud_review_correlation_id` — `gcr_{uuid5(domain, local_request_id)}`.
pub fn cloud_review_correlation_id(local_request_id: &str) -> String {
    assert!(
        !local_request_id.trim().is_empty(),
        "local_request_id is required"
    );
    let mut data = Vec::with_capacity(16 + local_request_id.len());
    data.extend_from_slice(&CORRELATION_DOMAIN);
    data.extend_from_slice(local_request_id.as_bytes());
    let digest = sha1(&data);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "gcr_{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

// ---------------------------------------------------------------------------
// `continuation_snapshot.py` — `validated_continuation_snapshot`.
// ---------------------------------------------------------------------------

const CONTINUATION_CAPABILITIES: &[&str] = &[
    "retry-only",
    "session-resume",
    "suspended-response",
    "unsupported",
];

fn is_valid_correlation(value: &str) -> bool {
    // `^gcr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`.
    let Some(rest) = value.strip_prefix("gcr_") else {
        return false;
    };
    let groups: Vec<&str> = rest.split('-').collect();
    let lengths = [8usize, 4, 4, 4, 12];
    groups.len() == 5
        && groups.iter().zip(lengths.iter()).all(|(group, length)| {
            group.len() == *length
                && group.chars().all(|character| {
                    character.is_ascii_hexdigit() && !character.is_ascii_uppercase()
                })
        })
}

/// `validated_continuation_snapshot` — `Some` when the decoded snapshot is a
/// well-formed continuation capability, `None` otherwise.
pub fn validated_continuation_snapshot(snapshot: &Value) -> Option<Map<String, Value>> {
    let map = snapshot.as_object()?;
    let capability = map.get("capability").and_then(Value::as_str);
    let correlation = map.get("correlationId").and_then(Value::as_str);
    let hook_attached = map.get("hookAttached");
    let target = map.get("opaqueTargetId");
    let deadline = map.get("waitDeadline");
    if correlation.is_none() || !correlation.map(is_valid_correlation).unwrap_or(false) {
        return None;
    }
    let capability = match capability {
        Some(value) if CONTINUATION_CAPABILITIES.contains(&value) => value,
        _ => return None,
    };
    let hook_attached = match hook_attached {
        Some(Value::Bool(flag)) => *flag,
        _ => return None,
    };
    if let Some(value) = target {
        match value {
            Value::String(text) if !text.trim().is_empty() => {}
            Value::Null => {}
            _ => return None,
        }
    }
    if let Some(value) = deadline {
        match value {
            Value::String(text) if !text.trim().is_empty() => {}
            Value::Null => {}
            _ => return None,
        }
    }
    if capability == "suspended-response" {
        if !hook_attached || deadline.is_none() || target.is_some() {
            return None;
        }
    } else if hook_attached || deadline.is_some() {
        return None;
    }
    if capability == "session-resume" {
        target?;
    } else if target.is_some() {
        return None;
    }
    Some(map.clone())
}

// ---------------------------------------------------------------------------
// `store_review_event_outbox_binding.py`
// ---------------------------------------------------------------------------

/// `review_event_oauth_subject_hash` — SHA-256 of the trimmed grant subject.
pub fn review_event_oauth_subject_hash(grant_id: Option<&str>) -> Option<String> {
    let normalized = grant_id.map(str::trim).unwrap_or("");
    if normalized.is_empty() {
        return None;
    }
    Some(hex::encode(Sha256::digest(normalized.as_bytes())))
}

fn oauth_binding_state_key(source: &str) -> String {
    if source == "default" {
        "oauth_local_credentials".to_string()
    } else {
        format!("oauth_local_credentials:{source}")
    }
}

/// `load_review_oauth_binding` — resolve the durable OAuth binding for one
/// source, or `None` when credentials are absent/malformed/incomplete.
pub fn load_review_oauth_binding(
    connection: &mut dyn Connection,
    source: &str,
) -> Option<Map<String, Value>> {
    let row = connection
        .query_row(
            "select payload_json from sync_state where state_key = ?",
            &[Value::String(oauth_binding_state_key(source))],
        )
        .ok()
        .flatten()?;
    let parsed: Value = serde_json::from_str(row_str(&row, "payload_json")).ok()?;
    let payload = parsed.as_object()?;
    let grant_id = payload.get("grant_id").and_then(Value::as_str);
    let subject_hash = review_event_oauth_subject_hash(grant_id)?;
    let workspace_id = payload.get("workspace_id").and_then(trimmed_str)?;
    let machine_id = payload.get("machine_id").and_then(trimmed_str)?;
    let device = connection
        .query_row(
            "select installation_id from guard_devices where device_key = 'local-device'",
            &[],
        )
        .ok()
        .flatten();
    let installation_id = device
        .as_ref()
        .and_then(|row| row.get("installation_id"))
        .and_then(trimmed_str)?;
    let mut binding = Map::new();
    binding.insert(
        "oauth_source".to_string(),
        Value::String(source.to_string()),
    );
    binding.insert(
        "oauth_subject_hash".to_string(),
        Value::String(subject_hash),
    );
    binding.insert("workspace_id".to_string(), Value::String(workspace_id));
    binding.insert("machine_id".to_string(), Value::String(machine_id));
    binding.insert(
        "machine_installation_id".to_string(),
        Value::String(installation_id),
    );
    Some(binding)
}

/// `normalized_delivery_binding` — validated 4-member identity tuple.
/// Returns `Err` when any member is blank.
pub fn normalized_delivery_binding(
    oauth_subject_hash: &str,
    workspace_id: &str,
    machine_id: &str,
    machine_installation_id: &str,
) -> Result<[String; 4], String> {
    let values = [
        oauth_subject_hash.trim().to_string(),
        workspace_id.trim().to_string(),
        machine_id.trim().to_string(),
        machine_installation_id.trim().to_string(),
    ];
    if values.iter().any(|value| value.is_empty()) {
        return Err("complete Cloud Review OAuth binding is required".to_string());
    }
    Ok(values)
}

/// `bind_review_events_for_request` — bind newly written events inside the
/// approval write transaction.
pub fn bind_review_events_for_request(
    connection: &mut dyn Connection,
    request_id: &str,
    oauth_source: &str,
) -> bool {
    let Some(binding) = load_review_oauth_binding(connection, oauth_source) else {
        return false;
    };
    let candidate = connection
        .query_row(
            "
            select stream_sequence, payload_json from guard_review_outbox_events
            where local_request_id = ?
              and request_sequence = 1
              and oauth_source = ?
              and binding_status = 'quarantined'
              and oauth_subject_hash is null
              and workspace_id is null
              and machine_id is null
              and machine_installation_id is null
              and not exists (
                select 1 from guard_review_outbox_events as later
                where later.local_request_id = guard_review_outbox_events.local_request_id
                  and later.request_sequence > 1
              )
            ",
            &[
                Value::String(request_id.to_string()),
                Value::String(oauth_source.to_string()),
            ],
        )
        .ok()
        .flatten();
    let Some(candidate) = candidate else {
        return false;
    };
    let payload_hash = review_event_payload_digest(
        row_str(&candidate, "payload_json"),
        Some(oauth_source),
        binding.get("oauth_subject_hash").and_then(Value::as_str),
        binding.get("workspace_id").and_then(Value::as_str),
        binding.get("machine_id").and_then(Value::as_str),
        binding
            .get("machine_installation_id")
            .and_then(Value::as_str),
    );
    let _ = connection.execute(
        "
        update guard_review_outbox_events
        set payload_hash = ?, oauth_subject_hash = ?, workspace_id = ?, machine_id = ?,
            machine_installation_id = ?, binding_status = 'ready', quarantine_reason = null
        where stream_sequence = ?
        ",
        &[
            Value::String(payload_hash),
            binding["oauth_subject_hash"].clone(),
            binding["workspace_id"].clone(),
            binding["machine_id"].clone(),
            binding["machine_installation_id"].clone(),
            row_get(&candidate, "stream_sequence").clone(),
        ],
    );
    let _ = connection.execute(
        "
        update guard_review_outbox_request_sequences
        set oauth_source = ?, oauth_subject_hash = ?, workspace_id = ?,
            machine_id = ?, machine_installation_id = ?
        where local_request_id = ?
        ",
        &[
            Value::String(oauth_source.to_string()),
            binding["oauth_subject_hash"].clone(),
            binding["workspace_id"].clone(),
            binding["machine_id"].clone(),
            binding["machine_installation_id"].clone(),
            Value::String(request_id.to_string()),
        ],
    );
    let _ = connection.execute(
        "update approval_requests set oauth_source = ? where request_id = ? and oauth_source is null",
        &[
            Value::String(oauth_source.to_string()),
            Value::String(request_id.to_string()),
        ],
    );
    true
}

/// `bind_new_review_events` — bind pending first-sequence events for one
/// source; returns the number rebound.
pub fn bind_new_review_events(connection: &mut dyn Connection, source: &str) -> i64 {
    let Some(binding) = load_review_oauth_binding(connection, source) else {
        return 0;
    };
    let candidates = connection
        .query_all(
            "
            select local_request_id, stream_sequence, payload_json
            from guard_review_outbox_events
            where binding_status = 'quarantined'
              and quarantine_reason = 'identity_incomplete'
              and (oauth_source is null or oauth_source = ?)
              and oauth_subject_hash is null and workspace_id is null
              and machine_id is null and machine_installation_id is null
            order by stream_sequence
            ",
            &[Value::String(source.to_string())],
        )
        .unwrap_or_default();
    let mut request_ids = BTreeSet::new();
    let mut rebound = 0i64;
    for candidate in &candidates {
        let payload_hash = review_event_payload_digest(
            row_str(candidate, "payload_json"),
            Some(source),
            binding.get("oauth_subject_hash").and_then(Value::as_str),
            binding.get("workspace_id").and_then(Value::as_str),
            binding.get("machine_id").and_then(Value::as_str),
            binding
                .get("machine_installation_id")
                .and_then(Value::as_str),
        );
        let _ = connection.execute(
            "
            update guard_review_outbox_events
            set payload_hash = ?, oauth_source = ?, oauth_subject_hash = ?,
                workspace_id = ?, machine_id = ?, machine_installation_id = ?,
                binding_status = 'ready', quarantine_reason = null
            where stream_sequence = ?
            ",
            &[
                Value::String(payload_hash),
                Value::String(source.to_string()),
                binding["oauth_subject_hash"].clone(),
                binding["workspace_id"].clone(),
                binding["machine_id"].clone(),
                binding["machine_installation_id"].clone(),
                row_get(candidate, "stream_sequence").clone(),
            ],
        );
        rebound += 1;
        request_ids.insert(row_str(candidate, "local_request_id").to_string());
    }
    if candidates.is_empty() {
        return 0;
    }
    let _ = connection.executemany(
        "
        update guard_review_outbox_request_sequences
        set oauth_source = ?, oauth_subject_hash = ?, workspace_id = ?, machine_id = ?,
            machine_installation_id = ?
        where local_request_id = ?
        ",
        &request_ids
            .iter()
            .map(|request_id| {
                vec![
                    Value::String(source.to_string()),
                    binding["oauth_subject_hash"].clone(),
                    binding["workspace_id"].clone(),
                    binding["machine_id"].clone(),
                    binding["machine_installation_id"].clone(),
                    Value::String(request_id.clone()),
                ]
            })
            .collect::<Vec<_>>(),
    );
    let _ = connection.executemany(
        "
        update approval_requests
        set oauth_source = ?
        where oauth_source is null
          and request_id = ?
        ",
        &request_ids
            .iter()
            .map(|request_id| {
                vec![
                    Value::String(source.to_string()),
                    Value::String(request_id.clone()),
                ]
            })
            .collect::<Vec<_>>(),
    );
    rebound
}

/// `refresh_same_subject_binding` — refresh machine metadata only when subject
/// and workspace are unchanged. Returns rebound + quarantined count.
pub fn refresh_same_subject_binding(connection: &mut dyn Connection, source: &str) -> i64 {
    let Some(binding) = load_review_oauth_binding(connection, source) else {
        return 0;
    };
    let candidates = connection
        .query_all(
            "
            select stream_sequence, payload_json from guard_review_outbox_events
            where oauth_source = ?
              and oauth_subject_hash = ?
              and workspace_id = ?
              and binding_status = 'ready'
              and (machine_id is not ? or machine_installation_id is not ?)
            ",
            &[
                Value::String(source.to_string()),
                binding["oauth_subject_hash"].clone(),
                binding["workspace_id"].clone(),
                binding["machine_id"].clone(),
                binding["machine_installation_id"].clone(),
            ],
        )
        .unwrap_or_default();
    for candidate in &candidates {
        let payload_hash = review_event_payload_digest(
            row_str(candidate, "payload_json"),
            Some(source),
            binding.get("oauth_subject_hash").and_then(Value::as_str),
            binding.get("workspace_id").and_then(Value::as_str),
            binding.get("machine_id").and_then(Value::as_str),
            binding
                .get("machine_installation_id")
                .and_then(Value::as_str),
        );
        let _ = connection.execute(
            "
            update guard_review_outbox_events
            set payload_hash = ?, machine_id = ?, machine_installation_id = ?,
                binding_status = 'ready', quarantine_reason = null
            where stream_sequence = ?
            ",
            &[
                Value::String(payload_hash),
                binding["machine_id"].clone(),
                binding["machine_installation_id"].clone(),
                row_get(candidate, "stream_sequence").clone(),
            ],
        );
    }
    let refreshed = candidates.len() as i64;
    let quarantined = connection
        .execute(
            "
            update guard_review_outbox_events
            set binding_status = 'quarantined',
                quarantine_reason = 'identity_changed_requires_confirmation'
            where oauth_source = ? and binding_status = 'ready'
              and (oauth_subject_hash is not ? or workspace_id is not ?)
            ",
            &[
                Value::String(source.to_string()),
                binding["oauth_subject_hash"].clone(),
                binding["workspace_id"].clone(),
            ],
        )
        .unwrap_or(0);
    refreshed + quarantined.max(0)
}

fn reassignment_filter(binding: &Map<String, Value>, only_unbound: bool) -> (String, Vec<Value>) {
    let mut query = "
        binding_status = 'quarantined'
        and quarantine_reason in ('identity_incomplete', 'identity_changed_requires_confirmation')
        and (oauth_source = ? or (oauth_source is null and (workspace_id is null or workspace_id = ?)))
    "
    .to_string();
    let mut parameters = vec![
        binding["oauth_source"].clone(),
        binding["workspace_id"].clone(),
    ];
    if only_unbound {
        query.push_str(" and quarantine_reason = 'identity_incomplete'");
        for column in BINDING_FIELDS {
            let _ = write_fragment(
                &mut query,
                &format!(" and ({column} is null or {column} = ?)"),
            );
            parameters.push(binding[column].clone());
        }
        for table in [
            "guard_review_outbox_request_sequences",
            "guard_review_outbox_events",
        ] {
            let mut conflicts = Vec::new();
            for column in binding.keys() {
                conflicts.push(format!(
                    "(prior.{column} is not null and prior.{column} != ?)"
                ));
                parameters.push(binding[column].clone());
            }
            let _ = write_fragment(
                &mut query,
                &format!(
                    " and not exists (select 1 from {table} prior where prior.local_request_id = guard_review_outbox_events.local_request_id and ({}))",
                    conflicts.join(" or ")
                ),
            );
        }
    }
    (query, parameters)
}

fn write_fragment(buffer: &mut String, fragment: &str) -> std::fmt::Result {
    use std::fmt::Write;
    buffer.write_str(fragment)
}

/// `count_recoverable_unbound_events`.
pub fn count_recoverable_unbound_events(connection: &mut dyn Connection, source: &str) -> i64 {
    let Some(binding) = load_review_oauth_binding(connection, source) else {
        return 0;
    };
    let (query, parameters) = reassignment_filter(&binding, true);
    connection
        .query_row(
            &format!("select count(*) as count from guard_review_outbox_events where {query}"),
            &parameters,
        )
        .ok()
        .flatten()
        .map(|row| row_i64(&row, "count"))
        .unwrap_or(0)
}

/// `explicitly_reassign_quarantined_events` — move quarantined rows onto the
/// current binding after explicit confirmation.
pub fn explicitly_reassign_quarantined_events(
    connection: &mut dyn Connection,
    source: &str,
) -> i64 {
    let Some(binding) = load_review_oauth_binding(connection, source) else {
        return 0;
    };
    let (query, mut parameters) = reassignment_filter(&binding, false);
    let candidates = connection
        .query_all(
            &format!(
                "select local_request_id, stream_sequence, payload_json from guard_review_outbox_events where {query} order by stream_sequence"
            ),
            &parameters,
        )
        .unwrap_or_default();
    parameters.clear();
    let mut request_ids = BTreeSet::new();
    let mut rebound = 0i64;
    for candidate in &candidates {
        let payload_hash = review_event_payload_digest(
            row_str(candidate, "payload_json"),
            Some(source),
            binding.get("oauth_subject_hash").and_then(Value::as_str),
            binding.get("workspace_id").and_then(Value::as_str),
            binding.get("machine_id").and_then(Value::as_str),
            binding
                .get("machine_installation_id")
                .and_then(Value::as_str),
        );
        let _ = connection.execute(
            "
            update guard_review_outbox_events
            set payload_hash = ?, oauth_source = ?, oauth_subject_hash = ?,
                workspace_id = ?, machine_id = ?, machine_installation_id = ?,
                binding_status = 'ready', quarantine_reason = null
            where stream_sequence = ?
            ",
            &[
                Value::String(payload_hash),
                Value::String(source.to_string()),
                binding["oauth_subject_hash"].clone(),
                binding["workspace_id"].clone(),
                binding["machine_id"].clone(),
                binding["machine_installation_id"].clone(),
                row_get(candidate, "stream_sequence").clone(),
            ],
        );
        rebound += 1;
        request_ids.insert(row_str(candidate, "local_request_id").to_string());
    }
    if candidates.is_empty() {
        return 0;
    }
    let _ = connection.executemany(
        "
        update guard_review_outbox_request_sequences
        set oauth_source = ?, oauth_subject_hash = ?, workspace_id = ?, machine_id = ?,
            machine_installation_id = ?
        where local_request_id = ?
        ",
        &request_ids
            .iter()
            .map(|request_id| {
                vec![
                    Value::String(source.to_string()),
                    binding["oauth_subject_hash"].clone(),
                    binding["workspace_id"].clone(),
                    binding["machine_id"].clone(),
                    binding["machine_installation_id"].clone(),
                    Value::String(request_id.clone()),
                ]
            })
            .collect::<Vec<_>>(),
    );
    let _ = connection.executemany(
        "
        update approval_requests
        set oauth_source = ?
        where oauth_source is null
          and request_id = ?
        ",
        &request_ids
            .iter()
            .map(|request_id| {
                vec![
                    Value::String(source.to_string()),
                    Value::String(request_id.clone()),
                ]
            })
            .collect::<Vec<_>>(),
    );
    rebound
}

// ---------------------------------------------------------------------------
// `store_review_event_outbox_writes.py`
// ---------------------------------------------------------------------------

fn binding_for_append(
    connection: &mut dyn Connection,
    request_id: &str,
    source: &str,
) -> (Map<String, Value>, &'static str, Option<String>) {
    let current = load_review_oauth_binding(connection, source);
    let prior = connection
        .query_row(
            "
            select oauth_subject_hash, workspace_id, machine_id, machine_installation_id
            from guard_review_outbox_request_sequences
            where local_request_id = ?
            ",
            &[Value::String(request_id.to_string())],
        )
        .ok()
        .flatten();
    let Some(prior) = prior else {
        let values = current.clone().unwrap_or_else(|| {
            let mut empty = Map::new();
            for field in BINDING_FIELDS {
                empty.insert(field.to_string(), Value::Null);
            }
            empty
        });
        return (
            values,
            if current.is_some() {
                "ready"
            } else {
                "quarantined"
            },
            if current.is_some() {
                None
            } else {
                Some("identity_incomplete".to_string())
            },
        );
    };
    let mut prior_values = Map::new();
    for key in BINDING_FIELDS {
        prior_values.insert(key.to_string(), row_get(&prior, key).clone());
    }
    let prior_complete = BINDING_FIELDS
        .iter()
        .all(|key| column_complete(&prior, key));
    if !prior_complete {
        return (
            prior_values,
            "quarantined",
            Some("identity_incomplete".to_string()),
        );
    }
    let Some(current_binding) = current else {
        return (
            prior_values,
            "quarantined",
            Some("identity_changed_requires_confirmation".to_string()),
        );
    };
    if row_str(&prior, "oauth_subject_hash")
        != current_binding["oauth_subject_hash"].as_str().unwrap_or("")
        || row_str(&prior, "workspace_id") != current_binding["workspace_id"].as_str().unwrap_or("")
    {
        return (
            prior_values,
            "quarantined",
            Some("identity_changed_requires_confirmation".to_string()),
        );
    }
    (current_binding, "ready", None)
}

/// `append_request_snapshot_event` — append a request snapshot without
/// replacing any unacknowledged event.
#[allow(clippy::too_many_arguments)]
pub fn append_request_snapshot_event(
    connection: &mut dyn Connection,
    request_id: &str,
    source: &str,
    event_type: &str,
    occurred_at: &str,
    continuation_result: Option<&Map<String, Value>>,
    request_snapshot: Option<&Map<String, Value>>,
    native_replay: bool,
) -> i64 {
    let request = match request_snapshot {
        None => {
            let row = connection
                .query_row(
                    "select * from approval_requests where request_id = ?",
                    &[Value::String(request_id.to_string())],
                )
                .ok()
                .flatten();
            match row {
                Some(row) => row,
                None => return 0,
            }
        }
        Some(snapshot) => {
            let mut request = snapshot.clone();
            if request.get("request_id").and_then(Value::as_str) != Some(request_id) {
                return 0;
            }
            for field in REQUEST_SNAPSHOT_JSON_FIELDS {
                if let Some(value) = request.get(field) {
                    if value.is_object() || value.is_array() {
                        let encoded = serde_json::to_string(value).unwrap_or_default();
                        request.insert(field.to_string(), Value::String(encoded));
                    }
                }
            }
            request
        }
    };
    let (values, binding_status, quarantine_reason) =
        binding_for_append(connection, request_id, source);
    let payload = match review_event_payload_json(
        &request,
        event_type,
        occurred_at,
        continuation_result,
        native_replay,
    ) {
        Ok(payload) => payload,
        Err(_) => return 0,
    };
    let _ = connection.execute(
        "
        insert into guard_review_outbox_request_sequences (
          local_request_id, last_sequence, updated_at, oauth_source,
          oauth_subject_hash, workspace_id, machine_id, machine_installation_id
        ) values (?, 1, ?, ?, ?, ?, ?, ?)
        on conflict(local_request_id) do update set
          last_sequence = guard_review_outbox_request_sequences.last_sequence + 1,
          updated_at = excluded.updated_at,
          oauth_source = coalesce(guard_review_outbox_request_sequences.oauth_source, excluded.oauth_source),
          oauth_subject_hash = coalesce(
            guard_review_outbox_request_sequences.oauth_subject_hash,
            excluded.oauth_subject_hash
          ),
          workspace_id = coalesce(guard_review_outbox_request_sequences.workspace_id, excluded.workspace_id),
          machine_id = coalesce(guard_review_outbox_request_sequences.machine_id, excluded.machine_id),
          machine_installation_id = coalesce(
            guard_review_outbox_request_sequences.machine_installation_id,
            excluded.machine_installation_id
          )
        ",
        &[
            Value::String(request_id.to_string()),
            Value::String(occurred_at.to_string()),
            Value::String(source.to_string()),
            values.get("oauth_subject_hash").cloned().unwrap_or(Value::Null),
            values.get("workspace_id").cloned().unwrap_or(Value::Null),
            values.get("machine_id").cloned().unwrap_or(Value::Null),
            values.get("machine_installation_id").cloned().unwrap_or(Value::Null),
        ],
    );
    let row = connection
        .query_row(
            "select last_sequence from guard_review_outbox_request_sequences where local_request_id = ?",
            &[Value::String(request_id.to_string())],
        )
        .ok()
        .flatten();
    let Some(row) = row else {
        panic!("Review event request sequence allocation failed.");
    };
    let request_sequence = row_i64(&row, "last_sequence");
    connection
        .execute(
            "
            insert into guard_review_outbox_events (
              event_id, local_request_id, request_sequence, event_type, event_schema_version,
              payload_json, payload_hash, occurred_at, oauth_source, oauth_subject_hash,
              workspace_id, machine_id, machine_installation_id, binding_status, quarantine_reason
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ",
            &[
                Value::String(uuid4_hex()),
                Value::String(request_id.to_string()),
                Value::Number(request_sequence.into()),
                Value::String(event_type.to_string()),
                Value::Number(REVIEW_EVENT_SCHEMA_VERSION.into()),
                Value::String(payload.clone()),
                Value::String(review_event_payload_digest(
                    &payload,
                    Some(source),
                    values.get("oauth_subject_hash").and_then(Value::as_str),
                    values.get("workspace_id").and_then(Value::as_str),
                    values.get("machine_id").and_then(Value::as_str),
                    values
                        .get("machine_installation_id")
                        .and_then(Value::as_str),
                )),
                Value::String(occurred_at.to_string()),
                Value::String(source.to_string()),
                values
                    .get("oauth_subject_hash")
                    .cloned()
                    .unwrap_or(Value::Null),
                values.get("workspace_id").cloned().unwrap_or(Value::Null),
                values.get("machine_id").cloned().unwrap_or(Value::Null),
                values
                    .get("machine_installation_id")
                    .cloned()
                    .unwrap_or(Value::Null),
                Value::String(binding_status.to_string()),
                quarantine_reason.map(Value::String).unwrap_or(Value::Null),
            ],
        )
        .unwrap_or(0)
        .max(0)
}

/// `recover_review_snapshot_sequences` — append snapshot events for pending
/// requests missing from the outbox sequence ledger.
pub fn recover_review_snapshot_sequences(
    connection: &mut dyn Connection,
    source: &str,
    occurred_at: &str,
) -> i64 {
    let rows = connection
        .query_all(
            "
            select request_id from approval_requests
            where status = 'pending' and oauth_source = ?
              and request_id not in (
                select local_request_id from guard_review_outbox_request_sequences
              )
            order by coalesce(last_seen_at, created_at), request_id
            ",
            &[Value::String(source.to_string())],
        )
        .unwrap_or_default();
    let mut recovered = 0i64;
    for row in rows {
        let request_id = row_str(&row, "request_id").to_string();
        if request_id.is_empty() {
            continue;
        }
        recovered += append_request_snapshot_event(
            connection,
            &request_id,
            source,
            "review.request.snapshot_recovered",
            occurred_at,
            None,
            None,
            false,
        );
    }
    recovered
}

/// `requeue_pending_request_events` — append `snapshot_requeued` events for
/// pending requests that still need an unacknowledged snapshot.
#[allow(clippy::too_many_arguments)]
pub fn requeue_pending_request_events(
    connection: &mut dyn Connection,
    source: &str,
    changed_at: &str,
    require_binding: bool,
    snapshot_repair_sequences: Option<&Map<String, Value>>,
    only_retry_identity_drift: bool,
    request_ids: Option<&BTreeSet<String>>,
    request_snapshots: Option<&Map<String, Value>>,
    native_replay: bool,
) -> i64 {
    let _ = connection.execute("begin immediate", &[]);
    let current_binding = load_review_oauth_binding(connection, source);
    if require_binding && current_binding.is_none() {
        return 0;
    }
    if let Some(sequences) = snapshot_repair_sequences {
        if sequences.is_empty() {
            return 0;
        }
    }
    let current_identity = current_binding.as_ref().map(|binding| {
        (
            source.to_string(),
            binding["oauth_subject_hash"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            binding["workspace_id"].as_str().unwrap_or("").to_string(),
            binding["machine_id"].as_str().unwrap_or("").to_string(),
            binding["machine_installation_id"]
                .as_str()
                .unwrap_or("")
                .to_string(),
        )
    });
    let mut request_query = "
        select request_id, continuation_snapshot_json from approval_requests
        where status = 'pending' and oauth_source = ?
    "
    .to_string();
    let mut request_parameters = vec![Value::String(source.to_string())];
    if let Some(sequences) = snapshot_repair_sequences {
        let placeholders = vec!["?"; sequences.len()].join(",");
        request_query.push_str(&format!(" and request_id in ({placeholders})"));
        for key in sequences.keys() {
            request_parameters.push(Value::String(key.clone()));
        }
    }
    if let Some(ids) = request_ids {
        if ids.is_empty() {
            return 0;
        }
        let placeholders = vec!["?"; ids.len()].join(",");
        request_query.push_str(&format!(" and request_id in ({placeholders})"));
        for id in ids {
            request_parameters.push(Value::String(id.clone()));
        }
    }
    let rows = connection
        .query_all(
            &format!("{request_query} order by coalesce(last_seen_at, created_at), request_id"),
            &request_parameters,
        )
        .unwrap_or_default();
    let mut appended = 0i64;
    for row in rows {
        let request_id = row_str(&row, "request_id").to_string();
        if only_retry_identity_drift {
            let frozen = serde_json::from_str::<Value>(row_str(&row, "continuation_snapshot_json"))
                .ok()
                .and_then(|value| validated_continuation_snapshot(&value));
            let drift = match frozen.as_ref() {
                Some(snapshot)
                    if matches!(
                        snapshot.get("capability").and_then(Value::as_str),
                        Some("retry-only") | Some("unsupported")
                    ) =>
                {
                    snapshot.get("correlationId").and_then(Value::as_str)
                        != Some(cloud_review_correlation_id(&request_id).as_str())
                }
                _ => false,
            };
            if !drift {
                continue;
            }
        }
        if require_binding && current_binding.is_some() {
            let binding = current_binding.as_ref().unwrap();
            let established = connection
                .query_row(
                    "
                    select 1 from guard_review_outbox_request_sequences
                    where local_request_id = ? and oauth_source = ?
                      and oauth_subject_hash = ? and workspace_id = ?
                      and machine_id = ? and machine_installation_id = ?
                    ",
                    &[
                        Value::String(request_id.clone()),
                        Value::String(source.to_string()),
                        binding["oauth_subject_hash"].clone(),
                        binding["workspace_id"].clone(),
                        binding["machine_id"].clone(),
                        binding["machine_installation_id"].clone(),
                    ],
                )
                .ok()
                .flatten();
            if established.is_none() {
                // Enabling decisions is not consent to upload another account's
                // requests or requests whose original identity was lost.
                continue;
            }
        }
        let mut snapshot_query = "
            select oauth_source, oauth_subject_hash, workspace_id, machine_id,
                   machine_installation_id, binding_status
            from guard_review_outbox_events
            where local_request_id = ?
              and event_type = 'review.request.snapshot_requeued'
        "
        .to_string();
        let mut snapshot_parameters = vec![Value::String(request_id.clone())];
        match snapshot_repair_sequences {
            None => snapshot_query.push_str(" and acknowledged_at is null"),
            Some(sequences) => {
                snapshot_query.push_str(" and request_sequence > ?");
                snapshot_parameters
                    .push(sequences.get(&request_id).cloned().unwrap_or(Value::Null));
            }
        }
        let existing_snapshot = connection
            .query_row(
                &format!("{snapshot_query} order by request_sequence desc limit 1"),
                &snapshot_parameters,
            )
            .ok()
            .flatten();
        if let (Some(existing), Some(identity)) =
            (existing_snapshot.as_ref(), current_identity.as_ref())
        {
            let ready = row_str(existing, "binding_status") == "ready";
            let matches_identity = (
                row_str(existing, "oauth_source").to_string(),
                row_str(existing, "oauth_subject_hash").to_string(),
                row_str(existing, "workspace_id").to_string(),
                row_str(existing, "machine_id").to_string(),
                row_str(existing, "machine_installation_id").to_string(),
            ) == *identity;
            if ready && matches_identity {
                continue;
            }
        }
        bind_review_events_for_request(connection, &request_id, source);
        let snapshot = request_snapshots
            .and_then(|snapshots| snapshots.get(&request_id))
            .and_then(Value::as_object);
        appended += append_request_snapshot_event(
            connection,
            &request_id,
            source,
            "review.request.snapshot_requeued",
            changed_at,
            None,
            snapshot,
            native_replay,
        );
    }
    appended
}

// ---------------------------------------------------------------------------
// `store_review_event_acknowledgment.py`
// ---------------------------------------------------------------------------

/// `acknowledge_review_events` — mark ready rows acknowledged, compact the
/// acknowledged prefix, and advance the durable cursor. Returns rows deleted.
pub fn acknowledge_review_events(
    connection: &mut dyn Connection,
    source: &str,
    sequences: &[i64],
    binding: &[String; 4],
    acknowledged_at: &str,
) -> i64 {
    let mut acknowledged: Vec<i64> = sequences
        .iter()
        .copied()
        .filter(|sequence| *sequence > 0)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    acknowledged.sort_unstable();
    if acknowledged.is_empty() {
        return 0;
    }
    let placeholders = vec!["?"; acknowledged.len()].join(",");
    let mut params = vec![Value::String(acknowledged_at.to_string())];
    params.extend(
        acknowledged
            .iter()
            .map(|sequence| Value::Number((*sequence).into())),
    );
    params.push(Value::String(source.to_string()));
    params.extend(binding.iter().cloned().map(Value::String));
    let _ = connection.execute(
        &format!(
            "
            update guard_review_outbox_events set acknowledged_at = ?
            where stream_sequence in ({placeholders})
              and oauth_source = ? and oauth_subject_hash = ? and workspace_id = ?
              and machine_id = ? and machine_installation_id = ?
              and binding_status = 'ready' and acknowledged_at is null
            "
        ),
        &params,
    );
    let mut rows_params = vec![Value::String(source.to_string())];
    rows_params.extend(binding.iter().cloned().map(Value::String));
    let rows = connection
        .query_all(
            "
            select stream_sequence, acknowledged_at from guard_review_outbox_events
            where oauth_source = ? and oauth_subject_hash = ? and workspace_id = ?
              and machine_id = ? and machine_installation_id = ?
              and binding_status = 'ready'
            order by stream_sequence
            ",
            &rows_params,
        )
        .unwrap_or_default();
    let mut prefix = Vec::new();
    for row in &rows {
        if row_is_null(row, "acknowledged_at") {
            break;
        }
        prefix.push(row_i64(row, "stream_sequence"));
    }
    if prefix.is_empty() {
        return 0;
    }
    let placeholders = vec!["?"; prefix.len()].join(",");
    let prefix_params: Vec<Value> = prefix
        .iter()
        .map(|sequence| Value::Number((*sequence).into()))
        .collect();
    let cursor = connection
        .execute(
            &format!(
                "
                delete from guard_review_outbox_events
                where stream_sequence in ({placeholders}) and binding_status = 'ready'
                "
            ),
            &prefix_params,
        )
        .unwrap_or(0);
    let mut cursor_params = vec![Value::String(source.to_string())];
    cursor_params.extend(binding.iter().cloned().map(Value::String));
    cursor_params.push(Value::Number((*prefix.last().unwrap()).into()));
    cursor_params.push(Value::String(acknowledged_at.to_string()));
    let _ = connection.execute(
        "
        insert into guard_review_outbox_cursors (
          oauth_source, oauth_subject_hash, workspace_id, machine_id,
          machine_installation_id, acknowledged_stream_sequence, updated_at
        ) values (?, ?, ?, ?, ?, ?, ?)
        on conflict(oauth_source, oauth_subject_hash, workspace_id, machine_id, machine_installation_id)
        do update set acknowledged_stream_sequence = max(
          guard_review_outbox_cursors.acknowledged_stream_sequence,
          excluded.acknowledged_stream_sequence
        ), updated_at = excluded.updated_at
        ",
        &cursor_params,
    );
    cursor.max(0)
}

// ---------------------------------------------------------------------------
// `store_review_event_outbox.py` — orchestrator.
// ---------------------------------------------------------------------------

/// `next_attempt_at` backoff — `REVIEW_RETRY_BACKOFF_BASE_SECONDS * 2 **
/// (attempt_count - 1)` capped at `REVIEW_RETRY_BACKOFF_MAX_SECONDS`.
pub fn retry_at(failed_at: &str, attempt_count: i64) -> String {
    // `REVIEW_RETRY_BACKOFF_BASE_SECONDS * 2 ** (attempt_count - 1)` capped at
    // `REVIEW_RETRY_BACKOFF_MAX_SECONDS`, added to `failed_at`.
    let exponent = (attempt_count - 1).max(0);
    let backoff = (REVIEW_RETRY_BACKOFF_BASE_SECONDS * 2f64.powi(exponent as i32))
        .min(REVIEW_RETRY_BACKOFF_MAX_SECONDS);
    format!("{failed_at}+{backoff}")
}

/// `StoredReviewEventError` — terminal decode/delivery failure for one row.
#[derive(Debug)]
pub struct StoredReviewEventError(pub String);

impl std::fmt::Display for StoredReviewEventError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for StoredReviewEventError {}

/// `decode_stored_review_event` — build the delivery envelope for one stored
/// row. Returns `Err(StoredReviewEventError)` when the row is undeliverable.
pub fn decode_stored_review_event(
    row: &DbRow,
) -> Result<Map<String, Value>, StoredReviewEventError> {
    let status = row_str(row, "binding_status");
    if status == "quarantined" {
        let reason = row_str(row, "quarantine_reason");
        return Err(StoredReviewEventError(format!(
            "Review event is quarantined ({reason})"
        )));
    }
    for column in [
        "oauth_source",
        "oauth_subject_hash",
        "workspace_id",
        "machine_id",
        "machine_installation_id",
    ] {
        if !row_is_present(row, column) {
            return Err(StoredReviewEventError(format!(
                "Review event is missing {column}"
            )));
        }
    }
    let payload: Value = serde_json::from_str(row_str(row, "payload_json"))
        .map_err(|_| StoredReviewEventError("Review event payload is malformed".to_string()))?;
    let payload_map = payload
        .as_object()
        .cloned()
        .ok_or_else(|| StoredReviewEventError("Review event payload is malformed".to_string()))?;
    let mut delivery = Map::new();
    delivery.insert(
        "requestId".to_string(),
        row_get(row, "local_request_id").clone(),
    );
    delivery.insert(
        "requestSequence".to_string(),
        row_get(row, "request_sequence").clone(),
    );
    delivery.insert("eventId".to_string(), row_get(row, "event_id").clone());
    delivery.insert("eventType".to_string(), row_get(row, "event_type").clone());
    delivery.insert(
        "occurredAt".to_string(),
        row_get(row, "occurred_at").clone(),
    );
    delivery.insert("payload".to_string(), Value::Object(payload_map));
    delivery.insert(
        "payloadHash".to_string(),
        row_get(row, "payload_hash").clone(),
    );
    delivery.insert(
        "oauthSource".to_string(),
        row_get(row, "oauth_source").clone(),
    );
    delivery.insert(
        "oauthSubjectHash".to_string(),
        row_get(row, "oauth_subject_hash").clone(),
    );
    delivery.insert(
        "workspaceId".to_string(),
        row_get(row, "workspace_id").clone(),
    );
    delivery.insert("machineId".to_string(), row_get(row, "machine_id").clone());
    delivery.insert(
        "machineInstallationId".to_string(),
        row_get(row, "machine_installation_id").clone(),
    );
    Ok(delivery)
}

/// `list_pending_review_request_ids` — `approval_requests` joined to the
/// sequence ledger, ordered by request id.
#[allow(clippy::too_many_arguments)]
pub fn list_pending_review_request_ids(
    connection: &mut dyn Connection,
    source: &str,
    oauth_subject_hash: &str,
    workspace_id: &str,
    machine_id: &str,
    machine_installation_id: &str,
    after_request_id: Option<&str>,
    through_request_id: Option<&str>,
    limit: i64,
    descending: bool,
) -> Vec<String> {
    let mut query = "
        select a.request_id
        from approval_requests as a
        join guard_review_outbox_request_sequences as s
          on s.local_request_id = a.request_id
        where a.status = 'pending'
          and a.oauth_source = ?
          and s.oauth_source = ?
          and s.oauth_subject_hash = ?
          and s.workspace_id = ?
          and s.machine_id = ?
          and s.machine_installation_id = ?
    "
    .to_string();
    let mut parameters = vec![
        Value::String(source.to_string()),
        Value::String(source.to_string()),
        Value::String(oauth_subject_hash.to_string()),
        Value::String(workspace_id.to_string()),
        Value::String(machine_id.to_string()),
        Value::String(machine_installation_id.to_string()),
    ];
    if let Some(after) = after_request_id {
        query.push_str(" and a.request_id > ?");
        parameters.push(Value::String(after.to_string()));
    }
    if let Some(through) = through_request_id {
        query.push_str(" and a.request_id <= ?");
        parameters.push(Value::String(through.to_string()));
    }
    query.push_str(&format!(
        " order by a.request_id {} limit ?",
        if descending { "desc" } else { "asc" }
    ));
    parameters.push(Value::Number(limit.max(1).into()));
    connection
        .query_all(&query, &parameters)
        .unwrap_or_default()
        .iter()
        .map(|row| row_str(row, "request_id").to_string())
        .collect()
}

/// `count_pending_review_request_snapshots`.
pub fn count_pending_review_request_snapshots(
    connection: &mut dyn Connection,
    source: &str,
    oauth_subject_hash: &str,
    workspace_id: &str,
    machine_id: &str,
    machine_installation_id: &str,
) -> i64 {
    connection
        .query_row(
            "
            select count(*) as count
            from approval_requests as a
            join guard_review_outbox_request_sequences as s
              on s.local_request_id = a.request_id
            where a.status = 'pending'
              and a.oauth_source = ?
              and s.oauth_source = ?
              and s.oauth_subject_hash = ?
              and s.workspace_id = ?
              and s.machine_id = ?
              and s.machine_installation_id = ?
            ",
            &[
                Value::String(source.to_string()),
                Value::String(source.to_string()),
                Value::String(oauth_subject_hash.to_string()),
                Value::String(workspace_id.to_string()),
                Value::String(machine_id.to_string()),
                Value::String(machine_installation_id.to_string()),
            ],
        )
        .ok()
        .flatten()
        .map(|row| row_i64(&row, "count"))
        .unwrap_or(0)
}

/// `repair_rejected_review_correlation` — restore only the deterministic
/// identity explicitly requested by Cloud.
pub fn repair_rejected_review_correlation(
    connection: &mut dyn Connection,
    source: &str,
    event_sequence: i64,
    binding: &Map<String, Value>,
    changed_at: &str,
) -> Result<i64, String> {
    let _ = connection.execute("begin immediate", &[]);
    let current_binding = load_review_oauth_binding(connection, source);
    let mismatch = current_binding.as_ref().is_none_or(|current| {
        BINDING_FIELDS.iter().any(|key| {
            current.get(*key).and_then(Value::as_str) != binding.get(*key).and_then(Value::as_str)
        })
    });
    if current_binding.is_none() || mismatch {
        return Ok(0);
    }
    let event = connection
        .query_row(
            "select * from guard_review_outbox_events where stream_sequence = ? and oauth_source = ?",
            &[
                Value::Number(event_sequence.into()),
                Value::String(source.to_string()),
            ],
        )
        .ok()
        .flatten();
    let Some(event) = event else {
        return Ok(0);
    };
    if BINDING_FIELDS.iter().any(|key| {
        event.get(*key).and_then(Value::as_str) != binding.get(*key).and_then(Value::as_str)
    }) {
        return Ok(0);
    }
    if row_str(&event, "binding_status") != "ready" || !row_is_null(&event, "acknowledged_at") {
        return Ok(0);
    }
    let request_id = row_str(&event, "local_request_id").to_string();
    let request = connection
        .query_row(
            "select continuation_snapshot_json from approval_requests
             where request_id = ? and oauth_source = ? and status = 'pending'",
            &[
                Value::String(request_id.clone()),
                Value::String(source.to_string()),
            ],
        )
        .ok()
        .flatten();
    let established = connection
        .query_row(
            "select * from guard_review_outbox_request_sequences where local_request_id = ?",
            &[Value::String(request_id.clone())],
        )
        .ok()
        .flatten();
    let (Some(request), Some(established)) = (request, established) else {
        return Ok(0);
    };
    if row_str(&established, "oauth_source") != source {
        return Ok(0);
    }
    if BINDING_FIELDS.iter().any(|key| {
        established.get(*key).and_then(Value::as_str) != binding.get(*key).and_then(Value::as_str)
    }) {
        return Ok(0);
    }
    let snapshot =
        match serde_json::from_str::<Value>(row_str(&request, "continuation_snapshot_json"))
            .ok()
            .and_then(|value| validated_continuation_snapshot(&value))
        {
            Some(snapshot) => snapshot,
            None => return Ok(0),
        };
    let repaired = {
        let mut snapshot = snapshot;
        snapshot.insert(
            "correlationId".to_string(),
            Value::String(cloud_review_correlation_id(&request_id)),
        );
        snapshot
    };
    let _ = connection.execute(
        "update approval_requests set continuation_snapshot_json = ? where request_id = ? and oauth_source = ?",
        &[
            Value::String(serde_json::to_string(&Value::Object(repaired)).unwrap_or_default()),
            Value::String(request_id.clone()),
            Value::String(source.to_string()),
        ],
    );
    let appended = append_request_snapshot_event(
        connection,
        &request_id,
        source,
        "review.request.snapshot_requeued",
        changed_at,
        None,
        None,
        false,
    );
    if appended == 0 {
        return Err("Retry identity repair did not append its replacement event".to_string());
    }
    let normalized = normalized_delivery_binding(
        binding["oauth_subject_hash"].as_str().unwrap_or(""),
        binding["workspace_id"].as_str().unwrap_or(""),
        binding["machine_id"].as_str().unwrap_or(""),
        binding["machine_installation_id"].as_str().unwrap_or(""),
    )?;
    let _ = acknowledge_review_events(
        connection,
        source,
        &[event_sequence],
        &normalized,
        changed_at,
    );
    Ok(appended)
}

/// `ReviewEventStore` — host-side store facade. The dispatcher constructs this
/// around a `rusqlite::Connection`; `guard-command` only depends on the seam.
pub trait ReviewEventStoreApi {
    fn connection(&mut self) -> &mut dyn Connection;
}

fn uuid4_hex() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        return "0".repeat(32);
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_review_correlation_id_matches_uuid5() {
        assert_eq!(
            cloud_review_correlation_id("req-123"),
            "gcr_3b03c5cc-e72c-5951-be76-8ab815d46d51"
        );
    }

    #[test]
    fn subject_hash_matches_sha256_of_trimmed() {
        assert_eq!(
            review_event_oauth_subject_hash(Some(" grant@x ")).unwrap(),
            "2e8a69e0eaa3ba5f36f04b0be292346970eb6db5fe4ac78c8c93fd11bf5df606"
        );
    }

    #[test]
    fn payload_digest_matches_python_hmac() {
        assert_eq!(
            crate::review_event_outbox_schema::review_event_payload_digest(
                "{}",
                Some("default"),
                Some("s"),
                Some("w"),
                Some("m"),
                Some("i"),
            ),
            "741c5a9a30cad81fbe652232c4aabfbdde1d5a52b1a10de49a03d683c1f84d35"
        );
        assert_eq!(
            crate::review_event_outbox_schema::review_event_payload_digest(
                "{}",
                Some("default"),
                None,
                None,
                None,
                None,
            ),
            "9f31eeb9b235c047e183eb7a7ba821ce38b2a91dbb8a1b73e69014571f5c588d"
        );
    }
}
