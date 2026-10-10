//! Atomic rebase of authenticated snapshot events after a Cloud stream
//! sequence collision.

use std::collections::BTreeMap;

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{
    exec, int, placeholders, query_all, query_one, StoreError, StoreResult,
};
use crate::guard_store_json::py_strip;
use crate::guard_store_outbox_binding::{load_binding, row_matches, Binding};
use crate::guard_store_outbox_decode::decode_stored_event;

const MAX_SAFE_STREAM_SEQUENCE: i64 = (1 << 53) - 1;
const MAX_COLLISIONS: usize = 256;
const REQUEUED: &str = "review.request.snapshot_requeued";

fn canonical(text: &str) -> bool {
    !text.is_empty() && py_strip(text) == text
}

/// Returns `[[old_sequence, new_sequence], ...]`, or `[]` when the recovery
/// preconditions do not hold.
pub(crate) fn recover_sequences(
    connection: &Connection,
    source: &str,
    args: &Args,
) -> StoreResult<Value> {
    let acknowledged_through = args.int("acknowledged_through")?;
    let pairs = args
        .raw("collisions")
        .and_then(Value::as_array)
        .ok_or(StoreError::Invalid("native_guard_store_args_invalid"))?;
    let mut collisions: BTreeMap<i64, &str> = BTreeMap::new();
    let mut valid = !pairs.is_empty() && pairs.len() <= MAX_COLLISIONS;
    for pair in pairs {
        let (Some(sequence), Some(event_id)) = (
            pair.get(0).and_then(Value::as_i64),
            pair.get(1).and_then(Value::as_str),
        ) else {
            return Err(StoreError::Invalid("native_guard_store_args_invalid"));
        };
        valid &= (1..=MAX_SAFE_STREAM_SEQUENCE).contains(&sequence) && canonical(event_id);
        valid &= collisions.insert(sequence, event_id).is_none();
    }
    let identity = args.object("binding")?;
    let part = |key: &str| identity.get(key).and_then(Value::as_str).unwrap_or("");
    let binding = Binding {
        subject_hash: part("oauth_subject_hash").to_owned(),
        workspace_id: part("workspace_id").to_owned(),
        machine_id: part("machine_id").to_owned(),
        installation_id: part("machine_installation_id").to_owned(),
    };
    valid &= binding.tuple().iter().all(|text| canonical(text));
    valid &= (0..=MAX_SAFE_STREAM_SEQUENCE).contains(&acknowledged_through);
    let mut ids: Vec<&str> = collisions.values().copied().collect();
    ids.sort_unstable();
    ids.dedup();
    valid &= ids.len() == collisions.len();
    if !valid || load_binding(connection, source)?.as_ref() != Some(&binding) {
        return Ok(json!([]));
    }

    let sequences: Vec<i64> = collisions.keys().copied().collect();
    let sequence_values: Vec<Value> = sequences.iter().map(|s| Value::from(*s)).collect();
    let rows = query_all(
        connection,
        &format!(
            "select * from guard_review_outbox_events where stream_sequence in ({})",
            placeholders(sequences.len())
        ),
        &sequence_values,
    )?;
    let by_sequence: BTreeMap<i64, _> = rows
        .iter()
        .map(|row| (int(row, "stream_sequence"), row))
        .collect();
    if by_sequence.len() != collisions.len() {
        return Ok(json!([]));
    }
    for (old_sequence, expected_id) in &collisions {
        let row = by_sequence[old_sequence];
        let mut params = vec![
            row.get("local_request_id").cloned().unwrap_or(Value::Null),
            row.get("request_sequence").cloned().unwrap_or(Value::Null),
            Value::from(source),
        ];
        params.extend(ids.iter().map(|id| Value::from(*id)));
        let later = query_one(
            connection,
            &format!(
                "select 1 as present from guard_review_outbox_events \
                 where local_request_id = ? and request_sequence > ? \
                 and acknowledged_at is null and oauth_source = ? \
                 and event_id not in ({}) limit 1",
                placeholders(ids.len())
            ),
            &params,
        )?;
        let trusted = later.is_none()
            && row.get("event_id").and_then(Value::as_str) == Some(*expected_id)
            && row.get("oauth_source").and_then(Value::as_str) == Some(source)
            && row_matches(row, &binding)
            && row.get("binding_status").and_then(Value::as_str) == Some("ready")
            && row.get("acknowledged_at").is_none_or(Value::is_null)
            && row.get("event_type").and_then(Value::as_str) == Some(REQUEUED);
        let decoded = if trusted {
            decode_stored_event(row)
        } else {
            None
        };
        let Some(event) = decoded else {
            return Ok(json!([]));
        };
        if event.stream_sequence != *old_sequence
            || event.event_id != *expected_id
            || event.event_type != REQUEUED
        {
            return Ok(json!([]));
        }
    }

    let mut cursor_params = vec![Value::from(source)];
    cursor_params.extend(binding.values());
    let local_cursor = query_one(
        connection,
        "select acknowledged_stream_sequence from guard_review_outbox_cursors \
         where oauth_source = ? and oauth_subject_hash = ? and workspace_id = ? \
         and machine_id = ? and machine_installation_id = ?",
        &cursor_params,
    )?
    .map_or(0, |row| int(&row, "acknowledged_stream_sequence"));
    let local_max = query_one(
        connection,
        "select coalesce(max(stream_sequence), 0) as maximum from guard_review_outbox_events",
        &[],
    )?
    .map_or(0, |row| int(&row, "maximum"));
    let sqlite_sequence = query_one(
        connection,
        "select seq from sqlite_sequence where name = 'guard_review_outbox_events'",
        &[],
    )?
    .map_or(0, |row| int(&row, "seq"));
    let base = acknowledged_through
        .max(local_cursor)
        .max(local_max)
        .max(sqlite_sequence);
    if base > MAX_SAFE_STREAM_SEQUENCE - sequences.len() as i64 {
        return Ok(json!([]));
    }
    let replacements: Vec<(i64, i64)> = sequences
        .iter()
        .enumerate()
        .map(|(index, old)| (*old, base + index as i64 + 1))
        .collect();
    for (old_sequence, new_sequence) in &replacements {
        let mut params = vec![
            Value::from(*new_sequence),
            Value::from(*old_sequence),
            Value::from(collisions[old_sequence]),
            Value::from(source),
        ];
        params.extend(binding.values());
        let changed = exec(
            connection,
            "update guard_review_outbox_events set stream_sequence = ? \
             where stream_sequence = ? and event_id = ? and oauth_source = ? \
             and oauth_subject_hash = ? and workspace_id = ? \
             and machine_id = ? and machine_installation_id = ? \
             and binding_status = 'ready' and acknowledged_at is null",
            &params,
        )?;
        if changed != 1 {
            return Err(StoreError::Integrity(
                "Review snapshot sequence recovery lost its validated row.".to_owned(),
            ));
        }
    }
    let final_sequence = replacements.last().map_or(base, |(_, new)| *new);
    let updated = exec(
        connection,
        "update sqlite_sequence set seq = max(seq, ?) where name = 'guard_review_outbox_events'",
        &[Value::from(final_sequence)],
    )?;
    if updated == 0 {
        exec(
            connection,
            "insert into sqlite_sequence (name, seq) values ('guard_review_outbox_events', ?)",
            &[Value::from(final_sequence)],
        )?;
    }
    Ok(Value::Array(
        replacements
            .iter()
            .map(|(old, new)| json!([old, new]))
            .collect(),
    ))
}
