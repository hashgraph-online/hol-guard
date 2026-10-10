//! Review outbox delivery reads and per-event state transitions: ready scan,
//! status, pending-request scan, retry scheduling, quarantine, and
//! acknowledgment with prefix compaction.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{
    exec, int, placeholders, query_all, query_one, text, value_error, Row, StoreError, StoreResult,
};
use crate::guard_store_json::{add_seconds_isoformat, py_prefix};
use crate::guard_store_outbox_binding::{load_binding, normalized_binding, Binding};
use crate::guard_store_outbox_decode::decode_stored_event;

const NO_BINDING: &str = "complete Review event OAuth binding is required";

/// Identity filter arguments: either absent or complete.
fn optional_identity(args: &Args) -> StoreResult<Option<Binding>> {
    let identity = args.identity();
    if identity.iter().all(Option::is_none) {
        return Ok(None);
    }
    let mut parts = [""; 4];
    for (slot, value) in parts.iter_mut().zip(identity) {
        *slot = match value.and_then(Value::as_str) {
            Some(text) => text,
            None => return value_error(NO_BINDING),
        };
    }
    normalized_binding(parts).map(Some)
}

fn required_binding(args: &Args) -> StoreResult<Binding> {
    let binding = args.object("binding")?;
    let part = |key: &str| {
        binding
            .get(key)
            .and_then(Value::as_str)
            .ok_or(StoreError::Invalid("native_guard_store_args_invalid"))
    };
    normalized_binding([
        part("oauth_subject_hash")?,
        part("workspace_id")?,
        part("machine_id")?,
        part("machine_installation_id")?,
    ])
}

fn delivered_binding(args: &Args) -> StoreResult<Binding> {
    let part = |key: &str| args.str(key);
    normalized_binding([
        part("oauth_subject_hash")?,
        part("workspace_id")?,
        part("machine_id")?,
        part("machine_installation_id")?,
    ])
}

fn positive_sequences(args: &Args) -> StoreResult<Vec<i64>> {
    let mut sequences: Vec<i64> = args
        .ints("sequences")?
        .into_iter()
        .filter(|s| *s > 0)
        .collect();
    sequences.sort_unstable();
    sequences.dedup();
    Ok(sequences)
}

pub(crate) fn list_ready(connection: &Connection, source: &str, args: &Args) -> StoreResult<Value> {
    let mut query = String::from(
        "select stream_sequence, event_id, local_request_id, request_sequence, \
         event_type, event_schema_version, payload_json, payload_hash, \
         occurred_at, oauth_source, oauth_subject_hash, workspace_id, \
         machine_id, machine_installation_id, attempt_count \
         from guard_review_outbox_events \
         where oauth_source = ? and binding_status = 'ready' and acknowledged_at is null \
         and (next_attempt_at is null or next_attempt_at <= ?)",
    );
    let mut params = vec![Value::from(source), Value::from(args.str("now")?)];
    if let Some(binding) = optional_identity(args)? {
        query.push_str(
            " and oauth_subject_hash = ? and workspace_id = ? \
             and machine_id = ? and machine_installation_id = ?",
        );
        params.extend(binding.values());
    }
    query.push_str(" order by stream_sequence asc limit ?");
    params.push(Value::from(args.int("limit")?.max(1)));
    let rows = query_all(connection, &query, &params)?;
    Ok(Value::Array(rows.iter().map(ready_event).collect()))
}

fn ready_event(row: &Row) -> Value {
    let null = Value::Null;
    let field = |name: &str| row.get(name).unwrap_or(&null).clone();
    json!({
        "sequence": field("stream_sequence"),
        "stream_sequence": field("stream_sequence"),
        "event_id": field("event_id"),
        "local_request_id": field("local_request_id"),
        "request_sequence": field("request_sequence"),
        "event_type": field("event_type"),
        "event_schema_version": field("event_schema_version"),
        "payload_json": field("payload_json"),
        "payload_hash": field("payload_hash"),
        "changed_at": field("occurred_at"),
        "oauth_source": field("oauth_source"),
        "oauth_subject_hash": field("oauth_subject_hash"),
        "workspace_id": field("workspace_id"),
        "machine_id": field("machine_id"),
        "machine_installation_id": field("machine_installation_id"),
        "attempt_count": field("attempt_count"),
    })
}

/// Pending review requests that the established binding owns, bounded.
pub(crate) fn list_pending_request_ids(
    connection: &Connection,
    source: &str,
    args: &Args,
) -> StoreResult<Value> {
    let normalized = required_binding(args)?;
    if load_binding(connection, source)?.as_ref() != Some(&normalized) {
        return Ok(json!([]));
    }
    let mut query = String::from(
        "select a.request_id from approval_requests as a \
         join guard_review_outbox_request_sequences as s on s.local_request_id = a.request_id \
         where a.status = 'pending' and a.oauth_source = ? and s.oauth_source = ? \
         and s.oauth_subject_hash = ? and s.workspace_id = ? \
         and s.machine_id = ? and s.machine_installation_id = ?",
    );
    let mut params = vec![Value::from(source), Value::from(source)];
    params.extend(normalized.values());
    if let Some(after) = args.opt_str("after_request_id")? {
        query.push_str(" and a.request_id > ?");
        params.push(Value::from(after));
    }
    if let Some(through) = args.opt_str("through_request_id")? {
        query.push_str(" and a.request_id <= ?");
        params.push(Value::from(through));
    }
    query.push_str(if args.flag("descending")? {
        " order by a.request_id desc limit ?"
    } else {
        " order by a.request_id asc limit ?"
    });
    params.push(Value::from(args.int("limit")?.max(1)));
    let rows = query_all(connection, &query, &params)?;
    Ok(Value::Array(
        rows.iter()
            .map(|row| Value::from(text(row, "request_id")))
            .collect(),
    ))
}

/// Decoded, authenticated snapshots of a request, newest first.
pub(crate) fn list_snapshots(
    connection: &Connection,
    source: &str,
    args: &Args,
) -> StoreResult<Value> {
    let rows = query_all(
        connection,
        "select stream_sequence, event_id, local_request_id, request_sequence, \
         event_type, event_schema_version, payload_json, payload_hash, \
         occurred_at, oauth_source, oauth_subject_hash, workspace_id, \
         machine_id, machine_installation_id \
         from guard_review_outbox_events \
         where local_request_id = ? and oauth_source = ? and binding_status = 'ready' \
         order by request_sequence desc, stream_sequence desc",
        &[Value::from(args.str("request_id")?), Value::from(source)],
    )?;
    Ok(Value::Array(
        rows.iter()
            .filter_map(decode_stored_event)
            .map(|event| Value::Object(event.snapshot))
            .collect(),
    ))
}

fn retry_at(now: &str, fallback_now: &str, attempts: i64) -> StoreResult<String> {
    let delay_micros = (500_000_i64 << attempts.clamp(0, 10)).min(300_000_000);
    add_seconds_isoformat(now, delay_micros)
        .or_else(|| add_seconds_isoformat(fallback_now, delay_micros))
        .ok_or(StoreError::Invalid("native_guard_store_args_invalid"))
}

pub(crate) fn retry_events(
    connection: &Connection,
    source: &str,
    args: &Args,
) -> StoreResult<Value> {
    let sequences = positive_sequences(args)?;
    if sequences.is_empty() {
        return Ok(json!(0));
    }
    let binding = delivered_binding(args)?;
    let (now, fallback_now) = (args.str("now")?, args.str("fallback_now")?);
    let error = py_prefix(args.str("error")?, 512);
    let mut updated = 0;
    for sequence in sequences {
        let mut params = vec![Value::from(sequence), Value::from(source)];
        params.extend(binding.values());
        let Some(row) = query_one(
            connection,
            "select attempt_count from guard_review_outbox_events \
             where stream_sequence = ? and oauth_source = ? and oauth_subject_hash = ? \
             and workspace_id = ? and machine_id = ? and machine_installation_id = ? \
             and acknowledged_at is null",
            &params,
        )?
        else {
            continue;
        };
        let attempts = int(&row, "attempt_count") + 1;
        updated += exec(
            connection,
            "update guard_review_outbox_events \
             set attempt_count = ?, next_attempt_at = ?, last_error = ? where stream_sequence = ?",
            &[
                Value::from(attempts),
                Value::from(retry_at(now, fallback_now, attempts)?),
                Value::from(error.clone()),
                Value::from(sequence),
            ],
        )?;
    }
    Ok(json!(updated))
}

pub(crate) fn quarantine_event(
    connection: &Connection,
    source: &str,
    args: &Args,
) -> StoreResult<Value> {
    let binding = delivered_binding(args)?;
    let mut params = vec![
        Value::from(py_prefix(args.str("reason")?, 128)),
        Value::from(py_prefix(args.str("error")?, 512)),
        Value::from(args.int("sequence")?),
        Value::from(source),
    ];
    params.extend(binding.values());
    let changed = exec(
        connection,
        "update guard_review_outbox_events \
         set binding_status = 'quarantined', quarantine_reason = ?, last_error = ? \
         where stream_sequence = ? and oauth_source = ? and oauth_subject_hash = ? \
         and workspace_id = ? and machine_id = ? and machine_installation_id = ? \
         and binding_status = 'ready' and acknowledged_at is null",
        &params,
    )?;
    Ok(json!(changed))
}

/// Mark events delivered, then compact the acknowledged prefix of the ready
/// stream while retaining quarantined evidence.
pub(crate) fn acknowledge(
    connection: &Connection,
    source: &str,
    sequences: &[i64],
    binding: &Binding,
    acknowledged_at: &str,
) -> StoreResult<i64> {
    if sequences.is_empty() {
        return Ok(0);
    }
    let mut params = vec![Value::from(acknowledged_at)];
    params.extend(sequences.iter().map(|sequence| Value::from(*sequence)));
    params.push(Value::from(source));
    params.extend(binding.values());
    exec(
        connection,
        &format!(
            "update guard_review_outbox_events set acknowledged_at = ? \
             where stream_sequence in ({}) and oauth_source = ? and oauth_subject_hash = ? \
             and workspace_id = ? and machine_id = ? and machine_installation_id = ? \
             and binding_status = 'ready' and acknowledged_at is null",
            placeholders(sequences.len())
        ),
        &params,
    )?;
    let mut params = vec![Value::from(source)];
    params.extend(binding.values());
    let rows = query_all(
        connection,
        "select stream_sequence, acknowledged_at from guard_review_outbox_events \
         where oauth_source = ? and oauth_subject_hash = ? and workspace_id = ? \
         and machine_id = ? and machine_installation_id = ? and binding_status = 'ready' \
         order by stream_sequence",
        &params,
    )?;
    let prefix: Vec<i64> = rows
        .iter()
        .take_while(|row| !crate::guard_store_db::is_null(row, "acknowledged_at"))
        .map(|row| int(row, "stream_sequence"))
        .collect();
    let Some(last) = prefix.last().copied() else {
        return Ok(0);
    };
    let deleted = exec(
        connection,
        &format!(
            "delete from guard_review_outbox_events \
             where stream_sequence in ({}) and binding_status = 'ready'",
            placeholders(prefix.len())
        ),
        &prefix
            .iter()
            .map(|sequence| Value::from(*sequence))
            .collect::<Vec<_>>(),
    )?;
    let mut params = vec![Value::from(source)];
    params.extend(binding.values());
    params.push(Value::from(last));
    params.push(Value::from(acknowledged_at));
    exec(
        connection,
        "insert into guard_review_outbox_cursors (\
         oauth_source, oauth_subject_hash, workspace_id, machine_id, \
         machine_installation_id, acknowledged_stream_sequence, updated_at \
         ) values (?, ?, ?, ?, ?, ?, ?) \
         on conflict(oauth_source, oauth_subject_hash, workspace_id, machine_id, machine_installation_id) \
         do update set acknowledged_stream_sequence = max(\
         guard_review_outbox_cursors.acknowledged_stream_sequence, \
         excluded.acknowledged_stream_sequence), updated_at = excluded.updated_at",
        &params,
    )?;
    Ok(deleted.max(0))
}

pub(crate) fn acknowledge_method(
    connection: &Connection,
    source: &str,
    args: &Args,
) -> StoreResult<Value> {
    let sequences = positive_sequences(args)?;
    if sequences.is_empty() {
        return Ok(json!(0));
    }
    let binding = delivered_binding(args)?;
    let acknowledged_at = args.str("acknowledged_at")?;
    Ok(json!(acknowledge(
        connection,
        source,
        &sequences,
        &binding,
        acknowledged_at
    )?))
}

/// Outbox depth plus quarantine diagnostics for one workspace or identity.
pub(crate) fn status(connection: &Connection, source: &str, args: &Args) -> StoreResult<Value> {
    let now = args.str("now")?;
    let workspace = args.raw("workspace_id");
    let mut query = String::from(
        "select count(*) as depth, min(occurred_at) as oldest_changed_at, \
         max(attempt_count) as max_attempt_count, max(last_error) as last_error, \
         min(next_attempt_at) as next_attempt_at, \
         sum(case when next_attempt_at is null or next_attempt_at <= ? then 1 else 0 end) as ready_depth \
         from guard_review_outbox_events where oauth_source = ? and binding_status = 'ready' \
         and acknowledged_at is null",
    );
    let mut params = vec![Value::from(now), Value::from(source)];
    let identity = args.identity();
    let only_workspace = workspace.is_some()
        && identity
            .iter()
            .enumerate()
            .all(|(index, value)| index == 1 || value.is_none());
    if only_workspace {
        query.push_str(" and workspace_id = ?");
        params.push(workspace.cloned().unwrap_or(Value::Null));
    } else if let Some(binding) = optional_identity(args)? {
        query.push_str(
            " and oauth_subject_hash = ? and workspace_id = ? \
             and machine_id = ? and machine_installation_id = ?",
        );
        params.extend(binding.values());
    }
    let (diagnostics, diagnostic_params) = diagnostics_query(source, workspace);
    let row = query_one(connection, &query, &params)?;
    let diagnostic = query_one(connection, &diagnostics, &diagnostic_params)?;
    let count = |name: &str| diagnostic.as_ref().map_or(0, |row| int(row, name));
    let identity_quarantined = count("identity_quarantined_depth");
    let null = Value::Null;
    let pick = |name: &str| {
        row.as_ref()
            .and_then(|row| row.get(name))
            .unwrap_or(&null)
            .clone()
    };
    let number = |name: &str| row.as_ref().map_or(0, |row| int(row, name));
    let mut out = Map::new();
    out.insert("oauth_source".into(), Value::from(source));
    out.insert(
        "oauth_subject_hash".into(),
        args.raw("oauth_subject_hash")
            .cloned()
            .unwrap_or(Value::Null),
    );
    out.insert(
        "binding_state".into(),
        Value::from(if identity_quarantined > 0 {
            "quarantined"
        } else {
            "healthy"
        }),
    );
    out.insert(
        "binding_hint".into(),
        if identity_quarantined > 0 {
            Value::from("Review events require explicit identity repair.")
        } else {
            Value::Null
        },
    );
    out.insert("depth".into(), Value::from(number("depth")));
    out.insert("ready_depth".into(), Value::from(number("ready_depth")));
    out.insert("oldest_changed_at".into(), pick("oldest_changed_at"));
    out.insert(
        "max_attempt_count".into(),
        Value::from(number("max_attempt_count")),
    );
    out.insert("last_error".into(), pick("last_error"));
    out.insert("next_attempt_at".into(), pick("next_attempt_at"));
    out.insert("unbound_depth".into(), Value::from(count("unbound_depth")));
    out.insert(
        "other_workspace_depth".into(),
        Value::from(count("other_workspace_depth")),
    );
    out.insert(
        "identity_mismatch_depth".into(),
        Value::from(count("identity_mismatch_depth")),
    );
    out.insert(
        "quarantined_depth".into(),
        Value::from(count("quarantined_depth")),
    );
    out.insert("checked_at".into(), Value::from(now));
    Ok(Value::Object(out))
}

const IDENTITY_REASONS: &str =
    "quarantine_reason in ('identity_incomplete', 'identity_changed_requires_confirmation')";

fn diagnostics_query(source: &str, workspace: Option<&Value>) -> (String, Vec<Value>) {
    let Some(workspace) = workspace else {
        return (
            format!(
                "select \
                 sum(case when binding_status = 'quarantined' then 1 else 0 end) as quarantined_depth, \
                 sum(case when binding_status = 'quarantined' and {IDENTITY_REASONS} then 1 else 0 end) as identity_quarantined_depth, \
                 sum(case when binding_status = 'quarantined' and {IDENTITY_REASONS} \
                   and oauth_source is not null and workspace_id is not null then 1 else 0 end) as identity_mismatch_depth, \
                 sum(case when binding_status = 'quarantined' \
                   and (oauth_source is null or workspace_id is null) then 1 else 0 end) as unbound_depth, \
                 0 as other_workspace_depth from guard_review_outbox_events"
            ),
            Vec::new(),
        );
    };
    let scope = "(oauth_source = ? or (oauth_source is null and (workspace_id is null or workspace_id = ?)))";
    let query = format!(
        "select \
         sum(case when binding_status = 'quarantined' and {scope} then 1 else 0 end) as quarantined_depth, \
         sum(case when binding_status = 'quarantined' and {IDENTITY_REASONS} and {scope} then 1 else 0 end) as identity_quarantined_depth, \
         sum(case when binding_status = 'quarantined' and {IDENTITY_REASONS} \
           and oauth_source is not null and workspace_id is not null \
           and oauth_source = ? and workspace_id = ? then 1 else 0 end) as identity_mismatch_depth, \
         sum(case when binding_status = 'quarantined' \
           and (oauth_source is null or workspace_id is null) \
           and (workspace_id is null or workspace_id = ?) then 1 else 0 end) as unbound_depth, \
         sum(case when binding_status = 'quarantined' and workspace_id is not null \
           and workspace_id != ? and (oauth_source = ? or oauth_source is null) then 1 else 0 end) as other_workspace_depth \
         from guard_review_outbox_events"
    );
    let s = Value::from(source);
    let w = workspace.clone();
    (
        query,
        vec![
            s.clone(),
            w.clone(),
            s.clone(),
            w.clone(),
            s.clone(),
            w.clone(),
            w.clone(),
            w,
            s,
        ],
    )
}
