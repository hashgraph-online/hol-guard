//! Requeueing pending requests into the Review outbox and repairing a
//! rejected retry identity without changing approval authority.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{
    exec, is_null, placeholders, query_all, query_one, text, StoreError, StoreResult,
};
use crate::guard_store_json::{dumps_sorted, Separators};
use crate::guard_store_outbox_append::append_request_snapshot_event;
use crate::guard_store_outbox_binding::{
    bind_events_for_request, load_binding, normalized_binding, row_matches,
};
use crate::guard_store_outbox_identity::{correlation_id, validated_continuation_snapshot};
use crate::guard_store_outbox_queries::acknowledge;

const REQUEUED: &str = "review.request.snapshot_requeued";
const UNREPRESENTABLE: StoreError = StoreError::Invalid("native_guard_store_value_unrepresentable");

/// Frozen snapshot whose correlation id differs from the canonical one for a
/// retry-only or unsupported capability.
fn has_identity_drift(request_id: &str, snapshot_json: Option<&str>) -> bool {
    let Some(frozen) = snapshot_json
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .and_then(|value| validated_continuation_snapshot(&value))
    else {
        return false;
    };
    matches!(
        frozen["capability"].as_str(),
        Some("retry-only" | "unsupported")
    ) && correlation_id(request_id).as_deref() != frozen["correlationId"].as_str()
}

pub(crate) struct RequeueOptions<'a> {
    pub require_binding: bool,
    pub only_retry_identity_drift: bool,
    pub native_replay: bool,
    /// Request id -> sequence above which a newer snapshot already repairs it.
    pub repair_sequences: Option<&'a Map<String, Value>>,
    pub request_ids: Option<Vec<&'a str>>,
    pub snapshots: Option<&'a Map<String, Value>>,
}

pub(crate) fn requeue_pending(
    connection: &Connection,
    source: &str,
    changed_at: &str,
    options: &RequeueOptions,
) -> StoreResult<i64> {
    let current = load_binding(connection, source)?;
    if options.require_binding && current.is_none() {
        return Ok(0);
    }
    if options.repair_sequences.is_some_and(Map::is_empty) {
        return Ok(0);
    }
    let mut query = String::from(
        "select request_id, continuation_snapshot_json from approval_requests \
         where status = 'pending' and oauth_source = ?",
    );
    let mut params = vec![Value::from(source)];
    if let Some(sequences) = options.repair_sequences {
        query.push_str(&format!(
            " and request_id in ({})",
            placeholders(sequences.len())
        ));
        params.extend(sequences.keys().map(|key| Value::from(key.as_str())));
    }
    if let Some(ids) = &options.request_ids {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        query.push_str(&format!(
            " and request_id in ({})",
            placeholders(sorted.len())
        ));
        params.extend(sorted.into_iter().map(Value::from));
    }
    query.push_str(" order by coalesce(last_seen_at, created_at), request_id");
    let mut appended = 0;
    for row in query_all(connection, &query, &params)? {
        let request_id = text(&row, "request_id");
        let frozen = row
            .get("continuation_snapshot_json")
            .and_then(Value::as_str);
        if options.only_retry_identity_drift && !has_identity_drift(request_id, frozen) {
            continue;
        }
        if let (true, Some(binding)) = (options.require_binding, &current) {
            let mut params = vec![Value::from(request_id), Value::from(source)];
            params.extend(binding.values());
            let established = query_one(
                connection,
                "select 1 as present from guard_review_outbox_request_sequences \
                 where local_request_id = ? and oauth_source = ? and oauth_subject_hash = ? \
                 and workspace_id = ? and machine_id = ? and machine_installation_id = ?",
                &params,
            )?;
            if established.is_none() {
                continue;
            }
        }
        let mut snapshot_query = String::from(
            "select oauth_source, oauth_subject_hash, workspace_id, machine_id, \
             machine_installation_id, binding_status from guard_review_outbox_events \
             where local_request_id = ? and event_type = 'review.request.snapshot_requeued'",
        );
        let mut snapshot_params = vec![Value::from(request_id)];
        match options.repair_sequences {
            None => snapshot_query.push_str(" and acknowledged_at is null"),
            Some(sequences) => {
                snapshot_query.push_str(" and request_sequence > ?");
                snapshot_params.push(sequences.get(request_id).cloned().unwrap_or(Value::Null));
            }
        }
        snapshot_query.push_str(" order by request_sequence desc limit 1");
        if let (Some(existing), Some(binding)) = (
            query_one(connection, &snapshot_query, &snapshot_params)?,
            &current,
        ) {
            if text(&existing, "binding_status") == "ready"
                && text(&existing, "oauth_source") == source
                && row_matches(&existing, binding)
            {
                continue;
            }
        }
        bind_events_for_request(connection, request_id, source)?;
        let supplied = options
            .snapshots
            .and_then(|all| all.get(request_id))
            .and_then(Value::as_object);
        appended += append_request_snapshot_event(
            connection,
            request_id,
            source,
            REQUEUED,
            changed_at,
            supplied,
            options.native_replay,
        )?;
    }
    Ok(appended)
}

pub(crate) fn requeue_method(
    connection: &Connection,
    source: &str,
    args: &Args,
    with_marker: bool,
) -> StoreResult<Value> {
    let ids = args.strings("request_ids")?;
    let options = RequeueOptions {
        require_binding: args.flag("require_binding")?,
        only_retry_identity_drift: args.flag("only_retry_identity_drift")?,
        native_replay: args.flag("native_replay")?,
        repair_sequences: args.opt_object("snapshot_repair_sequences")?,
        request_ids: ids,
        snapshots: args.opt_object("request_snapshots")?,
    };
    let changed_at = args.str("changed_at")?;
    let count = requeue_pending(connection, source, changed_at, &options)?;
    if with_marker {
        let [before, after] = marker_parts(args)?;
        exec(
            connection,
            "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?) \
             on conflict(state_key) do update set payload_json = excluded.payload_json, \
             updated_at = excluded.updated_at",
            &[
                Value::from(args.str("marker_key")?),
                Value::from(format!("{before}{count}{after}")),
                Value::from(changed_at),
            ],
        )?;
    }
    Ok(json!(count))
}

/// The marker JSON pre-rendered by the caller around the `requeued` count.
fn marker_parts<'a>(args: &Args<'a>) -> StoreResult<[&'a str; 2]> {
    let parts = args.strings("marker_json_parts")?.unwrap_or_default();
    match parts.as_slice() {
        [before, after] => Ok([before, after]),
        _ => Err(StoreError::Invalid("native_guard_store_args_invalid")),
    }
}

/// Restore only the deterministic correlation identity Cloud asked for.
pub(crate) fn repair_rejected_correlation(
    connection: &Connection,
    source: &str,
    args: &Args,
) -> StoreResult<Value> {
    let event_sequence = args.int("event_sequence")?;
    let changed_at = args.str("changed_at")?;
    let parts = args.object("binding")?;
    let part = |key: &str| {
        parts
            .get(key)
            .and_then(Value::as_str)
            .ok_or(StoreError::Invalid("native_guard_store_args_invalid"))
    };
    // The raw supplied binding must equal the stored one before normalization.
    let raw_matches = |row: &Map<String, Value>| {
        [
            "oauth_subject_hash",
            "workspace_id",
            "machine_id",
            "machine_installation_id",
        ]
        .iter()
        .all(|key| row.get(*key) == parts.get(*key))
    };
    let Some(current) = load_binding(connection, source)? else {
        return Ok(json!(0));
    };
    let current_row: Map<String, Value> = [
        ("oauth_subject_hash", current.subject_hash.clone()),
        ("workspace_id", current.workspace_id.clone()),
        ("machine_id", current.machine_id.clone()),
        ("machine_installation_id", current.installation_id.clone()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), Value::String(value)))
    .collect();
    if !raw_matches(&current_row) {
        return Ok(json!(0));
    }
    let Some(event) = query_one(
        connection,
        "select * from guard_review_outbox_events where stream_sequence = ? and oauth_source = ?",
        &[Value::from(event_sequence), Value::from(source)],
    )?
    else {
        return Ok(json!(0));
    };
    if !raw_matches(&event)
        || text(&event, "binding_status") != "ready"
        || !is_null(&event, "acknowledged_at")
    {
        return Ok(json!(0));
    }
    let request_id = text(&event, "local_request_id").to_owned();
    let request = query_one(
        connection,
        "select continuation_snapshot_json from approval_requests \
         where request_id = ? and oauth_source = ? and status = 'pending'",
        &[Value::from(request_id.as_str()), Value::from(source)],
    )?;
    let established = query_one(
        connection,
        "select * from guard_review_outbox_request_sequences where local_request_id = ?",
        &[Value::from(request_id.as_str())],
    )?;
    let (Some(request), Some(established)) = (request, established) else {
        return Ok(json!(0));
    };
    if text(&established, "oauth_source") != source || !raw_matches(&established) {
        return Ok(json!(0));
    }
    let Some(mut snapshot) = request
        .get("continuation_snapshot_json")
        .and_then(Value::as_str)
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .and_then(|value| validated_continuation_snapshot(&value))
    else {
        return Ok(json!(0));
    };
    if !matches!(
        snapshot["capability"].as_str(),
        Some("retry-only" | "unsupported")
    ) {
        return Ok(json!(0));
    }
    let Some(expected) = correlation_id(&request_id) else {
        return Err(StoreError::Value("local_request_id is required".to_owned()));
    };
    if snapshot["correlationId"].as_str() == Some(expected.as_str()) {
        return Ok(json!(0));
    }
    snapshot.insert("correlationId".to_owned(), Value::String(expected));
    let serialized =
        dumps_sorted(&Value::Object(snapshot), Separators::Compact).ok_or(UNREPRESENTABLE)?;
    exec(
        connection,
        "update approval_requests set continuation_snapshot_json = ? \
         where request_id = ? and oauth_source = ?",
        &[
            Value::from(serialized),
            Value::from(request_id.as_str()),
            Value::from(source),
        ],
    )?;
    let appended = append_request_snapshot_event(
        connection,
        &request_id,
        source,
        REQUEUED,
        changed_at,
        None,
        false,
    )?;
    if appended == 0 {
        return Err(StoreError::Integrity(
            "Retry identity repair did not append its replacement event".to_owned(),
        ));
    }
    let supplied = normalized_binding([
        part("oauth_subject_hash")?,
        part("workspace_id")?,
        part("machine_id")?,
        part("machine_installation_id")?,
    ])?;
    acknowledge(connection, source, &[event_sequence], &supplied, changed_at)?;
    Ok(json!(appended))
}
