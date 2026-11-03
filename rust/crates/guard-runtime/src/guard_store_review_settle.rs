//! `settle_rejected_review_events`: what becomes of the events Cloud rejected
//! in one delivery batch, decided in one store transaction.
//!
//! A rejected event is, in order: rebased when Cloud reports a snapshot
//! sequence collision for exactly the event that was sent, repaired when Cloud
//! asks for the canonical correlation, quarantined when Cloud's answer can
//! never change, and otherwise counted. An event Cloud rejected
//! `MAX_REJECTED_DELIVERY_ATTEMPTS` times is dead-lettered. Quarantined and
//! dead-lettered events keep their evidence; only the retry stops.
//!
//! A per-event `retryAfterMs` hint, or a snapshot request for a request that
//! is still pending, is not counted: neither shows the event can never be
//! accepted. The counters live in `guard_store_review_rejection_counts`.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_one, text, value_error, StoreError, StoreResult};
use crate::guard_store_outbox_binding::normalized_binding;
use crate::guard_store_outbox_queries as queries;
use crate::guard_store_outbox_reads as reads;
use crate::guard_store_outbox_recover::recover_sequences;
use crate::guard_store_outbox_requeue::repair_rejected_correlation;
use crate::guard_store_review_rejection_counts::{load_counts, save_counts};

/// Server rejections tolerated for one event before it is dead-lettered.
const MAX_REJECTED_DELIVERY_ATTEMPTS: i64 = 12;
const MAX_SAFE_STREAM_SEQUENCE: i64 = (1 << 53) - 1;
const BINDING_KEYS: [&str; 4] = [
    "oauth_subject_hash",
    "workspace_id",
    "machine_id",
    "machine_installation_id",
];

const SEQUENCE_COLLISION: &str = "review_event_snapshot_sequence_collision";
const CORRELATION_REQUIRED: &str = "review_event_canonical_correlation_required";
const CONTINUATION_MISMATCH: &str = "review_continuation_binding_mismatch";
const RETRY_EXHAUSTED: &str = "review_event_retry_exhausted";
/// Cloud stores these quarantines against the event id and never revalidates
/// them, so every retry of the same event returns the same result.
const TERMINAL_CODES: [&str; 1] = ["review_event_runtime_grant_missing"];
/// Cloud keeps the same stored quarantine for these codes once it has
/// recorded them. Only a result whose status is "quarantined" is that stored
/// decision.
const STORED_QUARANTINE_CODES: [&str; 3] = [
    "review_event_payload_hash_mismatch",
    "review_event_snapshot_claim_mismatch",
    "review_event_request_correlation_mismatch",
];
/// A newer snapshot event can heal these, but only while the local request is
/// still pending and can be requeued.
const SNAPSHOT_REPAIR_CODES: [&str; 2] =
    ["review_event_snapshot_required", "missing_request_snapshot"];

const INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");

/// One rejected event: its stream sequence, Cloud's result and the fields of
/// the event that was sent.
struct Rejection<'a> {
    sequence: i64,
    result: &'a Map<String, Value>,
    event: Option<&'a Map<String, Value>>,
}

impl Rejection<'_> {
    fn code(&self) -> Option<&str> {
        self.result.get("code").and_then(Value::as_str)
    }

    fn event_text(&self, key: &str) -> Option<&str> {
        self.event?.get(key).and_then(Value::as_str)
    }

    fn request_id(&self) -> Option<&str> {
        self.event_text("localRequestId")
            .filter(|request| !request.is_empty())
    }
}

/// Answers `{"retained": [index, ...], "progressed": bool}`: the indexes of
/// the rejections that stay retryable, and whether the batch made progress
/// (Cloud acknowledged something, or a rejected event left the retry path).
pub(crate) fn settle(connection: &Connection, source: &str, args: &Args) -> StoreResult<Value> {
    let sequences = args.ints("sequences")?;
    let results = objects(args, "results")?;
    if results.len() != sequences.len() {
        return Err(INVALID);
    }
    let events = sent_events(args)?;
    let binding = args.object("binding")?;
    if !BINDING_KEYS
        .iter()
        .all(|key| binding.get(*key).is_some_and(Value::is_string))
    {
        return Err(INVALID);
    }
    let acknowledged = args.ints("acknowledged")?;
    let changed_at = args.str("changed_at")?;
    let rejections: Vec<Rejection> = sequences
        .iter()
        .zip(results)
        .map(|(sequence, result)| Rejection {
            sequence: *sequence,
            result,
            event: events.get(sequence).copied(),
        })
        .collect();

    let mut open: Vec<usize> = (0..rejections.len()).collect();
    let rebased = rebase_collisions(connection, source, args, &rejections, binding)?;
    open.retain(|index| !rebased.contains(&rejections[*index].sequence));
    let repaired =
        repair_correlations(connection, source, &rejections, &open, binding, changed_at)?;
    open.retain(|index| !repaired.contains(&rejections[*index].sequence));
    open = quarantine_terminal(connection, source, &rejections, &open, binding)?;

    let still_open: BTreeSet<i64> = open
        .iter()
        .map(|index| rejections[*index].sequence)
        .collect();
    let resolved: Vec<i64> = sequences
        .iter()
        .copied()
        .filter(|sequence| !still_open.contains(sequence))
        .collect();
    let cleared: Vec<i64> = acknowledged.iter().chain(&resolved).copied().collect();
    let (retryable, dead_lettered) = dead_letter_exhausted(
        connection,
        source,
        &rejections,
        &open,
        &cleared,
        binding,
        changed_at,
    )?;
    let retained: Vec<usize> = open
        .into_iter()
        .filter(|index| retryable.contains(&rejections[*index].sequence))
        .collect();
    Ok(json!({
        "retained": retained,
        "progressed": !acknowledged.is_empty() || !resolved.is_empty() || dead_lettered > 0,
    }))
}

fn objects<'a>(args: &Args<'a>, key: &str) -> StoreResult<Vec<&'a Map<String, Value>>> {
    args.raw(key)
        .and_then(Value::as_array)
        .ok_or(INVALID)?
        .iter()
        .map(|item| item.as_object().ok_or(INVALID))
        .collect()
}

/// `events` is `[[sequence, {eventId, eventType, localRequestId}], ...]`.
fn sent_events<'a>(args: &Args<'a>) -> StoreResult<BTreeMap<i64, &'a Map<String, Value>>> {
    let mut events = BTreeMap::new();
    for pair in args
        .raw("events")
        .and_then(Value::as_array)
        .ok_or(INVALID)?
    {
        let (Some(sequence), Some(event)) = (
            pair.get(0).and_then(Value::as_i64),
            pair.get(1).and_then(Value::as_object),
        ) else {
            return Err(INVALID);
        };
        events.insert(sequence, event);
    }
    Ok(events)
}

fn binding_args(binding: &Map<String, Value>) -> Map<String, Value> {
    BINDING_KEYS
        .iter()
        .map(|key| ((*key).to_owned(), binding[*key].clone()))
        .collect()
}

/// The sequence collisions Cloud reported for exactly the event that was
/// sent, by stream sequence.
fn sent_collisions<'a>(rejections: &[Rejection<'a>]) -> BTreeMap<i64, &'a str> {
    let mut collisions = BTreeMap::new();
    for rejection in rejections {
        let event_id = rejection.result.get("eventId").and_then(Value::as_str);
        if let Some(event_id) = event_id.filter(|id| {
            rejection.code() == Some(SEQUENCE_COLLISION)
                && rejection.event_text("eventId") == Some(*id)
        }) {
            collisions.insert(rejection.sequence, event_id);
        }
    }
    collisions
}

/// Cloud's high-water mark when it is a safe stream sequence. Zero is valid
/// for a fresh rejected stream.
fn safe_high_water(value: Option<&Value>) -> Option<i64> {
    value
        .and_then(Value::as_i64)
        .filter(|through| (0..=MAX_SAFE_STREAM_SEQUENCE).contains(through))
}

/// Rebase the snapshot events Cloud reported as sequence collisions, when the
/// result names exactly the event that was sent and Cloud's high-water mark is
/// a safe integer. Returns the rebased sequences.
fn rebase_collisions(
    connection: &Connection,
    source: &str,
    args: &Args,
    rejections: &[Rejection],
    binding: &Map<String, Value>,
) -> StoreResult<BTreeSet<i64>> {
    let collisions = sent_collisions(rejections);
    let Some(acknowledged_through) =
        safe_high_water(args.raw("acknowledged_through")).filter(|_| !collisions.is_empty())
    else {
        return Ok(BTreeSet::new());
    };
    let Ok(normalized) = normalized_binding(BINDING_KEYS.map(|key| text(binding, key))) else {
        return Ok(BTreeSet::new());
    };
    let request = json!({
        "collisions": collisions.iter().map(|(sequence, id)| json!([sequence, id])).collect::<Vec<_>>(),
        "acknowledged_through": acknowledged_through,
        "binding": {
            "oauth_subject_hash": normalized.subject_hash,
            "workspace_id": normalized.workspace_id,
            "machine_id": normalized.machine_id,
            "machine_installation_id": normalized.installation_id,
        },
    });
    let pairs = recover_sequences(
        connection,
        source,
        &Args(request.as_object().ok_or(INVALID)?),
    )?;
    Ok(pairs
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|pair| pair.get(0).and_then(Value::as_i64))
        .collect())
}

/// Requeue the events Cloud rejected for a missing canonical correlation.
/// Returns the repaired sequences.
fn repair_correlations(
    connection: &Connection,
    source: &str,
    rejections: &[Rejection],
    open: &[usize],
    binding: &Map<String, Value>,
    changed_at: &str,
) -> StoreResult<BTreeSet<i64>> {
    let mut repaired = BTreeSet::new();
    for rejection in open.iter().map(|index| &rejections[*index]) {
        if rejection.code() != Some(CORRELATION_REQUIRED) {
            continue;
        }
        let request = json!({
            "event_sequence": rejection.sequence,
            "binding": binding_args(binding),
            "changed_at": changed_at,
        });
        let changed = repair_rejected_correlation(
            connection,
            source,
            &Args(request.as_object().ok_or(INVALID)?),
        )?;
        if changed.as_i64().is_some_and(|count| count > 0) {
            repaired.insert(rejection.sequence);
        }
    }
    Ok(repaired)
}

/// `quarantine_review_event`: true when the event was quarantined.
fn quarantine(
    connection: &Connection,
    source: &str,
    sequence: i64,
    reason: &str,
    error: &str,
    binding: &Map<String, Value>,
) -> StoreResult<bool> {
    let mut request = binding_args(binding);
    request.insert("sequence".to_owned(), Value::from(sequence));
    request.insert("reason".to_owned(), Value::from(reason));
    request.insert("error".to_owned(), Value::from(error));
    let changed = queries::quarantine_event(connection, source, &Args(&request))?;
    Ok(changed.as_i64().is_some_and(|count| count > 0))
}

/// Quarantine the rejections whose result Cloud will never change, and keep
/// the rest. A failed store transition stays retryable, so a concurrent
/// delivery or a changed binding cannot silently discard unacknowledged
/// evidence.
fn quarantine_terminal(
    connection: &Connection,
    source: &str,
    rejections: &[Rejection],
    open: &[usize],
    binding: &Map<String, Value>,
) -> StoreResult<Vec<usize>> {
    let mut retained = Vec::new();
    for index in open {
        let rejection = &rejections[*index];
        let code = rejection.code();
        // A frozen terminal result cannot acquire a different continuation
        // binding through retries. Keep the rejected evidence unacknowledged.
        if code == Some(CONTINUATION_MISMATCH)
            && rejection
                .event_text("eventType")
                .is_some_and(|kind| kind.starts_with("continuation_"))
            && quarantine(
                connection,
                source,
                rejection.sequence,
                CONTINUATION_MISMATCH,
                "Cloud rejected the immutable continuation binding; retained for diagnostics.",
                binding,
            )?
        {
            continue;
        }
        if let Some(code) = code {
            let terminal = TERMINAL_CODES.contains(&code)
                || (STORED_QUARANTINE_CODES.contains(&code)
                    && rejection.result.get("status").and_then(Value::as_str)
                        == Some("quarantined"))
                || (SNAPSHOT_REPAIR_CODES.contains(&code)
                    && snapshot_cannot_be_requeued(
                        connection, source, rejections, open, rejection,
                    )?);
            if terminal
                && quarantine(
                    connection,
                    source,
                    rejection.sequence,
                    code,
                    "Cloud quarantined this event permanently; retained for diagnostics.",
                    binding,
                )?
            {
                continue;
            }
        }
        retained.push(*index);
    }
    Ok(retained)
}

/// Whether the local approval request exists and is still pending.
fn request_is_pending(connection: &Connection, request_id: &str) -> StoreResult<bool> {
    let sql = "select 1 from approval_requests where request_id = ? and status = 'pending'";
    Ok(query_one(connection, sql, &[Value::from(request_id)])?.is_some())
}

/// True when no snapshot can reach Cloud for the request behind a rejection.
///
/// Requeueing only repairs pending requests, so a resolved, expired or
/// missing request can only get the snapshot Cloud asks for from an event that
/// is already queued for it. Events Cloud rejected in this batch do not count;
/// any other queued event of the request, for example one in backoff, may
/// still carry that snapshot.
fn snapshot_cannot_be_requeued(
    connection: &Connection,
    source: &str,
    rejections: &[Rejection],
    open: &[usize],
    rejection: &Rejection,
) -> StoreResult<bool> {
    let Some(request_id) = rejection.request_id() else {
        return Ok(false);
    };
    if request_is_pending(connection, request_id)? {
        return Ok(false);
    }
    let rejected_here = open
        .iter()
        .filter(|index| rejections[**index].event_text("localRequestId") == Some(request_id))
        .count();
    snapshots_at_most(connection, source, request_id, rejected_here)
}

/// Whether the request's queued snapshot history holds at most `limit`
/// snapshots, read page by page and stopped once it holds more.
fn snapshots_at_most(
    connection: &Connection,
    source: &str,
    request_id: &str,
    limit: usize,
) -> StoreResult<bool> {
    let mut count = 0usize;
    let mut cursor = Value::Null;
    loop {
        let mut request = Map::new();
        request.insert("request_id".to_owned(), Value::from(request_id));
        if !cursor.is_null() {
            request.insert("after".to_owned(), cursor.clone());
        }
        let page = reads::list_snapshots(connection, source, &Args(&request))?;
        count += page["snapshots"].as_array().map_or(0, Vec::len);
        if count > limit {
            return Ok(false);
        }
        let next = page["next"].clone();
        if next.is_null() {
            return Ok(true);
        }
        if next == cursor {
            return value_error("Review snapshot paging made no progress.");
        }
        cursor = next;
    }
}

/// A rejection that is not evidence the event can never be accepted: a
/// per-event `retryAfterMs` hint, or a snapshot request for a request that is
/// still pending, which the requeue repair resolves.
fn is_uncounted(connection: &Connection, rejection: &Rejection) -> StoreResult<bool> {
    if rejection
        .result
        .get("retryAfterMs")
        .and_then(Value::as_i64)
        .is_some_and(|after| after > 0)
    {
        return Ok(true);
    }
    match (rejection.code(), rejection.request_id()) {
        (Some(code), Some(request_id)) if SNAPSHOT_REPAIR_CODES.contains(&code) => {
            request_is_pending(connection, request_id)
        }
        _ => Ok(false),
    }
}

/// Count this batch's rejections and dead-letter the events that reached the
/// cap. Transport failures never get here, so an outage cannot dead-letter
/// healthy events. Returns the sequences that stay retryable and the number
/// dead-lettered.
fn dead_letter_exhausted(
    connection: &Connection,
    source: &str,
    rejections: &[Rejection],
    open: &[usize],
    cleared: &[i64],
    binding: &Map<String, Value>,
    changed_at: &str,
) -> StoreResult<(BTreeSet<i64>, usize)> {
    let original = load_counts(connection, source)?;
    let mut counts = original.clone();
    for sequence in cleared {
        counts.remove(&sequence.to_string());
    }
    let mut retained = BTreeSet::new();
    let mut dead_lettered = 0;
    for rejection in open.iter().map(|index| &rejections[*index]) {
        if is_uncounted(connection, rejection)? {
            retained.insert(rejection.sequence);
            continue;
        }
        let name = rejection.sequence.to_string();
        let attempts = counts.get(&name).copied().unwrap_or(0) + 1;
        if attempts >= MAX_REJECTED_DELIVERY_ATTEMPTS
            && quarantine(
                connection,
                source,
                rejection.sequence,
                RETRY_EXHAUSTED,
                &format!("Cloud rejected this event {attempts} times; retained for diagnostics."),
                binding,
            )?
        {
            counts.remove(&name);
            dead_lettered += 1;
            continue;
        }
        counts.insert(name, attempts);
        retained.insert(rejection.sequence);
    }
    save_counts(connection, source, &counts, &original, changed_at)?;
    Ok((retained, dead_lettered))
}

#[cfg(test)]
#[path = "guard_store_review_settle_tests.rs"]
mod tests;
