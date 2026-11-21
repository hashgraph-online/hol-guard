//! Native workspace review replay markers: one `sync_state` row per pending
//! Cloud Review request that records its last native context probe.
//!
//! Port of the marker rules in `runtime/native_workspace_review_replay.py`,
//! `native_workspace_review_replay_loop.py` and
//! `native_workspace_review_replay_delivery.py`. Python still builds the
//! context and requeues the events; the store decides when a request is due
//! for another probe and writes each marker change from the stored row inside
//! its write transaction.

use rusqlite::Connection;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::guard_store_args::Args;
use crate::guard_store_db::{value_error, StoreResult};
use crate::guard_store_json::{add_micros_aware_isoformat, aware_epoch_micros};
use crate::guard_store_sync_state::{read_payload, write_encoded};

/// `_REPLAY_MARKER`.
const MARKER: &str = "guard_cloud_review_native_workspace_review_replay";
const SCHEMA: &str = "guard-cloud-review-native-workspace-review-request.v1";
const RETRY_BASE_SECONDS: i64 = 60;
const RETRY_MAX_SECONDS: i64 = 15 * 60;
const PROBE_INTERVAL_SECONDS: i64 = 5 * 60;
const REPLAY_DELAYS_SECONDS: [i64; 4] = [5 * 60, 15 * 60, 60 * 60, 6 * 60 * 60];
const DIGEST_LENGTH: usize = 64;
/// Fields a failed probe keeps from the previous marker.
const RETAINED: [&str; 7] = [
    "authority_generation",
    "authority_record_digest",
    "requeued",
    "replay_attempts",
    "accepted",
    "accepted_at",
    "request_snapshot",
];
/// Retained only while the marker's binding is the current one.
const BINDING_BOUND: [&str; 2] = ["accepted", "accepted_at"];

/// One request's marker row and the caller's view of now.
pub(crate) struct Request<'a> {
    pub(crate) key: String,
    pub(crate) request_id: &'a str,
    pub(crate) binding: &'a Map<String, Value>,
    pub(crate) now: &'a str,
    pub(crate) now_micros: i128,
}

/// `_marker_key`: the source and a digest of the request id.
pub(crate) fn marker_key(source: &str, request_id: &str) -> String {
    let digest = hex::encode(Sha256::digest(request_id.as_bytes()));
    format!("{MARKER}:{source}:request:{digest}")
}

pub(crate) fn request<'a>(args: &Args<'a>) -> StoreResult<Request<'a>> {
    let source = args.str("source")?;
    let request_id = args.str("request_id")?;
    if source.is_empty() || request_id.is_empty() {
        return value_error("invalid_request");
    }
    let binding = args.object("binding")?;
    if binding.is_empty() || !binding.values().all(Value::is_string) {
        return value_error("invalid_binding");
    }
    let now = args.str("now")?;
    let Some(now_micros) = aware_epoch_micros(now) else {
        return value_error("invalid_now");
    };
    Ok(Request {
        key: marker_key(source, request_id),
        request_id,
        binding,
        now,
        now_micros,
    })
}

/// The stored marker, when it is an object.
pub(crate) fn stored(
    connection: &Connection,
    key: &str,
) -> StoreResult<Option<Map<String, Value>>> {
    Ok(match read_payload(connection, key)? {
        Some(Value::Object(marker)) => Some(marker),
        _ => None,
    })
}

pub(crate) fn same_binding(marker: &Map<String, Value>, binding: &Map<String, Value>) -> bool {
    marker.get("binding").and_then(Value::as_object) == Some(binding)
}

/// `type(value) is int`: JSON booleans are not integers here.
fn int(marker: &Map<String, Value>, field: &str) -> Option<i64> {
    marker.get(field).and_then(Value::as_i64)
}

fn retry_delay(attempts: i64) -> i64 {
    let exponent = u32::try_from(attempts.clamp(0, 4)).unwrap_or(4);
    RETRY_MAX_SECONDS.min(RETRY_BASE_SECONDS * 2_i64.pow(exponent))
}

fn replay_delay(attempts: i64) -> i64 {
    let last = REPLAY_DELAYS_SECONDS.len() - 1;
    let index = usize::try_from(attempts.saturating_sub(1).max(0))
        .unwrap_or(last)
        .min(last);
    REPLAY_DELAYS_SECONDS[index]
}

pub(crate) fn after(request: &Request<'_>, seconds: i64) -> StoreResult<String> {
    add_micros_aware_isoformat(request.now, seconds * 1_000_000)
        .map_or_else(|| value_error("invalid_now"), Ok)
}

/// `_probe_due`: no marker, another binding, or a retry time that has come.
pub(crate) fn probe_due(
    marker: Option<&Map<String, Value>>,
    request: &Request<'_>,
    force: bool,
) -> bool {
    let Some(marker) = marker.filter(|marker| !force && same_binding(marker, request.binding))
    else {
        return true;
    };
    marker
        .get("next_probe_at")
        .and_then(Value::as_str)
        .and_then(aware_epoch_micros)
        .is_none_or(|retry_at| retry_at <= request.now_micros)
}

/// `_failure_marker`: count the attempt and back off before the next probe.
pub(crate) fn failure_marker(
    marker: Option<&Map<String, Value>>,
    request: &Request<'_>,
) -> StoreResult<Map<String, Value>> {
    // No marker, or one without the field, counts from zero.
    let previous = marker.map_or(Some(0), |marker| {
        marker.get("attempts").map_or(Some(0), Value::as_i64)
    });
    let attempts = previous
        .filter(|attempts| *attempts >= 0)
        .map_or(1, |attempts| attempts.saturating_add(1));
    let mut result = base(request);
    result.insert("attempts".to_owned(), json!(attempts));
    result.insert(
        "next_probe_at".to_owned(),
        json!(after(request, retry_delay(attempts))?),
    );
    if let Some(marker) = marker {
        let bound = same_binding(marker, request.binding);
        for field in RETAINED {
            if BINDING_BOUND.contains(&field) && !bound {
                continue;
            }
            if let Some(value) = marker.get(field) {
                result.insert(field.to_owned(), value.clone());
            }
        }
    }
    Ok(result)
}

fn base(request: &Request<'_>) -> Map<String, Value> {
    let mut marker = Map::new();
    marker.insert("schema".to_owned(), json!(SCHEMA));
    marker.insert("request_id".to_owned(), json!(request.request_id));
    marker.insert("binding".to_owned(), Value::Object(request.binding.clone()));
    marker
}

fn valid_digest(value: &str) -> bool {
    value.len() == DIGEST_LENGTH
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// `_authority_marker`: a positive generation and a lowercase SHA-256 digest.
pub(crate) fn authority_marker(
    context: Option<&Map<String, Value>>,
    request: &Request<'_>,
) -> Option<Map<String, Value>> {
    let context = context?;
    let generation = int(context, "authority_generation").filter(|generation| *generation > 0)?;
    let digest = context
        .get("authority_record_digest")
        .and_then(Value::as_str)
        .filter(|digest| valid_digest(digest))?;
    let mut marker = base(request);
    marker.insert("authority_generation".to_owned(), json!(generation));
    marker.insert("authority_record_digest".to_owned(), json!(digest));
    Some(marker)
}

fn same_authority(marker: &Map<String, Value>, authority: &Map<String, Value>) -> bool {
    ["authority_generation", "authority_record_digest"]
        .iter()
        .all(|field| marker.get(*field) == authority.get(*field))
}

/// `_authority_is_replayed`: this authority was requeued or replayed before.
pub(crate) fn authority_is_replayed(
    marker: Option<&Map<String, Value>>,
    authority: &Map<String, Value>,
) -> bool {
    marker.is_some_and(|marker| {
        same_authority(marker, authority)
            && (int(marker, "requeued").is_some_and(|count| count > 0)
                || int(marker, "replay_attempts").is_some_and(|count| count > 0))
    })
}

/// `_authority_is_accepted`: the server accepted this authority's claim.
pub(crate) fn authority_is_accepted(
    marker: Option<&Map<String, Value>>,
    authority: &Map<String, Value>,
) -> bool {
    marker.is_some_and(|marker| {
        marker.get("accepted") == Some(&Value::Bool(true)) && same_authority(marker, authority)
    })
}

/// The marker a requeue writes with its events: the retry and replay counts
/// and the cooldown before this authority is replayed again.
pub(crate) fn replay_seed(
    previous: Option<&Map<String, Value>>,
    authority: &Map<String, Value>,
    request: &Request<'_>,
) -> StoreResult<Map<String, Value>> {
    let replayed = authority_is_replayed(previous, authority);
    let next = |field: &str, counted: bool| {
        let stored = match previous {
            Some(marker) if counted && !marker.is_empty() => {
                marker.get(field).map_or(Some(0), Value::as_i64)
            }
            _ => Some(0),
        };
        stored.map_or(1, |count| count.saturating_add(1))
    };
    let retry_attempts = next("attempts", true);
    let replay_attempts = next("replay_attempts", replayed);
    let cooldown = if replayed {
        replay_delay(replay_attempts)
    } else {
        PROBE_INTERVAL_SECONDS
    };
    let mut seed = authority.clone();
    seed.insert("attempts".to_owned(), json!(retry_attempts));
    seed.insert("native_replay".to_owned(), json!(true));
    seed.insert("replay_attempts".to_owned(), json!(replay_attempts));
    seed.insert("next_probe_at".to_owned(), json!(after(request, cooldown)?));
    Ok(seed)
}

pub(crate) fn write(
    connection: &Connection,
    request: &Request<'_>,
    marker: Map<String, Value>,
    changed_at: &str,
) -> StoreResult<Value> {
    let marker = Value::Object(marker);
    let encoded =
        serde_json::to_string(&marker).map_or_else(|_| value_error("invalid_payload"), Ok)?;
    write_encoded(connection, &request.key, &encoded, changed_at)?;
    Ok(marker)
}

/// `native_workspace_review_replay_marker`: the stored marker and whether the
/// request is due for another context probe.
pub(crate) fn read_method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let request = request(args)?;
    let marker = stored(connection, &request.key)?;
    let due = probe_due(marker.as_ref(), &request, args.flag("force_probe")?);
    Ok(json!({
        "key": request.key,
        "marker": marker.map_or(Value::Null, Value::Object),
        "due": due,
    }))
}

#[path = "guard_store_review_replay_step.rs"]
pub(crate) mod step;

#[path = "guard_store_review_replay_scan.rs"]
pub(crate) mod scan;

#[cfg(test)]
#[path = "guard_store_review_replay_marker_tests.rs"]
mod tests;
