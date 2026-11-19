//! Upload the local Guard event queue and the cloud pain signals
//! (`runner.sync_guard_events`; the pain signals are in
//! [`crate::cloud_pain_signal_sync`]).
//!
//! Both run inside [`crate::cloud_bundle_fetch::brokered`]: each exchange is
//! answered by the caller under the machine's managed network policy, and a
//! round that is still waiting on one stops before it writes anything. A batch
//! the cloud already accepted is marked in the store before the next batch is
//! sent, so a replayed round starts from the events that are still pending.

use std::path::{Path, PathBuf};

use guard_command::cloud_scrub::redact_sensitive_text;
use guard_command::egress_broker;
use guard_command::guard_sync_transport::{self as gst, SyncBudget, SyncFetchError};
use guard_command::local_supply_chain::{
    parse_timestamp, utc_now_iso, SupplyChainStore, Timestamp,
};
use guard_command::supply_chain_package_eval::EvalError;
use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use serde_json::{json, Map, Value};

use crate::cloud_bundle_fetch::{
    http_answer, resolve_auth, sync_url, unreachable_message, SyncError,
};
use crate::cloud_bundle_sync::{base_url, BundleStore};
use crate::local_store_read::STORE_FILE_NAME;

pub(crate) const GUARD_EVENTS_SUMMARY_KEY: &str = "guard_events_v1_summary";
const GUARD_EVENTS_BATCH: usize = 200;
/// `GuardStore(guard_event_queue_limit=1000)`, the only limit callers use.
const EVENT_QUEUE_LIMIT: i64 = 1000;
const SYNC_HTTP_TIMEOUT_SECONDS: f64 = 20.0;
const SYNC_HTTP_RETRY_TIMEOUT_SECONDS: f64 = 120.0;
/// Upload bodies stay below the broker's request-body limit
/// (`EGRESS_MAX_NEED_BODY_BYTES`).
const EVENTS_BODY_LIMIT: usize = guard_contracts::EGRESS_MAX_NEED_BODY_BYTES - 1024;
/// `{"events":[]}`.
const EVENTS_BODY_OVERHEAD: usize = 13;
const PAIN_SIGNAL_TIMEOUT_SECONDS: f64 = 10.0;
const PAIN_SIGNAL_RETRY_TIMEOUT_SECONDS: f64 = 90.0;
/// The time one upload, retries and rate-limit waits included, may take.
const UPLOAD_BUDGET_SECONDS: f64 = 300.0;
/// `_GUARD_EVENTS_ENDPOINT_UNAVAILABLE_RETRY_MINUTES`.
const ENDPOINT_UNAVAILABLE_RETRY_MICROS: i64 = 5 * 60 * 1_000_000;
/// `parse_retry_after_header` without a usable header.
const RATE_LIMIT_DEFAULT_SECONDS: i64 = 60;
const STORE_BUSY_TIMEOUT_MS: u64 = 5_000;
const ENDPOINT_UNAVAILABLE: &str = "guard_events_endpoint_unavailable";
const RATE_LIMITED: &str = "guard_events_rate_limited";
const RECONNECT_MESSAGE: &str =
    "Guard Cloud sync endpoint is not trusted. Run `hol-guard connect` to restore Cloud sync.";

/// The Guard home a sync reads its queue from and the store it records in.
pub(crate) struct EventStore<'a> {
    pub(crate) home: PathBuf,
    pub(crate) bundle: &'a BundleStore,
}

impl EventStore<'_> {
    pub(crate) fn call(&self, method: &str, args: Value) -> Result<Value, SyncError> {
        let Value::Object(args) = args else {
            return Err(SyncError::Failed(
                "Guard store request is invalid.".to_owned(),
            ));
        };
        crate::guard_store_op::evaluate(&GuardStoreRequestV1 {
            schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
            request_id: "cloud-event-sync".to_owned(),
            store_path: self.store_path().to_string_lossy().into_owned(),
            guard_home: self.home.to_string_lossy().into_owned(),
            method: method.to_owned(),
            source: "cloud-event-sync".to_owned(),
            busy_timeout_ms: STORE_BUSY_TIMEOUT_MS,
            args,
        })
        .map(|(payload, _)| payload)
        .map_err(|error| SyncError::Failed(format!("Guard store {method} failed: {error:?}")))
    }

    pub(crate) fn store_path(&self) -> PathBuf {
        self.home.join(STORE_FILE_NAME)
    }

    pub(crate) fn payload(&self, key: &str) -> Option<Value> {
        self.bundle.resident.get_sync_payload(key)
    }

    pub(crate) fn save(&self, key: &str, payload: &Value, now: &str) -> Result<(), SyncError> {
        self.bundle.set_payload(key, payload, now)
    }
}

/// `_validate_guard_sync_url(_auth_context_sync_url(auth))`.
pub(crate) fn trusted_base(auth: &Map<String, Value>) -> Result<String, SyncError> {
    let base = base_url(auth)
        .map_err(|_| SyncError::Failed("Guard sync URL is unavailable.".to_owned()))?;
    gst::validate_guard_sync_endpoint(&base, None)
        .map_err(|reason| SyncError::EndpointUntrusted(format!("{RECONNECT_MESSAGE} {reason}")))
}

pub(crate) fn route_url(route: &str, base: &str) -> Result<String, SyncError> {
    sync_url(route, base, &[])
        .ok_or_else(|| SyncError::Failed(format!("Guard sync URL is invalid: {base}")))
}

/// Why one upload got no answer it can use.
pub(crate) enum Refusal {
    Http {
        status: u16,
        answer: Option<Value>,
        retry_after: Option<String>,
    },
    Transport(String),
}

pub(crate) fn post(
    auth: &Map<String, Value>,
    url: &str,
    body: &Value,
    parse_json: bool,
) -> Result<Option<Value>, Result<Refusal, SyncError>> {
    let data = body.to_string().into_bytes();
    let request = gst::guard_sync_request(
        &Value::Object(auth.clone()),
        url,
        "POST",
        Some(data.as_slice()),
        None,
        None,
    )
    .map_err(|error| Err(SyncError::Failed(error.to_string())))?;
    let budget = SyncBudget::new(UPLOAD_BUDGET_SECONDS);
    let answer = if parse_json {
        gst::urlopen_json_detailed(
            &request,
            SYNC_HTTP_TIMEOUT_SECONDS,
            SYNC_HTTP_RETRY_TIMEOUT_SECONDS,
            &budget,
        )
        .map(Some)
    } else {
        gst::urlopen_detailed(
            &request,
            PAIN_SIGNAL_TIMEOUT_SECONDS,
            PAIN_SIGNAL_RETRY_TIMEOUT_SECONDS,
            &budget,
        )
        .map(|()| None)
    };
    answer.map_err(|error| {
        if egress_broker::needs_pending() {
            return Err(SyncError::Pending);
        }
        Ok(match error {
            SyncFetchError::Http(failure) => Refusal::Http {
                status: failure.status,
                answer: http_answer(&failure),
                retry_after: failure
                    .headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
                    .map(|(_, value)| value.clone()),
            },
            SyncFetchError::Other(EvalError::Internal(reason)) => Refusal::Transport(reason),
            SyncFetchError::Other(other) => Refusal::Transport(other.to_string()),
        })
    })
}

pub(crate) fn answer_text(answer: Option<&Value>, key: &str, status: u16) -> String {
    answer
        .and_then(|answer| answer.get(key))
        .and_then(Value::as_str)
        .map_or_else(
            || format!("Guard sync failed with HTTP {status}."),
            str::to_owned,
        )
}

/// `parse_retry_after_header`: whole seconds, at least one.
fn retry_after_seconds(header: Option<&str>) -> i64 {
    header
        .and_then(|value| value.trim().parse::<i64>().ok())
        .map_or(RATE_LIMIT_DEFAULT_SECONDS, |seconds| seconds.max(1))
}

fn parse_micros(value: &str) -> Option<i64> {
    let normalized = value.replace('Z', "+00:00");
    parse_timestamp(&normalized).map(|stamp| stamp.unix_seconds() * 1_000_000)
}

/// `_sync_timestamp`: the cloud's `syncedAt` when it is a timestamp.
fn synced_at(payload: &Value) -> String {
    match payload.get("syncedAt").and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() && parse_micros(value).is_some() => {
            value.to_owned()
        }
        _ => utc_now_iso(),
    }
}

/// `_guard_events_endpoint_unavailable_recently`.
fn endpoint_unavailable_recently(summary: &Value) -> bool {
    let reason = summary.get("sync_reason").and_then(Value::as_str);
    if !matches!(reason, Some(ENDPOINT_UNAVAILABLE | RATE_LIMITED)) {
        return false;
    }
    let Some(stamp) = summary
        .get("synced_at")
        .and_then(Value::as_str)
        .and_then(parse_micros)
    else {
        return true;
    };
    let now = parse_micros(&utc_now_iso()).unwrap_or(stamp);
    now - stamp < ENDPOINT_UNAVAILABLE_RETRY_MICROS
}

struct Totals {
    events: usize,
    accepted: i64,
}

/// `_record_guard_events_sync_failure`, then the error it raises.
fn record_failure(
    store: &EventStore<'_>,
    totals: &Totals,
    pending: usize,
    error_type: &str,
    message: &str,
) -> Result<(), SyncError> {
    let recorded_at = utc_now_iso();
    let next_retry_after = parse_micros(&recorded_at).map(|micros| {
        Timestamp::from_unix_micros(micros + (SYNC_HTTP_RETRY_TIMEOUT_SECONDS as i64) * 1_000_000)
            .isoformat()
    });
    let summary = json!({
        "synced_at": null,
        "status": "failed",
        "events": totals.events,
        "accepted": totals.accepted,
        "pending_events": pending,
        "error_type": error_type,
        "message": redact_sensitive_text(message),
        "retry_after_seconds": SYNC_HTTP_RETRY_TIMEOUT_SECONDS as i64,
        "next_retry_after": next_retry_after,
    });
    store.save(GUARD_EVENTS_SUMMARY_KEY, &summary, &recorded_at)
}

/// A refused upload: the summary it leaves and the error, if any, it raises.
fn guard_events_refusal(
    store: &EventStore<'_>,
    totals: &Totals,
    pending: usize,
    stamp: &str,
    refusal: Refusal,
) -> Result<Value, SyncError> {
    let (status, answer, retry_after) = match refusal {
        Refusal::Transport(reason) => {
            let message = unreachable_message(&reason);
            record_failure(store, totals, pending, "URLError", &message)?;
            return Err(SyncError::Failed(redact_sensitive_text(&message)));
        }
        Refusal::Http {
            status,
            answer,
            retry_after,
        } => (status, answer, retry_after),
    };
    if status == 404 || status == 429 {
        let mut summary = json!({
            "synced_at": stamp,
            "events": totals.events,
            "accepted": totals.accepted,
            "skipped": 0,
            "sync_skipped": true,
            "sync_reason": if status == 404 { ENDPOINT_UNAVAILABLE } else { RATE_LIMITED },
            "pending_count": pending,
        });
        if status == 429 {
            summary["retry_after_seconds"] = json!(retry_after_seconds(retry_after.as_deref()));
        }
        store.save(GUARD_EVENTS_SUMMARY_KEY, &summary, stamp)?;
        return Ok(summary);
    }
    if status == 403 {
        let message = answer_text(answer.as_ref(), "plan_message", status);
        if answer
            .as_ref()
            .is_some_and(|answer| answer["plan_restricted"] == Value::Bool(true))
        {
            return Err(SyncError::NotAvailable {
                message,
                retryable: false,
            });
        }
        record_failure(store, totals, pending, "HTTPError", &message)?;
        return Err(SyncError::Failed(message));
    }
    let message = answer_text(answer.as_ref(), "sync_message", status);
    record_failure(store, totals, pending, "HTTPError", &message)?;
    Err(SyncError::Failed(redact_sensitive_text(&message)))
}

/// The leading events whose upload body fits the egress broker's request limit;
/// the rest go in the next round. One event always goes, so an oversized event
/// surfaces as a failed upload instead of stalling the queue silently.
fn batch_within_body_limit(pending: &[Value]) -> Vec<Value> {
    let mut size = EVENTS_BODY_OVERHEAD;
    let mut payloads = Vec::new();
    for event in pending {
        let payload = event.get("payload").cloned().unwrap_or(Value::Null);
        size += serde_json::to_vec(&payload).map_or(0, |bytes| bytes.len()) + 1;
        if !payloads.is_empty() && size > EVENTS_BODY_LIMIT {
            break;
        }
        payloads.push(payload);
    }
    payloads
}

/// `sync_guard_events`: push the pending GuardEventV1 envelopes.
pub(crate) fn sync_guard_events(store: &EventStore<'_>) -> Result<Value, SyncError> {
    let auth = resolve_auth(&store.bundle.resident, false, store.bundle.auth.as_ref())?;
    let url = route_url("guard_events", &trusted_base(&auth)?)?;
    let previous = store.payload(GUARD_EVENTS_SUMMARY_KEY);
    let mut totals = Totals {
        events: 0,
        accepted: 0,
    };
    let mut last_synced_at = utc_now_iso();
    loop {
        let pending = store.call(
            "list_guard_events_v1",
            json!({"uploaded": false, "limit": GUARD_EVENTS_BATCH, "now": utc_now_iso()}),
        )?;
        let pending = pending.as_array().cloned().unwrap_or_default();
        if pending.is_empty() {
            if let Some(previous) = previous.as_ref().filter(|previous| {
                totals.events == 0
                    && previous.get("sync_reason").and_then(Value::as_str)
                        == Some(ENDPOINT_UNAVAILABLE)
                    && endpoint_unavailable_recently(previous)
            }) {
                return Ok(previous.clone());
            }
            break;
        }
        let listed = pending.len();
        let payloads = batch_within_body_limit(&pending);
        let pending = &pending[..payloads.len()];
        let answer = match post(&auth, &url, &json!({"events": payloads}), true) {
            Ok(answer) => answer.unwrap_or(Value::Null),
            Err(Err(error)) => return Err(error),
            Err(Ok(refusal)) => {
                return guard_events_refusal(store, &totals, listed, &last_synced_at, refusal);
            }
        };
        let ids = crate::runner_sync_signals::completed_event_ids(&json!({"payload": answer}))
            .ok()
            .and_then(|ids| ids.get("ids").cloned())
            .unwrap_or_else(|| json!([]));
        last_synced_at = synced_at(&answer);
        let uploaded = store.call(
            "mark_guard_events_v1_uploaded",
            json!({"event_ids": ids, "uploaded_at": last_synced_at, "event_queue_limit": EVENT_QUEUE_LIMIT}),
        )?;
        let uploaded = uploaded.as_i64().unwrap_or(0);
        totals.events += pending.len();
        totals.accepted += uploaded;
        if uploaded == 0 || (listed < GUARD_EVENTS_BATCH && pending.len() == listed) {
            break;
        }
    }
    let summary =
        json!({"synced_at": last_synced_at, "events": totals.events, "accepted": totals.accepted});
    store.save(GUARD_EVENTS_SUMMARY_KEY, &summary, &last_synced_at)?;
    Ok(summary)
}

/// The Guard home's store for a sync request.
pub(crate) fn event_store<'a>(guard_home: &Path, bundle: &'a BundleStore) -> EventStore<'a> {
    EventStore {
        home: guard_home.to_path_buf(),
        bundle,
    }
}

#[cfg(test)]
#[path = "cloud_event_sync_tests.rs"]
mod tests;
