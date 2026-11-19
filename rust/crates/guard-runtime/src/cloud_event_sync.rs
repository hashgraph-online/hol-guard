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
/// The Guard-events request timeouts.
pub(crate) const EVENT_TIMEOUTS: Timeouts =
    (SYNC_HTTP_TIMEOUT_SECONDS, SYNC_HTTP_RETRY_TIMEOUT_SECONDS);
/// `_PAIN_SIGNAL_TIMEOUT_SECONDS` / `_PAIN_SIGNAL_RETRY_TIMEOUT_SECONDS`.
pub(crate) const PAIN_SIGNAL_TIMEOUTS: Timeouts = (10.0, 90.0);
/// One attempt's timeout and the retry's, in seconds.
pub(crate) type Timeouts = (f64, f64);
/// Upload bodies stay below the broker's request-body limit
/// (`EGRESS_MAX_NEED_BODY_BYTES`).
pub(crate) const EVENTS_BODY_LIMIT: usize = guard_contracts::EGRESS_MAX_NEED_BODY_BYTES - 1024;
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
    /// Uploads already committed by an earlier broker round. A round that
    /// left a need behind is run again from the start, but the batches it
    /// uploaded and marked before that need stay uploaded, so the totals the
    /// sync reports carry over instead of counting only the last round.
    pub(crate) progress: std::cell::RefCell<Progress>,
}

/// What earlier broker rounds of one sync already uploaded.
#[derive(Debug, Default, Clone)]
pub(crate) struct Progress {
    pub(crate) events: usize,
    pub(crate) accepted: i64,
    pub(crate) synced_at: Option<String>,
    pub(crate) pain_signals: usize,
    /// The warning counts as of the last saved pain-signal cursor, so a
    /// rerun round resumes the same per-call dedupe instead of starting over.
    pub(crate) pain_warn_counts: Option<Value>,
    /// The listed count and rows of an event batch whose upload a broker
    /// round left pending. The next round sends the same rows, so it can use
    /// the answer, instead of listing again and picking up newer events.
    pub(crate) held_events: Option<(usize, Vec<Value>)>,
    /// The cursor and candidates of a pending pain-signal batch, likewise.
    pub(crate) held_pain_signals: Option<(i64, Vec<Value>)>,
}

impl EventStore<'_> {
    pub(crate) fn call(&self, method: &str, args: Value) -> Result<Value, SyncError> {
        let Value::Object(args) = args else {
            return Err(SyncError::Failed(
                "Guard store request is invalid.".to_owned(),
            ));
        };
        let _gate = self.hold_gate()?;
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

    /// The shared storage gate, so a store read or write waits out a recovery
    /// that is moving the database. Held only around local store access, never
    /// across a network wait.
    pub(crate) fn hold_gate(
        &self,
    ) -> Result<crate::hook_evidence_store_gate::StorageGateHold, SyncError> {
        crate::hook_evidence_store_gate::hold_storage_gate(
            &self.home,
            std::time::Duration::from_millis(STORE_BUSY_TIMEOUT_MS),
        )
        .map_err(|error| SyncError::Failed(format!("Guard store is busy: {error}")))
    }

    pub(crate) fn store_path(&self) -> PathBuf {
        self.home.join(STORE_FILE_NAME)
    }

    /// A saved sync payload. A busy gate is an error, not an absent payload,
    /// so a cursor is never read as unset while a recovery holds the store.
    pub(crate) fn payload(&self, key: &str) -> Result<Option<Value>, SyncError> {
        let _gate = self.hold_gate()?;
        Ok(self.bundle.resident.get_sync_payload(key))
    }

    pub(crate) fn save(&self, key: &str, payload: &Value, now: &str) -> Result<(), SyncError> {
        let _gate = self.hold_gate()?;
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

/// A sync URL a caller supplied is checked before sign-in resolution, which
/// would otherwise report the same refusal as an expired sign-in. A supplied
/// issuer must match the sync URL's origin as well.
pub(crate) fn screen_supplied(supplied: Option<&Map<String, Value>>) -> Result<(), SyncError> {
    let Some(auth) = supplied.filter(|auth| auth.get("sync_url").is_some_and(Value::is_string))
    else {
        return Ok(());
    };
    let base = trusted_base(auth)?;
    match auth.get("issuer").and_then(Value::as_str) {
        Some(issuer) if !issuer.trim().is_empty() => {
            gst::validate_guard_sync_endpoint(&base, Some(issuer))
                .map(|_| ())
                .map_err(|reason| {
                    SyncError::EndpointUntrusted(format!("{RECONNECT_MESSAGE} {reason}"))
                })
        }
        _ => Ok(()),
    }
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
    (timeout, retry_timeout): Timeouts,
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
        gst::urlopen_json_detailed(&request, timeout, retry_timeout, &budget).map(Some)
    } else {
        gst::urlopen_detailed(&request, timeout, retry_timeout, &budget).map(|()| None)
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

/// Cloud's message for a refused upload, redacted: it is returned to the
/// caller and may echo a credential.
pub(crate) fn answer_text(answer: Option<&Value>, key: &str, status: u16) -> String {
    answer
        .and_then(|answer| answer.get(key))
        .and_then(Value::as_str)
        .map_or_else(
            || format!("Guard sync failed with HTTP {status}."),
            redact_sensitive_text,
        )
}

/// `parse_retry_after_header`: whole seconds, at least one.
pub(crate) fn retry_after_seconds(header: Option<&str>) -> i64 {
    header
        .and_then(|value| value.trim().parse::<i64>().ok())
        .map_or(RATE_LIMIT_DEFAULT_SECONDS, |seconds| seconds.max(1))
}

fn parse_micros(value: &str) -> Option<i64> {
    let normalized = value.replace('Z', "+00:00");
    parse_timestamp(&normalized).map(|stamp| stamp.unix_seconds() * 1_000_000)
}

/// `_sync_timestamp`: the cloud's `syncedAt` when it is a timestamp.
pub(crate) fn synced_at(payload: &Value) -> String {
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

/// `sync_guard_events`: push the pending GuardEventV1 envelopes.
pub(crate) fn sync_guard_events(store: &EventStore<'_>) -> Result<Value, SyncError> {
    screen_supplied(store.bundle.auth.as_ref())?;
    let auth = resolve_auth(&store.bundle.resident, false, store.bundle.auth.as_ref())?;
    let url = route_url("guard_events", &trusted_base(&auth)?)?;
    let previous = store.payload(GUARD_EVENTS_SUMMARY_KEY)?;
    let carried = store.progress.borrow().clone();
    let mut totals = Totals {
        events: carried.events,
        accepted: carried.accepted,
    };
    let mut last_synced_at = carried.synced_at.unwrap_or_else(utc_now_iso);
    loop {
        let held = store.progress.borrow_mut().held_events.take();
        let (listed, pending) = match held {
            Some(held) => held,
            None => {
                let pending = store.call(
                    "list_guard_events_v1",
                    json!({"uploaded": false, "limit": GUARD_EVENTS_BATCH, "now": utc_now_iso()}),
                )?;
                let pending = pending.as_array().cloned().unwrap_or_default();
                (pending.len(), pending)
            }
        };
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
        let payloads = batch_within_body_limit(&pending);
        let pending = &pending[..payloads.len()];
        if let Some(event_id) = too_large_alone(&payloads) {
            // Settled like an event Cloud rejects: it leaves the queue unsent.
            let settled = store.call(
                "mark_guard_events_v1_uploaded",
                json!({"event_ids": [event_id], "uploaded_at": utc_now_iso(), "event_queue_limit": EVENT_QUEUE_LIMIT}),
            )?;
            if settled.as_i64().unwrap_or(0) == 0 {
                // Nothing left the queue, so another round would pick it again.
                return Err(SyncError::Failed(
                    "A Guard event is too large to upload.".to_owned(),
                ));
            }
            continue;
        }
        let answer = match post(
            &auth,
            &url,
            &json!({"events": payloads}),
            true,
            EVENT_TIMEOUTS,
        ) {
            Ok(answer) => answer.unwrap_or(Value::Null),
            Err(Err(SyncError::Pending)) => {
                store.progress.borrow_mut().held_events = Some((listed, pending.to_vec()));
                return Err(SyncError::Pending);
            }
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
        {
            let mut progress = store.progress.borrow_mut();
            progress.events = totals.events;
            progress.accepted = totals.accepted;
            progress.synced_at = Some(last_synced_at.clone());
        }
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
        progress: std::cell::RefCell::new(Progress::default()),
    }
}

#[path = "cloud_event_batch.rs"]
mod batch;
use batch::{batch_within_body_limit, too_large_alone};

#[cfg(test)]
#[path = "cloud_event_sync_tests.rs"]
mod tests;
