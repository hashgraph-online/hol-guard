//! The resident operation that runs the hook evidence writer.
//!
//! `daemon.runtime_hook_evidence_writer.RuntimeHookEvidenceWriter` keeps one
//! long-lived writer per Guard home: a queue, a journal and a background
//! thread that drains both into the store. Python callers only ever push a
//! record onto it and occasionally read its counters, so the whole object can
//! live here and be reached over the resident protocol.
//!
//! The writer is built from the all-native seams rather than the Python ones:
//! [`NativeEvidenceStore`] for the store, [`NativeCorrelation`] for the
//! installation key, [`NativeReceiptValidation`] for receipt shape,
//! [`NativeComposio`] for provider discovery and [`NativeEvidenceJournal`] for
//! the on-disk journal. Nothing in the path recalculates a verdict; the writer
//! records what the decision path already decided.
//!
//! One writer per Guard home is a process-wide resource, so it is held in a
//! registry instead of being rebuilt per request. The registry keeps the
//! first request's `source` for that home, matching the single `GuardStore`
//! the daemon builds at startup and hands to the writer.
//!
//! The request carries the Guard home and no store path. The resident
//! validates the home like every other operation, and the store seam
//! derives its database from that home the same way the daemon does, so a
//! caller cannot point a writer at a database outside the home it named.
//!
//! `store_review_event_outbox` closes the native policy barrier after a
//! Composio discovery write. In Python that wakes the in-process snapshot
//! publishers through `notify_native_policy_mutation`, which walks a registry
//! of Python publisher objects this process cannot see. The barrier here
//! counts those mutations instead, and `stats` hands the count back so the
//! caller can wake its own publishers. Rust still owns the write; Python only
//! refreshes what it pushes.
//!
//! A fatal store failure is reported the same way. `_native_store_call`
//! quarantines and rebuilds a store a probe has proven unusable, which the
//! `GuardStore` object owns and this process has no handle on. The store seam
//! records the failure instead and the caller runs
//! `GuardStore._recover_fatal_sqlite_store` for it.
//!
//! Every reply carries that signal and the policy-mutation count, not only
//! `stats` and `stop`. The writer drains on its own thread, so a store that
//! fails there would otherwise wait for a read the daemon never has to make,
//! and every later write would go to the same failed store. A submission is
//! the one call the daemon always makes, so the signals ride back on it.
//!
//! Neither signal is cleared by the read that reports it. The reply can be
//! lost in transport and the client's recovery can fail, so the resident
//! holds the failure until the client acknowledges the identifier it
//! recovered from in a later request.

use std::io;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::TryLockError;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

#[path = "hook_evidence_writer_registry.rs"]
mod registry;

#[cfg(test)]
pub(crate) use registry::while_slot_busy;
use registry::{canonical_home, slot, with_running, with_writer, ResidentWriter};
pub(crate) use registry::{drained_fatal, record_direct, record_drained, record_edge_receipt};

pub(crate) const HOOK_EVIDENCE_WRITER_REQUEST_SCHEMA: &str =
    "guard-hook-evidence-writer-request.v1";
pub(crate) const HOOK_EVIDENCE_WRITER_RESULT_SCHEMA: &str = "guard-hook-evidence-writer-result.v1";
/// The feature advertised to callers that route evidence here.
pub(crate) const HOOK_EVIDENCE_WRITER_FEATURE: &str = "hook-evidence-writer-v1";
pub(crate) const HOOK_EVIDENCE_POST_TOOL_FEATURE: &str = "hook-evidence-post-tool-v1";

/// `submit_command_activity(approval_reuse_status=)` default (:153).
const APPROVAL_REUSE_NOT_APPLICABLE: &str = "not-applicable";
/// The client's own request bound (`_MAX_REQUEST_BYTES`): a request larger
/// than this never reaches the resident, so the digest refuses it too.
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024 + 4096;

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct HookEvidenceWriterRequestV1 {
    pub(crate) schema: String,
    pub(crate) request_id: String,
    pub(crate) guard_home: String,
    /// `GuardStore.guard_source` of the store the Python writer was built on.
    pub(crate) source: String,
    /// The fatal-store failure the client has finished recovering from, by
    /// the identifier the signal carried. Absent until the client has one to
    /// report, and always present on the wire so the digest both sides take
    /// over this request is taken over the same JSON.
    #[serde(default)]
    pub(crate) store_fatal_ack: Option<String>,
    #[serde(flatten)]
    pub(crate) action: HookEvidenceWriterActionV1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub(crate) enum HookEvidenceWriterActionV1 {
    /// `submit_command_activity` (:143-154).
    SubmitCommandActivity {
        harness: String,
        event: String,
        payload: Map<String, Value>,
        succeeded: bool,
        #[serde(default)]
        policy_action: Option<String>,
        #[serde(default)]
        receipt_id: Option<String>,
        #[serde(default)]
        prompted: bool,
        #[serde(default = "approval_reuse_default")]
        approval_reuse_status: String,
    },
    /// `submit_composio_discovery` (:197-203). The Python entry point reads
    /// the tool name out of the payload and refuses an unsuccessful call, so
    /// the same narrowing happens here rather than at each caller.
    SubmitComposioDiscovery {
        harness: String,
        payload: Map<String, Value>,
        succeeded: bool,
    },
    /// Classify the tool result and queue discovery before command activity.
    SubmitPostToolActivity {
        harness: String,
        event: String,
        payload: Map<String, Value>,
    },
    /// `submit_native_decision_receipt` (:243).
    SubmitNativeDecisionReceipt { receipt: Map<String, Value> },
    /// Build this home's writer without queueing anything.
    ///
    /// Construction recovers the journal, which the Python writer paid for at
    /// daemon startup because the daemon built the writer itself. A daemon
    /// that warms the writer this way keeps that replay off the first hook's
    /// decision path.
    Start,
    /// `stats` (:396), plus the policy mutations observed since the last read.
    Stats,
    /// `stop` (:432). The writer is dropped from the registry either way, so
    /// a later submit builds a fresh one rather than queueing onto a drained
    /// writer.
    Stop {
        #[serde(default = "stop_timeout_default")]
        timeout_seconds: f64,
    },
}

fn approval_reuse_default() -> String {
    APPROVAL_REUSE_NOT_APPLICABLE.to_owned()
}

fn stop_timeout_default() -> f64 {
    2.0
}

#[derive(Debug, Serialize)]
struct HookEvidenceWriterResultV1 {
    schema: String,
    request_id: String,
    /// SHA-256 over the canonical request, binding the result to its request
    /// the way every other resident operation does.
    request_sha256: String,
    status: String,
    code: String,
    payload: Value,
}

/// The widest drain a caller may ask for. `timeout_seconds` arrives as an
/// unvalidated JSON number, and the duration a drain deadline is built from
/// panics on a value a `Duration` cannot hold.
const MAX_STOP_TIMEOUT_SECONDS: f64 = 60.0;

fn stop_timeout(value: f64) -> f64 {
    if value.is_nan() {
        return stop_timeout_default();
    }
    value.clamp(0.0, MAX_STOP_TIMEOUT_SECONDS)
}

/// The two signals a reply carries whatever it was asked for: the provider
/// policy mutations this caller must wake its publishers for, and the fatal
/// store failure it must recover from.
///
/// The mutation count is read and cleared, because a second reader waking the
/// same publishers again is waste. The failure is read and left, because the
/// client that must recover from it may never receive this reply, or may fail
/// to recover; it clears the slot by acknowledging the identifier.
fn signals(resident: &ResidentWriter) -> (u64, Value) {
    (
        resident.mutations.swap(0, Ordering::SeqCst),
        resident.fatal.peek(),
    )
}

/// No writer runs for this home, so there is nothing to report.
fn idle_signals() -> (u64, Value) {
    (0, Value::Null)
}

/// A submission reply: what the queue did with the record, plus the signals.
fn queued_payload(queued: bool, (mutations, fatal): (u64, Value)) -> Value {
    json!({
        "queued": queued,
        "policy_mutations": mutations,
        "store_fatal": fatal,
    })
}

/// A record the op refused before it reached a writer. Nothing was queued,
/// and the signals are whatever a writer already running for this home holds.
fn refused_payload(guard_home: &Path) -> Value {
    queued_payload(
        false,
        with_running(guard_home, signals).unwrap_or_else(idle_signals),
    )
}

fn stats_payload(resident: &ResidentWriter) -> Value {
    let stats = resident.writer.stats();
    let (mutations, fatal) = signals(resident);
    json!({
        "queued": stats.queued,
        "queued_bytes": stats.queued_bytes,
        "accepted": stats.accepted,
        "processed": stats.processed,
        "dropped": stats.dropped,
        "failures": stats.failures,
        "recovered": stats.recovered,
        "durable_pending": stats.durable_pending,
        "degraded": stats.degraded,
        "running": stats.running,
        "receipt_accepted": stats.receipt_accepted,
        "receipt_processed": stats.receipt_processed,
        "receipt_deduped": stats.receipt_deduped,
        "receipt_dropped": stats.receipt_dropped,
        "receipt_failures": stats.receipt_failures,
        "receipt_durable_pending": stats.receipt_durable_pending,
        "policy_mutations": mutations,
        "store_fatal": fatal,
        "started": true,
    })
}

/// The writer's counters for the daemon's health details, without taking
/// the signals its client reads: a health read must not swallow a policy
/// mutation or a fatal store error.
pub(crate) fn health_stats(guard_home: &Path) -> Value {
    // Never waits on a slot that is starting or draining a writer.
    let slot = slot(&canonical_home(guard_home));
    let held = match slot.writer.try_lock() {
        Ok(held) => Some(held),
        Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
        Err(TryLockError::WouldBlock) => None,
    };
    let mut payload = held
        .as_ref()
        .and_then(|held| held.as_ref())
        .map(|resident| {
            let stats = resident.writer.stats();
            json!({
                "queued": stats.queued,
                "queued_bytes": stats.queued_bytes,
                "accepted": stats.accepted,
                "processed": stats.processed,
                "dropped": stats.dropped,
                "failures": stats.failures,
                "recovered": stats.recovered,
                "durable_pending": stats.durable_pending,
                "degraded": stats.degraded,
                "running": stats.running,
                "receipt_accepted": stats.receipt_accepted,
                "receipt_processed": stats.receipt_processed,
                "receipt_deduped": stats.receipt_deduped,
                "receipt_dropped": stats.receipt_dropped,
                "receipt_failures": stats.receipt_failures,
                "receipt_durable_pending": stats.receipt_durable_pending,
                "started": true,
            })
        })
        .unwrap_or_else(idle_stats);
    if let Some(fields) = payload.as_object_mut() {
        fields.remove("policy_mutations");
        fields.remove("store_fatal");
    }
    payload
}

/// A writer that was never started has nothing queued and is not running.
fn idle_stats() -> Value {
    json!({
        "queued": 0,
        "queued_bytes": 0,
        "accepted": 0,
        "processed": 0,
        "dropped": 0,
        "failures": 0,
        "recovered": 0,
        "durable_pending": 0,
        "degraded": false,
        "running": false,
        "receipt_accepted": 0,
        "receipt_processed": 0,
        "receipt_deduped": 0,
        "receipt_dropped": 0,
        "receipt_failures": 0,
        "receipt_durable_pending": 0,
        "policy_mutations": 0,
        "store_fatal": Value::Null,
        // Nothing has asked this home for a writer yet. A reader that treats
        // `running: false` as a fault needs to tell that apart from a writer
        // that was started and then stopped running.
        "started": false,
    })
}

pub(crate) fn evaluate_hook_evidence_writer_request(
    request: &HookEvidenceWriterRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 =
        crate::package_authority_op::request_digest_with_limit(request, MAX_REQUEST_BYTES)
            .map_err(|_| "native_hook_evidence_writer_invalid".to_owned())?;
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), payload),
        Err(error) => (
            "error".to_owned(),
            error.0.to_owned(),
            json!({ "message": error.1 }),
        ),
    };
    crate::encode_response(&HookEvidenceWriterResultV1 {
        schema: HOOK_EVIDENCE_WRITER_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

/// `(code, message)` — the shape the result carries for a refused request.
struct WriterError(&'static str, String);

fn evaluate(request: &HookEvidenceWriterRequestV1) -> Result<Value, WriterError> {
    if request.schema != HOOK_EVIDENCE_WRITER_REQUEST_SCHEMA {
        return Err(WriterError(
            "invalid_schema",
            format!("unsupported schema: {}", request.schema),
        ));
    }
    if request.guard_home.is_empty() {
        return Err(WriterError(
            "invalid_guard_home",
            "guard home is required".to_owned(),
        ));
    }
    let guard_home = canonical_home(Path::new(&request.guard_home));
    // Before anything this request reports: a failure recorded after the
    // acknowledgement is a new one and must still be reported.
    if let Some(acknowledged) = &request.store_fatal_ack {
        let _ = with_running(&guard_home, |resident| {
            resident.fatal.acknowledge(acknowledged);
        });
    }
    let started = |error: io::Error| WriterError("writer_unavailable", error.to_string());
    match &request.action {
        HookEvidenceWriterActionV1::SubmitCommandActivity {
            harness,
            event,
            payload,
            succeeded,
            policy_action,
            receipt_id,
            prompted,
            approval_reuse_status,
        } => {
            let (queued, reported) = with_writer(&guard_home, &request.source, |resident| {
                let queued = resident.writer.submit_command_activity(
                    harness,
                    event,
                    payload,
                    *succeeded,
                    policy_action.as_deref(),
                    receipt_id.as_deref(),
                    *prompted,
                    approval_reuse_status,
                );
                (queued, signals(resident))
            })
            .map_err(started)?;
            Ok(queued_payload(queued, reported))
        }
        HookEvidenceWriterActionV1::SubmitComposioDiscovery {
            harness,
            payload,
            succeeded,
        } => {
            let Some(tool_name) = payload.get("tool_name").and_then(Value::as_str) else {
                return Ok(refused_payload(&guard_home));
            };
            if !succeeded {
                return Ok(refused_payload(&guard_home));
            }
            let (queued, reported) = with_writer(&guard_home, &request.source, |resident| {
                let queued = resident
                    .writer
                    .submit_composio_discovery(harness, tool_name, payload);
                (queued, signals(resident))
            })
            .map_err(started)?;
            Ok(queued_payload(queued, reported))
        }
        HookEvidenceWriterActionV1::SubmitNativeDecisionReceipt { receipt } => {
            let (queued, reported) = with_writer(&guard_home, &request.source, |resident| {
                let queued = resident.writer.submit_native_decision_receipt(receipt);
                (queued, signals(resident))
            })
            .map_err(started)?;
            Ok(queued_payload(queued, reported))
        }
        HookEvidenceWriterActionV1::SubmitPostToolActivity {
            harness,
            event,
            payload,
        } => {
            let (queued, reported) = with_writer(&guard_home, &request.source, |resident| {
                let queued = crate::edge_receipt::queue_post_tool_activity(
                    &resident.writer,
                    harness,
                    event,
                    payload,
                );
                (queued, signals(resident))
            })
            .map_err(started)?;
            Ok(queued_payload(queued, reported))
        }
        HookEvidenceWriterActionV1::Start => {
            with_writer(&guard_home, &request.source, stats_payload).map_err(started)
        }
        HookEvidenceWriterActionV1::Stats => {
            Ok(with_running(&guard_home, stats_payload).unwrap_or_else(idle_stats))
        }
        HookEvidenceWriterActionV1::Stop { timeout_seconds } => {
            let slot = slot(&guard_home);
            let mut held = slot.writer.lock().unwrap_or_else(|e| e.into_inner());
            let Some(resident) = held.take() else {
                return Ok(json!({
                    "drained": true,
                    "policy_mutations": 0,
                    "store_fatal": Value::Null,
                }));
            };
            // The writer leaves the registry here, so nothing is left to
            // acknowledge a failure reported now. The client keeps it pending
            // on its own side until its recovery succeeds.
            // The slot stays locked across the drain. A submission racing this
            // stop waits for it and then builds its own writer, rather than
            // queueing onto a writer that will never run its thread again or
            // appending to the journal the draining writer still owns.
            let drained = resident.writer.stop(stop_timeout(*timeout_seconds));
            let (mutations, fatal) = signals(&resident);
            if !drained && !resident.writer.has_exited() {
                // The deadline passed with the worker still inside journal or
                // store I/O. It owns the journal until it leaves, and it may
                // still raise a mutation or a store failure. Dropping the
                // resident here would let the next submission build a second
                // writer for the same file and would lose those signals, so
                // it goes back into the slot and requests wait for its exit.
                *held = Some(resident);
            }
            Ok(json!({
                "drained": drained,
                "policy_mutations": mutations,
                "store_fatal": fatal,
            }))
        }
    }
}

#[cfg(test)]
#[path = "hook_evidence_writer_op_tests.rs"]
mod tests;
