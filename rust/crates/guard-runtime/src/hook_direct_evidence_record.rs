//! What a direct answer left to the daemon, recorded as its page leaves.
//!
//! The drain records a paged record whose receipt the resident has not
//! written yet: the receipt, then, for a tool answer the bound daemon let the
//! resident record, its command activity. A hook the resident held through a
//! policy update's fence also leaves its wait, which is saved as the fence
//! window event the daemon would record, and a Codex receipt goes to the
//! opt-in binding capture when its private marker exists. This starts the
//! hook evidence writer with the source of the store the bound daemon
//! publishes, as the daemon's own submission would, and marks the queued
//! record `receipt_recorded`, `activity_recorded`, `fence_wait_recorded` and
//! `capture_recorded` for what was recorded, so a page sent again does not
//! record it twice. Whatever the writer refuses, or a lane bound without a
//! source, stays with the daemon.
//!
//! A connector-setup review's desktop notice needs no writer, so it is raised
//! for every paged record that names one and marked `connector_notice_raised`.
//!
//! A hook record left with nothing for the daemon to record then leaves the
//! page: `record_direct_hook_evidence` would submit no receipt, fence window,
//! capture, activity or notice for it, so its only work there was the
//! unmanaged-harness check, whose answer changes nothing for such a record.
//! The page's cursor still covers it, so it leaves the queue with the
//! daemon's acknowledgement like any paged record, and a page sent again
//! leaves it out again.

use std::path::Path;
use std::time::{Duration, Instant};

use guard_command::hook_evidence_writer::{
    RuntimeHookEvidenceWriter, POLICY_SOURCE_FENCE_WINDOW_EVENT,
};
use guard_command::local_supply_chain::Timestamp;
use serde_json::{json, Value};

use super::{DirectEvidenceQueue, Paged, RECEIPT_VALID};
use crate::edge_receipt::{DIRECT_ACTIVITY_RECORDED, DIRECT_RECEIPT_RECORDED};
use crate::hook_direct::CONNECTOR_NOTICE_FIELD;

/// The writer took the fence window this record's wait reports.
const FENCE_WAIT_RECORDED: &str = "fence_wait_recorded";
/// The binding capture sealed this record's Codex receipt.
const CAPTURE_RECORDED: &str = "capture_recorded";
/// `native_codex_binding_capture._MARKER_PARTS`.
#[cfg(unix)]
const CAPTURE_MARKER: [&str; 2] = ["diagnostics", "codex-binding-capture.v2.json"];
/// `native_codex_binding_capture._MAX_TEXT_BYTES`.
#[cfg(unix)]
const CAPTURE_TEXT_BYTES: usize = 64 * 1024;
/// How long one page may spend on captures. A capture waits on the capture
/// file's lock, so a busy file must not hold the page's receipts past the
/// drain's deadline; what is left over stays unmarked for the daemon.
const CAPTURE_PAGE_BUDGET: Duration = Duration::from_millis(250);
/// `hook_policy_fence_window.REBUILD_WAIT_SECONDS`, in milliseconds: no
/// window reports a longer wait than a hook may poll.
const REBUILD_WAIT_MS: u64 = 8_000;
/// The hook events the daemon's drain records, `_PRE_TOOL_USE` the default
/// of a record that names none.
const PRE_TOOL_USE: &str = "PreToolUse";
const POST_TOOL_USE: &str = "PostToolUse";
const USER_PROMPT_SUBMIT: &str = "UserPromptSubmit";

fn flagged(record: &Value, field: &str) -> bool {
    record.get(field) == Some(&Value::Bool(true))
}

/// The fence wait a record reports and has not had recorded.
fn fence_wait_ms(record: &Value) -> Option<u64> {
    if flagged(record, FENCE_WAIT_RECORDED) {
        return None;
    }
    record
        .get("fence_wait_ms")
        .and_then(Value::as_u64)
        .filter(|waited| *waited > 0)
}

fn receipt_pending(paged: &Paged) -> bool {
    flagged(&paged.record, RECEIPT_VALID)
        && (!flagged(&paged.record, DIRECT_RECEIPT_RECORDED)
            || (paged.activity && !flagged(&paged.record, DIRECT_ACTIVITY_RECORDED)))
}

/// Whether the binding capture still wants this record: a checked Codex
/// receipt, while the private marker that turns the capture on exists.
fn capture_pending(paged: &Paged, capturing: bool) -> bool {
    capturing
        && flagged(&paged.record, RECEIPT_VALID)
        && !flagged(&paged.record, CAPTURE_RECORDED)
        && paged.record.get("harness").and_then(Value::as_str) == Some("codex")
        && paged.record.get("receipt").is_some_and(Value::is_object)
}

/// `CodexBindingCaptureWriter.submit_native_capture`, sealed in process. The
/// capture is diagnostics only, so one it cannot seal is left unrecorded.
#[cfg(unix)]
fn capture(guard_home: &Path, record: &Value) -> bool {
    let (Some(payload), Some(receipt)) = (record.get("payload"), record.get("receipt")) else {
        return false;
    };
    let Some(event_name) = receipt.get("event_name").and_then(Value::as_str) else {
        return false;
    };
    let (Ok(payload), Ok(receipt_text)) = (
        serde_json::to_string(payload),
        serde_json::to_string(receipt),
    ) else {
        return false;
    };
    if payload.len() > CAPTURE_TEXT_BYTES || receipt_text.len() > CAPTURE_TEXT_BYTES {
        return false;
    }
    crate::binding_capture_capture::record_native_worker(
        guard_home,
        &payload,
        "codex",
        event_name,
        &receipt_text,
        crate::binding_capture_op::now_seconds(),
    )
}

/// Python never captures on Windows.
#[cfg(not(unix))]
fn capture(_guard_home: &Path, _record: &Value) -> bool {
    false
}

#[cfg(unix)]
fn capture_marker_present(guard_home: &Path) -> bool {
    guard_home.is_absolute()
        && std::fs::symlink_metadata(guard_home.join(CAPTURE_MARKER[0]).join(CAPTURE_MARKER[1]))
            .is_ok()
}

#[cfg(not(unix))]
fn capture_marker_present(_guard_home: &Path) -> bool {
    false
}

/// `PolicySourceFenceWindow.absorb_direct` for a wait no daemon window holds:
/// a window of its own that ends now and admitted the one hook.
fn submit_fence_window(writer: &RuntimeHookEvidenceWriter, waited_ms: u64) -> bool {
    let ended = Timestamp::now_utc();
    let waited = waited_ms.min(REBUILD_WAIT_MS) as f64 / 1_000.0;
    let ended_at = ended.isoformat();
    let Value::Object(payload) = json!({
        "started_at": ended.add_seconds_f64(-waited).isoformat(),
        "ended_at": ended_at,
        "absorbed_calls": 1,
        "exhausted_calls": 0,
    }) else {
        return false;
    };
    writer.submit_guard_event(POLICY_SOURCE_FENCE_WINDOW_EVENT, payload, &ended_at)
}

/// Record the receipts, the activity the bound daemon allowed, the fence
/// waits and the Codex captures that the paged records still leave to the
/// daemon, and mark them on the page and in the queue. Returns the store
/// failure the writer holds, or `None` when the writer could not run, or no
/// record needed it and none is running.
pub(super) fn leftovers(
    queue: &DirectEvidenceQueue,
    guard_home: &str,
    source: &str,
    paged: &mut [Paged],
) -> Option<Value> {
    let home = Path::new(guard_home);
    // The notice needs no writer, so it is raised whatever the writer does.
    let mut notices = Vec::new();
    let mut noticed = Vec::new();
    for paged in paged.iter() {
        if let Some((request_id, connector_name)) = super::notice::pending(&paged.record) {
            notices.push(super::notice::Notice::Connector {
                request_id,
                connector_name,
            });
            noticed.push((paged.seq, vec![super::notice::NOTICE_RAISED]));
        }
    }
    super::notice::raise(guard_home, source, notices);
    let capturing = capture_marker_present(home);
    let capture_deadline = Instant::now() + CAPTURE_PAGE_BUDGET;
    let pending = |paged: &Paged| {
        receipt_pending(paged)
            || fence_wait_ms(&paged.record).is_some()
            || capture_pending(paged, capturing)
    };
    if !paged.iter().any(pending) {
        // The writer saves on its own thread, so a store failure can follow
        // the page that gave it the last record.
        mark(queue, paged, &noticed);
        return crate::hook_evidence_writer_op::drained_fatal(home);
    }
    let recorded = crate::hook_evidence_writer_op::record_drained(home, source, |writer| {
        let mut marks = Vec::new();
        for paged in paged.iter().filter(|paged| pending(paged)) {
            let mut recorded = Vec::new();
            if fence_wait_ms(&paged.record)
                .is_some_and(|waited| submit_fence_window(writer, waited))
            {
                recorded.push(FENCE_WAIT_RECORDED);
            }
            if receipt_pending(paged) {
                let mut receipt_taken = flagged(&paged.record, DIRECT_RECEIPT_RECORDED);
                if !receipt_taken {
                    receipt_taken = paged
                        .record
                        .get("receipt")
                        .and_then(Value::as_object)
                        .is_some_and(|receipt| writer.submit_native_decision_receipt(receipt));
                    if receipt_taken {
                        recorded.push(DIRECT_RECEIPT_RECORDED);
                    }
                }
                // The activity cites the receipt, so it follows one the writer took.
                if receipt_taken
                    && paged.activity
                    && !flagged(&paged.record, DIRECT_ACTIVITY_RECORDED)
                    && crate::edge_receipt::submit_activity(writer, &paged.record)
                {
                    recorded.push(DIRECT_ACTIVITY_RECORDED);
                }
            }
            if capture_pending(paged, capturing)
                && Instant::now() < capture_deadline
                && capture(home, &paged.record)
            {
                recorded.push(CAPTURE_RECORDED);
            }
            marks.push((paged.seq, recorded));
        }
        marks
    });
    mark(queue, paged, &noticed);
    let (marks, fatal) = recorded?;
    mark(queue, paged, &marks);
    Some(fatal)
}

/// Leave out of the page the records the daemon has nothing left to record
/// for.
pub(super) fn drop_settled(paged: &mut Vec<Paged>, guard_home: &str) {
    let capturing = capture_marker_present(Path::new(guard_home));
    paged.retain(|paged| !settled(paged, capturing));
}

/// Whether `record_direct_hook_evidence` would record nothing for this
/// record: no receipt the store accepts and the resident has not recorded, no
/// fence wait, no capture the marker turns on, and for a tool answer its
/// activity recorded and no connector-setup notice left to raise. A relayed
/// MCP record, and an event the drain does not know, stay on the page.
pub(super) fn settled(paged: &Paged, capturing: bool) -> bool {
    let record = &paged.record;
    let event = match record.get("event") {
        None => PRE_TOOL_USE,
        Some(event) => match event.as_str() {
            Some(event) => event,
            None => return false,
        },
    };
    if record.get("kind").is_some()
        || ![PRE_TOOL_USE, POST_TOOL_USE, USER_PROMPT_SUBMIT].contains(&event)
    {
        return false;
    }
    let receipt_left = flagged(record, RECEIPT_VALID)
        && record.get("receipt").is_some_and(Value::is_object)
        && !flagged(record, DIRECT_RECEIPT_RECORDED);
    if receipt_left || fence_wait_ms(record).is_some() || capture_pending(paged, capturing) {
        return false;
    }
    if event == USER_PROMPT_SUBMIT {
        // The daemon records no activity for a prompt it answers.
        return true;
    }
    flagged(record, DIRECT_ACTIVITY_RECORDED)
        && (event == POST_TOOL_USE
            || flagged(record, super::notice::NOTICE_RAISED)
            || record.get(CONNECTOR_NOTICE_FIELD).is_none())
}

/// Mark what was recorded on the page and in the queue.
fn mark(queue: &DirectEvidenceQueue, paged: &mut [Paged], marks: &[(u64, Vec<&str>)]) {
    let mut state = queue.state.lock().ok();
    for (seq, recorded) in marks {
        if let Some(state) = state.as_mut() {
            state.mark(*seq, recorded);
        }
        let page = paged.iter_mut().find(|paged| paged.seq == *seq);
        if let Some(fields) = page.and_then(|paged| paged.record.as_object_mut()) {
            for marker in recorded {
                fields.insert((*marker).to_owned(), Value::Bool(true));
            }
        }
    }
}
