//! The edge records its own decision receipt.
//!
//! The daemon used to submit every edge answer's receipt to the hook evidence
//! writer in a second resident request. When the envelope asks for it, the
//! edge queues the receipt with the writer itself and says so in its answer,
//! so the daemon skips that request.
//!
//! Only a writer already running for the request's Guard home takes the
//! receipt: starting one replays its journal, and a stop drains it, neither of
//! which a hook answer waits for. Without a live writer free to take it, or
//! when the writer refuses it, the answer says nothing was recorded and the
//! daemon submits the receipt as before, which starts the writer. The receipt
//! is queued only once the answer is encoded, so a call that fails closed on
//! an answer too large to send leaves no receipt behind. It is queued before
//! the answer leaves, so it precedes the command activity that links to it.
//!
//! A hook the resident answers directly records its receipt the same way:
//! with a writer already running, the resident queues the receipt and marks
//! the evidence record it queues for the daemon's drain, which then submits
//! the rest of that record's evidence but not the receipt. For a tool answer
//! it queues the command activity behind that receipt as well, after a
//! post-tool call's Composio discovery, and marks the record for that too,
//! which saves the drain another writer request per hook. An edge
//! `PostToolUse` answer whose envelope asked queues its activity behind the
//! receipt the same way, and says so with `activity_recorded`. So does a
//! `PreToolUse` answer the daemon returns as the edge rendered it: one no
//! approval pause, saved exact-command block or containment rewrite of the
//! daemon's can still change.

use std::path::Path;
use std::time::{Duration, Instant};

use guard_command::hook_evidence_writer::RuntimeHookEvidenceWriter;
use guard_contracts::{GuardHookEdgeResultV2, GuardHookEnvelopeV2};
use serde_json::{Map, Value};

use crate::hook_direct_evidence::DirectEvidenceQueue;
use crate::hook_evidence_writer_op as writer_op;

/// The resident feature under which an envelope may ask for this.
pub(crate) const EDGE_RECEIPT_RECORD_FEATURE: &str = "edge-receipt-record-v1";
/// The resident queues an edge `PostToolUse` answer's activity when asked.
pub(crate) const EDGE_ACTIVITY_RECORD_FEATURE: &str = "edge-activity-record-v1";
/// The resident queues an edge `PreToolUse` answer's activity when asked.
pub(crate) const EDGE_PRE_TOOL_ACTIVITY_RECORD_FEATURE: &str = "edge-pre-tool-activity-record-v1";
/// The field of a direct answer's evidence record that says the resident
/// already queued its receipt with the writer.
const DIRECT_RECEIPT_RECORDED: &str = "receipt_recorded";
/// The field that says the resident queued its command activity as well.
const DIRECT_ACTIVITY_RECORDED: &str = "activity_recorded";
/// `hook_post_succeeded`'s compact spelling of a failed tool call's event.
const POST_TOOL_USE_FAILURE: &str = "posttoolusefailure";
/// The `minimum_action`s the daemon pauses for an approval
/// (`_NATIVE_PRE_TOOL_APPROVAL_ACTIONS`, `hook_worker_native.py`).
const APPROVAL_ACTIONS: [&str; 2] = ["review", "require-reapproval"];

/// Encode the checked `edge`, recording its receipt when the envelope asked
/// and a writer runs for its Guard home. `resident` is false for a caller
/// outside the resident's own edge request, which never records.
pub(crate) fn encode(
    envelope: &GuardHookEnvelopeV2,
    resident: bool,
    edge: GuardHookEdgeResultV2,
    started: Instant,
) -> Result<Vec<u8>, String> {
    let mut edge = crate::edge_structured::attached(envelope, edge, started);
    if resident && envelope.record_receipt && !budget_spent(envelope, started) {
        let activity = edge_activity(envelope, &edge);
        edge.receipt_recorded = true;
        edge.activity_recorded = activity.is_some();
        let mut activity_queued = true;
        let recorded = writer_op::record_edge_receipt(
            Path::new(&envelope.source.guard_home),
            &edge.receipt,
            || crate::encode_response(&edge),
            |writer| match activity {
                Some(EdgeActivity::PostTool(payload)) => {
                    activity_queued = queue_post_tool_activity(writer, &edge.harness, payload);
                }
                Some(EdgeActivity::PreTool(payload, activity)) => {
                    let receipt_id = Some(edge.receipt.decision_id.as_str());
                    activity_queued = activity.submit(writer, &edge.harness, payload, receipt_id);
                }
                None => {}
            },
        );
        if let Some(encoded) = recorded {
            if activity_queued || encoded.is_err() {
                return encoded;
            }
            // The writer took the receipt but refused the activity, so the
            // daemon submits the activity itself.
            edge.activity_recorded = false;
            return crate::encode_response(&edge);
        }
        edge.receipt_recorded = false;
        edge.activity_recorded = false;
    }
    crate::encode_response(&edge)
}

/// Whether the daemon's budget for this answer ran out while the edge worked.
///
/// A daemon that stops waiting records the hook as unavailable on its own, so
/// an edge that records evidence after that point would leave two records for
/// one hook. Past the budget the edge records nothing and leaves it all to a
/// daemon that may still read the answer.
fn budget_spent(envelope: &GuardHookEnvelopeV2, started: Instant) -> bool {
    envelope
        .deadline_budget_ms
        .is_some_and(|budget| started.elapsed() >= Duration::from_millis(budget))
}

/// The command activity an edge answer queues behind its receipt.
enum EdgeActivity<'a> {
    PostTool(&'a Map<String, Value>),
    PreTool(&'a Map<String, Value>, PreToolActivity),
}

/// The activity `envelope` asked the edge to queue for `edge`, if the edge
/// can record it as the daemon would.
fn edge_activity<'a>(
    envelope: &'a GuardHookEnvelopeV2,
    edge: &GuardHookEdgeResultV2,
) -> Option<EdgeActivity<'a>> {
    let payload = envelope.raw_payload.as_object()?;
    match edge.event_name.as_str() {
        "PostToolUse" if envelope.record_activity => Some(EdgeActivity::PostTool(payload)),
        "PreToolUse" if envelope.record_pre_tool_activity => {
            let response = daemon_response(envelope, edge)?.as_object()?;
            Some(EdgeActivity::PreTool(
                payload,
                PreToolActivity::of(response)?,
            ))
        }
        _ => None,
    }
}

/// The response the daemon returns for a `PreToolUse` edge answer, when
/// nothing it does after the edge can change it: the answer of a call
/// recorded only that the edge did not allow, a custom rule's block, or the
/// edge's own answer once no approval pause, saved exact-command block or
/// sink rewrite applies. `None` leaves the activity to the daemon, as does
/// an answer the edge does not stamp with its route.
fn daemon_response<'a>(
    envelope: &GuardHookEnvelopeV2,
    edge: &'a GuardHookEdgeResultV2,
) -> Option<&'a Value> {
    let text = |key: &str| edge.result.get(key).and_then(Value::as_str);
    let action = text("minimum_action").unwrap_or_default();
    let allowed = action == "allow" && text("decision") == Some("allow");
    if envelope.recording_only && !allowed {
        return edge.harness_response.as_ref();
    }
    if APPROVAL_ACTIONS.contains(&action) {
        return None;
    }
    if let Some(rule) = edge.local_cli_rule.as_ref().filter(|rule| rule.blocked) {
        return Some(&rule.harness_response);
    }
    // The daemon's saved exact-command block lookup reads only a shell
    // action outside Watch, and skips one the edge found no block for.
    let shell = matches!(
        edge.result
            .pointer("/action/action_type")
            .and_then(Value::as_str),
        Some("command" | "package" | "process_service" | "network" | "shell" | "shell_command")
    );
    if shell && !envelope.recording_only && edge.exact_command_block != Some(false) {
        return None;
    }
    match (
        edge.containment_route.as_deref(),
        edge.containment_rewrite.as_deref(),
    ) {
        (Some("none" | "grant"), _) | (Some("sink"), Some("kept")) => {
            edge.harness_response.as_ref()
        }
        _ => None,
    }
}

/// The fields of a `PreToolUse` activity read from the response it records.
struct PreToolActivity {
    policy_action: Option<String>,
    prompted: bool,
    approval_reuse_status: String,
}

impl PreToolActivity {
    /// `None` for a response whose fields the activity cannot take.
    fn of(response: &Map<String, Value>) -> Option<Self> {
        let policy_action = match response.get("policy_action") {
            None | Some(Value::Null) => None,
            Some(Value::String(action)) => Some(action.clone()),
            Some(_) => return None,
        };
        let approval_reuse_status = match response.get("approval_reuse_status") {
            None => "not-applicable".to_owned(),
            Some(Value::String(status)) => status.clone(),
            Some(_) => return None,
        };
        Some(Self {
            policy_action,
            prompted: response.get("prompted") == Some(&Value::Bool(true)),
            approval_reuse_status,
        })
    }

    /// Queue the activity, citing the receipt the writer just accepted.
    fn submit(
        &self,
        writer: &RuntimeHookEvidenceWriter,
        harness: &str,
        payload: &Map<String, Value>,
        receipt_id: Option<&str>,
    ) -> bool {
        writer.submit_command_activity(
            harness,
            "PreToolUse",
            payload,
            true,
            self.policy_action.as_deref(),
            receipt_id,
            self.prompted,
            &self.approval_reuse_status,
        )
    }
}

/// Queue a direct answer's `evidence` for the drain, recording its receipt
/// and then, with `record_activity`, its command activity first when a writer
/// already runs for `guard_home`. The record carries `receipt_recorded` and
/// `activity_recorded` only for what that writer accepted; the drain submits
/// the rest itself, which starts the writer when none runs. False when the
/// queue cannot hold the record: nothing was queued or recorded, so the
/// daemon answering the hook records it once.
pub(crate) fn offer_direct(
    queue: &DirectEvidenceQueue,
    guard_home: &Path,
    evidence: Value,
    record_activity: bool,
) -> bool {
    if !evidence.get("receipt").is_some_and(Value::is_object) {
        return queue.offer(evidence);
    }
    let mut pending = Some(evidence);
    let queued = writer_op::record_direct(guard_home, |writer| {
        pending.take().is_some_and(|record| {
            let markers = [DIRECT_RECEIPT_RECORDED, DIRECT_ACTIVITY_RECORDED];
            queue
                .try_offer_recorded(record, &markers, |record| {
                    let Some(receipt) = record.get("receipt").and_then(Value::as_object) else {
                        return 0;
                    };
                    if !writer.submit_native_decision_receipt(receipt) {
                        return 0;
                    }
                    1 + usize::from(record_activity && submit_activity(writer, record))
                })
                .is_ok()
        })
    });
    queued.unwrap_or_else(|| pending.is_some_and(|record| queue.offer(record)))
}

/// Queue a direct tool answer's command activity as the drain would. False
/// leaves it to the drain, which also gets any answer whose fields the
/// activity cannot take.
fn submit_activity(writer: &RuntimeHookEvidenceWriter, record: &Value) -> bool {
    match record.get("event").and_then(Value::as_str) {
        Some("PreToolUse") => submit_pre_tool_activity(writer, record),
        Some("PostToolUse") => submit_post_tool_activity(writer, record),
        _ => false,
    }
}

/// The drain's post-tool recording: the Composio discovery of a call that
/// succeeded, then the activity. The writer refusing either drops it as it
/// would for the drain, so once both are submitted the drain has nothing
/// left to send.
fn submit_post_tool_activity(writer: &RuntimeHookEvidenceWriter, record: &Value) -> bool {
    let (Some(harness), Some(payload)) = (
        record.get("harness").and_then(Value::as_str),
        record.get("payload").and_then(Value::as_object),
    ) else {
        return false;
    };
    queue_post_tool_activity(writer, harness, payload);
    true
}

/// Queue a post-tool call's Composio discovery, when it succeeded, and then
/// its command activity, as the daemon's `_record_post_tool_activity` does.
/// True when the writer took the activity.
fn queue_post_tool_activity(
    writer: &RuntimeHookEvidenceWriter,
    harness: &str,
    payload: &Map<String, Value>,
) -> bool {
    let succeeded = post_succeeded(payload);
    let tool_name = payload.get("tool_name").and_then(Value::as_str);
    if let Some(tool_name) = tool_name.filter(|_| succeeded) {
        writer.submit_composio_discovery(harness, tool_name, payload);
    }
    writer.submit_command_activity(
        harness,
        "PostToolUse",
        payload,
        succeeded,
        None,
        None,
        false,
        "not-applicable",
    )
}

/// `hook_post_succeeded("PostToolUse", payload)`: only bounded failure
/// signals count, and their absence means the call succeeded.
fn post_succeeded(payload: &Map<String, Value>) -> bool {
    for name in ["hook_event_name", "hookEventName"] {
        if let Some(event) = payload.get(name).and_then(Value::as_str) {
            let compact: String = event.chars().filter(|c| *c != '_' && *c != '-').collect();
            if compact.to_lowercase() == POST_TOOL_USE_FAILURE {
                return false;
            }
        }
    }
    let flagged = |key: &str, value: bool| payload.get(key) == Some(&Value::Bool(value));
    if ["is_error", "isError", "failed"]
        .into_iter()
        .any(|key| flagged(key, true))
        || flagged("success", false)
    {
        return false;
    }
    // Python's `type(code) is int`: a float or a bool is not an exit code.
    let exit_code = payload.get("exit_code").or_else(|| payload.get("exitCode"));
    !exit_code
        .and_then(Value::as_number)
        .is_some_and(|code| code.as_i64().map_or(code.is_u64(), |code| code != 0))
}

/// The `PreToolUse` activity, citing the receipt the writer just accepted.
fn submit_pre_tool_activity(writer: &RuntimeHookEvidenceWriter, record: &Value) -> bool {
    let (Some(harness), Some(payload), Some(response)) = (
        record.get("harness").and_then(Value::as_str),
        record.get("payload").and_then(Value::as_object),
        record.get("harness_response").and_then(Value::as_object),
    ) else {
        return false;
    };
    let Some(activity) = PreToolActivity::of(response) else {
        return false;
    };
    let receipt_id = record
        .get("receipt")
        .and_then(|receipt| receipt.get("decision_id"))
        .and_then(Value::as_str);
    activity.submit(writer, harness, payload, receipt_id)
}

#[cfg(test)]
#[path = "edge_receipt_deadline_tests.rs"]
mod deadline_tests;
#[cfg(test)]
#[path = "edge_receipt_tests.rs"]
mod tests;
