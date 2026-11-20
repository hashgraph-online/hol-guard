//! `command-result --stdin`: the result a settled Guard Cloud command job posts.
//!
//! Port of `result_payload` in `runtime/command_queue_protocol.py` and
//! `exact_result` in `runtime/exact_cloud_review_transport.py`. The Python
//! command queue still leases jobs, runs them and posts the answer; this op
//! turns a job and its local execution into the wire payload Guard Cloud
//! records, including the versioned exact Review result and its contract
//! checks (`contracts/guard-cloud-review/v2/command-result.json`).
//!
//! A job without an id or a lease id is refused, as before. An exact Review
//! result that does not satisfy its contract becomes a `failed` payload with
//! `exact_result_contract_invalid`, so the lease still closes.

use std::io::Read;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use contract::{contract_result, Fields};

#[path = "command_result_contract.rs"]
mod contract;

pub(crate) const COMMAND: &str = "command-result";
pub(crate) const FEATURE: &str = "native-command-result-v1";
const SCHEMA: &str = "command-result.v1";
/// Guard Cloud accepts result bodies up to 8 MiB; the request also carries
/// the job, so this leaves room for both.
const MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;

const INVALID: &str = "command_result_request_invalid";
pub(crate) const JOB_ID_MISSING: &str = "command_job_id_missing";
pub(crate) const LEASE_ID_MISSING: &str = "command_job_lease_missing";

const TRANSPORT_MARKER: &str = "_guardCommandTransport";
const EXACT_TRANSPORT: &str = "cloud_review";
const PROTOCOL_VERSION: i64 = 2;
const CONTRACT_INVALID: &str = "exact_result_contract_invalid";
const NATIVE_PAYLOAD_FIELDS: [&str; 3] = ["localRequestId", "receiptId", "envelope"];
const INVALID_NATIVE: &str = "remote_native_workspace_review_invalid";
const MAX_NATIVE_ID_CHARS: usize = 128;

const APPLICATION_STATUSES: [&str; 6] = [
    "applied",
    "failed_retryable",
    "failed_terminal",
    "not_applicable",
    "rejected_binding",
    "rejected_stale",
];
const CONTINUATION_STATUSES: [&str; 8] = [
    "already_resumed",
    "blocked_not_resumed",
    "failed",
    "manual_retry_required",
    "not_applicable",
    "resumed",
    "unsupported",
    "waiting",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    schema: String,
    job: Map<String, Value>,
    execution: Map<String, Value>,
    /// The caller's clock in ISO form: the result time when the executor
    /// reported none.
    now: String,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == COMMAND
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "command_result_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("command_result_request_too_large".to_owned());
    }
    let response = match serde_json::from_slice::<Request>(&bytes) {
        Ok(request) => match handle(&request) {
            Ok(result) => json!({"ok": true, "result": result}),
            Err(code) => json!({"ok": false, "error": code}),
        },
        Err(_) => json!({"ok": false, "error": INVALID}),
    };
    serde_json::to_vec(&response).map_err(|_| "command_result_response_encode_failed".to_owned())
}

pub(crate) fn handle(request: &Request) -> Result<Value, &'static str> {
    if request.schema != SCHEMA {
        return Err(INVALID);
    }
    Ok(Value::Object(result_payload(
        &request.job,
        &request.execution,
        &request.now,
    )?))
}

/// The posted payload for one settled job. Errors only for a job that carries
/// no lease id or no id, checked in that order like the Python helpers.
pub(crate) fn result_payload(
    job: &Map<String, Value>,
    execution: &Map<String, Value>,
    now: &str,
) -> Result<Map<String, Value>, &'static str> {
    let lease = non_empty_str(job.get("leaseId")).ok_or(LEASE_ID_MISSING)?;
    let id = non_empty_str(job.get("id")).ok_or(JOB_ID_MISSING)?;
    let exact = job.get(TRANSPORT_MARKER).and_then(Value::as_str) == Some(EXACT_TRANSPORT);
    let mut payload = Map::new();
    if exact {
        payload.insert("protocolVersion".to_owned(), json!(PROTOCOL_VERSION));
    }
    payload.insert("leaseId".to_owned(), json!(lease));
    if execution.get("waitingLocalConfirm") == Some(&Value::Bool(true)) {
        let mut sanitized = execution.clone();
        sanitized.remove("waitingLocalConfirm");
        return Ok(finish(
            payload,
            id,
            lease,
            "waiting_local_confirm",
            [("result", Value::Object(sanitized))],
        ));
    }
    if let Some(code) = non_empty_str(execution.get("failureCode")) {
        return Ok(failed(
            payload,
            id,
            lease,
            code,
            &failure_message(execution, code),
        ));
    }
    let result = if exact {
        match exact_result(job, execution, now) {
            Ok(result) => Value::Object(result),
            Err(_) => {
                return Ok(failed(
                    payload,
                    id,
                    lease,
                    CONTRACT_INVALID,
                    "The exact Guard Review result did not satisfy the canonical contract.",
                ));
            }
        }
    } else {
        Value::Object(execution.clone())
    };
    Ok(finish(
        payload,
        id,
        lease,
        "succeeded",
        [("result", result)],
    ))
}

fn failed(
    payload: Map<String, Value>,
    id: &str,
    lease: &str,
    code: &str,
    message: &str,
) -> Map<String, Value> {
    finish(
        payload,
        id,
        lease,
        "failed",
        [
            ("failureCode", json!(code)),
            ("failureMessage", json!(message)),
        ],
    )
}

fn finish<const N: usize>(
    mut payload: Map<String, Value>,
    id: &str,
    lease: &str,
    status: &str,
    extra: [(&str, Value); N],
) -> Map<String, Value> {
    payload.insert(
        "idempotencyKey".to_owned(),
        json!(format!("{id}:{lease}:{status}")),
    );
    payload.insert("status".to_owned(), json!(status));
    for (key, value) in extra {
        payload.insert(key.to_owned(), value);
    }
    payload
}

/// `str(execution.get("failureMessage") or failure_code)` for the messages
/// the queue writes: a non-empty string is kept, anything else falls back to
/// the code.
fn failure_message(execution: &Map<String, Value>, code: &str) -> String {
    non_empty_str(execution.get("failureMessage"))
        .unwrap_or(code)
        .to_owned()
}

fn non_empty_str(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
}

/// The exact Review result for a successful execution, checked against the
/// v2 command-result contract. Any error makes the caller post a failure.
pub(crate) fn exact_result(
    job: &Map<String, Value>,
    execution: &Map<String, Value>,
    now: &str,
) -> Result<Map<String, Value>, &'static str> {
    let correlation_id = required_text(job.get("id"), "exact_result_correlation_missing")?;
    let payload = mapping(job.get("payload"));
    let native = native_workspace_review(&payload)?;
    let signed_decision = if native.is_none() {
        mapping(payload.get("remoteApproval"))
    } else {
        Map::new()
    };
    let binding = mapping(job.get("serverResolvedBinding"));
    let bound_request_id = required_text(
        binding.get("localRequestId"),
        "exact_result_local_request_binding_missing",
    )?;
    let (decision_request_id, receipt_id) = match native {
        Some(ids) => ids,
        None => (
            required_text(
                signed_decision.get("localRequestId"),
                "exact_result_local_request_missing",
            )?,
            required_text(
                signed_decision.get("receiptId"),
                "exact_result_receipt_missing",
            )?,
        ),
    };
    if bound_request_id != decision_request_id {
        return Err("exact_result_local_request_binding_mismatch");
    }
    let data = mapping(execution.get("data"));
    let generated_at = text(execution.get("generatedAt")).unwrap_or_else(|| now.to_owned());
    if data.is_empty() {
        return contract_result(Fields {
            correlation_id,
            local_request_id: bound_request_id,
            receipt_id,
            application_status: "failed_terminal".to_owned(),
            application_reason: Some("exact_result_invalid".to_owned()),
            continuation_status: "failed".to_owned(),
            continuation_reason: Some("exact_result_invalid".to_owned()),
            application_updated_at: generated_at.clone(),
            continuation_updated_at: generated_at,
        });
    }
    let application_status = text(data.get("applicationStatus"))
        .filter(|status| APPLICATION_STATUSES.contains(&status.as_str()))
        .ok_or("exact_result_application_status_invalid")?;
    let application_reason = text(data.get("applicationReason"));
    let continuation_status = text(data.get("continuationStatus"))
        .filter(|status| CONTINUATION_STATUSES.contains(&status.as_str()))
        .ok_or("exact_result_continuation_status_invalid")?;
    let continuation_reason = text(data.get("continuationReason"));
    let application_updated_at = required_text(
        data.get("applicationUpdatedAt"),
        "exact_result_application_timestamp_missing",
    )?;
    let continuation_updated_at = required_text(
        data.get("continuationUpdatedAt"),
        "exact_result_continuation_timestamp_missing",
    )?;
    let data_request_id = required_text(
        data.get("localRequestId"),
        "exact_result_local_request_missing",
    )?;
    let data_receipt_id = required_text(data.get("receiptId"), "exact_result_receipt_missing")?;
    if data_request_id != bound_request_id || data_receipt_id != receipt_id {
        return Err("exact_result_execution_binding_mismatch");
    }
    contract_result(Fields {
        correlation_id,
        local_request_id: bound_request_id,
        receipt_id,
        application_status,
        application_reason,
        continuation_status,
        continuation_reason,
        application_updated_at,
        continuation_updated_at,
    })
}

/// The ids a native workspace-review payload names, `None` when the payload is
/// not one, and an error when it is one only in part.
fn native_workspace_review(
    payload: &Map<String, Value>,
) -> Result<Option<(String, String)>, &'static str> {
    if !NATIVE_PAYLOAD_FIELDS
        .iter()
        .any(|field| payload.contains_key(*field))
    {
        return Ok(None);
    }
    if payload.len() != NATIVE_PAYLOAD_FIELDS.len()
        || !NATIVE_PAYLOAD_FIELDS
            .iter()
            .all(|field| payload.contains_key(*field))
    {
        return Err(INVALID_NATIVE);
    }
    let local_request_id = native_id(payload.get("localRequestId")).ok_or(INVALID_NATIVE)?;
    let receipt_id = native_id(payload.get("receiptId")).ok_or(INVALID_NATIVE)?;
    let envelope_ok = payload
        .get("envelope")
        .and_then(Value::as_object)
        .is_some_and(|envelope| !envelope.is_empty());
    let id_ok = local_request_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'));
    if !envelope_ok || !id_ok {
        return Err(INVALID_NATIVE);
    }
    Ok(Some((local_request_id.to_owned(), receipt_id.to_owned())))
}

/// An identifier with no surrounding whitespace and at most 128 characters.
fn native_id(value: Option<&Value>) -> Option<&str> {
    let value = value?.as_str()?;
    (!value.is_empty() && py_strip(value) == value && value.chars().count() <= MAX_NATIVE_ID_CHARS)
        .then_some(value)
}

fn mapping(value: Option<&Value>) -> Map<String, Value> {
    value
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

/// Python's `str.strip()` result when non-empty.
fn text(value: Option<&Value>) -> Option<String> {
    let stripped = py_strip(value?.as_str()?);
    (!stripped.is_empty()).then(|| stripped.to_owned())
}

fn required_text(value: Option<&Value>, error: &'static str) -> Result<String, &'static str> {
    text(value).ok_or(error)
}

/// Python's `str.strip()`: Unicode whitespace plus the four ASCII separators
/// Python also treats as space.
fn py_strip(value: &str) -> &str {
    value.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

#[cfg(test)]
#[path = "command_result_tests.rs"]
mod tests;
