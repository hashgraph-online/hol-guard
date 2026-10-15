//! `DataFlowAnalyze` resident op: shell data-flow exfiltration detection.
//!
//! Wraps `guard_command::data_flow_rules::detect_data_flow_exfiltration` and
//! binds the reply to the request with `request_id` plus the canonical
//! request digest. Any internal failure is reported as an `error` status so
//! the Python transport fails closed; it never recomputes the verdict.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use guard_command::data_flow_rules::{detect_data_flow_exfiltration, GuardActionEnvelopeView};
use guard_contracts::{
    write_canonical_json_with_limit, DataFlowAnalyzeRequestV1, DataFlowAnalyzeResultV1,
    DATA_FLOW_ANALYZE_MAX_COMMAND_BYTES, DATA_FLOW_ANALYZE_REQUEST_SCHEMA,
    DATA_FLOW_ANALYZE_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use serde_json::Value;

fn request_digest(request: &DataFlowAnalyzeRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| "native_data_flow_analyze_invalid")?;
    let mut canonical = Vec::with_capacity(256);
    write_canonical_json_with_limit(
        &material,
        &mut canonical,
        usize::MAX,
        "native_data_flow_analyze_invalid",
    )
    .map_err(|_| "native_data_flow_analyze_invalid")?;
    Ok(digest_bytes(&canonical))
}

fn analyze(request: &DataFlowAnalyzeRequestV1) -> Result<Vec<Value>, &'static str> {
    if request.schema != DATA_FLOW_ANALYZE_REQUEST_SCHEMA {
        return Err("native_data_flow_analyze_schema_mismatch");
    }
    if request
        .command
        .as_ref()
        .is_some_and(|command| command.len() > DATA_FLOW_ANALYZE_MAX_COMMAND_BYTES)
    {
        return Err("native_data_flow_analyze_command_too_large");
    }
    let view = GuardActionEnvelopeView {
        action_type: &request.action_type,
        command: request.command.as_deref(),
    };
    let workspace = request.workspace.as_deref().map(Path::new);
    catch_unwind(AssertUnwindSafe(|| {
        detect_data_flow_exfiltration(&view, workspace)
    }))
    .map(|signals| signals.iter().map(|signal| signal.to_value()).collect())
    .map_err(|_| "native_data_flow_analyze_failed")
}

pub(crate) fn evaluate_data_flow_analyze(
    request: &DataFlowAnalyzeRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request).map_err(str::to_owned)?;
    let (status, code, signals) = match analyze(request) {
        Ok(signals) => ("ok", "ok", Some(signals)),
        Err(code) => ("error", code, None),
    };
    crate::encode_response(&DataFlowAnalyzeResultV1 {
        schema: DATA_FLOW_ANALYZE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        signals,
    })
}

#[cfg(test)]
#[path = "data_flow_analyze_op_tests.rs"]
mod tests;
