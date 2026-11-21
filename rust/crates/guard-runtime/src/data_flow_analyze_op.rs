//! `DataFlowAnalyze` resident op: shell data-flow exfiltration detection.
//!
//! Wraps `guard_command::data_flow_rules::detect_data_flow_exfiltration` and
//! binds the reply to the request with `request_id` plus the canonical
//! request digest. Any internal failure is reported as an `error` status so
//! the Python transport fails closed; it never recomputes the verdict.
//!
//! When the request carries naming, the reply also carries the artifact those
//! signals earn. The artifact id is the key the review is saved under, so it
//! leaves with the signals that decide it rather than being rebuilt from them
//! on the other side of the wire.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use guard_command::data_flow_request_artifact::build_data_flow_request_artifact;
use guard_command::data_flow_rules::{detect_data_flow_exfiltration, GuardActionEnvelopeView};
use guard_contracts::{
    write_canonical_json_with_limit, DataFlowAnalyzeRequestV1, DataFlowAnalyzeResultV1,
    RiskSignalV2, DATA_FLOW_ANALYZE_MAX_COMMAND_BYTES, DATA_FLOW_ANALYZE_REQUEST_SCHEMA,
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

fn analyze(request: &DataFlowAnalyzeRequestV1) -> Result<Vec<RiskSignalV2>, &'static str> {
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
    .map_err(|_| "native_data_flow_analyze_failed")
}

/// The artifact for `signals`, or none when the request asked for signals
/// alone or the command raised none: an action with no data flow earns no
/// review, so there is nothing to key one under.
fn artifact_for(request: &DataFlowAnalyzeRequestV1, signals: &[RiskSignalV2]) -> Option<Value> {
    fn non_empty(value: &str) -> Option<&str> {
        (!value.is_empty()).then_some(value)
    }
    let naming = request.naming.as_ref()?;
    if signals.is_empty() {
        return None;
    }
    let command_text = request
        .command
        .as_deref()
        .and_then(non_empty)
        .or_else(|| naming.tool_name.as_deref().and_then(non_empty))
        .unwrap_or(&request.action_type);
    Some(build_data_flow_request_artifact(
        &naming.harness,
        naming.tool_name.as_deref(),
        command_text,
        signals,
        &naming.config_path,
        &naming.source_scope,
    ))
}

pub(crate) fn evaluate_data_flow_analyze(
    request: &DataFlowAnalyzeRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request).map_err(str::to_owned)?;
    let (status, code, signals, artifact) = match analyze(request) {
        Ok(found) => {
            let artifact = artifact_for(request, &found);
            let signals = found.iter().map(RiskSignalV2::to_value).collect();
            ("ok", "ok", Some(signals), artifact)
        }
        Err(code) => ("error", code, None, None),
    };
    crate::encode_response(&DataFlowAnalyzeResultV1 {
        schema: DATA_FLOW_ANALYZE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        signals,
        artifact,
    })
}

#[cfg(test)]
#[path = "data_flow_analyze_op_tests.rs"]
mod tests;
