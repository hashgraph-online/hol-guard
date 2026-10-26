//! `SkillWorkflowPreflight` — resident op for a skill's declared tool
//! dependencies and the advisory requirements they draw.
//!
//! Pure: reads a declaration and the saved rows a caller already holds, then
//! answers through `guard_command::skill_dependency_manifest`. No IO.
//!
//! The answer is advisory, not authority. A requirement never grants a call:
//! `saved-allow` still carries `live-runtime-check-still-required`, and a
//! caller that cannot reach the resident has no requirements at all rather
//! than ones it worked out for itself.

use guard_command::skill_dependency_manifest::{parse_dependencies, preflight};
use guard_contracts::{
    SkillWorkflowPreflightRequestV1, SkillWorkflowPreflightResultV1,
    SKILL_WORKFLOW_PREFLIGHT_MAX_BYTES, SKILL_WORKFLOW_PREFLIGHT_REQUEST_SCHEMA,
    SKILL_WORKFLOW_PREFLIGHT_RESULT_SCHEMA,
};
use serde_json::Value;

use crate::mcp_tool_policy_composio::requires_action_review;
use crate::package_authority_op::request_digest_with_limit;

pub(crate) fn evaluate_skill_workflow_preflight_request(
    request: &SkillWorkflowPreflightRequestV1,
) -> Result<Vec<u8>, String> {
    // Bound the complete canonical request before any work; an oversized
    // request has no digest to bind.
    let request_sha256 = request_digest_with_limit(request, SKILL_WORKFLOW_PREFLIGHT_MAX_BYTES)
        .map_err(|_| "native_skill_workflow_preflight_too_large".to_owned())?;
    let (status, code, payload) = evaluate(request);
    crate::encode_response(&SkillWorkflowPreflightResultV1 {
        schema: SKILL_WORKFLOW_PREFLIGHT_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

fn evaluate(
    request: &SkillWorkflowPreflightRequestV1,
) -> (&'static str, &'static str, Option<Value>) {
    if request.schema != SKILL_WORKFLOW_PREFLIGHT_REQUEST_SCHEMA {
        return (
            "error",
            "native_skill_workflow_preflight_schema_mismatch",
            None,
        );
    }
    match request.subop.as_str() {
        "dependencies" => match request.dependencies.as_ref() {
            Some(input) => (
                "ok",
                "ok",
                Some(parse_dependencies(input.present, input.text.as_deref())),
            ),
            None => (
                "error",
                "native_skill_workflow_preflight_missing_input",
                None,
            ),
        },
        "preflight" => match request.preflight.as_ref() {
            Some(input) => (
                "ok",
                "ok",
                Some(preflight(
                    &input.dependencies,
                    &input.connections,
                    input.authority_revision,
                    &requires_action_review,
                )),
            ),
            None => (
                "error",
                "native_skill_workflow_preflight_missing_input",
                None,
            ),
        },
        _ => (
            "error",
            "native_skill_workflow_preflight_unknown_subop",
            None,
        ),
    }
}

#[cfg(test)]
#[path = "skill_workflow_preflight_op_tests.rs"]
mod tests;
