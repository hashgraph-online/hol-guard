//! `NativeExactAction` — resident op for the exact-action and review-binding
//! identity proofs of a native review.
//!
//! The resident owns every proof: the code a command would run, the files it
//! reads, the repository configuration git would consult and the rules that
//! judged it. A proof that fails is a successful reply carrying the once-only
//! reason, so only a malformed request is an `error`.

mod binding;
mod context;
mod fs_path;
mod git_config;
mod git_identity;
mod launch;
mod launcher_sets;
mod operands;
mod reasons;
mod runner_bin;
mod token;
mod tool_target;

use std::time::{Duration, Instant};

use guard_contracts::{
    NativeExactActionPayloadV1, NativeExactActionQueryV1, NativeExactActionRequestV1,
    NativeExactActionResultV1, NATIVE_EXACT_ACTION_MAX_BUDGET_MS, NATIVE_EXACT_ACTION_MAX_BYTES,
    NATIVE_EXACT_ACTION_REQUEST_SCHEMA, NATIVE_EXACT_ACTION_RESULT_SCHEMA,
};

use crate::package_authority_op::request_digest_with_limit;
use context::{Engines, ResidentEngines};

pub(crate) fn evaluate_native_exact_action_request(
    request: &NativeExactActionRequestV1,
) -> Result<Vec<u8>, String> {
    evaluate_with(request, &ResidentEngines)
}

fn evaluate_with(
    request: &NativeExactActionRequestV1,
    engines: &dyn Engines,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, NATIVE_EXACT_ACTION_MAX_BYTES)
        .map_err(|_| "native_exact_action_too_large".to_owned())?;
    let (status, code, payload) = match decide(request, engines) {
        Ok(payload) => ("ok", "ok", Some(payload)),
        Err(code) => ("error", code, None),
    };
    crate::encode_response(&NativeExactActionResultV1 {
        schema: NATIVE_EXACT_ACTION_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

fn decide(
    request: &NativeExactActionRequestV1,
    engines: &dyn Engines,
) -> Result<NativeExactActionPayloadV1, &'static str> {
    if request.schema != NATIVE_EXACT_ACTION_REQUEST_SCHEMA {
        return Err("native_exact_action_schema_mismatch");
    }
    Ok(match &request.query {
        NativeExactActionQueryV1::ReviewBinding {
            harness,
            command,
            workspace_bound,
            facts,
            receipt,
            policy_binding,
        } => NativeExactActionPayloadV1::ReviewBinding {
            binding: binding::review_binding(
                harness,
                command.as_deref(),
                *workspace_bound,
                facts,
                receipt.as_ref(),
                policy_binding,
            ),
        },
        NativeExactActionQueryV1::ExactAction { budget_ms, .. } => {
            let budget = Duration::from_millis((*budget_ms).min(NATIVE_EXACT_ACTION_MAX_BUDGET_MS));
            let deadline = Instant::now() + budget;
            match token::exact_action(&request.query, deadline, engines) {
                Ok(token) => NativeExactActionPayloadV1::ExactAction {
                    token: Some(token),
                    once_only_reason: None,
                },
                Err(reason) => NativeExactActionPayloadV1::ExactAction {
                    token: None,
                    once_only_reason: Some(reason.to_owned()),
                },
            }
        }
    })
}

#[cfg(test)]
#[path = "native_exact_action_op_tests.rs"]
mod tests;
