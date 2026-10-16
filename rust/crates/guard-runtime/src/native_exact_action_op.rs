//! `NativeExactAction` — resident op for the exact-action and review-binding
//! identity proofs of a native review.
//!
//! The resident owns every proof: the code a command would run, the files it
//! reads, the repository configuration git would consult and the rules that
//! judged it. A proof that fails is a successful reply carrying the once-only
//! reason, so only a malformed request is an `error`.

mod binding;
pub(crate) mod context;
mod fs_path;
#[cfg(windows)]
mod fs_path_windows;
mod git_config;
mod git_identity;
#[cfg(windows)]
mod git_windows;
mod launch;
#[cfg(windows)]
mod launch_windows;
mod launcher_sets;
// Windows launches refuse interpreters (`launch.rs`), so these POSIX
// module-graph proofs are unreached there.
#[cfg_attr(windows, allow(dead_code))]
mod node_script;
#[cfg_attr(windows, allow(dead_code))]
mod node_source;
mod operands;
#[cfg_attr(windows, allow(dead_code))]
mod python_modules;
#[cfg_attr(windows, allow(dead_code))]
mod python_script;
#[cfg_attr(windows, allow(dead_code))]
mod python_source;
mod reasons;
mod reuse_shape;
pub(crate) mod runner_bin;
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

/// The persistent exact-action token of `query`, or the reason the action
/// stays one-time, for a resident caller that already holds the query.
pub(crate) fn exact_action_token(query: &NativeExactActionQueryV1) -> Result<String, &'static str> {
    let NativeExactActionQueryV1::ExactAction { budget_ms, .. } = query else {
        return Err("native_exact_action_query_invalid");
    };
    let budget = Duration::from_millis((*budget_ms).min(NATIVE_EXACT_ACTION_MAX_BUDGET_MS));
    token::exact_action(query, Instant::now() + budget, &ResidentEngines)
}

/// The review identity the daemon binds an approve-once retry of `query` to
/// (`native_review_binding`), for a resident caller that holds the query.
pub(crate) fn review_binding_for(
    query: &NativeExactActionQueryV1,
    receipt: Option<&serde_json::Value>,
) -> Option<String> {
    let NativeExactActionQueryV1::ExactAction {
        harness,
        command,
        payload_cwd,
        workspace,
        facts,
        policy_binding,
        ..
    } = query
    else {
        return None;
    };
    binding::review_binding(
        harness,
        command.as_deref(),
        payload_cwd
            .as_deref()
            .or(workspace.as_deref())
            .map(std::path::Path::new),
        workspace.is_some(),
        facts,
        receipt,
        policy_binding,
    )
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
            cwd,
            workspace_bound,
            facts,
            receipt,
            policy_binding,
        } => NativeExactActionPayloadV1::ReviewBinding {
            binding: binding::review_binding(
                harness,
                command.as_deref(),
                cwd.as_deref().map(std::path::Path::new),
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

#[cfg(all(test, windows))]
#[path = "native_exact_action_op/windows_tests.rs"]
mod windows_tests;
