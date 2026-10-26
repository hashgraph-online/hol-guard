//! `ContainedWrapperPlan` - resident op telling the execution sink which
//! wrapper the pre-tool classification peeled.
//!
//! Faithful port of `contained_wrapper.peel_contained_wrapper` and the two
//! sibling-root helpers beside it. The Python copy was a second peel: it had
//! its own lexer, its own sibling-repository rule and its own output-filter
//! grammar, and on Windows it treated every directory as the agent's own
//! because it could not read an owner SID. It therefore accepted checkouts
//! the classifier had refused and handed the sandbox a core no receipt
//! covered, which the sink reported as exit 126. One peel now answers both.

use guard_command::pretool::{contained_wrapper_plan, ContainedOutput, ContainedWrapperPlan};
use guard_contracts::{
    ContainedWrapperPlanRequestV1, ContainedWrapperPlanResultV1, CONTAINED_WRAPPER_PLAN_MAX_BYTES,
    CONTAINED_WRAPPER_PLAN_REQUEST_SCHEMA, CONTAINED_WRAPPER_PLAN_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use crate::package_authority_op::request_digest_with_limit;

pub(crate) fn evaluate_contained_wrapper_plan_request(
    request: &ContainedWrapperPlanRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, CONTAINED_WRAPPER_PLAN_MAX_BYTES)
        .map_err(|_| "native_contained_wrapper_plan_too_large".to_owned())?;
    let (status, code, payload) = match refusal(request) {
        Some(code) => ("error", code, None),
        None => ("ok", "ok", Some(evaluate(request))),
    };
    crate::encode_response(&ContainedWrapperPlanResultV1 {
        schema: CONTAINED_WRAPPER_PLAN_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

/// The conditions the op refuses rather than answers.
fn refusal(request: &ContainedWrapperPlanRequestV1) -> Option<&'static str> {
    // A request naming another contract is not this op's to answer: the field
    // is the sender's own statement of which request shape it built.
    if request.schema != CONTAINED_WRAPPER_PLAN_REQUEST_SCHEMA {
        return Some("native_contained_wrapper_plan_schema_mismatch");
    }
    // Without a workspace there is no root to peel against, and the sink
    // cannot be told to run a core somewhere the request never named.
    if request.workspace.is_empty() {
        return Some("native_contained_wrapper_plan_missing_workspace");
    }
    None
}

pub(crate) fn evaluate(request: &ContainedWrapperPlanRequestV1) -> Value {
    let plan = contained_wrapper_plan(
        &request.command,
        &request.workspace,
        request.cwd.as_deref(),
        request.home_dir.as_deref(),
        request.project_root_query.as_deref(),
    );
    encode(&plan)
}

fn encode(plan: &ContainedWrapperPlan) -> Value {
    json!({
        "plan": plan.plan.as_ref().map(|core| json!({
            "core": core.core,
            "directory": core.directory.to_string_lossy(),
            "output": core.output.as_ref().map(encode_output),
        })),
        "refusal": plan.refusal,
        "anchored_sibling_root": plan
            .anchored_sibling_root
            .as_ref()
            .map(|root| root.to_string_lossy()),
        "project_root": plan.project_root.as_ref().map(|root| root.to_string_lossy()),
    })
}

fn encode_output(output: &ContainedOutput) -> Value {
    json!({
        "kind": output.kind,
        "count": output.count,
        "merge_stderr": output.merge_stderr,
        "status_label": output.status_label,
        "stages": output.stages,
    })
}

#[cfg(test)]
#[path = "contained_wrapper_plan_op_tests.rs"]
mod tests;
