//! The queue-time hint a reviewed `PreToolUse` is stored with.
//!
//! This is `native_review_hint` for the reviews the resident queues itself,
//! and, through the `extension_review_hint` op ([`op`]), for the ones the
//! daemon queues. A review grouped under a connector is stored with the
//! connector-setup hint instead and never reaches here
//! (`hook_direct_review_connector.rs`).
//!
//! Every queued review carries the coverage hint when an extension observed
//! its command. A definite extension review of a command-only shell call also
//! gets the allow hint: the command is reviewed again with the extension
//! evidence under the admitted snapshot, and only when that review is exactly
//! the one that paused (same observations, same effective controls, same
//! action and reason) does the counterfactual run, inside the same command
//! authority lease. The allow hint runs only once the review is certain to be
//! queued here, right before the store write. The hint is advisory: any
//! failure leaves it out and never changes the review.

use std::time::{Duration, Instant};

use guard_command::hook_responses::Object;
use guard_command::native_command_controls::CompiledNativeCommandControls;
use guard_command::CommandModelRequestV1;
use guard_contracts::{
    ExtensionAllowHintQueryV1, ExtensionAllowHintRequestV1, ExtensionAllowHintV1,
    EXTENSION_ALLOW_HINT_QUERY_KIND, EXTENSION_ALLOW_HINT_REQUEST_SCHEMA,
};
use serde_json::{Map, Value};

use super::query::pre_tool_command;
use super::review_request::allow_hint_candidate;
use super::{Context, HintScope};
use crate::hook_direct::EXECUTION_ENVIRONMENT_FIELD;
use crate::oneshot::PreToolRequestV1;

/// Approval persistence and the hook response still need time after the hint.
const SAFETY_MARGIN: Duration = Duration::from_millis(350);
/// Below this the daemon does not start the re-review.
const MIN_BUDGET: Duration = Duration::from_millis(150);
/// The resident answers a bounded reduction after its budget; the daemon
/// leaves it at most this long, and never more than half the time left.
const MAX_SLACK: Duration = Duration::from_secs(2);
const MAX_ASK: Duration = Duration::from_secs(5);

/// The `extension_allow_hint` value a request is built with: the coverage
/// hint alone. The allow hint is added by [`settle`] once nothing but the
/// store write is left, so a review the daemon takes back has not spent the
/// hook's budget on it.
pub(super) fn coverage_hint(result: &Object) -> Value {
    crate::extension_coverage_hint::compute(result).unwrap_or(Value::Null)
}

/// `request` with the allow hint added for a hint candidate, right before it
/// is written.
pub(super) fn settle(context: &Context<'_>, result: &Object, request: Value) -> Value {
    settled(
        context.hint,
        context.recorded_payload,
        context.workspace,
        context.home_dir,
        result,
        request,
    )
}

fn settled(
    scope: Option<&HintScope<'_>>,
    payload: &Map<String, Value>,
    workspace: &str,
    home_dir: &str,
    result: &Object,
    mut request: Value,
) -> Value {
    let Some(scope) = scope.filter(|_| allow_hint_candidate(payload, result) == Some(true)) else {
        return request;
    };
    let Some(allow) = allow_hint(scope, payload, workspace, home_dir, result) else {
        return request;
    };
    if let Some(hint) = crate::extension_coverage_hint::with_coverage(
        Some(allow),
        crate::extension_coverage_hint::compute(result),
    ) {
        request["extension_allow_hint"] = hint;
    }
    request
}

/// The time left before the safety margin, if any.
fn remaining(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())?
        .checked_sub(SAFETY_MARGIN)
        .filter(|left| !left.is_zero())
}

/// `_native_review_extension_allow_hint` for a hint candidate.
fn allow_hint(
    scope: &HintScope<'_>,
    payload: &Map<String, Value>,
    workspace: &str,
    home_dir: &str,
    result: &Object,
) -> Option<Value> {
    if remaining(scope.deadline)? < MIN_BUDGET {
        return None;
    }
    let review = shell_review(payload, workspace, home_dir)?;
    let deadline = scope.deadline;
    crate::command_effect::with_store(Some(scope.policy_store), |controls| {
        // Without admitted extension controls there is no snapshot to bind.
        controls.map_or(Ok(None), |controls| {
            hint_under(controls, &review, result, deadline)
        })
    })
    .ok()
    .flatten()
    .and_then(|hint| serde_json::to_value(hint).ok())
}

/// The extension-evidence review of the payload's shell command, in the
/// launch directory the daemon would use.
fn shell_review(
    payload: &Map<String, Value>,
    workspace: &str,
    home_dir: &str,
) -> Option<PreToolRequestV1> {
    let command = pre_tool_command(payload).ok()??;
    let cwd = super::super::local_cli::launch_cwd(payload, workspace).ok()?;
    let home_dir = Some(home_dir.to_owned()).filter(|home| !home.is_empty());
    // The hint reviews the command in the shell the hook was stamped from,
    // never the resident's own environment.
    Some(PreToolRequestV1 {
        model: CommandModelRequestV1 {
            command,
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        },
        cwd,
        home_dir,
        execution_environment: payload
            .get(EXECUTION_ENVIRONMENT_FIELD)
            .filter(|stamp| stamp.is_object())
            .cloned(),
        extension_evidence: true,
    })
}

/// The allow hint for `review` under the admitted `controls`, once the fresh
/// review proves to be the one that paused.
fn hint_under(
    controls: &CompiledNativeCommandControls,
    review: &PreToolRequestV1,
    result: &Object,
    deadline: Instant,
) -> Result<Option<ExtensionAllowHintV1>, String> {
    let fresh = crate::pre_tool_extension_evidence_op::evidence_response(review, Some(controls))?;
    // The counterfactual is only sound for the evidence the hook paused on.
    if !same_review(result, &fresh) {
        return Ok(None);
    }
    counterfactual(controls, review, fresh, deadline)
}

/// The permissions whose Allow would let `review` run, given its `fresh`
/// extension evidence under `controls`.
fn counterfactual(
    controls: &CompiledNativeCommandControls,
    review: &PreToolRequestV1,
    fresh: Value,
    deadline: Instant,
) -> Result<Option<ExtensionAllowHintV1>, String> {
    // The fresh review used part of the budget; the counterfactual needs the
    // same floor the hint started with.
    let Some(budget) = remaining(deadline)
        .filter(|left| *left >= MIN_BUDGET)
        .map(reduction_budget)
    else {
        return Ok(None);
    };
    let request = ExtensionAllowHintRequestV1 {
        schema: EXTENSION_ALLOW_HINT_REQUEST_SCHEMA.to_owned(),
        request_id: String::new(),
        query: ExtensionAllowHintQueryV1 {
            kind: EXTENSION_ALLOW_HINT_QUERY_KIND.to_owned(),
            command_text: review.model.command.clone(),
            canonical_command: fresh.get("command_model").cloned().unwrap_or(Value::Null),
            control_snapshot: serde_json::to_value(controls.control_binding())
                .map_err(|_| "native_extension_allow_hint_invalid".to_owned())?,
            native_extension_evidence: fresh,
            cwd: review.cwd.clone(),
            home_dir: review.home_dir.clone(),
            reduction_budget_ms: Some(u32::try_from(budget.as_millis()).unwrap_or(u32::MAX)),
        },
    };
    crate::extension_allow_hint_op::decide(&request, Some(controls))
}

/// The daemon's timing for the hint call: it waits at most `MAX_ASK`, and
/// keeps half of that, up to `MAX_SLACK`, for the answer after the reduction
/// pass stops.
fn reduction_budget(left: Duration) -> Duration {
    let ask = left.min(MAX_ASK);
    ask - (ask / 2).min(MAX_SLACK)
}

/// `hint_for_reviewed_command`'s check: the fresh review is the one that
/// paused, bound to the same observations and effective controls.
fn same_review(paused: &Object, fresh: &Value) -> bool {
    fn present(value: Option<&Value>) -> Option<&Value> {
        value.filter(|value| !value.is_null())
    }
    let binding = |evidence: Option<&Value>| {
        evidence
            .and_then(|evidence| evidence.get("binding"))
            .filter(|binding| binding.is_object())
            .cloned()
    };
    let (Some(old), Some(new)) = (
        binding(paused.get("command_extensions")),
        binding(fresh.get("command_extensions")),
    ) else {
        return false;
    };
    ["observations_digest", "control_effective_digest"]
        .iter()
        .all(|key| present(old.get(*key)) == present(new.get(*key)))
        && ["minimum_action", "reason_code"]
            .iter()
            .all(|key| present(paused.get(*key)) == present(fresh.get(*key)))
}

#[path = "hook_direct_review_hint_op.rs"]
pub(crate) mod op;

#[cfg(test)]
#[path = "hook_direct_review_hint_tests.rs"]
mod tests;
