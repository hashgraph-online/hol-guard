#![forbid(unsafe_code)]

//! Apply the authenticated effective policy to native hook results.
//!
//! The hook classifiers establish an intrinsic minimum action from the raw
//! request.  This module only joins that result with the already-installed
//! policy snapshot.  It never replaces a stronger native result with a
//! weaker policy value and it never reads configuration or request content
//! outside the native edge.
//!
//! `warn` is an allow-with-warning action, not a deny. In `observe` mode no
//! post-tool outcome stops the harness: the response is rewritten to an
//! allow-original warn that records the canonical output digest and the
//! observed intrinsic action.

use guard_contracts::{
    GuardHookPayloadKindV2, HookReviewResponseV1, NativeHookRequestV1, NativePromptRiskClassV1,
    PreToolActionTypeV1, PreToolResultV1,
};
use guard_policy_snapshot::PolicySnapshotV3;
use serde_json::Value;

#[path = "policy_enforcement_facts.rs"]
mod policy_enforcement_facts;
#[path = "policy_enforcement_helpers.rs"]
mod policy_enforcement_helpers;
#[path = "policy_enforcement_matrix.rs"]
mod policy_enforcement_matrix;
#[path = "policy_enforcement_mcp_provider.rs"]
mod policy_enforcement_mcp_provider;
#[path = "policy_enforcement_policy.rs"]
mod policy_enforcement_policy;
#[path = "policy_enforcement_reason.rs"]
mod policy_enforcement_reason;
pub(crate) use policy_enforcement_matrix::{validate_pre_tool_result_matrix, ActionFloor};
pub(crate) use prompt::deferred_prompt_review;

/// Recheck business rules above the authenticated native receipt's intrinsic
/// floor. This validates review eligibility; it grants no execution authority.
pub(crate) fn ensure_business_review_permitted(
    snapshot: &PolicySnapshotV3,
    facts: &guard_contracts::BusinessActionV1,
    intrinsic: &str,
) -> Result<(), String> {
    let binding = snapshot
        .business_policy
        .as_ref()
        .ok_or_else(|| "native_workspace_review_business_invalid".to_owned())?;
    if binding.budgets.is_some() {
        return Err("native_business_budget_executor_unavailable".to_owned());
    }
    let intrinsic = ActionFloor::parse(intrinsic)
        .ok_or_else(|| "native_workspace_review_business_invalid".to_owned())?;
    let policy = policy_enforcement_business::CompiledBusinessPolicy::new(binding)?;
    if binding.budgets.is_some() {
        return Err("native_business_budget_executor_unavailable".into());
    }
    let floor = policy.floor(intrinsic, Some(facts));
    if floor.action >= ActionFloor::SandboxRequired {
        return Err("native_workspace_review_business_blocked".to_owned());
    }
    Ok(())
}

use policy_enforcement_facts::{
    classify_tool_name, collect_fact_maps, payload_facts, preferred_tool_name, PATH_KEYS,
};
use policy_enforcement_helpers::{
    action_rank, join_action, normalized_harness, policy_floor_with_cause_and_delivery, FloorCause,
    FloorInput,
};
use policy_enforcement_policy::CompiledEffectivePolicy;
use policy_enforcement_reason::{
    policy_override_reason, PromptStop, NO_SCRIPT_INSTALL_ALTERNATIVE,
};

#[path = "policy_enforcement_admission.rs"]
mod policy_enforcement_admission;
pub(crate) use policy_enforcement_admission::AdmittedPolicySnapshot;
pub(crate) use policy_enforcement_helpers::risk_action;

#[path = "policy_enforcement_business.rs"]
mod policy_enforcement_business;

#[cfg(test)]
#[path = "policy_enforcement_tests.rs"]
pub(crate) mod tests;
const MAX_SELECTOR_VALUE_BYTES: usize = 4 * 1024;
const MAX_FACT_DEPTH: usize = 32;
const MAX_FACT_NODES: usize = 2_048;

/// Apply the authenticated policy to a generic native PreTool result.
/// A package-manager install proven to run no lifecycle scripts has nothing
/// for the `package_script` risk setting to govern. The proof is the native
/// command authority's; every other floor and intrinsic review still applies.
fn package_scripts_disabled(payload: &Value, result: &PreToolResultV1) -> bool {
    result.action.action_type == PreToolActionTypeV1::Package
        && (result.reason_code == LOCKFILE_INSTALL_REASON
            || (result.reason_code == "native_package_review"
                && guard_command::pretool::generic::extract_untrusted_command_context(payload)
                    .ok()
                    .and_then(|context| context.command)
                    .is_some_and(|command| {
                        guard_command::pretool::no_script_install_command(&command)
                    })))
}

/// The native allow for a frozen install whose lockfile pins every package
/// and integrity hash and whose lifecycle scripts are off.
const LOCKFILE_INSTALL_REASON: &str = "native_exact_safe_lockfile_install";

/// Whether `payload` runs Guard's own approval inspection on the Guard home
/// the hook reports, the wait Guard tells the agent to run after a review
/// (`guard_command::pretool::guard_approval_inspection_command`).
fn guard_approval_inspection(payload: &Value, guard_home: &str, cwd: Option<&str>) -> bool {
    guard_command::pretool::generic::extract_untrusted_command_context(payload)
        .ok()
        .and_then(|context| context.command)
        .is_some_and(|command| {
            guard_command::pretool::guard_approval_inspection_command(&command, guard_home, cwd)
        })
}

/// `PreToolUse` policy for one hook envelope. Guard's own approval wait is
/// proven against the Guard home and working directory this hook reports.
pub(crate) fn apply_pre_tool_policy_for_hook(
    snapshot: &AdmittedPolicySnapshot,
    envelope: &guard_contracts::GuardHookEnvelopeV2,
    result: PreToolResultV1,
) -> Result<PreToolResultV1, String> {
    let inspection = guard_approval_inspection(
        &envelope.raw_payload,
        &envelope.source.guard_home,
        envelope.source.cwd.as_deref(),
    );
    // Guard's own safety guide passes the execution floors only where the
    // native verdict already allows the read; it never turns a review into
    // an allow.
    let guide = result.minimum_action == "allow"
        && guard_safety_guide_read(&envelope.raw_payload, &envelope.source.home_dir);
    apply_pre_tool_policy_with_inspection(
        snapshot,
        &envelope.raw_payload,
        result,
        inspection || guide,
        envelope.source.cwd.as_deref(),
    )
}

/// Whether `payload` is one plain read of Guard's own safety guide below the
/// hook's user home, the read Guard's managed agent instructions ask for
/// (`guard_command::pretool::guard_safety_guide_read_command`).
fn guard_safety_guide_read(payload: &Value, home_dir: &str) -> bool {
    guard_command::pretool::generic::extract_untrusted_command_context(payload)
        .ok()
        .and_then(|context| context.command)
        .is_some_and(|command| {
            guard_command::pretool::guard_safety_guide_read_command(&command, home_dir)
        })
}

/// The native review of a `--home` Guard's launcher cannot place, lifted when
/// that home is the one this hook reports and nothing else held the command.
const OWN_INSPECTION_REVIEW_REASON: &str = "native_command_review_required";
const OWN_INSPECTION_ALLOW_REASON: &str = "native_exact_safe_command";

#[cfg(any(test, target_os = "macos"))]
pub(crate) fn apply_pre_tool_policy(
    snapshot: &AdmittedPolicySnapshot,
    payload: &Value,
    result: PreToolResultV1,
) -> Result<PreToolResultV1, String> {
    apply_pre_tool_policy_with_inspection(snapshot, payload, result, false, None)
}

/// `apply_pre_tool_policy`, told whether the call is Guard's own approval
/// inspection on this hook's Guard home ([`guard_approval_inspection`]). That
/// wait is part of answering a review, so the execution floors an approval
/// would lift (`subprocess_action`, the default and harness actions) do not
/// send it to a second review. Every other floor still applies.
pub(crate) fn apply_pre_tool_policy_with_inspection(
    snapshot: &AdmittedPolicySnapshot,
    payload: &Value,
    mut result: PreToolResultV1,
    guard_inspection: bool,
    cwd: Option<&str>,
) -> Result<PreToolResultV1, String> {
    if !matches!(snapshot.mode.as_str(), "enforce" | "observe") {
        return Err("native_policy_mode_invalid".to_owned());
    }
    validate_pre_tool_result_matrix(&result)?;
    let guard_inspection = guard_inspection
        && result.action.action_type == PreToolActionTypeV1::Command
        && !result.action.sensitive_target
        && result.command_extensions.as_ref().is_none_or(|evidence| {
            evidence.binding.observation_count == 0 && evidence.evaluation_error.is_none()
        });
    if guard_inspection
        && result.reason_code == OWN_INSPECTION_REVIEW_REASON
        && result.minimum_action == "review"
    {
        result.minimum_action = "allow".into();
        result.policy_action = "allow".into();
        result.decision = "allow".into();
        result.explicitly_benign = true;
        result.reason_code = OWN_INSPECTION_ALLOW_REASON.into();
        result.reason = "Guard's own approval inspection on this hook's Guard home.".into();
    }
    let guard_inspection = guard_inspection && result.minimum_action == "allow";
    policy_enforcement_business::guard_untrusted_business_context(snapshot, payload, &mut result)?;
    let harness = normalized_harness(&result.action.harness);
    let mut facts = payload_facts(
        payload,
        &harness,
        result.action.action_type,
        // The classified operation is what says this call only reads the file
        // it names; an action type alone cannot, because the types that cover
        // tool calls and MCP calls cover their writes too.
        result.action.operation == guard_contracts::PreToolOperationV1::Read,
        &result.reason_code,
        cwd,
    )?;
    facts.sensitive_target |= result.action.sensitive_target;
    let benign_prompt = result.action.event == "UserPromptSubmit"
        && result.action.action_type == PreToolActionTypeV1::Prompt
        && result.explicitly_benign
        && result.reason_code == "native_prompt_benign"
        && !facts.sensitive_target;
    let mut operator_allowed_mcp_tool = false;
    if result.action.action_type == PreToolActionTypeV1::McpTool {
        let tool = policy_enforcement_mcp_provider::mcp_tool_name(payload, &harness)?;
        if let Some(tool) = tool {
            let composio_name = tool
                .rsplit("__")
                .next()
                .unwrap_or(&tool)
                .to_ascii_lowercase();
            let composio_execution = composio_name.starts_with("composio_")
                && !matches!(
                    composio_name.as_str(),
                    "composio_search_tools" | "composio_get_tool_schemas"
                );
            if composio_execution && action_rank(&result.minimum_action) < action_rank("review") {
                result.minimum_action = "review".into();
                result.policy_action = "review".into();
                result.decision = "deny".into();
                result.explicitly_benign = false;
                result.reason_code = "native_composio_action_review".into();
                result.reason =
                    "Review the underlying Composio actions and account before execution.".into();
            }
            if let Some(reason) = policy_enforcement_mcp_provider::denied_provider_execution(
                &snapshot.effective_policy.mcp_provider_actions,
                &harness,
                &tool,
                payload,
            ) {
                result.minimum_action = "block".into();
                result.policy_action = "block".into();
                result.decision = "deny".into();
                result.explicitly_benign = false;
                result.reason_code = reason.into();
                result.reason = if reason == "native_composio_denied_batch_member" {
                    "This batch includes an action denied for this connection. No batch member may execute."
                } else {
                    "Guard cannot enforce this connection's action denies inside opaque execution. Use an explicit batch."
                }.into();
            }
            let choice = guard_policy_snapshot::observed_mcp_tool_action(
                &snapshot.effective_policy.mcp_tool_actions,
                &harness,
                &tool,
            );
            if choice == Some("block") && result.minimum_action != "block" {
                result.minimum_action = "block".into();
                result.policy_action = "block".into();
                result.decision = "deny".into();
                result.explicitly_benign = false;
                result.reason_code = "native_custom_mcp_tool_block".into();
                result.reason =
                    "This MCP tool is blocked by a custom extension on this device.".into();
            } else if choice == Some("review")
                && action_rank(&result.minimum_action) < action_rank("review")
            {
                result.minimum_action = "review".into();
                result.policy_action = "review".into();
                result.decision = "deny".into();
                result.explicitly_benign = false;
                result.reason_code = "native_custom_mcp_tool_review".into();
                result.reason =
                    "This MCP tool requires approval under its custom extension settings.".into();
            }
            operator_allowed_mcp_tool = !composio_execution
                && policy_enforcement_mcp_provider::operator_allows_tool(
                    &snapshot.effective_policy.mcp_tool_actions,
                    &harness,
                    &tool,
                )
                && result.action.bounded
                && !facts.sensitive_target
                && !facts.changed_hash
                && result.command_extensions.as_ref().is_none_or(|evidence| {
                    evidence.binding.observation_count == 0 && evidence.evaluation_error.is_none()
                });
            if operator_allowed_mcp_tool
                && result.minimum_action == "review"
                && result.reason_code == "native_mcp_tool_review"
            {
                // Only explicit operator authority in the admitted, authenticated
                // snapshot can replace the unknown-tool review. Independent
                // native findings and every installed policy floor still apply.
                result.minimum_action = "allow".into();
                result.policy_action = "allow".into();
                result.decision = "allow".into();
                result.explicitly_benign = true;
                result.reason_code = "native_custom_mcp_tool_allow".into();
                result.reason =
                    "This exact MCP tool is allowed by a custom extension on this device.".into();
                // The explicit operator choice satisfies the generic unknown
                // publisher review for this namespace. Stronger publisher
                // actions and independent MCP risk policies remain floors.
                if facts.publisher.is_none()
                    && snapshot.effective_policy.unknown_publisher_action == "review"
                {
                    facts.publisher_relevant = false;
                }
            }
        }
    }
    // A proven frozen install fetches only the packages and integrity hashes
    // the project already committed, and runs none of their code, so it
    // chooses no new publisher. That proof satisfies the default unknown
    // publisher review; a stronger publisher action and every other floor
    // still apply.
    if result.reason_code == LOCKFILE_INSTALL_REASON
        && result.action.action_type == PreToolActionTypeV1::Package
        && facts.publisher.is_none()
        && facts.artifact.is_none()
        && snapshot.effective_policy.unknown_publisher_action == "review"
    {
        facts.publisher_relevant = false;
    }
    let (policy_floor, floor_cause) = policy_floor_with_cause_and_delivery(
        &snapshot.effective_policy,
        &snapshot.compiled,
        &harness,
        result.action.action_type,
        &FloorInput {
            facts: &facts,
            reason_code: &result.reason_code,
            prompt_classes: &result.prompt_risk_classes,
            benign_prompt,
            package_scripts_disabled: package_scripts_disabled(payload, &result),
            operator_allowed_mcp_tool,
        },
        false,
        guard_inspection && !facts.sensitive_target,
    )?;
    let effective = join_action(&result.minimum_action, &policy_floor)?;
    let policy_raised = action_rank(&effective) > action_rank(&result.minimum_action);
    let mut output = result;

    if snapshot.mode == "observe" {
        // Observe suppresses only an escalation introduced by the installed
        // policy. Every intrinsic review, reapproval, sandbox, block, and
        // malformed/unknown result remains authoritative. A native block
        // paired with an inconsistent allow decision is repaired fail-closed.
        let intrinsic_rank = action_rank(&output.minimum_action)
            .ok_or_else(|| "native_policy_action_invalid".to_owned())?;
        let policy_only_warning = policy_raised
            && intrinsic_rank <= action_rank("warn").unwrap_or(1)
            && output.decision == "allow";
        if policy_only_warning {
            // Only a warn floor over a proven allow is the silent policy
            // warning. A stronger floor, or one over an intrinsic warning,
            // keeps a rendered code so the harness still sees it.
            output.reason_code = if output.minimum_action == "allow" && effective == "warn" {
                "native_policy_warning"
            } else {
                "native_policy_observed_floor"
            }
            .to_owned();
            output.reason =
                "HOL Guard observed a stricter installed native policy floor.".to_owned();
            output.policy_action = "warn".to_owned();
            output.minimum_action = "warn".to_owned();
            output.decision = "allow".to_owned();
            output.explicitly_benign = false;
        } else {
            output.policy_action = effective.clone();
            output.minimum_action = effective.clone();
            output.decision =
                if action_rank(&effective).unwrap_or(5) <= action_rank("warn").unwrap_or(1) {
                    "allow".to_owned()
                } else {
                    "deny".to_owned()
                };
            output.explicitly_benign = effective == "allow";
        }
        prompt::defer_prompt_review(&mut output);
        validate_pre_tool_result_matrix(&output)?;
        return Ok(output);
    }

    if policy_raised {
        let (reason_code, reason) = policy_override_reason(
            &effective,
            Some(floor_cause),
            if output.action.action_type == guard_contracts::PreToolActionTypeV1::Prompt {
                PromptStop::Prompt {
                    injection_detected: output
                        .prompt_risk_classes
                        .contains(&NativePromptRiskClassV1::PromptInjectionIntent),
                }
            } else {
                PromptStop::NotPrompt
            },
        );
        output.reason_code = reason_code.to_owned();
        output.reason = reason;
        if floor_cause == FloorCause::Risk("package_script")
            && output.action.action_type == guard_contracts::PreToolActionTypeV1::Package
            && output.action.operation == guard_contracts::PreToolOperationV1::Install
            && guard_command::pretool::held_command_installs(payload)
        {
            output.reason.push(' ');
            output.reason.push_str(NO_SCRIPT_INSTALL_ALTERNATIVE);
        }
    }
    output.policy_action = effective.clone();
    output.minimum_action = effective.clone();
    output.decision = if matches!(effective.as_str(), "allow" | "warn") {
        "allow".to_owned()
    } else {
        "deny".to_owned()
    };
    output.explicitly_benign = effective == "allow";
    prompt::defer_prompt_review(&mut output);
    validate_pre_tool_result_matrix(&output)?;
    Ok(output)
}

#[path = "policy_enforcement_omp_eval.rs"]
mod eval_output;
#[path = "policy_enforcement_post.rs"]
mod post;
#[path = "policy_enforcement_prompt.rs"]
mod prompt;
#[cfg(test)]
pub(crate) use post::apply_post_tool_policy;
pub(crate) use post::apply_post_tool_policy_for_hook;
#[cfg(test)]
pub(crate) use post::apply_post_tool_policy_with_delivery;
#[cfg(test)]
pub(crate) use post::apply_post_tool_policy_with_witness;
