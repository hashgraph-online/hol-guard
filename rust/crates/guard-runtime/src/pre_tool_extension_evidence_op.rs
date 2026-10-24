//! A pre-tool review that carries the device's command-extension evidence.
//!
//! The plain `pre_tool_use` review models a command without the extension
//! controls, so it carries no `command_extensions`. A caller that resolves the
//! review against those controls — the review inbox's allow hint, `command
//! explain` — needs the evidence the hook edge gives for the same command.
//! This answers under the controls of the snapshot the resident admitted, the
//! ones the hook edge reads, and writes no receipt.

use guard_command::native_command_controls::CompiledNativeCommandControls;
use guard_command::parse_command;
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use guard_contracts::GuardExecutionEnvironmentV1;
use serde_json::{json, Value};

use crate::oneshot::{stamped_environment, PreToolRequestV1};

/// Says this runtime reads `extension_evidence` on a pre-tool request. A
/// caller that does not see it leaves the field out: an older runtime would
/// answer without evidence and every review resolved against the controls
/// would fail.
pub(crate) const PRE_TOOL_EXTENSION_EVIDENCE_FEATURE: &str = "pre-tool-extension-evidence-v1";

pub(crate) fn evaluate_with_store(
    request: &PreToolRequestV1,
    store: Option<&crate::policy_store::PolicySnapshotStore>,
) -> Result<Vec<u8>, String> {
    crate::command_effect::with_store(store, |controls| {
        crate::encode_response(&evidence_response(request, controls)?)
    })
}

/// The legacy `pre_tool_use` answer, decided under `controls`, with the
/// evidence those controls produced.
///
/// Every decision field comes from the same evaluation as the evidence, so a
/// caller never pairs one evaluation's action with another's observations.
pub(crate) fn evidence_response(
    request: &PreToolRequestV1,
    controls: Option<&CompiledNativeCommandControls>,
) -> Result<Value, String> {
    let command_model = parse_command(&request.model)?;
    let unavailable = GuardExecutionEnvironmentV1::unavailable();
    let environment = stamped_environment(request.execution_environment.as_ref());
    crate::edge_git_push::install();
    let result = evaluate_pre_tool_envelope_with_execution_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": request.model.command}}),
        controls,
        None,
        PathContext {
            home_dir: request.home_dir.as_deref(),
            cwd: request.cwd.as_deref(),
            cdpath_unset: false,
            rustup_override_absent: false,
            npm_config_inert: false,
            pip_config_inert: false,
            shell_home_matches: false,
            ripgrep_config_absent: false,
            psql_environment: Default::default(),
            creates_nothing: false,
        },
        Some(environment.as_ref().unwrap_or(&unavailable)),
    );
    let mut response = json!({
        "authority": "rust",
        "request_id": "",
        "decision": result.decision,
        "policy_action": result.policy_action,
        "minimum_action": result.minimum_action,
        "reason_code": result.reason_code,
        "reason": result.reason,
        "explicitly_benign": result.explicitly_benign,
        "command_model": command_model,
    });
    if let Some(evidence) = result.command_extensions {
        response["command_extensions"] = serde_json::to_value(evidence)
            .map_err(|_| "native_pre_tool_extension_evidence_invalid".to_owned())?;
    }
    Ok(response)
}

#[cfg(test)]
#[path = "pre_tool_extension_evidence_op_tests.rs"]
mod tests;
