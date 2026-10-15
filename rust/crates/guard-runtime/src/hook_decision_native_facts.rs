//! Verdicts the resident computes itself from the raw tool call.
//!
//! The transport forwards the payload's tool call and observed caller facts in
//! `native_request`; nothing here asks Python. A missing or oversized request
//! is "not benign", so the configured default is never relaxed on bad input.

use std::path::Path;

use guard_command::benign_request_api::{
    is_benign_native_file_read, is_benign_tool_action, ToolActionControls,
};
use guard_command::command_evaluation_controls::{
    authority_failure_for_health, control_layers_from_wire,
};
use guard_command::Ctx;
use guard_contracts::{CodexToolOutputFactsV1, HookCompositionInputsV1};

use crate::codex_tool_output_op::ResidentInspectionHost;

const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_ENVIRONMENT: usize = 128;
const MAX_GROUPS: usize = 256;

fn path_is_bounded(value: &str) -> bool {
    value.len() <= MAX_TEXT_BYTES && !value.contains('\0')
}

fn host_is_bounded(host: &CodexToolOutputFactsV1) -> bool {
    path_is_bounded(&host.process_cwd)
        && path_is_bounded(&host.home)
        && host.account_home.as_deref().is_none_or(path_is_bounded)
        && host.git_executable.as_deref().is_none_or(path_is_bounded)
        && host.groups.len() <= MAX_GROUPS
        && host.environment.len() <= MAX_ENVIRONMENT
        && host
            .environment
            .iter()
            .all(|(key, value)| key.len() <= 256 && path_is_bounded(value))
}

/// `is_explicitly_benign_native_file_read_request` for the hook's tool call.
pub(crate) fn benign_native_file_read(inputs: &HookCompositionInputsV1) -> bool {
    let Some(request) = &inputs.native_request else {
        return false;
    };
    let bounded_path = |value: &Option<String>| value.as_deref().is_none_or(path_is_bounded);
    if !host_is_bounded(&request.host)
        || !bounded_path(&request.cwd)
        || !bounded_path(&request.home_dir)
    {
        return false;
    }
    let host = ResidentInspectionHost {
        facts: &request.host,
    };
    let ctx = Ctx::new(&host, &request.host.process_cwd, &request.host.home);
    is_benign_native_file_read(
        &request.tool_name,
        &request.tool_input,
        request.cwd.as_deref().map(Path::new),
        request.home_dir.as_deref().map(Path::new),
        &ctx,
    )
}

/// `is_explicitly_benign_tool_action_request` for the hook's tool call.
///
/// The extension-control snapshot the transport saw is the one that applies;
/// an unknown health value or any input that cannot be bounded is not benign.
pub(crate) fn benign_tool_action(inputs: &HookCompositionInputsV1) -> bool {
    let Some(request) = &inputs.native_request else {
        return false;
    };
    let bounded_path = |value: &Option<String>| value.as_deref().is_none_or(path_is_bounded);
    if !host_is_bounded(&request.host)
        || !bounded_path(&request.cwd)
        || !bounded_path(&request.home_dir)
        || request.tool_input.to_string().len() > MAX_TEXT_BYTES
    {
        return false;
    }
    let controls = match &request.control_snapshot {
        None => None,
        Some(snapshot) => {
            let Ok(authority_failure) = authority_failure_for_health(&snapshot.health) else {
                return false;
            };
            let Ok(layers) = control_layers_from_wire(&snapshot.layers) else {
                return false;
            };
            Some(ToolActionControls {
                layers,
                authority_failure,
            })
        }
    };
    let host = ResidentInspectionHost {
        facts: &request.host,
    };
    let ctx = Ctx::new(&host, &request.host.process_cwd, &request.host.home);
    is_benign_tool_action(
        &request.tool_name,
        &request.tool_input,
        request.cwd.as_deref().map(Path::new),
        request.home_dir.as_deref().map(Path::new),
        &ctx,
        controls.as_ref(),
    )
}
