//! Recheck bounded OMP eval reads and shell calls, result reports,
//! names-only listings and read-only language server queries after output
//! scanning.
//!
//! An eval proved as literal tool calls keeps the action type of the calls it
//! makes: reads stay file reads, and a cell that runs `tool.bash` is a command,
//! exactly like the same `bash` call made directly. Its output then meets the
//! same scans and installed floors as that call's output, instead of the
//! unknown-action floor every unproved eval falls to.
//!
//! A `github` lookup is proved the same way. The native authority already
//! reads one of the tool's read-only operations as a request to GitHub, so
//! after the call its result is a network read's output and takes the
//! installed network floor, not the floor for a tool nothing recognizes.
//!
//! The recheck is judged as the call's `PreToolUse` was: with the installed
//! command controls and the execution environment the hook stamped. A commit
//! draft is settled by the local Git write proof, which reads the agent's
//! own Git setup from that environment and cannot answer without it.
use guard_command::native_command_controls::CompiledNativeCommandControls;
use guard_contracts::{GuardExecutionEnvironmentV1, NativeHookRequestV1, PreToolActionTypeV1};
use serde_json::Value;

#[cfg(test)]
pub(super) fn bounded_output_action(request: &NativeHookRequestV1) -> Option<PreToolActionTypeV1> {
    bounded_output_action_in(request, None, None)
}

pub(super) fn bounded_output_action_in(
    request: &NativeHookRequestV1,
    controls: Option<&CompiledNativeCommandControls>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> Option<PreToolActionTypeV1> {
    let root = request.payload.as_object()?;
    let tool = root.get("tool_name").and_then(Value::as_str)?;
    // Pi ships the same `find` and `ls` built-ins and gets the same listing proof.
    let proved_tool = match request.harness.as_str() {
        "omp" => matches!(tool, "eval" | "yield" | "find" | "ls" | "lsp" | "github"),
        "pi" => matches!(tool, "find" | "ls"),
        _ => false,
    };
    if !proved_tool {
        return None;
    }
    let input = Value::Object(
        root.iter()
            .filter(|(key, _)| {
                !matches!(
                    key.as_str(),
                    "tool_response" | "toolResponse" | "toolResultPreview"
                )
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    );
    // The same budget the call's `PreToolUse` had: the Git write proof runs
    // Git to read the repository's setup and needs more than a listing does.
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_millis(request.deadline_budget_ms.unwrap_or(9_000).min(9_000));
    let proof = match execution_environment {
        Some(environment) => {
            guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
                &request.harness,
                "PreToolUse",
                &input,
                controls,
                Some(deadline),
                guard_command::pretool::PathContext {
                    home_dir: Some(&request.home_dir),
                    guard_home: Some(&request.guard_home),
                    cwd: request.cwd.as_deref(),
                    ..Default::default()
                },
                Some(environment),
            )
        }
        None => guard_command::pretool::evaluate_pre_tool_envelope_with_context(
            &request.harness,
            "PreToolUse",
            &input,
            controls,
            Some(deadline),
            Some(&request.home_dir),
            request.cwd.as_deref(),
        ),
    };
    let proof =
        crate::omp_yield_input_scan::scan(&input, request.deadline_budget_ms, proof).ok()?;
    if proof.minimum_action != "allow" || proof.action.sensitive_target {
        return None;
    }
    match (proof.reason_code.as_str(), proof.action.action_type) {
        ("native_omp_eval_bounded_tools", PreToolActionTypeV1::FileRead)
        | ("native_omp_directory_listing", PreToolActionTypeV1::FileRead)
        | ("native_omp_lsp_read", PreToolActionTypeV1::FileRead) => {
            Some(PreToolActionTypeV1::FileRead)
        }
        ("native_omp_eval_bounded_tools", PreToolActionTypeV1::Command) => {
            Some(PreToolActionTypeV1::Command)
        }
        ("native_github_read", PreToolActionTypeV1::Network) => Some(PreToolActionTypeV1::Network),
        (
            "native_omp_yield_metadata"
            | "native_omp_eval_pure_compute"
            | "native_omp_eval_loopback_browser",
            PreToolActionTypeV1::Harness,
        ) => Some(PreToolActionTypeV1::Harness),
        _ => None,
    }
}
