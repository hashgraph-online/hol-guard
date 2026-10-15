//! Recheck bounded OMP eval reads and shell calls, result reports,
//! names-only listings and read-only language server queries after output
//! scanning.
//!
//! An eval proved as literal tool calls keeps the action type of the calls it
//! makes: reads stay file reads, and a cell that runs `tool.bash` is a command,
//! exactly like the same `bash` call made directly. Its output then meets the
//! same scans and installed floors as that call's output, instead of the
//! unknown-action floor every unproved eval falls to.
use guard_contracts::{NativeHookRequestV1, PreToolActionTypeV1};
use serde_json::Value;

pub(super) fn bounded_output_action(request: &NativeHookRequestV1) -> Option<PreToolActionTypeV1> {
    let root = request.payload.as_object()?;
    let tool = root.get("tool_name").and_then(Value::as_str)?;
    // Pi ships the same `find` and `ls` built-ins and gets the same listing proof.
    let proved_tool = match request.harness.as_str() {
        "omp" => matches!(tool, "eval" | "yield" | "find" | "ls" | "lsp"),
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
    let proof = guard_command::pretool::evaluate_pre_tool_envelope_with_context(
        &request.harness,
        "PreToolUse",
        &input,
        None,
        Some(std::time::Instant::now() + std::time::Duration::from_millis(100)),
        Some(&request.home_dir),
        request.cwd.as_deref(),
    );
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
        ("native_omp_yield_metadata", PreToolActionTypeV1::Harness) => {
            Some(PreToolActionTypeV1::Harness)
        }
        _ => None,
    }
}
