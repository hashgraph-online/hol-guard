//! Harness code-evaluation tools whose whole program is a constant: a number
//! expression, a plain string, or a print of one. Such code has no name
//! lookup, import, file, network, environment or process effect, so there is
//! nothing to review. Everything else keeps the ordinary review path.

use super::extract::GenericSignals;
use super::result::{generic_action, generic_result};
use guard_contracts::{PreToolActionTypeV1, PreToolOperationV1, PreToolResultV1};
use serde_json::Value;

pub(super) fn evaluate(
    harness: &str,
    event: &str,
    payload: &Value,
    signals: &GenericSignals,
) -> Option<PreToolResultV1> {
    if event != "PreToolUse"
        || signals.sensitive_target
        || signals.command.is_some()
        || signals.package_present
        || !signals.url_values.is_empty()
        || !signals.path_values.is_empty()
        || signals.prompt_present
    {
        return None;
    }
    let input = super::omp::strict_tool_input(payload)?;
    let code = input.get("code")?.as_str()?;
    let (action_type, operation, proven) = match (harness, signals.tool_name.as_deref()?) {
        ("zcode", "mcp__node_repl__js") => (
            PreToolActionTypeV1::McpTool,
            PreToolOperationV1::Call,
            input.iter().all(|(key, value)| match key.as_str() {
                "code" | "title" => value.is_string(),
                "timeout_ms" => value.is_number(),
                _ => false,
            }) && super::super::pure_expression::javascript_pure_program(code),
        ),
        ("omp", "eval") => (
            PreToolActionTypeV1::Harness,
            PreToolOperationV1::Read,
            matches!(input.get("language")?.as_str()?, "py" | "python")
                && input.iter().all(|(key, value)| match key.as_str() {
                    "code" | "language" | "title" => value.is_string(),
                    "reset" => value.is_boolean(),
                    "timeout" => value.is_number(),
                    _ => false,
                })
                && super::super::pure_expression::python_print_program(code),
        ),
        _ => return None,
    };
    proven.then(|| {
        generic_result(
            generic_action(
                harness,
                event,
                action_type,
                operation,
                true,
                false,
            ),
            "allow",
            "native_pure_constant_eval",
            "The Rust authority proved this evaluation is a constant expression or print with no import, file, network, environment or process effect.",
        )
    })
}
