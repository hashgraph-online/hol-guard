use serde_json::Value;

pub(crate) fn evaluate(
    operation: &str,
    input: &Value,
    budget: &crate::request_context_op::Budget,
) -> Result<Value, &'static str> {
    budget.check()?;
    let bytes = serde_json::to_vec(input).map_err(|_| "native_restricted_pytest_input_invalid")?;
    if bytes.len() > 2 * 1024 * 1024 || operation.len() > 64 {
        return Err("native_restricted_pytest_input_invalid");
    }
    if matches!(
        operation,
        "linux_readonly_argv"
            | "linux_read_grants"
            | "linux_elf_loader"
            | "linux_socket_filter"
            | "linux_mount_targets"
            | "linux_validate_records"
    ) {
        let result = crate::restricted_linux_launch::evaluate(operation, input, budget.deadline());
        budget.check()?;
        return Ok(result);
    }
    if operation == "process_ceiling" {
        let result = crate::restricted_process_ceiling::evaluate(budget.deadline());
        budget.check()?;
        return Ok(result);
    }
    #[cfg(unix)]
    let result = guard_command::restricted_pytest::evaluate_with_deadline(
        operation,
        input,
        budget.deadline(),
    );
    #[cfg(not(unix))]
    let result = if let Some(result) = guard_command::contained_argv::evaluate(operation, input) {
        result
    } else if operation == "normalized_command" {
        guard_command::restricted_command::evaluate_normalized(input)
    } else if cfg!(windows) && operation == "prepare_inline" {
        #[cfg(windows)]
        let result = crate::windows_readonly::prepare_inline(input);
        #[cfg(not(windows))]
        let result = Value::Null;
        result
    } else {
        serde_json::json!({
            "reason_code": "pytest_restricted_sandbox_unavailable",
            "message": "No enforceable restricted pytest backend is available for this platform; execution was not started."
        })
    };
    budget.check()?;
    Ok(result)
}
