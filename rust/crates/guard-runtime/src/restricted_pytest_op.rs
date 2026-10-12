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
    #[cfg(unix)]
    let result = guard_command::restricted_pytest::evaluate(operation, input);
    #[cfg(not(unix))]
    let result = if operation == "normalized_command" {
        guard_command::restricted_command::evaluate_normalized(input)
    } else {
        serde_json::json!({
            "reason_code": "pytest_restricted_sandbox_unavailable",
            "message": "No enforceable restricted pytest backend is available for this platform; execution was not started."
        })
    };
    budget.check()?;
    Ok(result)
}
