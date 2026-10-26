use serde_json::{json, Value};

const MAX_ARG_COUNT: usize = 4096;
const MAX_ARG_BYTES: usize = 1_048_576;
const PYTEST_INVALID_COMMAND_REASON_CODE: &str = "pytest_restricted_invalid_command";

#[derive(Debug, Clone)]
pub struct RestrictedPytestError {
    pub reason_code: String,
    pub message: String,
}

impl RestrictedPytestError {
    pub(crate) fn new(reason_code: &str, message: impl Into<String>) -> Self {
        Self {
            reason_code: reason_code.to_owned(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for RestrictedPytestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for RestrictedPytestError {}

pub fn normalized_command(command: &[String]) -> Result<Vec<String>, RestrictedPytestError> {
    let mut normalized: Vec<String> = command.to_vec();
    if normalized.first().map(|s| s.as_str()) == Some("--") {
        normalized.remove(0);
    }
    let total_bytes: usize = normalized.iter().map(|item| item.len()).sum();
    if normalized.is_empty() || normalized.len() > MAX_ARG_COUNT || total_bytes > MAX_ARG_BYTES {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest requires a bounded, non-empty argv after `--`.",
        ));
    }
    if normalized.iter().any(|item| item.contains('\0')) {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest argv cannot contain NUL bytes.",
        ));
    }
    Ok(normalized)
}

pub fn evaluate_normalized(input: &Value) -> Value {
    let command = input.get("command").cloned().unwrap_or_else(|| json!([]));
    let result = serde_json::from_value::<Vec<String>>(command)
        .map_err(|_| {
            RestrictedPytestError::new(
                PYTEST_INVALID_COMMAND_REASON_CODE,
                "Invalid restricted execution request.",
            )
        })
        .and_then(|command| normalized_command(&command));
    match result {
        Ok(value) => json!({"value": value}),
        Err(error) => error_reply(error),
    }
}

pub fn error_reply(error: RestrictedPytestError) -> Value {
    let message = if error.message.len() > 4096 {
        "Restricted execution request was refused; error details exceed the response limit."
            .to_owned()
    } else {
        error.message
    };
    json!({"reason_code": error.reason_code, "message": message})
}

#[cfg(test)]
#[path = "restricted_command_tests.rs"]
mod tests;
