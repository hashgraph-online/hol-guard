use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorEnvelope {
    error: String,
    #[serde(default)]
    retryable: Option<bool>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "native-error-code"
}

pub(crate) fn run(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value: serde_json::Value = crate::resident_protocol::strict_json_value(bytes)?;
    if !value.is_object() {
        return Err("native_request_invalid_json".to_owned());
    }
    let envelope: ErrorEnvelope =
        serde_json::from_value(value).map_err(|_| "native_request_invalid_json".to_owned())?;
    let known = guard_contracts::NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES
        .contains(&envelope.error.as_str())
        || guard_contracts::NATIVE_APPROVAL_ERROR_CODES.contains(&envelope.error.as_str())
        || guard_contracts::NATIVE_COMMAND_CONTROL_ERROR_CODES.contains(&envelope.error.as_str());
    if !known {
        return Ok(b"null".to_vec());
    }
    let _ = envelope.retryable;
    serde_json::to_vec(&serde_json::json!({"error": envelope.error}))
        .map_err(|_| "native_response_encode_failed".to_owned())
}

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn accepts_only_contract_error_codes() {
        assert_eq!(
            run(br#"{"error":"native_overloaded","retryable":true}"#).unwrap(),
            br#"{"error":"native_overloaded"}"#
        );
        assert_eq!(
            run(br#"{"error":"unknown","retryable":false}"#).unwrap(),
            b"null"
        );
        assert_eq!(
            run(br#"{"error":"native_overloaded","extra":1}"#).unwrap_err(),
            "native_request_invalid_json"
        );
        assert_eq!(
            run(br#"["native_overloaded",true]"#).unwrap_err(),
            "native_request_invalid_json"
        );
    }
}
