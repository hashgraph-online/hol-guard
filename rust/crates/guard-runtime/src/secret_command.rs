//! Native secret-reference operations behind the hol-guard secrets CLI.
//!
//! Values are accepted only as an internal request field and are consumed by
//! the resident runtime. Responses contain metadata and digests only.

use serde::Deserialize;
use serde_json::{json, Value};
use std::io::Read;

use crate::secret_reference::SecretReference;
use crate::secret_store_platform;

pub(crate) const COMMAND: &str = "secret-store";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    command: String,
    reference: String,
    #[serde(default)]
    value: Option<String>,
}

pub(crate) fn run_command(bytes: &[u8]) -> Value {
    let Ok(request) = serde_json::from_slice::<Request>(bytes) else {
        return refusal("secret_request_invalid");
    };
    let Ok(reference) = SecretReference::parse(&request.reference) else {
        return refusal("secret_reference_invalid");
    };
    if reference.provider != "native" {
        return refusal("secret_provider_managed_by_connection");
    }
    let account = reference.canonical_digest();
    match request.command.as_str() {
        "metadata" => metadata(&reference, &account),
        "set" => {
            let Some(value) = request.value.as_deref() else {
                return refusal("secret_value_required");
            };
            match secret_store_platform::write(&account, value) {
                Ok(()) => metadata_with_state(&reference, &account, "available"),
                Err(error) => refusal(&error),
            }
        }
        "delete" => match secret_store_platform::delete(&account) {
            Ok(()) => json!({
                "ok": true,
                "reference": reference.to_string(),
                "reference_digest": account,
                "deleted": true,
            }),
            Err(error) => refusal(&error),
        },
        "resolve" => refusal("secret_value_delivery_requires_bound_sink"),
        _ => refusal("secret_command_unknown"),
    }
}

#[cfg(unix)]
pub(crate) fn run_prompt(reference_text: &str) -> Value {
    let Ok(reference) = SecretReference::parse(reference_text) else {
        return refusal("secret_reference_invalid");
    };
    crate::runtime_output::stderr_line(format_args!("Secret value: "));
    let mut input = Vec::new();
    #[cfg(unix)]
    let echo_disabled = std::process::Command::new("stty")
        .arg("-echo")
        .status()
        .is_ok_and(|status| status.success());
    let read_result = std::io::stdin()
        .take((secret_store_platform::MAX_SECRET_BYTES + 1) as u64)
        .read_to_end(&mut input);
    #[cfg(unix)]
    if echo_disabled {
        let _ = std::process::Command::new("stty").arg("echo").status();
        crate::runtime_output::stderr_line(format_args!(""));
    }
    if read_result.is_err() {
        return refusal("secret_value_unreadable");
    }
    let Ok(input) = String::from_utf8(input) else {
        return refusal("native_secret_store_invalid");
    };
    let value = input.trim_end_matches(['\r', '\n']);
    if value.is_empty() || value.len() > secret_store_platform::MAX_SECRET_BYTES {
        return refusal("native_secret_store_invalid");
    }
    let account = reference.canonical_digest();
    if let Err(error) = secret_store_platform::write(&account, value) {
        return refusal(&error);
    }
    metadata_with_state(&reference, &account, "available")
}

#[cfg(not(unix))]
pub(crate) fn run_prompt(_reference_text: &str) -> Value {
    refusal("native_secret_store_unavailable")
}

pub(crate) fn run_stdin_value(reference_text: &str) -> Value {
    let Ok(reference) = SecretReference::parse(reference_text) else {
        return refusal("secret_reference_invalid");
    };
    let mut input = Vec::new();
    #[cfg(unix)]
    let echo_disabled = std::process::Command::new("stty")
        .arg("-echo")
        .status()
        .is_ok_and(|status| status.success());
    if std::io::stdin()
        .take((secret_store_platform::MAX_SECRET_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .is_err()
    {
        #[cfg(unix)]
        if echo_disabled {
            let _ = std::process::Command::new("stty").arg("echo").status();
        }
        return refusal("secret_value_unreadable");
    }
    #[cfg(unix)]
    if echo_disabled {
        let _ = std::process::Command::new("stty").arg("echo").status();
        crate::runtime_output::stderr_line(format_args!(""));
    }
    let value =
        String::from_utf8(input).map(|value| value.trim_end_matches(['\r', '\n']).to_owned());
    let Ok(value) = value else {
        return refusal("native_secret_store_invalid");
    };
    if value.is_empty() || value.len() > secret_store_platform::MAX_SECRET_BYTES {
        return refusal("native_secret_store_invalid");
    }
    let account = reference.canonical_digest();
    if let Err(error) = secret_store_platform::write(&account, &value) {
        return refusal(&error);
    }
    metadata_with_state(&reference, &account, "available")
}

fn metadata(reference: &SecretReference, account: &str) -> Value {
    let state = match secret_store_platform::read(account) {
        Ok(Some(_)) => "available",
        Ok(None) => "missing",
        Err(_) => "unavailable",
    };
    metadata_with_state(reference, account, state)
}

fn metadata_with_state(reference: &SecretReference, account: &str, state: &str) -> Value {
    json!({
        "ok": true,
        "reference": reference.to_string(),
        "reference_digest": account,
        "provider": reference.provider,
        "scope": reference.scope,
        "name": reference.name,
        "field": reference.field,
        "version": reference.version,
        "state": state,
        "delivery": ["environment", "stdin", "file_descriptor"],
    })
}

fn refusal(code: &str) -> Value {
    json!({"ok": false, "error": code})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_requests_are_value_free() {
        let result =
            run_command(br#"{"command":"resolve","reference":"guard-secret://native/scope/name"}"#);
        assert_eq!(result["ok"], false);
        assert_eq!(result["error"], "secret_value_delivery_requires_bound_sink");
        assert!(!result.to_string().contains("fixture-value-7"));
    }

    #[test]
    fn metadata_contains_binding_fields_without_a_value() {
        let result = run_command(
            br#"{"command":"metadata","reference":"guard-secret://native/scope/name"}"#,
        );
        assert_eq!(result["ok"], true);
        assert_eq!(result["provider"], "native");
        assert!(result
            .get("reference_digest")
            .and_then(Value::as_str)
            .is_some());
        assert!(result.get("delivery").is_some());
        assert!(result.get("value").is_none());
    }
}
