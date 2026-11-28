//! Metadata-only secret lifecycle hooks and resident output redaction.
//!
//! Hook payloads never carry values. Redaction is applied in the resident
//! delivery boundary before child output can become agent-visible.

use serde::Deserialize;
use serde_json::json;

use crate::secret_store_platform::NativeSecret;

pub(crate) const FEATURE: &str = "secret-hooks-v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) hook: String,
    pub(crate) reference_digest: String,
    pub(crate) binding_digest: String,
    pub(crate) outcome: String,
}

pub(crate) fn evaluate(request: &Request) -> Result<serde_json::Value, String> {
    if !matches!(
        request.hook.as_str(),
        "pre_tool.secret_request"
            | "pre_exec.secret_delivery"
            | "post_tool.output"
            | "lease.expiring"
            | "provider.revoked"
            | "cloud.policy.updated"
    ) {
        return Err("secret_hook_unknown".to_owned());
    }
    if !valid_digest(&request.reference_digest) || !valid_digest(&request.binding_digest) {
        return Err("secret_hook_binding_invalid".to_owned());
    }
    if request.outcome.is_empty() || request.outcome.len() > 64 {
        return Err("secret_hook_outcome_invalid".to_owned());
    }
    Ok(json!({
        "ok": true,
        "hook": request.hook,
        "reference_digest": request.reference_digest,
        "binding_digest": request.binding_digest,
        "outcome": request.outcome,
    }))
}

pub(crate) fn redact_output(mut output: String, secrets: &[&NativeSecret]) -> String {
    for secret in secrets {
        if !secret.expose().is_empty() {
            output = output.replace(secret.expose(), "[REDACTED]");
        }
    }
    output
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_hook_has_no_value_field() {
        let result = evaluate(&Request {
            hook: "pre_exec.secret_delivery".to_owned(),
            reference_digest: "a".repeat(64),
            binding_digest: "b".repeat(64),
            outcome: "approved".to_owned(),
        })
        .unwrap();
        assert!(result.get("value").is_none());
        assert!(!result.to_string().contains("fixture-value-7"));
    }

    #[test]
    fn output_reflection_is_redacted() {
        let secret = NativeSecret::new("fixture-value-7".to_owned());
        assert_eq!(
            redact_output("echo fixture-value-7".to_owned(), &[&secret]),
            "echo [REDACTED]"
        );
    }
}
