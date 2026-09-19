//! Derive scoped identities from supported original hook input.
//!
//! This producer covers bounded shell, local read and MCP paths whose Python
//! producer uses a generic tool artifact. Runtime package/file/compound
//! producers and content-context identities require their own parity proof.
//! Unsupported requests fail closed; a supplied digest is never evidence.

use guard_command::exact_command::{exact_command_sha256, exact_shell_command_from_hook};
use guard_command::pretool::evaluate_pre_tool;
use guard_command::CommandModelRequestV1;
use guard_contracts::GuardHookEnvelopeV2;
use guard_policy_snapshot::scoped_authority::{
    ExactPolicyContextInputs, PolicyIdentityInputs, ScopedPolicyRequest,
};
use serde_json::{Map, Value};
use std::path::Path;

#[path = "policy_scoped_tool_request.rs"]
mod tool_request;

const UNSUPPORTED: &str = "native_scoped_request_identity_unsupported";

fn display_text(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

// The Python ingress maps each camel-case selector before constructing the
// artifact. Preserve that single value; conflicting aliases never pick a
// convenient default identity.
fn selector_text<'a>(
    payload: &'a Map<String, Value>,
    primary: &str,
    alias: &str,
) -> Result<Option<&'a str>, String> {
    match (payload.get(primary), payload.get(alias)) {
        (None, None) => Ok(None),
        (Some(value), None) | (None, Some(value)) => value
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(Some)
            .ok_or_else(|| UNSUPPORTED.to_owned()),
        _ => Err(UNSUPPORTED.to_owned()),
    }
}

pub(crate) fn generic_shell_artifact(
    envelope: &GuardHookEnvelopeV2,
    harness: &str,
) -> Result<String, String> {
    if envelope.harness != harness || envelope.event != "PreToolUse" {
        return Err(UNSUPPORTED.to_owned());
    }
    let cwd = envelope.source.cwd.as_deref().ok_or(UNSUPPORTED)?;
    // The generic producer requires a complete local execution context. A
    // missing working directory produces an unmodeled runtime artifact.
    if !Path::new(cwd).is_absolute() || !Path::new(cwd).is_dir() {
        return Err(UNSUPPORTED.to_owned());
    }
    let payload = envelope.raw_payload.as_object().ok_or(UNSUPPORTED)?;
    if payload.contains_key("guard_source_ref") || payload.contains_key("guard_payload_ref") {
        return Err(UNSUPPORTED.to_owned());
    }
    let command = exact_shell_command_from_hook(&envelope.raw_payload).ok_or(UNSUPPORTED)?;
    let tool = payload
        .get("tool_name")
        .or_else(|| payload.get("toolName"))
        .and_then(Value::as_str)
        .ok_or(UNSUPPORTED)?;
    // Claude treats unknown tools as MCP identities. This spelling has no
    // generic shell artifact on that producer and must not be invented.
    if harness == "claude-code" && tool.eq_ignore_ascii_case("exec_command") {
        return Err(UNSUPPORTED.to_owned());
    }
    let arguments = ["tool_input", "arguments", "tool_args", "toolArgs"]
        .iter()
        .find_map(|name| payload.get(*name))
        .and_then(Value::as_object)
        .ok_or(UNSUPPORTED)?;
    if arguments.len() != 1 {
        return Err(UNSUPPORTED.to_owned());
    }
    let native = evaluate_pre_tool(&CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })?;
    let model = native.command_model;
    if model.segments.len() != 1
        || !model.wrapper_chain.is_empty()
        || model.path_overridden
        || !model.segments[0].environment_names.is_empty()
    {
        return Err(UNSUPPORTED.to_owned());
    }
    let benign = native.reason_code == "native_exact_safe_command"
        && native.explicitly_benign
        && matches!(
            model.segments[0].executable.as_deref(),
            Some("pwd" | "true" | "echo" | "printf" | "whoami" | "uname")
        );
    // A destination-only SSH action stays on the actual generic producer.
    // Flags, a remote command, wrappers and shell syntax require a different
    // typed runtime identity and cannot be projected into this path.
    let destination_only = native.reason_code == "native_command_review_required"
        && model.segments[0].executable.as_deref() == Some("ssh")
        && model.segments[0].arguments.len() == 1
        && model.segments[0].arguments[0].len() <= 255
        && model.segments[0].arguments[0].starts_with(|value: char| value.is_ascii_alphanumeric())
        && model.segments[0].arguments[0].bytes().all(|value| {
            value.is_ascii_alphanumeric() || matches!(value, b'@' | b'.' | b'_' | b'-')
        });
    if !benign && !destination_only {
        return Err(UNSUPPORTED.to_owned());
    }
    let scope = selector_text(payload, "source_scope", "sourceScope")?.unwrap_or("project");
    if scope != "project" {
        return Err(UNSUPPORTED.to_owned());
    }
    Ok(selector_text(payload, "artifact_id", "artifactId")?
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{harness}:{scope}:{tool}")))
}

/// Caller validates the envelope and preserves intrinsic/managed floors.
/// This does not authorize an action or establish resident application.
pub(crate) fn derive_scoped_policy_request(
    envelope: &GuardHookEnvelopeV2,
    canonical_harness: &str,
) -> Result<ScopedPolicyRequest, String> {
    if crate::edge::authoritative_event(envelope)? != "PreToolUse" {
        return Err(UNSUPPORTED.to_owned());
    }
    let (artifact, digest) = if exact_shell_command_from_hook(&envelope.raw_payload).is_some() {
        let artifact = generic_shell_artifact(envelope, canonical_harness)?;
        let command = exact_shell_command_from_hook(&envelope.raw_payload).ok_or(UNSUPPORTED)?;
        (
            artifact,
            Some(exact_command_sha256(command).ok_or(UNSUPPORTED)?),
        )
    } else {
        (
            tool_request::generic_tool_artifact(envelope, canonical_harness)
                .or_else(|| {
                    crate::policy_scoped_sensitive_read::derive_sensitive_read_artifact(
                        envelope,
                        canonical_harness,
                    )
                    .ok()
                    .map(|artifact| artifact.artifact_id)
                })
                .ok_or(UNSUPPORTED)?,
            None,
        )
    };
    ScopedPolicyRequest::from_native_identity(PolicyIdentityInputs {
        harness: canonical_harness,
        artifact_id: Some(&artifact),
        artifact_hash: None,
        workspace: envelope.source.cwd.as_deref(),
        publisher: display_text(envelope.raw_payload.get("publisher")),
        exact_command_sha256: digest.as_deref(),
        exact: ExactPolicyContextInputs::default(),
    })
    .map_err(|_| "native_scoped_request_identity_invalid".to_owned())
}

#[cfg(test)]
#[path = "policy_scoped_request_tests.rs"]
mod tests;
