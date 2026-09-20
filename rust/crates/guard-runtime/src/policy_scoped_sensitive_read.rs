//! Exact path/tool identities for a bounded sensitive-file request shape.
//!
//! This is a request identity and a risk signal, not a hash of file contents,
//! an approval, a scanner result, or a replacement for configured policy.
//! The lexical path matches the existing Python request producer: it does not
//! resolve symlinks or read the requested file.

use guard_contracts::GuardHookEnvelopeV2;
use guard_secure_fs::sensitive_path_family;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

const UNSUPPORTED: &str = "native_sensitive_read_identity_unsupported";
const TOOL_KEYS: [&str; 2] = ["tool_name", "toolName"];
const ARGUMENT_KEYS: [&str; 4] = ["tool_input", "arguments", "tool_args", "toolArgs"];
const PATH_KEYS: [&str; 4] = ["file_path", "filePath", "path", "filepath"];
const EVENT_KEYS: [&str; 6] = [
    "event",
    "eventName",
    "hook_event_name",
    "hookEventName",
    "hook_name",
    "hookName",
];

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SensitiveReadArtifact {
    pub artifact_id: String,
    pub normalized_path: String,
    pub path_class: &'static str,
    pub risk_class: &'static str,
}

/// Derive only a supported original sensitive-read request, without granting it.
pub(crate) fn derive_sensitive_read_artifact(
    envelope: &GuardHookEnvelopeV2,
    harness: &str,
) -> Result<SensitiveReadArtifact, String> {
    if envelope.harness != harness
        || envelope.event != "PreToolUse"
        || !matches!(harness, "codex" | "claude-code" | "cline" | "cursor")
    {
        return Err(UNSUPPORTED.to_owned());
    }
    let payload = envelope.raw_payload.as_object().ok_or(UNSUPPORTED)?;
    // This shape has one direct tool call. Prompt, MCP, nested calls, additional
    // policy hints and alternate source projections need their own semantics.
    if payload.keys().any(|key| {
        !TOOL_KEYS.contains(&key.as_str())
            && !ARGUMENT_KEYS.contains(&key.as_str())
            && !EVENT_KEYS.contains(&key.as_str())
            && !matches!(
                key.as_str(),
                "source_scope"
                    | "sourceScope"
                    | "cwd"
                    | "artifact_id"
                    | "artifactId"
                    | "artifact_hash"
                    | "artifactHash"
                    | "tool_call_id"
                    | "toolCallId"
                    | "request_id"
                    | "requestId"
                    | "session_id"
                    | "sessionId"
                    | "timestamp"
                    | "event_timestamp"
            )
    }) {
        return Err(UNSUPPORTED.to_owned());
    }
    let event = sole_value(payload, &EVENT_KEYS)?;
    if event.is_some_and(|value| value.as_str() != Some("PreToolUse")) {
        return Err(UNSUPPORTED.to_owned());
    }
    let scope = sole_value(payload, &["source_scope", "sourceScope"])?;
    if scope.is_some_and(|value| value.as_str() != Some("project")) {
        return Err(UNSUPPORTED.to_owned());
    }
    let tool = sole_value(payload, &TOOL_KEYS)?
        .and_then(Value::as_str)
        .ok_or(UNSUPPORTED)?;
    let tool = tool.to_ascii_lowercase();
    if !matches!(
        tool.as_str(),
        "read" | "read_file" | "open_file" | "view" | "view_file" | "cat_file"
    ) || (harness == "cline" && tool == "view")
    {
        return Err(UNSUPPORTED.to_owned());
    }
    let arguments = sole_value(payload, &ARGUMENT_KEYS)?
        .and_then(Value::as_object)
        .ok_or(UNSUPPORTED)?;
    if arguments.len() != 1 {
        return Err(UNSUPPORTED.to_owned());
    }
    let requested = sole_value(arguments, &PATH_KEYS)?
        .and_then(Value::as_str)
        .ok_or(UNSUPPORTED)?;
    let cwd = absolute_lexical(envelope.source.cwd.as_deref().ok_or(UNSUPPORTED)?)?;
    let home = absolute_lexical(&envelope.source.home_dir)?;
    if let Some(value) = payload.get("cwd") {
        if absolute_lexical(value.as_str().ok_or(UNSUPPORTED)?)? != cwd {
            return Err(UNSUPPORTED.to_owned());
        }
    }
    let expanded = if let Some(rest) = requested.strip_prefix("~/") {
        // Python Path(home) / rest resets to a root when rest starts with '/'.
        // Repeated-slash home expansion is outside this bounded contract.
        if rest.starts_with('/') {
            return Err(UNSUPPORTED.to_owned());
        }
        format!("{home}/{rest}")
    } else if requested.starts_with('/') {
        requested.to_owned()
    } else {
        format!("{cwd}/{requested}")
    };
    let normalized_path = absolute_lexical(&expanded)?;
    // A standalone ~ and named-user expansion have no shared bounded contract.
    if requested.is_empty() || requested.contains('~') && !requested.starts_with("~/") {
        return Err(UNSUPPORTED.to_owned());
    }
    let path_class = supported_family(&normalized_path).ok_or(UNSUPPORTED)?;
    // Python's json.dumps(sort_keys=True) uses spaces after these delimiters.
    // Accepted strings are ASCII, so its default ensure_ascii has no other effect.
    let identity = format!(
        "{{\"harness\": {}, \"normalized_path\": {}, \"tool_name\": {}}}",
        serde_json::to_string(harness).map_err(|_| UNSUPPORTED)?,
        serde_json::to_string(&normalized_path).map_err(|_| UNSUPPORTED)?,
        serde_json::to_string(&tool).map_err(|_| UNSUPPORTED)?,
    );
    Ok(SensitiveReadArtifact {
        artifact_id: format!(
            "{harness}:project:file-read:{}",
            hex::encode(Sha256::digest(identity.as_bytes()))
        ),
        normalized_path,
        path_class,
        risk_class: "local_secret_read",
    })
}

fn sole_value<'a>(
    payload: &'a Map<String, Value>,
    keys: &[&str],
) -> Result<Option<&'a Value>, String> {
    let mut values = keys.iter().filter_map(|key| payload.get(*key));
    let first = values.next();
    if values.next().is_some() {
        return Err(UNSUPPORTED.to_owned());
    }
    Ok(first)
}

fn absolute_lexical(value: &str) -> Result<String, String> {
    if !value.starts_with('/')
        || value.starts_with("//")
        || value.len() > 4096
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        return Err(UNSUPPORTED.to_owned());
    }
    let mut parts = Vec::new();
    for part in value.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    Ok(format!("/{}", parts.join("/")))
}

fn supported_family(path: &str) -> Option<&'static str> {
    let lowered = path.to_ascii_lowercase();
    let parts: Vec<_> = lowered.split('/').filter(|part| !part.is_empty()).collect();
    let basename = *parts.last()?;
    let direct = basename == ".env"
        || basename.starts_with(".env.")
        || matches!(
            basename,
            ".npmrc" | ".pypirc" | ".netrc" | ".git-credentials" | "terraform.tfvars"
        );
    let suffix = parts.len() >= 2
        && matches!(
            (parts[parts.len() - 2], basename),
            (".aws", "credentials") | (".ssh", "id_rsa" | "id_ed25519" | "id_ecdsa")
        );
    // The general family helper has broader directory matching than the Python
    // producer. Refuse ambiguous nested families until their full parity exists.
    let sensitive_directories = parts
        .iter()
        .filter(|part| matches!(**part, ".aws" | ".ssh" | ".gnupg" | ".docker" | ".kube"))
        .count();
    if !(direct || suffix && sensitive_directories == 1) {
        return None;
    }
    sensitive_path_family(Path::new(path)).map(|(family, _)| family)
}
