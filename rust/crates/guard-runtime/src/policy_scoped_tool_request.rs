//! Bounded non-shell identities from the existing hook artifact producer.
//!
//! These identities only select policy rows. They do not relax the native
//! action floor, confer an approval, or trust caller-provided content hashes.

use guard_contracts::GuardHookEnvelopeV2;
use guard_secure_fs::{classify_source_path, sensitive_path_family};
use serde_json::{Map, Value};
use std::path::Path;

const ARGUMENT_KEYS: [&str; 4] = ["tool_input", "arguments", "tool_args", "toolArgs"];
const PATH_KEYS: [&str; 4] = ["file_path", "filePath", "path", "filepath"];

fn original_arguments(payload: &Map<String, Value>) -> Option<&Map<String, Value>> {
    let mut found = ARGUMENT_KEYS.iter().filter_map(|key| payload.get(*key));
    let arguments = found.next()?.as_object()?;
    found.next().is_none().then_some(arguments)
}

fn generic_file_read(tool: &str, arguments: &Map<String, Value>, workspace: &Path) -> bool {
    if !matches!(
        tool.to_ascii_lowercase().as_str(),
        "read" | "read_file" | "open_file" | "view" | "view_file" | "cat_file"
    ) || arguments.len() != 1
    {
        return false;
    }
    let Some(raw) = PATH_KEYS
        .iter()
        .find_map(|key| arguments.get(*key))
        .and_then(Value::as_str)
    else {
        return false;
    };
    if raw.is_empty() || raw.len() > 4096 || raw.trim() != raw || raw.contains('\\') {
        return false;
    }
    let decision = classify_source_path(raw, workspace, None, false);
    let Ok(root) = workspace.canonicalize() else {
        return false;
    };
    decision.allowed
        && decision.resolved_path.is_some_and(|resolved| {
            resolved.starts_with(root)
                && resolved.is_file()
                && sensitive_path_family(&resolved).is_none()
        })
}

fn generic_mcp(tool: &str, arguments: &Map<String, Value>) -> bool {
    let fields: Vec<_> = tool.split("__").collect();
    arguments.is_empty()
        && fields.len() == 3
        && fields[0].eq_ignore_ascii_case("mcp")
        && fields[1..].iter().all(|part| {
            !part.is_empty()
                && part.len() <= 128
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
}

/// Return an identity only for source shapes shared with the Python producer.
pub(super) fn generic_tool_artifact(
    envelope: &GuardHookEnvelopeV2,
    harness: &str,
) -> Option<String> {
    if envelope.harness != harness || envelope.event != "PreToolUse" {
        return None;
    }
    let workspace = Path::new(envelope.source.cwd.as_deref()?);
    if !workspace.is_absolute() || !workspace.is_dir() {
        return None;
    }
    let payload = envelope.raw_payload.as_object()?;
    if ["guard_source_ref", "guard_payload_ref"]
        .iter()
        .any(|key| payload.contains_key(*key))
    {
        return None;
    }
    let tool = match (payload.get("tool_name"), payload.get("toolName")) {
        (Some(value), None) | (None, Some(value)) => value.as_str()?.trim(),
        _ => return None,
    };
    let arguments = original_arguments(payload)?;
    let mcp = generic_mcp(tool, arguments);
    if !mcp && !generic_file_read(tool, arguments, workspace) {
        return None;
    }
    let scope = super::selector_text(payload, "source_scope", "sourceScope")
        .ok()?
        .unwrap_or("project");
    if scope != "project" {
        return None;
    }
    Some(
        super::selector_text(payload, "artifact_id", "artifactId")
            .ok()?
            .map(str::to_owned)
            .unwrap_or_else(|| {
                if harness == "claude-code" && mcp {
                    format!("{harness}:{scope}:mcp:{tool}")
                } else {
                    format!("{harness}:{scope}:{tool}")
                }
            }),
    )
}
