//! Bounded typed artifact identities, derived from original request fields.
//!
//! These identities do not supply approval context or relax any policy floor.
//! Directory changes, wrappers, execution evidence and non-registry package
//! sources need their own complete producer contract and are refused here.

use guard_command::exact_command::{exact_command_sha256, exact_shell_command_from_hook};
use guard_command::{parse_command, CommandModelRequestV1};
use guard_contracts::GuardHookEnvelopeV2;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const UNSUPPORTED: &str = "native_typed_artifact_identity_unsupported";

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TypedShellArtifact {
    pub artifact_id: String,
    pub artifact_type: &'static str,
    pub exact_command_sha256: String,
}

/// Produce an identity only for the independently verified typed request shape.
pub(crate) fn derive_typed_shell_artifact(
    envelope: &GuardHookEnvelopeV2,
    harness: &str,
) -> Result<TypedShellArtifact, String> {
    if envelope.harness != harness
        || envelope.event != "PreToolUse"
        || !matches!(harness, "codex" | "claude-code" | "cline" | "cursor")
    {
        return Err(UNSUPPORTED.to_owned());
    }
    let payload = envelope.raw_payload.as_object().ok_or(UNSUPPORTED)?;
    if payload.contains_key("guard_source_ref") || payload.contains_key("guard_payload_ref") {
        return Err(UNSUPPORTED.to_owned());
    }
    if (payload.contains_key("source_scope") && payload.contains_key("sourceScope"))
        || ["source_scope", "sourceScope"].iter().any(|key| {
            payload.get(*key).is_some_and(|value| {
                value
                    .as_str()
                    .is_none_or(|scope| !scope.trim().is_empty() && scope.trim() != "project")
            })
        })
        || [
            "event",
            "eventName",
            "hook_event_name",
            "hookEventName",
            "hook_name",
            "hookName",
        ]
        .iter()
        .any(|key| {
            payload.get(*key).is_some_and(|value| {
                value
                    .as_str()
                    .is_none_or(|event| !event.trim().eq_ignore_ascii_case("PreToolUse"))
            })
        })
    {
        return Err(UNSUPPORTED.to_owned());
    }
    let command = exact_shell_command_from_hook(&envelope.raw_payload).ok_or(UNSUPPORTED)?;
    let tool = payload
        .get("tool_name")
        .or_else(|| payload.get("toolName"))
        .and_then(Value::as_str)
        .ok_or(UNSUPPORTED)?;
    if !tool.eq_ignore_ascii_case("bash") && !tool.eq_ignore_ascii_case("shell") {
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
    let cwd = existing_workspace(envelope.source.cwd.as_deref().ok_or(UNSUPPORTED)?)?;
    let normalized = command.trim_matches(|character: char| character.is_ascii_whitespace());
    // Every accepted token has its literal POSIX spelling. No shell expansion,
    // quoting, redirection, control flow or hidden environment may be omitted.
    if !normalized.is_ascii()
        || normalized.len() > 4096
        || !normalized.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'-' | b'_' | b'.' | b'@' | b'/')
        })
    {
        return Err(UNSUPPORTED.to_owned());
    }
    let tokens: Vec<&str> = normalized.split(' ').collect();
    if tokens.iter().any(|token| token.is_empty()) || !(2..=18).contains(&tokens.len()) {
        return Err(UNSUPPORTED.to_owned());
    }
    let model = parse_command(&CommandModelRequestV1 {
        command: normalized.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })?;
    if model.confidence != "exact"
        || model.segments.len() != 1
        || !model.wrapper_chain.is_empty()
        || model.path_overridden
        || !model.segments[0].environment_names.is_empty()
        || model.segments[0].tokens != tokens
    {
        return Err(UNSUPPORTED.to_owned());
    }
    let (kind, fingerprint) = if tokens[0] == "ssh" {
        (
            "tool-action",
            remote_command_fingerprint(harness, tool, normalized, &tokens)?,
        )
    } else {
        (
            "package-request",
            package_fingerprint(harness, normalized, &tokens, &cwd)?,
        )
    };
    if existing_workspace(envelope.source.cwd.as_deref().ok_or(UNSUPPORTED)?)? != cwd {
        return Err(UNSUPPORTED.to_owned());
    }
    Ok(TypedShellArtifact {
        artifact_id: format!("{harness}:project:{kind}:{fingerprint}"),
        artifact_type: if kind == "tool-action" {
            "tool_action_request"
        } else {
            "package_request"
        },
        exact_command_sha256: exact_command_sha256(command).ok_or(UNSUPPORTED)?,
    })
}

fn existing_workspace(value: &str) -> Result<PathBuf, String> {
    let input = Path::new(value);
    if !input.is_absolute() || !input.is_dir() {
        return Err(UNSUPPORTED.to_owned());
    }
    input.canonicalize().map_err(|_| UNSUPPORTED.to_owned())
}

fn remote_command_fingerprint(
    harness: &str,
    tool: &str,
    command: &str,
    tokens: &[&str],
) -> Result<String, String> {
    if tokens.len() != 3
        || !matches!(tokens[2], "id" | "whoami" | "pwd" | "uname")
        || tokens[1].len() > 255
        || !tokens[1].starts_with(|character: char| character.is_ascii_alphanumeric())
        || !tokens[1]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'.' | b'_' | b'-'))
    {
        return Err(UNSUPPORTED.to_owned());
    }
    fingerprint(&json!({
        "harness":harness, "tool_name":tool.to_ascii_lowercase(), "command_text":command,
        "action_class":"SSH remote execution command", "shell_execution_context_hash":null,
        "interpreter_executable_identities":[]
    }))
}

fn package_fingerprint(
    harness: &str,
    command: &str,
    tokens: &[&str],
    workspace: &Path,
) -> Result<String, String> {
    let manager = tokens[0];
    let (intent, manifests, locks): (&str, &[&str], &[&str]) = match (manager, tokens[1]) {
        ("npm", "install" | "i" | "add" | "update") => {
            ("install", &["package.json"], &["package-lock.json"])
        }
        ("npm", "ci") if tokens.len() == 2 => ("sync", &["package.json"], &["package-lock.json"]),
        ("pnpm", "add" | "install" | "i") => (
            "install",
            &["package.json", "pnpm-workspace.yaml"],
            &["pnpm-lock.yaml"],
        ),
        ("yarn", "add" | "install" | "up") => ("install", &["package.json"], &["yarn.lock"]),
        ("bun", "add" | "install") => ("install", &["package.json"], &["bun.lock", "bun.lockb"]),
        _ => return Err(UNSUPPORTED.to_owned()),
    };
    let targets = tokens[2..]
        .iter()
        .map(|token| registry_target(token))
        .collect::<Result<Vec<_>, _>>()?;
    let manifest_paths = existing_paths(workspace, manifests)?;
    let lockfile_paths = existing_paths(workspace, locks)?;
    let digest = fingerprint(&json!({
        "harness":harness,"package_manager":manager,"intent_kind":intent,
        "redacted_command":command,"targets":targets,"manifest_paths":manifest_paths,
        "lockfile_paths":lockfile_paths,"local_executions":[],"execution_context_hashes":[],
        "execution_context_cwds":[],"execution_context_reason_codes":[]
    }))?;
    if existing_paths(workspace, manifests)? != manifest_paths
        || existing_paths(workspace, locks)? != lockfile_paths
    {
        return Err(UNSUPPORTED.to_owned());
    }
    Ok(digest)
}

fn registry_target(spec: &str) -> Result<Value, String> {
    let split = spec.rfind('@').filter(|index| *index > 0);
    let (name, version) = split.map_or((spec, None), |index| {
        (&spec[..index], Some(&spec[index + 1..]))
    });
    let parts: Vec<&str> = name.strip_prefix('@').unwrap_or(name).split('/').collect();
    if name.len() > 214
        || parts.len() != if name.starts_with('@') { 2 } else { 1 }
        || parts.iter().any(|part| {
            part.is_empty()
                || !part.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                || !part.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
                })
        })
        || version.is_some_and(|value| {
            value.is_empty()
                || value.len() > 64
                || !value.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        })
    {
        return Err(UNSUPPORTED.to_owned());
    }
    Ok(json!({
        "ecosystem":"npm","package_name":name,"raw_spec":spec,"requested_specifier":version,
        "source_url":null,"source_kind":null,"source_repository":null,"source_revision_kind":null,
        "source_identity":null,"source_invalid_reason":null,"alias":null,"dependency_group":null,
        "extras":[],"editable":false,"raw_spec_hash":hex::encode(Sha256::digest(spec.as_bytes()))
    }))
}

fn existing_paths(workspace: &Path, candidates: &[&str]) -> Result<Vec<String>, String> {
    let mut result = Vec::new();
    for candidate in candidates {
        let metadata = match workspace.join(candidate).symlink_metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(UNSUPPORTED.to_owned()),
        };
        // The existing producer can describe additional filesystem shapes.
        // This slice proves regular, direct entries only; never reinterpret a
        // directory or a link as the supported dependency-file case.
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(UNSUPPORTED.to_owned());
        }
        let resolved = match workspace.join(candidate).canonicalize() {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(UNSUPPORTED.to_owned()),
        };
        let relative = resolved.strip_prefix(workspace).map_err(|_| UNSUPPORTED)?;
        let parts = relative
            .components()
            .map(|part| {
                part.as_os_str()
                    .to_str()
                    .filter(|value| value.is_ascii() && !value.contains('\\'))
                    .ok_or(UNSUPPORTED)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if parts.is_empty() {
            return Err(UNSUPPORTED.to_owned());
        }
        let text = parts.join("/");
        if !result.contains(&text) {
            result.push(text);
        }
    }
    Ok(result)
}

// Existing Python artifact builders hash json.dumps(sort_keys=True), including
// its separator spaces. Every accepted string is ASCII, so escaping is exact.
fn fingerprint(value: &Value) -> Result<String, String> {
    fn render(value: &Value) -> Result<String, String> {
        Ok(match value {
            Value::Object(values) => {
                let mut fields = values.iter().collect::<Vec<_>>();
                fields.sort_by_key(|(key, _)| *key);
                let fields = fields
                    .into_iter()
                    .map(|(key, value)| Ok(format!("{}: {}", render(&json!(key))?, render(value)?)))
                    .collect::<Result<Vec<_>, String>>()?;
                format!("{{{}}}", fields.join(", "))
            }
            Value::Array(values) => format!(
                "[{}]",
                values
                    .iter()
                    .map(render)
                    .collect::<Result<Vec<_>, _>>()?
                    .join(", ")
            ),
            Value::String(text) if !text.is_ascii() => return Err(UNSUPPORTED.to_owned()),
            _ => serde_json::to_string(value).map_err(|_| UNSUPPORTED)?,
        })
    }
    Ok(hex::encode(Sha256::digest(render(value)?.as_bytes())))
}
