//! Interpreter launch candidate modeling (`interpreter_launch.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::PyPath;
use crate::env_wrapper::parse_env_wrapper;
use crate::launch_identity::build_runtime_executable_identity;
use crate::sfrs_interpreter_scripts::is_python_interpreter_command;
use crate::sfrs_interpreter_trust::{
    interpreter_token_has_path, python_interpreter_trust, resolve_strict,
};
use crate::sfrs_patterns::{SHELL_ASSIGNMENT_PATTERN, SHELL_COMMAND_WRAPPERS};
use crate::sfrs_shell_tokens::{
    leading_shell_redirection_tokens_consumed, normalized_shell_command_name,
    shell_command_token_without_attached_redirection, wrapper_option_tokens_consumed,
};

/// Python's `os.defpath` on POSIX.
const DEFPATH: &str = "/bin:/usr/bin";

pub(crate) type Environment = BTreeMap<String, String>;

/// `_ShellLaunchCandidate`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ShellLaunchCandidate {
    pub(crate) tokens: Vec<String>,
    pub(crate) command_index: usize,
    pub(crate) effective_cwd: PyPath,
    pub(crate) environment: Environment,
    pub(crate) resolution_reason: Option<String>,
}

/// `_normalized_interpreter_cwd`.
pub(crate) fn normalized_interpreter_cwd(cwd: Option<&PyPath>, ctx: &Ctx) -> PyPath {
    let candidate = cwd.cloned().unwrap_or_else(|| ctx.process_cwd.clone());
    let expanded = ctx
        .expanduser(&candidate.to_string())
        .unwrap_or_else(|| candidate.clone());
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        ctx.process_cwd.join(&expanded.to_string())
    };
    pyfs::resolve(&absolute).unwrap_or(absolute)
}

fn path_expression_unresolved(environment: &Environment) -> bool {
    environment
        .get("PATH")
        .is_some_and(|value| value.contains('$') || value.contains('`'))
}

/// `_shell_launch_candidate`.
pub(crate) fn shell_launch_candidate(
    tokens: &[String],
    cwd: &PyPath,
    environment: &Environment,
    depth: usize,
    resolution_reason: Option<&str>,
    ctx: &Ctx,
) -> Option<ShellLaunchCandidate> {
    if depth > 8 {
        return None;
    }
    let working: Vec<String> = tokens.to_vec();
    let mut effective_environment = environment.clone();
    let mut effective_cwd = cwd.clone();
    let mut reason: Option<String> = resolution_reason.map(ToOwned::to_owned);
    let mut index = 0;
    while index < working.len() {
        let redirected = leading_shell_redirection_tokens_consumed(&working, index);
        if redirected > 0 {
            index += redirected;
            continue;
        }
        let token = shell_command_token_without_attached_redirection(&working[index]);
        let token = crate::codex_output_py::py_strip(&token).to_owned();
        if SHELL_ASSIGNMENT_PATTERN.is_match(&token).unwrap_or(false) {
            let (name, value) = token.split_once('=').unwrap_or((token.as_str(), ""));
            let (name, value) = match name.strip_suffix('+') {
                Some(base) => {
                    let existing = effective_environment.get(base).cloned().unwrap_or_default();
                    (base.to_owned(), format!("{existing}{value}"))
                }
                None => (name.to_owned(), value.to_owned()),
            };
            effective_environment.insert(name, value);
            index += 1;
            continue;
        }
        let command_name = normalized_shell_command_name(&token);
        if command_name == "env" {
            let effective = effective_cwd.to_string();
            let parsed = parse_env_wrapper(
                &working[index + 1..],
                Some(&effective_environment),
                Some(Path::new(&effective)),
            );
            if !parsed.complete || parsed.executable_argv.is_empty() {
                return None;
            }
            let parsed_environment: Environment =
                parsed.effective_environment?.into_iter().collect();
            let parsed_cwd = PyPath::new(&parsed.effective_cwd?.to_string_lossy());
            let env_reason = if path_expression_unresolved(&parsed_environment) {
                Some("path_expression_unresolved".to_owned())
            } else {
                reason.clone()
            };
            return shell_launch_candidate(
                &parsed.executable_argv,
                &parsed_cwd,
                &parsed_environment,
                depth + 1,
                env_reason.as_deref(),
                ctx,
            );
        }
        if !SHELL_COMMAND_WRAPPERS.contains(&command_name.as_str()) {
            let final_reason = if path_expression_unresolved(&effective_environment) {
                Some("path_expression_unresolved".to_owned())
            } else {
                reason
            };
            return Some(ShellLaunchCandidate {
                tokens: working,
                command_index: index,
                effective_cwd,
                environment: effective_environment,
                resolution_reason: final_reason,
            });
        }
        if command_name == "sudo" {
            let (next_index, next_cwd, sudo_reason) =
                consume_sudo_wrapper_for_interpreter(&working, index + 1, &effective_cwd, ctx);
            index = next_index;
            effective_cwd = next_cwd;
            reason = reason.or(sudo_reason);
            continue;
        }
        index += 1;
        while index < working.len() && working[index].starts_with('-') {
            let wrapper_token = &working[index];
            if command_name == "command" && wrapper_token.trim_start_matches('-').contains('p') {
                effective_environment.insert("PATH".to_owned(), DEFPATH.to_owned());
            }
            index += wrapper_option_tokens_consumed(&command_name, wrapper_token);
        }
    }
    None
}

/// `_consume_sudo_wrapper_for_interpreter`.
pub(crate) fn consume_sudo_wrapper_for_interpreter(
    tokens: &[String],
    mut index: usize,
    cwd: &PyPath,
    ctx: &Ctx,
) -> (usize, PyPath, Option<String>) {
    let mut chdir_value: Option<String> = None;
    let mut reason: Option<String> = Some("sudo_path_resolution_unproven".to_owned());
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if token == "--" {
            return (index + 1, cwd.clone(), reason);
        }
        if !token.starts_with('-') {
            break;
        }
        if matches!(token, "-R" | "--chroot")
            || token.starts_with("-R")
            || token.starts_with("--chroot=")
        {
            reason = Some("sudo_chroot_unresolved".to_owned());
        }
        if token == "-D" || token == "--chdir" {
            let Some(next) = tokens.get(index + 1) else {
                return (
                    tokens.len(),
                    cwd.clone(),
                    Some("sudo_chdir_missing".to_owned()),
                );
            };
            chdir_value = Some(next.clone());
        } else if let Some(value) = token.strip_prefix("--chdir=") {
            chdir_value = Some(value.to_owned());
        } else if token.starts_with("-D") && token != "-D" {
            chdir_value = Some(token.chars().skip(2).collect());
        }
        index += wrapper_option_tokens_consumed("sudo", token);
    }
    let Some(chdir) = chdir_value else {
        return (index, cwd.clone(), reason);
    };
    let unresolved = || (index, cwd.clone(), Some("sudo_chdir_unresolved".to_owned()));
    if chdir.is_empty() || chdir.contains(['$', '`', '\0']) {
        return unresolved();
    }
    let Some(candidate) = ctx.expanduser(&chdir) else {
        return unresolved();
    };
    let candidate = if candidate.is_absolute() {
        candidate
    } else {
        cwd.join(&candidate.to_string())
    };
    match resolve_strict(&candidate) {
        Some(resolved) if matches!(pyfs::is_dir(&resolved), Ok(true)) => (index, resolved, reason),
        _ => unresolved(),
    }
}

/// `_ambiguous_python_evidence_from_tokens`.
pub(crate) fn ambiguous_python_evidence_from_tokens(
    tokens: &[String],
    cwd: &PyPath,
    environment: &Environment,
    workspace_root: &PyPath,
    home_dir: Option<&PyPath>,
    reason: &str,
    ctx: &Ctx,
) -> Vec<Value> {
    tokens
        .iter()
        .filter_map(|token| {
            let raw = shell_command_token_without_attached_redirection(token);
            let raw = crate::codex_output_py::py_strip(&raw);
            is_python_interpreter_command(raw).then(|| {
                python_interpreter_executable_identity(
                    raw,
                    cwd,
                    environment,
                    workspace_root,
                    home_dir,
                    Some(reason),
                    ctx,
                )
            })
        })
        .collect()
}

fn random_nonce(ctx: &Ctx) -> String {
    ctx.host.reuse_nonce().unwrap_or_else(|| {
        let mut bytes = [0u8; 16];
        match getrandom::fill(&mut bytes) {
            Ok(()) => hex::encode(bytes),
            Err(_) => "0".repeat(32),
        }
    })
}

/// `_python_interpreter_executable_identity`.
pub(crate) fn python_interpreter_executable_identity(
    raw_token: &str,
    cwd: &PyPath,
    environment: &Environment,
    workspace_root: &PyPath,
    home_dir: Option<&PyPath>,
    resolution_reason: Option<&str>,
    ctx: &Ctx,
) -> Value {
    let search_path = environment.get("PATH").map(String::as_str);
    let cwd_text = cwd.to_string();
    let mut identity = ctx
        .host
        .runtime_executable_identity(raw_token, search_path, &cwd_text)
        .unwrap_or_else(|| {
            build_runtime_executable_identity(
                &Value::String(raw_token.to_owned()),
                search_path,
                Some(Path::new(&cwd_text)),
                None,
                true,
            )
        });
    if let (Some(reason), false) = (resolution_reason, interpreter_token_has_path(raw_token)) {
        if let Some(map) = identity.as_object_mut() {
            map.insert("resolution_reason".to_owned(), json!(reason));
            map.insert("reuse_nonce".to_owned(), json!(random_nonce(ctx)));
        }
    }
    let trust = python_interpreter_trust(
        raw_token,
        &identity,
        workspace_root,
        home_dir,
        resolution_reason,
        ctx,
    );
    let digest = hex::encode(Sha256::digest(search_path.unwrap_or("").as_bytes()));
    json!({
        "effective_cwd": cwd_text,
        "executable": identity,
        "normalized_name": normalized_shell_command_name(raw_token),
        "raw_token": raw_token,
        "search_path_sha256": digest,
        "trust": trust,
    })
}

/// `_without_interpreter_reuse_nonces`.
pub(crate) fn without_interpreter_reuse_nonces(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(key, _)| key.as_str() != "reuse_nonce")
                .map(|(key, item)| (key.clone(), without_interpreter_reuse_nonces(item)))
                .collect::<Map<String, Value>>(),
        ),
        Value::Array(items) => {
            Value::Array(items.iter().map(without_interpreter_reuse_nonces).collect())
        }
        other => other.clone(),
    }
}
