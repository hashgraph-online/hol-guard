//! Python interpreter and pytest configuration trust
//! (`interpreter_trust.py`).
//!
//! Also here: `_contains_shell_network_file_upload` and
//! `_curl_stdin_config_uses_file_upload`, built on the network-upload,
//! credential-exfiltration and stdin-source ports.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::{py_strip, PyPath};
use crate::false_positive_rules::fd_arg_requests_exec;
use crate::sfrs_constants::{FIND_EXEC_ACTION_FLAGS, TRUSTED_INTERPRETER_INSTALL_ROOTS};
use crate::sfrs_credential_exfil::local_shell_script_payloads;
use crate::sfrs_gh_pr_expansion::is_pytest_python_interpreter_command;
use crate::sfrs_interpreter_heredoc::shell_heredoc_payloads;
use crate::sfrs_network_upload::{
    command_uses_curl_stdin_heredoc, curl_segment_reads_config_from_stdin,
    curl_segment_uses_file_upload, segment_uses_network_file_upload, UploadScan,
};
use crate::sfrs_patterns::{
    PYTEST_COMMAND_NAMES, PYTEST_COMMAND_RUNNER_SUBCOMMANDS, PYTEST_EXECUTOR_COMMANDS,
};
use crate::sfrs_pytest_config::{combine_pytest_config_assessments, PytestConfigAssessment};
use crate::sfrs_pytest_config_read::PATH_INVALID;
use crate::sfrs_pytest_config_search::pytest_config_assessment;
use crate::sfrs_pytest_target::{
    pytest_args_from_argument_sequence, pytest_args_from_runner_argument_sequence,
    segment_targets_pytest, shell_command_targets_pytest,
};
use crate::sfrs_selectors::pytest_args_from_python;
use crate::sfrs_shell_tokens::{
    normalized_shell_command_name, shell_segment_primary_command, split_shell_parts,
};
use crate::sfrs_stdin_sources::{
    shell_pipeline_stdin_payloads, shell_pipeline_stdin_uses_local_file,
};
use crate::sfrs_substitution::{
    env_split_string_payloads, iter_shell_pipelines, shell_command_scripts,
    shell_command_substitution_payloads,
};
use crate::shell_command_wrappers::is_trusted_absolute_command_path;
use crate::shell_execution_context::{validate_shell_execution_segment, ShellExecutionContext};

fn invalid_assessment(reason: &str) -> PytestConfigAssessment {
    PytestConfigAssessment {
        results: Vec::new(),
        complete: false,
        unsafe_options: true,
        reason_codes: vec![reason.to_owned()],
        identity_sha256: None,
    }
}

/// `_pytest_config_assessment_for_command`.
pub(crate) fn pytest_config_assessment_for_command(
    command_text: &str,
    cwd: Option<&Path>,
    execution_context: &ShellExecutionContext,
) -> PytestConfigAssessment {
    let Some(cwd) = cwd else {
        return invalid_assessment(PATH_INVALID);
    };
    let mut assessments: Vec<PytestConfigAssessment> = Vec::new();
    for context_segment in &execution_context.segments {
        if context_segment.directory_operation.is_some() {
            continue;
        }
        let segment = &context_segment.tokens;
        let (Some(command_name), Some(command_index)) = shell_segment_primary_command(segment)
        else {
            continue;
        };
        if !segment_targets_pytest(segment, &command_name, command_index, 0) {
            continue;
        }
        let (segment_cwd, reason_code) =
            validate_shell_execution_segment(execution_context, context_segment);
        let Some(segment_cwd) = segment_cwd.filter(|_| reason_code.is_none()) else {
            assessments.push(invalid_assessment(
                reason_code.as_deref().unwrap_or(PATH_INVALID),
            ));
            continue;
        };
        assessments.push(match pytest_args_from_segment(segment, command_index) {
            Some(args) => pytest_config_assessment(&segment_cwd, &args),
            None => invalid_assessment(PATH_INVALID),
        });
    }
    if assessments.is_empty() && shell_command_targets_pytest(command_text, 0) {
        assessments.push(pytest_config_assessment(cwd, &[]));
    }
    combine_pytest_config_assessments(&assessments)
}

/// `_pytest_args_from_segment`.
pub(crate) fn pytest_args_from_segment(
    segment: &[String],
    command_index: usize,
) -> Option<Vec<String>> {
    let command_name = normalized_shell_command_name(&segment[command_index]);
    let command_args = &segment[command_index + 1..];
    if PYTEST_COMMAND_NAMES.contains(&command_name.as_str()) {
        return Some(command_args.to_vec());
    }
    if is_pytest_python_interpreter_command(&command_name) {
        return pytest_args_from_python(command_args);
    }
    if command_name == "uvx" || PYTEST_EXECUTOR_COMMANDS.contains(&command_name.as_str()) {
        return pytest_args_from_argument_sequence(command_args);
    }
    if let Some((_, subcommands)) = PYTEST_COMMAND_RUNNER_SUBCOMMANDS
        .iter()
        .find(|(name, _)| *name == command_name)
    {
        return command_args
            .iter()
            .position(|token| subcommands.contains(&token.as_str()))
            .and_then(|index| {
                pytest_args_from_runner_argument_sequence(&command_name, &command_args[index + 1..])
            });
    }
    if command_name == "find" {
        return command_args
            .iter()
            .position(|token| FIND_EXEC_ACTION_FLAGS.contains(&token.as_str()))
            .and_then(|index| pytest_args_from_argument_sequence(&command_args[index + 1..]));
    }
    if command_name == "fd" {
        return command_args
            .iter()
            .position(|token| fd_arg_requests_exec(token))
            .and_then(|index| pytest_args_from_argument_sequence(&command_args[index + 1..]));
    }
    None
}

/// `Path.absolute()`.
fn absolute(ctx: &Ctx, path: &PyPath) -> PyPath {
    if path.is_absolute() {
        path.clone()
    } else {
        ctx.process_cwd.join(&path.to_string())
    }
}

/// `Path.resolve(strict=True)`; `None` is the `OSError` or `RuntimeError`.
pub(crate) fn resolve_strict(path: &PyPath) -> Option<PyPath> {
    // `realpath(strict=True)` looks at every component it walks, so a missing
    // directory fails even when a later `..` would cancel it.
    if !path.is_absolute() || path.root() == "//" {
        return None;
    }
    let mut current = PyPath::new("/");
    let text = path.to_string();
    for component in text
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
    {
        if component == ".." {
            current = pyfs::resolve(&current)?.parent();
            continue;
        }
        let next = current.join(component);
        if !matches!(pyfs::exists(&next), Ok(true)) {
            return None;
        }
        current = pyfs::resolve(&next)?;
    }
    let resolved = pyfs::resolve(&current)?;
    matches!(pyfs::exists(&resolved), Ok(true)).then_some(resolved)
}

/// `_python_interpreter_trust`.
pub(crate) fn python_interpreter_trust(
    raw_token: &str,
    identity: &Value,
    workspace_root: &PyPath,
    home_dir: Option<&PyPath>,
    resolution_reason: Option<&str>,
    ctx: &Ctx,
) -> String {
    let status = match identity.get("status") {
        Some(Value::String(text)) if !text.is_empty() => text.as_str(),
        _ => "unknown",
    };
    if resolution_reason.is_some() && !interpreter_token_has_path(raw_token) {
        return "ambiguous".to_owned();
    }
    if matches!(status, "unresolved" | "unreadable" | "path_unreadable") {
        return "missing".to_owned();
    }
    if status == "not_executable" {
        return "non_executable".to_owned();
    }
    if status != "verified" {
        return if matches!(
            status,
            "foreign_platform_path" | "invalid_path" | "path_changed"
        ) {
            "ambiguous"
        } else {
            "unknown"
        }
        .to_owned();
    }
    let (Some(launch_text), Some(canonical_text)) = (
        identity.get("launch_path").and_then(Value::as_str),
        identity.get("path").and_then(Value::as_str),
    ) else {
        return "unknown".to_owned();
    };
    let launch_path = PyPath::new(launch_text);
    let canonical = PyPath::new(canonical_text);
    if let Some(executable) = ctx.host.guard_executable() {
        let guard_launch = ctx
            .expanduser(&executable)
            .map_or_else(|| PyPath::new(&executable), |path| absolute(ctx, &path));
        let guard_canonical = resolve_strict(&guard_launch).unwrap_or_else(|| guard_launch.clone());
        if canonical == guard_canonical
            && (launch_path == guard_launch
                || launch_path == guard_canonical
                || launch_path.parent() == guard_launch.parent())
        {
            return "trusted_guard".to_owned();
        }
    }
    if interpreter_path_is_within(&launch_path, workspace_root, ctx) {
        return "workspace_local".to_owned();
    }
    if home_dir.is_some_and(|home| interpreter_path_is_within(&launch_path, home, ctx)) {
        return "user_controlled".to_owned();
    }
    if cfg!(windows) {
        return "user_controlled".to_owned();
    }
    if TRUSTED_INTERPRETER_INSTALL_ROOTS
        .iter()
        .any(|root| interpreter_path_is_within(&launch_path, &PyPath::new(root), ctx))
        && interpreter_identity_path_chain_is_stable(identity)
    {
        return "trusted_system".to_owned();
    }
    let launch = launch_path.to_string();
    let workspace = workspace_root.to_string();
    let home = home_dir.map(ToString::to_string);
    if is_trusted_absolute_command_path(
        Path::new(&launch),
        Some(Path::new(&workspace)),
        home.as_deref().map(Path::new),
    ) {
        return "trusted_system".to_owned();
    }
    "user_controlled".to_owned()
}

/// Python `isinstance(mode, int)` and `mode & 0o022 == 0` over a JSON number;
/// a `bool` is an `int`. An integer too wide for 64 bits is refused.
fn mode_is_stable(mode: &Value) -> bool {
    match mode {
        Value::Bool(_) => true,
        Value::Number(number) => number
            .as_i64()
            .map(|value| value & 0o022 == 0)
            .or_else(|| number.as_u64().map(|value| value & 0o022 == 0))
            .unwrap_or(false),
        _ => false,
    }
}

/// `_interpreter_identity_path_chain_is_stable`.
pub(crate) fn interpreter_identity_path_chain_is_stable(identity: &Value) -> bool {
    let Some(chain) = identity.get("path_chain").and_then(Value::as_array) else {
        return false;
    };
    if chain.is_empty() {
        return false;
    }
    chain.iter().all(|item| {
        item.as_object()
            .and_then(|map| map.get("mode"))
            .is_some_and(mode_is_stable)
    })
}

/// `_interpreter_token_has_path`.
pub(crate) fn interpreter_token_has_path(raw_token: &str) -> bool {
    let normalized = py_strip(raw_token);
    let mut chars = normalized.chars();
    let drive_prefix = matches!(
        (chars.next(), chars.next()),
        (Some(letter), Some(':')) if letter.is_ascii_alphabetic()
    );
    normalized.contains('/')
        || normalized.contains('\\')
        || drive_prefix
        || normalized.starts_with("//")
}

/// `_interpreter_path_is_within`.
pub(crate) fn interpreter_path_is_within(path: &PyPath, root: &PyPath, ctx: &Ctx) -> bool {
    absolute(ctx, path)
        .relative_to(&absolute(ctx, root))
        .is_some()
}

/// `_contains_shell_network_file_upload`.
pub(crate) fn contains_shell_network_file_upload(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    allowed_roots: Option<&[PathBuf]>,
) -> bool {
    network_file_upload_at(command_text, cwd, home_dir, allowed_roots, 0, &[])
}

fn network_file_upload_at(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    allowed_roots: Option<&[PathBuf]>,
    depth: usize,
    visited_script_paths: &[String],
) -> bool {
    if depth > 4 {
        return false;
    }
    let normalized = py_strip(command_text);
    if normalized.is_empty() {
        return false;
    }
    let parts = split_shell_parts(normalized);
    if parts.is_empty() {
        return false;
    }
    if curl_stdin_config_uses_file_upload(normalized, &parts, cwd, home_dir, allowed_roots) {
        return true;
    }
    for pipeline in iter_shell_pipelines(&parts) {
        for (index, segment) in pipeline.iter().enumerate() {
            let stdin_uses_local_file =
                shell_pipeline_stdin_uses_local_file(&pipeline, index, cwd, home_dir);
            if segment_uses_network_file_upload(
                segment,
                cwd,
                home_dir,
                allowed_roots,
                stdin_uses_local_file,
            ) {
                return true;
            }
        }
    }
    let nested = env_split_string_payloads(&parts)
        .into_iter()
        .chain(shell_command_substitution_payloads(normalized))
        .chain(shell_command_scripts(&parts));
    for text in nested {
        if network_file_upload_at(
            &text,
            cwd,
            home_dir,
            allowed_roots,
            depth + 1,
            visited_script_paths,
        ) {
            return true;
        }
    }
    for (script_text, script_cwd, script_path) in
        local_shell_script_payloads(&parts, cwd, home_dir, allowed_roots, visited_script_paths)
    {
        let mut visited = visited_script_paths.to_vec();
        visited.push(script_path);
        if network_file_upload_at(
            &script_text,
            script_cwd.as_deref(),
            home_dir,
            allowed_roots,
            depth + 1,
            &visited,
        ) {
            return true;
        }
    }
    false
}

/// `_curl_stdin_config_uses_file_upload`.
pub(crate) fn curl_stdin_config_uses_file_upload(
    command_text: &str,
    parts: &[String],
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    allowed_roots: Option<&[PathBuf]>,
) -> bool {
    let heredoc_payloads = shell_heredoc_payloads(command_text);
    for pipeline in iter_shell_pipelines(parts) {
        for (index, segment) in pipeline.iter().enumerate() {
            let (Some(command_name), Some(command_index)) = shell_segment_primary_command(segment)
            else {
                continue;
            };
            if command_name != "curl" {
                continue;
            }
            let segment_args = &segment[command_index + 1..];
            let stdin_payloads =
                shell_pipeline_stdin_payloads(&pipeline, index, cwd, home_dir, allowed_roots);
            let stdin_uses_local_file =
                shell_pipeline_stdin_uses_local_file(&pipeline, index, cwd, home_dir);
            if !stdin_payloads.is_empty() {
                let mut scan = UploadScan::new(cwd, home_dir);
                scan.allowed_roots = allowed_roots;
                scan.stdin_config_payloads = &stdin_payloads;
                scan.stdin_uses_local_file = stdin_uses_local_file;
                if curl_segment_uses_file_upload(segment_args, &scan) {
                    return true;
                }
            }
            if !heredoc_payloads.is_empty()
                && stdin_payloads.is_empty()
                && curl_segment_reads_config_from_stdin(segment_args)
                && command_uses_curl_stdin_heredoc(command_text)
            {
                let payloads: Vec<(String, Option<PathBuf>)> = heredoc_payloads
                    .iter()
                    .map(|payload| (payload.clone(), cwd.map(Path::to_path_buf)))
                    .collect();
                let mut scan = UploadScan::new(cwd, home_dir);
                scan.stdin_config_payloads = &payloads;
                if curl_segment_uses_file_upload(segment_args, &scan) {
                    return true;
                }
            }
        }
    }
    false
}
