//! The credential-looking post-tool output artifact
//! (`_codex_post_tool_output_artifact`): which command read the output, what
//! local secrets it references, whether a read-only inspection or focused
//! pytest run can skip the finding, and the artifact fingerprint and copy.
//! Python collects the response text and builds the artifact around the
//! answer; everything between, including which commands the payload names,
//! runs here under one deadline.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use guard_contracts::{
    MAX_REQUEST_CONTEXT_PATH_BYTES, MAX_REQUEST_CONTEXT_SCRIPT_BYTES, MAX_REQUEST_CONTEXT_SEGMENTS,
    MAX_REQUEST_CONTEXT_SEGMENT_PROOFS, MAX_REQUEST_CONTEXT_TOTAL_PROOFS,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::benign_request_api::ovalue_from_json;
use crate::codex_output_commands::{is_focused_pytest_verification, is_read_only_git_metadata};
use crate::codex_output_entry::{git_pathspec_identity, scope_of};
use crate::codex_output_env::Ctx;
use crate::codex_output_inspection_flow::is_read_only_source_inspection;
use crate::codex_output_post_tool_commands::post_tool_command_texts;
use crate::codex_output_post_tool_copy::{
    request_summary, runtime_reason, runtime_summary, OutputCopy,
};
use crate::codex_output_post_tool_skips::{focused_pytest_can_skip, source_inspection_can_skip};
use crate::codex_output_post_tool_sources::{
    local_secret_source_label, may_read_local_content, sensitive_local_source_matches,
};
use crate::codex_output_py::PyPath;
use crate::content_sensitivity;
use crate::sfrs_json::dumps_sorted;
use crate::sfrs_kubernetes_commands::kubernetes_secret_read_source;
use crate::sfrs_requests::extract_sensitive_file_read_request;
use crate::shell_command_wrappers::normalize_transparent_shell_command;
use crate::shell_execution_context::{
    model_shell_execution_context_bounded, shell_execution_context_metadata, ShellExecutionContext,
    ShellModelLimit, ShellModelLimits,
};
use crate::shell_secret_read_support::SecretPathMatch;

pub(crate) type PostToolError = &'static str;

const INVALID: PostToolError = "native_codex_post_tool_invalid";
const DEADLINE: PostToolError = "native_codex_post_tool_deadline_exceeded";
const MAX_DEADLINE_MS: u64 = 60_000;
const OUTPUT_CLASS: &str = "credential-looking output";
const NATIVE_UNAVAILABLE: &str = "shell_cwd_native_unavailable";
const FIELDS: [&str; 10] = [
    "harness_label",
    "tool_label",
    "tool_name",
    "tool_input",
    "arguments",
    "tool_input_present",
    "response_text",
    "cwd",
    "home_dir",
    "deadline_ms",
];
/// The command texts older clients derive themselves and send along.
const LEGACY_COMMAND_TEXTS: &str = "command_texts";
const READ_ONLY_PAYLOAD_FIELDS: [&str; 4] = ["tool_name", "tool_input", "cwd", "home_dir"];
/// The bounds the per-command read-only action holds a client-sent list to.
const MAX_READ_ONLY_COMMANDS: usize = 256;
const MAX_READ_ONLY_COMMAND_BYTES: usize = 64 * 1024;

/// One review: the caller facts and the single deadline every step shares.
pub(crate) struct Run<'r, 'c> {
    pub(crate) ctx: &'r Ctx<'c>,
    pub(crate) deadline: Instant,
}

impl Run<'_, '_> {
    pub(crate) fn check(&self) -> Result<(), PostToolError> {
        if Instant::now() >= self.deadline {
            Err(DEADLINE)
        } else {
            Ok(())
        }
    }
}

/// The hook payload projection Python sends.
pub(crate) struct Input {
    harness_label: String,
    tool_label: String,
    tool_name: Value,
    pub(crate) tool_input: Value,
    arguments: Value,
    tool_input_present: bool,
    command_texts: Vec<String>,
    pub(crate) response_text: String,
    pub(crate) cwd: Option<PyPath>,
    pub(crate) home_dir: Option<PyPath>,
    deadline_ms: u64,
}

fn text(body: &Value, key: &str) -> Result<String, PostToolError> {
    body[key].as_str().map(str::to_owned).ok_or(INVALID)
}

fn optional_path(body: &Value, key: &str) -> Result<Option<PyPath>, PostToolError> {
    match &body[key] {
        Value::Null => Ok(None),
        Value::String(path) if path.starts_with('/') => Ok(Some(PyPath::new(path))),
        _ => Err(INVALID),
    }
}

impl Input {
    pub(crate) fn parse(body: &Value) -> Result<Self, PostToolError> {
        let object = body.as_object().ok_or(INVALID)?;
        let legacy = object.contains_key(LEGACY_COMMAND_TEXTS);
        if object.len() != FIELDS.len() + usize::from(legacy)
            || !FIELDS.iter().all(|key| object.contains_key(*key))
        {
            return Err(INVALID);
        }
        let command_texts = if legacy {
            body[LEGACY_COMMAND_TEXTS]
                .as_array()
                .ok_or(INVALID)?
                .iter()
                .map(|item| item.as_str().map(str::to_owned).ok_or(INVALID))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            post_tool_command_texts(&body["tool_name"], &body["tool_input"])
        };
        let deadline_ms = body["deadline_ms"].as_u64().ok_or(INVALID)?;
        if deadline_ms == 0 || deadline_ms > MAX_DEADLINE_MS {
            return Err(INVALID);
        }
        Ok(Self {
            harness_label: text(body, "harness_label")?,
            tool_label: text(body, "tool_label")?,
            tool_name: body["tool_name"].clone(),
            tool_input: body["tool_input"].clone(),
            arguments: body["arguments"].clone(),
            tool_input_present: body["tool_input_present"].as_bool().ok_or(INVALID)?,
            command_texts,
            response_text: text(body, "response_text")?,
            cwd: optional_path(body, "cwd")?,
            home_dir: optional_path(body, "home_dir")?,
            deadline_ms,
        })
    }

    pub(crate) fn tool_name(&self) -> &Value {
        &self.tool_name
    }
}

fn os_path(path: Option<&PyPath>) -> Option<PathBuf> {
    path.map(|path| PathBuf::from(path.to_string()))
}

/// The context the resident request-context build returns when it cannot
/// model the script (`_unavailable_context`).
fn unavailable(command: &str) -> ShellExecutionContext {
    ShellExecutionContext {
        command_text: command.to_owned(),
        initial_cwd: None,
        workspace_root: None,
        workspace_identity: None,
        segments: Vec::new(),
        complete: false,
        reason_code: Some(NATIVE_UNAVAILABLE.to_owned()),
        directory_change_present: true,
    }
}

fn path_is_bounded(path: &str) -> bool {
    path.len() <= MAX_REQUEST_CONTEXT_PATH_BYTES && !path.contains('\0')
}

/// `model_shell_execution_context(command, cwd=cwd, workspace_root=cwd)` as
/// the resident request-context build answers it.
pub(crate) fn model(
    run: &Run,
    command: &str,
    cwd: Option<&PyPath>,
) -> Result<ShellExecutionContext, PostToolError> {
    run.check()?;
    let declared = cwd.map(|path| absolute(run.ctx, path).to_string());
    let effective = declared
        .clone()
        .unwrap_or_else(|| run.ctx.process_cwd.to_string());
    if command.len() > MAX_REQUEST_CONTEXT_SCRIPT_BYTES || !path_is_bounded(&effective) {
        return Ok(unavailable(command));
    }
    let limits = ShellModelLimits {
        max_segments: MAX_REQUEST_CONTEXT_SEGMENTS,
        max_segment_proofs: MAX_REQUEST_CONTEXT_SEGMENT_PROOFS,
        max_total_proofs: MAX_REQUEST_CONTEXT_TOTAL_PROOFS,
        deadline: Some(run.deadline),
    };
    let modeled = model_shell_execution_context_bounded(
        command,
        Some(Path::new(&effective)),
        declared.as_deref().map(Path::new),
        None,
        &limits,
    );
    let mut context = match modeled {
        Ok(context) => context,
        Err(ShellModelLimit::Deadline) => return Err(DEADLINE),
        Err(_) => return Ok(unavailable(command)),
    };
    if declared.is_none() {
        for segment in &mut context.segments {
            if segment.cwd_source == "workspace" {
                segment.cwd_source = "process".to_owned();
            }
        }
    }
    Ok(context)
}

/// `Path(path).absolute()`.
pub(crate) fn absolute(ctx: &Ctx, path: &PyPath) -> PyPath {
    if path.is_absolute() {
        path.clone()
    } else {
        ctx.process_cwd.join(&path.to_string())
    }
}

/// `classify_secret_content(text, suppress_samples=...)`.
fn classify_content(
    run: &Run,
    text: &str,
    suppress_samples: bool,
) -> Result<Vec<Value>, PostToolError> {
    let body = json!({
        "text": text,
        "suppress_samples": suppress_samples,
        "documentation_sample_context": false,
    });
    let mut result = content_sensitivity::evaluate("content", &body, run.deadline)?;
    match result["ok"].take() {
        Value::Array(matches) => Ok(matches),
        _ => Err(INVALID),
    }
}

/// The command whose output is reviewed, with what it reads.
struct Source {
    command: String,
    local: Vec<SecretPathMatch>,
    normalized: String,
    kubernetes: Option<&'static str>,
}

fn source(run: &Run, input: &Input, command: &str) -> Result<Source, PostToolError> {
    let cwd = input.cwd.as_ref();
    let local = sensitive_local_source_matches(run, command, cwd, false)?;
    let normalized = normalize_transparent_shell_command(
        command,
        os_path(cwd).as_deref(),
        os_path(input.home_dir.as_ref()).as_deref(),
    )
    .normalized_command;
    let kubernetes = kubernetes_secret_read_source(&normalized);
    Ok(Source {
        command: command.to_owned(),
        local,
        normalized,
        kubernetes,
    })
}

/// The first command, or the last later one that may read local content
/// (stopping at a Kubernetes secret read).
fn reviewed_source(run: &Run, input: &Input) -> Result<Source, PostToolError> {
    let first = input
        .command_texts
        .first()
        .unwrap_or(&input.tool_label)
        .clone();
    let mut chosen = source(run, input, &first)?;
    for candidate in input.command_texts.iter().skip(1) {
        let found = source(run, input, candidate)?;
        let references = !found.local.is_empty()
            || found.kubernetes.is_some()
            || may_read_local_content(run, candidate, input.cwd.as_ref())?;
        if !references {
            continue;
        }
        let kubernetes = found.kubernetes.is_some();
        chosen = found;
        if kubernetes {
            break;
        }
    }
    Ok(chosen)
}

/// `_codex_post_tool_command_is_read_only_source_inspection`: every command
/// is a read-only source inspection or git metadata read.
pub(crate) fn post_tool_commands_read_only(
    ctx: &Ctx,
    commands: &[String],
    cwd: Option<&PyPath>,
    home_dir: Option<&PyPath>,
) -> bool {
    let scope = scope_of(ctx, cwd, home_dir);
    !commands.is_empty()
        && commands.iter().all(|command| {
            is_read_only_source_inspection(command, scope)
                || is_read_only_git_metadata(command, scope.without_home())
        })
}

fn post_tool_read_only(ctx: &Ctx, input: &Input) -> bool {
    post_tool_commands_read_only(
        ctx,
        &input.command_texts,
        input.cwd.as_ref(),
        input.home_dir.as_ref(),
    )
}

/// The same verdict over the commands a post-tool payload names. A payload
/// naming more or longer commands than a client-sent list may carry is not
/// read-only, as the bounded per-command action refuses it.
pub(crate) fn review_post_tool_read_only_payload(
    ctx: &Ctx,
    body: &Value,
) -> Result<bool, PostToolError> {
    let body = content_sensitivity::decode_input(body)?;
    let object = body.as_object().ok_or(INVALID)?;
    if object.len() != READ_ONLY_PAYLOAD_FIELDS.len()
        || !READ_ONLY_PAYLOAD_FIELDS
            .iter()
            .all(|key| object.contains_key(*key))
    {
        return Err(INVALID);
    }
    let cwd = optional_path(&body, "cwd")?;
    let home_dir = optional_path(&body, "home_dir")?;
    let commands = post_tool_command_texts(&body["tool_name"], &body["tool_input"]);
    if commands.len() > MAX_READ_ONLY_COMMANDS
        || commands
            .iter()
            .any(|command| command.len() > MAX_READ_ONLY_COMMAND_BYTES)
    {
        return Ok(false);
    }
    Ok(post_tool_commands_read_only(
        ctx,
        &commands,
        cwd.as_ref(),
        home_dir.as_ref(),
    ))
}

/// Review one post-tool payload; the JSON answer text.
pub(crate) fn review_post_tool_output(ctx: &Ctx, body: &Value) -> Result<String, PostToolError> {
    let body = content_sensitivity::decode_input(body)?;
    let input = Input::parse(&body)?;
    let run = Run {
        ctx,
        deadline: Instant::now() + Duration::from_millis(input.deadline_ms),
    };
    let artifact = artifact(&run, &input)?;
    run.check()?;
    let read_only = artifact.is_none() && post_tool_read_only(ctx, &input);
    run.check()?;
    Ok(json!({ "artifact": artifact, "read_only": read_only }).to_string())
}

fn artifact(run: &Run, input: &Input) -> Result<Option<Value>, PostToolError> {
    let source = reviewed_source(run, input)?;
    let cwd = input.cwd.as_ref();
    let read_arguments = if input.tool_input_present {
        &input.tool_input
    } else {
        &input.arguments
    };
    let sensitive_file_request = extract_sensitive_file_read_request(
        &ovalue_from_json(&input.tool_name),
        &ovalue_from_json(read_arguments),
        os_path(cwd).as_deref(),
        os_path(input.home_dir.as_ref()).as_deref(),
    );
    let references_local_content = !source.local.is_empty()
        || source.kubernetes.is_some()
        || sensitive_file_request.is_some()
        || may_read_local_content(run, &source.command, cwd)?;
    let mut content = classify_content(run, &input.response_text, true)?;
    if content.is_empty() && references_local_content {
        content = classify_content(run, &input.response_text, false)?;
    }
    if content.is_empty()
        || source_inspection_can_skip(
            run,
            input,
            &source.command,
            &content,
            sensitive_file_request.is_some(),
        )?
        || focused_pytest_can_skip(run, input, &source.command, &content)?
    {
        return Ok(None);
    }
    run.check()?;
    let command = source.command.as_str();
    let merged_output_capture = command.contains("2>&1") || command.contains("|&");
    let focused_pytest = is_focused_pytest_verification(command);
    let context = model(run, command, cwd)?;
    let git_identity = git_pathspec_identity(run.ctx, &source.normalized, cwd);
    run.check()?;
    let fingerprint = hex::encode(Sha256::digest(
        dumps_sorted(&json!({
            "tool_name": input.tool_label,
            "command_text": command,
            "output_class": OUTPUT_CLASS,
            "shell_execution_context_hash": context
                .directory_change_present
                .then(|| context.context_hash()),
            "git_pathspec_selection_identity": git_identity,
        }))
        .as_bytes(),
    ));
    let label = source
        .kubernetes
        .map(str::to_owned)
        .or_else(|| local_secret_source_label(&source.local, command));
    let mut signals = vec![json!("tool output contains credential-looking material")];
    if references_local_content {
        signals.push(json!(match &label {
            Some(label) => format!("command references local secrets from {label}"),
            None => "command references local secrets".to_owned(),
        }));
    }
    let local_secret_source =
        label.or_else(|| sensitive_file_request.map(|request| request.path_match.family));
    let copy = OutputCopy {
        harness_label: &input.harness_label,
        local_secret_source: local_secret_source.as_deref(),
        merged_output_capture,
        focused_pytest,
    };
    let action_class = match (references_local_content, source.kubernetes.is_some()) {
        (true, true) => "Kubernetes secret read command",
        (true, false) => "credential exfiltration shell command",
        (false, _) => "credential-looking tool output",
    };
    let mut metadata: Vec<(String, Value)> = vec![
        ("tool_name".to_owned(), json!(input.tool_label)),
        ("command_text".to_owned(), json!(command)),
        ("action_class".to_owned(), json!(action_class)),
        (
            "guard_default_action".to_owned(),
            json!(if references_local_content {
                "require-reapproval"
            } else {
                "warn"
            }),
        ),
        (
            "request_summary".to_owned(),
            json!(request_summary(&copy, &input.tool_label, command)),
        ),
        ("runtime_request_signals".to_owned(), Value::Array(signals)),
        (
            "runtime_request_summary".to_owned(),
            json!(runtime_summary(&copy)),
        ),
        (
            "runtime_request_reason".to_owned(),
            json!(runtime_reason(&copy)),
        ),
    ];
    if context.directory_change_present {
        let shell: Map<String, Value> = match shell_execution_context_metadata(&context) {
            Value::Object(map) => map,
            _ => return Err(INVALID),
        };
        for (key, value) in shell {
            upsert(&mut metadata, key, value);
        }
    }
    if let Some(identity) = git_identity {
        upsert(
            &mut metadata,
            "git_pathspec_selection_identity".to_owned(),
            json!(identity),
        );
    }
    if merged_output_capture {
        upsert(
            &mut metadata,
            "output_capture_mode".to_owned(),
            json!("merged-stderr"),
        );
    }
    if let Some(family) = &local_secret_source {
        upsert(
            &mut metadata,
            "secret_source_family".to_owned(),
            json!(family),
        );
    }
    let pairs: Vec<Value> = metadata
        .into_iter()
        .map(|(key, value)| json!([key, value]))
        .collect();
    Ok(Some(json!({
        "fingerprint": fingerprint,
        "metadata": pairs,
    })))
}

/// `dict[key] = value`: replaces in place, else appends.
fn upsert(metadata: &mut Vec<(String, Value)>, key: String, value: Value) {
    match metadata.iter_mut().find(|(existing, _)| *existing == key) {
        Some(entry) => entry.1 = value,
        None => metadata.push((key, value)),
    }
}

#[cfg(all(test, unix))]
#[path = "codex_output_post_tool_payload_tests.rs"]
mod payload_tests;
