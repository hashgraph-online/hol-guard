//! Bounded, non-executing evidence for shell reads and local script launches
//! (`runtime/shell_secret_reads.py`, 357 lines — verbatim).
//!
//! A script without detected secret references is not a proof of safety.
//! Imports, computed paths and subprocesses can still access local data, so
//! script launches retain an execution floor. Inspection can only raise or
//! explain that floor.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use sha2::{Digest, Sha256};

use crate::command_model::parse_shell_command;
use crate::home_path_text::{expand_home, normalize_path};
use crate::runtime_read_paths::{
    read_small_runtime_text_file, resolved_runtime_path, runtime_read_roots,
};
use crate::shell_execution_context::{model_shell_execution_context, ShellExecutionContext};
use crate::shell_execution_context_support::{
    SHELL_CWD_UNRESOLVED_PARENT_SHELL, SHELL_CWD_WORKSPACE_ESCAPE,
};
use crate::shell_read_literal_wrapper::literal_shell_read_payload;
use crate::shell_secret_read_flow::{
    failed_cd_short_circuit_state, flow_operator_before, parse_execution_segment,
    segment_may_touch_local_data,
};
use crate::shell_secret_read_support::{
    command_may_need_read_assessment, command_name_for, cwd_shadowed_executable,
    direct_secret_read_paths, direct_secret_read_paths_from_tokens, interpreter_inline_launch,
    interpreter_stdin_launch, known_python_module_launch, literal_read_paths,
    local_executable_operand, python_executable, python_module_launch, script_operand,
    sensitive_path, shell_command_string, unresolved_local_script_launch, unwrap_execution_builtin,
    MAX_DEPTH, MAX_INLINE_SCRIPT_BYTES, MAX_SCRIPTS, MAX_TOTAL_BYTES, SHELLS,
};
use crate::shell_structure::extract_heredocs;

fn delay_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s*sleep\s+([1-9]\d{0,3})\s*&&\s*").expect("delay"))
}

/// `ShellReadAssessment` (:56-74).
#[derive(Clone, Debug)]
pub struct ShellReadAssessment {
    pub sensitive_paths: Vec<String>,
    /// `(source_name, sha256_hex)` pairs.
    pub script_sources: Vec<(String, String)>,
    pub script_requested: bool,
    pub incomplete: bool,
}

impl ShellReadAssessment {
    /// `requires_review` (:64-67).
    pub fn requires_review(&self) -> bool {
        !self.sensitive_paths.is_empty() || self.script_requested || self.incomplete
    }
    /// `identity_sha256` (:70-74). Compact JSON tuple → sha256 hex.
    pub fn identity_sha256(&self) -> String {
        let payload = serde_json::json!([
            self.sensitive_paths,
            self.script_sources,
            self.script_requested,
            self.incomplete,
        ]);
        format!("{:x}", Sha256::digest(payload.to_string().as_bytes()))
    }
}

fn empty_assessment() -> ShellReadAssessment {
    ShellReadAssessment {
        sensitive_paths: Vec::new(),
        script_sources: Vec::new(),
        script_requested: false,
        incomplete: false,
    }
}

/// `assess_shell_reads` (:77-354).
pub fn assess_shell_reads(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> ShellReadAssessment {
    let original_command_text = command_text;
    let command_text = literal_shell_read_payload(command_text);
    if !command_may_need_read_assessment(
        &command_text,
        cwd,
        command_text.as_str() != original_command_text,
    ) {
        return empty_assessment();
    }

    let roots = runtime_read_roots(cwd, home_dir);
    let mut pending: Vec<(String, Option<PathBuf>, usize)> =
        vec![(command_text, cwd.map(Path::to_path_buf), 0)];
    let mut sensitive: Vec<String> = Vec::new();
    let mut sources: Vec<(String, String)> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut requested = false;
    let mut incomplete = false;
    let mut total_bytes = 0usize;

    while let Some((mut text, current_cwd, depth)) = pending.pop() {
        // A literal delay cannot change cwd or introduce a file read. Inspect
        // its conditional successor conservatively without inventing a cwd
        // failure for the delay itself.
        if let Some(caps) = delay_re().captures(&text) {
            let m = caps.get(0).unwrap();
            let secs: u64 = caps[1].parse().unwrap_or(u64::MAX);
            if secs <= 3600 && !cwd_shadowed_executable("sleep", current_cwd.as_deref()) {
                text = text[m.end()..].to_owned();
            }
        }
        let mut context =
            model_shell_execution_context(&text, current_cwd.as_deref(), cwd, home_dir);
        if context.segments.is_empty() {
            if [".env", "credentials", ".npmrc", ".pypirc", ".netrc"]
                .iter()
                .any(|marker| text.contains(marker))
            {
                incomplete = true;
            }
            continue;
        }
        if context.reason_code.as_deref() == Some(SHELL_CWD_WORKSPACE_ESCAPE) && home_dir.is_some()
        {
            // Inspection may follow a proven directory inside the same home
            // even when execution policy has a narrower workspace boundary.
            let alternate = model_shell_execution_context(
                &text,
                current_cwd.as_deref().or(home_dir),
                home_dir,
                home_dir,
            );
            let first = alternate.segments.first();
            let literal_cd = first.is_some_and(|f| {
                f.directory_operation.as_deref() == Some("cd")
                    && f.control_before.is_empty()
                    && f.tokens.len() == 2
                    && (Path::new(&f.tokens[1]).is_absolute() || f.tokens[1].starts_with("~/"))
            });
            if alternate.complete && (current_cwd.is_some() || literal_cd) {
                context = alternate;
            } else if current_cwd.is_none() {
                // `low_risk_compound_developer_execution_context` requires the
                // git-index/developer-inspection chain; when it cannot prove a
                // rescue the context stays incomplete — identical fail-closed
                // outcome to returning None.
                if let Some(proven) = low_risk_compound_rescue(&text, home_dir) {
                    if proven.complete {
                        context = proven;
                    }
                }
            }
        }
        if context.reason_code.as_deref() == Some(SHELL_CWD_WORKSPACE_ESCAPE)
            && current_cwd.is_some()
        {
            // Read assessment needs the actual literal cwd, not authorization
            // to execute there. Keep script inspection constrained to the
            // original roots below; this evidence-only model cannot grant
            // execution.
            let anchor = current_cwd
                .as_deref()
                .filter(|c| c.is_absolute())
                .map(|_| PathBuf::from("/"));
            if let Some(anchor) = anchor {
                let literal_context = model_shell_execution_context(
                    &text,
                    current_cwd.as_deref(),
                    Some(&anchor),
                    home_dir,
                );
                if literal_context.complete {
                    context = literal_context;
                }
            }
        }
        let raw_model = parse_shell_command(
            &text,
            current_cwd.as_deref(),
            home_dir,
            "posix",
            "shell_string",
            "guard-shell",
            false,
        );
        let raw_segments: Vec<_> = raw_model
            .segments
            .iter()
            .filter(|s| s.execution_context.starts_with("top:"))
            .collect();
        let aligned = raw_segments.len() == context.segments.len();
        let heredocs = extract_heredocs(&raw_model.normalized_text);
        let mut failed_cd_short_circuit = false;
        for index in 0..context.segments.len() {
            let mut execution = context.segments[index].clone();
            let (next_short, unreachable) =
                failed_cd_short_circuit_state(&execution, failed_cd_short_circuit);
            failed_cd_short_circuit = next_short;
            if unreachable {
                continue;
            }
            let raw_segment = if aligned {
                raw_segments.get(index).copied()
            } else {
                None
            };
            if index == 0
                && raw_segment.is_some()
                && matches!(
                    raw_segment.and_then(|s| s.executable.as_deref()),
                    Some("source") | Some(".")
                )
                && execution.control_before.is_empty()
                && context.reason_code.as_deref() == Some(SHELL_CWD_UNRESOLVED_PARENT_SHELL)
                && context.initial_cwd.is_some()
            {
                // A first source invocation reads its operand before sourced
                // code can change the caller's cwd. Later segments stay closed.
                execution.effective_cwd = context.initial_cwd.clone();
                execution.complete = true;
                execution.reason_code = None;
            }
            let model = parse_execution_segment(&execution, &raw_model, raw_segment);
            let owned_substitutions: Vec<_> = raw_model
                .embedded_commands
                .iter()
                .filter(|embedded| {
                    embedded.kind == "substitution"
                        && raw_segment.is_some_and(|rs| {
                            (rs.start <= embedded.start && embedded.start < rs.end)
                                || heredocs.iter().any(|item| {
                                    rs.start <= item.operator_start
                                        && item.operator_start < rs.end
                                        && item.body_start <= embedded.start
                                        && embedded.start < item.end
                                })
                        })
                })
                .collect();
            let Some(model) = model else {
                sensitive.extend(direct_secret_read_paths_from_tokens(
                    &execution.tokens,
                    execution.effective_cwd.as_deref(),
                    home_dir,
                ));
                if segment_may_touch_local_data(&execution) || !owned_substitutions.is_empty() {
                    requested = true;
                    incomplete = true;
                }
                continue;
            };
            let effective_cwd = execution.effective_cwd.clone();
            for substitution in &owned_substitutions {
                if depth >= MAX_DEPTH || substitution.text.len() > MAX_INLINE_SCRIPT_BYTES {
                    requested = true;
                    incomplete = true;
                } else {
                    pending.push((substitution.text.clone(), effective_cwd.clone(), depth + 1));
                }
            }
            sensitive.extend(direct_secret_read_paths(
                &model,
                effective_cwd.as_deref(),
                home_dir,
            ));
            if model.segments.len() > 1 {
                // Embedded commands are included by the command parser but do
                // not have independently proven cwd contexts here.
                requested = true;
                incomplete = true;
            }
            let Some(primary) = model.segments.first() else {
                continue;
            };
            let (executable, arguments, unwrap_incomplete) = unwrap_execution_builtin(
                primary.executable.as_deref().unwrap_or(""),
                &primary.arguments,
            );
            if unwrap_incomplete {
                requested = true;
                incomplete = true;
                continue;
            }
            let Some(executable) = executable else {
                continue;
            };
            let name = command_name_for(&executable);
            let owned_heredocs: Vec<_> = heredocs
                .iter()
                .filter(|item| {
                    primary.start <= item.operator_start && item.operator_start < primary.end
                })
                .collect();
            for heredoc in &owned_heredocs {
                if SHELLS.contains(&name.as_str()) {
                    requested = true;
                    if depth >= MAX_DEPTH || heredoc.body.len() > MAX_INLINE_SCRIPT_BYTES {
                        incomplete = true;
                    } else {
                        pending.push((heredoc.body.clone(), effective_cwd.clone(), depth + 1));
                    }
                } else if ["node", "bun", "ruby", "perl"].contains(&name.as_str())
                    || python_executable(&name)
                {
                    for literal in literal_read_paths(&heredoc.body) {
                        if let Some(path) =
                            sensitive_path(&literal, effective_cwd.as_deref(), home_dir)
                        {
                            sensitive.push(path);
                        }
                    }
                }
            }
            let (payload, command_string_requested) = shell_command_string(&executable, &arguments);
            let shell_stdin_mode =
                SHELLS.contains(&name.as_str()) && arguments.iter().any(|a| a == "-s");
            let input_redirect = model.redirects.iter().any(|r| {
                let op = r.operator.trim_start_matches(|c: char| c.is_ascii_digit());
                op == "<" || op == "<>"
            });
            if shell_stdin_mode
                && (flow_operator_before(&execution).map(String::as_str) == Some("|")
                    || input_redirect)
            {
                requested = true;
                incomplete = true;
            }
            if command_string_requested {
                requested = true;
                match payload {
                    Some(p) if p.len() <= MAX_INLINE_SCRIPT_BYTES && depth < MAX_DEPTH => {
                        pending.push((p, effective_cwd.clone(), depth + 1));
                    }
                    _ => incomplete = true,
                }
            }
            if python_module_launch(&executable, &arguments, effective_cwd.as_deref()) {
                requested = true;
                incomplete = true;
                continue;
            }
            if known_python_module_launch(&executable, &arguments, effective_cwd.as_deref()) {
                continue;
            }
            if interpreter_stdin_launch(&executable, &arguments) {
                if owned_heredocs.is_empty() {
                    requested = true;
                    incomplete = true;
                }
                continue;
            }
            if interpreter_inline_launch(&executable, &arguments) {
                continue;
            }
            let invocation = script_operand(&executable, &arguments);
            if SHELLS.contains(&name.as_str())
                && executable == name
                && arguments.len() == 2
                && arguments[0] == "-n"
                && invocation.is_some()
            {
                // Syntax checking reads this file but does not execute its
                // body.
                let inv = invocation.as_ref().unwrap();
                if let Some(direct) = sensitive_path(&inv.0, effective_cwd.as_deref(), home_dir) {
                    sensitive.push(direct);
                }
                continue;
            }
            let invocation = match invocation {
                Some(inv) => inv,
                None => {
                    if !owned_heredocs.is_empty()
                        && (SHELLS.contains(&name.as_str())
                            || ["node", "bun", "ruby", "perl"].contains(&name.as_str())
                            || python_executable(&name))
                    {
                        continue;
                    }
                    let local_executable = local_executable_operand(
                        &executable,
                        effective_cwd.as_deref(),
                        home_dir,
                        &roots,
                    );
                    if local_executable.is_none() || !unresolved_local_script_launch(&executable) {
                        if local_executable.is_none()
                            && (unresolved_local_script_launch(&executable)
                                || cwd_shadowed_executable(&executable, effective_cwd.as_deref()))
                        {
                            requested = true;
                            incomplete = true;
                        }
                        continue;
                    }
                    (local_executable.unwrap(), false)
                }
            };
            requested = true;
            let (operand, is_shell) = invocation;
            if let Some(direct) = sensitive_path(&operand, effective_cwd.as_deref(), home_dir) {
                sensitive.push(direct);
                continue;
            }
            let literal_source = model.segments.len() == 1
                && (executable == "source" || executable == ".")
                && effective_cwd.is_some();
            if (!context.complete && !literal_source)
                || depth >= MAX_DEPTH
                || visited.len() >= MAX_SCRIPTS
            {
                incomplete = true;
                continue;
            }
            let Some(source) =
                resolved_runtime_path(&operand, effective_cwd.as_deref(), home_dir, Some(&roots))
            else {
                incomplete = true;
                continue;
            };
            let lexical_source = PathBuf::from(normalize_path(
                &expand_home(&operand, home_dir),
                effective_cwd.as_deref(),
            ));
            if source != lexical_source {
                incomplete = true;
                continue;
            }
            let source_name = source.to_string_lossy().into_owned();
            if visited.contains(&source_name) {
                incomplete = true;
                continue;
            }
            visited.insert(source_name.clone());
            let Some(payload) = read_small_runtime_text_file(&source, &roots) else {
                incomplete = true;
                continue;
            };
            let encoded_len = payload.len();
            total_bytes += encoded_len;
            if total_bytes > MAX_TOTAL_BYTES {
                incomplete = true;
                continue;
            }
            sources.push((
                source_name,
                format!("{:x}", Sha256::digest(payload.as_bytes())),
            ));
            if is_shell {
                pending.push((payload, effective_cwd.clone(), depth + 1));
            } else {
                for literal in literal_read_paths(&payload) {
                    if let Some(path) = sensitive_path(&literal, effective_cwd.as_deref(), home_dir)
                    {
                        sensitive.push(path);
                    }
                }
            }
        }
    }
    let mut deduped: Vec<String> = Vec::new();
    for path in sensitive {
        if !deduped.contains(&path) {
            deduped.push(path);
        }
    }
    ShellReadAssessment {
        sensitive_paths: deduped,
        script_sources: sources,
        script_requested: requested,
        incomplete,
    }
}

/// `low_risk_compound_developer_execution_context` rescue — the full
/// git-index/developer-inspection chain is not ported; it can only PROVE an
/// alternate context (precision), never weaken one. Returning `None` keeps
/// the identical fail-closed outcome the unproven path produces.
fn low_risk_compound_rescue(
    _text: &str,
    _home_dir: Option<&Path>,
) -> Option<ShellExecutionContext> {
    None
}
