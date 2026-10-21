//! Side-effect-free shell working-directory execution context modeling
//! (`runtime/shell_execution_context.py`, 479 lines — verbatim).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::shell_execution_context_support::*;
pub use crate::shell_execution_context_support::{ShellPathIdentity, ShellPathProof};
pub use crate::shell_model_limits::{ShellModelLimit, ShellModelLimits};

fn shell_directory_command_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?:^|(?:&&|\|\||[;|&(){}\n]))\s*(?:(?:builtin|command|time)\s+(?:-[^\s]+\s+)*|function\s+|!\s+)?(?:cd|pushd|popd)\b",
        )
        .expect("shell directory command")
    })
}

/// `ShellExecutionSegment` (:41-63).
#[derive(Clone, Debug)]
pub struct ShellExecutionSegment {
    pub tokens: Vec<String>,
    pub segment_index: usize,
    pub control_before: Vec<String>,
    pub control_after: Vec<String>,
    pub effective_cwd: Option<PathBuf>,
    pub cwd_identity: Option<ShellPathIdentity>,
    pub cwd_path_proofs: Vec<ShellPathProof>,
    pub cwd_source: String,
    pub directory_stack: Vec<PathBuf>,
    pub complete: bool,
    pub reason_code: Option<String>,
    pub directory_operation: Option<String>,
}

impl ShellExecutionSegment {
    #[allow(dead_code)] // consumed by unix read-floor callers gated off on Windows
    pub fn command_text(&self) -> String {
        crate::command_launcher_floors::shlex_join(&self.tokens)
    }
    pub fn control_operator(&self) -> Option<&String> {
        last_flow_operator(&self.control_after)
    }
}

/// `ShellExecutionContext` (:66-89).
#[derive(Clone, Debug)]
pub struct ShellExecutionContext {
    pub command_text: String,
    pub initial_cwd: Option<PathBuf>,
    pub workspace_root: Option<PathBuf>,
    pub workspace_identity: Option<ShellPathIdentity>,
    pub segments: Vec<ShellExecutionSegment>,
    pub complete: bool,
    pub reason_code: Option<String>,
    #[allow(dead_code)] // consumed by unix read-floor callers gated off on Windows
    pub directory_change_present: bool,
}

impl ShellExecutionContext {
    pub fn effective_cwds(&self) -> Vec<PathBuf> {
        let mut result: Vec<PathBuf> = Vec::new();
        for segment in &self.segments {
            if segment.directory_operation.is_some()
                || !segment.complete
                || segment.effective_cwd.is_none()
            {
                continue;
            }
            let cwd = segment.effective_cwd.clone().unwrap();
            if !result.contains(&cwd) {
                result.push(cwd);
            }
        }
        result
    }
    pub fn context_hash(&self) -> String {
        shell_execution_context_hash(self)
    }
}

#[derive(Clone, Debug)]
struct ShellState {
    cwd: Option<PathBuf>,
    cwd_identity: Option<ShellPathIdentity>,
    cwd_path_proofs: Vec<ShellPathProof>,
    cwd_source: String,
    stack: Vec<DirectoryStackEntry>,
    reason_code: Option<String>,
}

#[derive(Clone, Debug)]
struct DirectoryStackEntry {
    cwd: PathBuf,
    cwd_identity: ShellPathIdentity,
    cwd_path_proofs: Vec<ShellPathProof>,
}

/// `model_shell_execution_context` (:113-249).
pub fn model_shell_execution_context(
    command_text: &str,
    cwd: Option<&Path>,
    workspace_root: Option<&Path>,
    home_dir: Option<&Path>,
) -> ShellExecutionContext {
    model_shell_execution_context_bounded(
        command_text,
        cwd,
        workspace_root,
        home_dir,
        &ShellModelLimits::unbounded(),
    )
    .unwrap_or_else(|_| unreachable!("unbounded modeling has no limit to exceed"))
}

/// The same model, refusing once a segment, proof or time limit is crossed.
pub fn model_shell_execution_context_bounded(
    command_text: &str,
    cwd: Option<&Path>,
    workspace_root: Option<&Path>,
    home_dir: Option<&Path>,
    limits: &ShellModelLimits,
) -> Result<ShellExecutionContext, ShellModelLimit> {
    let directory_change_present = shell_directory_command_re().is_match(command_text);
    let initial_input = cwd
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok());
    let root_input = workspace_root
        .map(Path::to_path_buf)
        .or_else(|| initial_input.clone());
    let (initial_cwd, initial_identity, initial_reason) = match initial_input.as_deref() {
        Some(p) => existing_directory(p),
        None => (None, None, Some(SHELL_CWD_MISSING_DIRECTORY)),
    };
    let (root, root_identity, root_reason) = match root_input.as_deref() {
        Some(p) => existing_directory(p),
        None => (None, None, Some(SHELL_CWD_MISSING_DIRECTORY)),
    };
    let mut reason_code = initial_reason.or(root_reason).map(str::to_owned);
    if reason_code.is_none()
        && initial_cwd.is_some()
        && root.is_some()
        && !is_within(initial_cwd.as_ref().unwrap(), root.as_ref().unwrap())
    {
        reason_code = Some(SHELL_CWD_WORKSPACE_ESCAPE.to_owned());
    }
    let ctx_empty = |reason: Option<String>| ShellExecutionContext {
        command_text: command_text.to_owned(),
        initial_cwd: initial_cwd.clone(),
        workspace_root: root.clone(),
        workspace_identity: root_identity.clone(),
        segments: Vec::new(),
        complete: reason.is_none() && !directory_change_present,
        reason_code: reason.or(if directory_change_present {
            Some(SHELL_CWD_UNRESOLVED_SYNTAX.to_owned())
        } else {
            None
        }),
        directory_change_present,
    };
    let tokens = match split_shell_tokens(command_text) {
        Ok(t) => t,
        Err(_) => {
            return Ok(ShellExecutionContext {
                complete: !directory_change_present,
                reason_code: if directory_change_present {
                    Some(SHELL_CWD_UNRESOLVED_SYNTAX.to_owned())
                } else {
                    None
                },
                ..ctx_empty(reason_code.clone())
            });
        }
    };

    let (raw_segments, trailing_controls) = ordered_segments(&tokens);
    limits.admit_segments(raw_segments.len())?;
    let parent_shell_reason = parent_shell_cwd_construct_reason(&raw_segments, &trailing_controls);
    let mut directory_change_present = directory_change_present;
    if let Some(psr) = parent_shell_reason {
        if reason_code.is_none() {
            reason_code = Some(psr.to_owned());
        }
        directory_change_present = true;
    }
    if raw_segments.is_empty() {
        return Ok(ctx_empty(reason_code));
    }

    let mut state = ShellState {
        cwd: if reason_code.is_none() {
            initial_cwd.clone()
        } else {
            None
        },
        cwd_identity: if reason_code.is_none() {
            initial_identity.clone()
        } else {
            None
        },
        cwd_path_proofs: Vec::new(),
        cwd_source: if cwd.is_some() {
            "workspace".to_owned()
        } else {
            "process".to_owned()
        },
        stack: Vec::new(),
        reason_code: reason_code.clone(),
    };
    let mut group_states: Vec<(String, Option<ShellState>)> = Vec::new();
    let mut segments: Vec<ShellExecutionSegment> = Vec::new();
    let mut first_reason = reason_code.clone();
    let mut proof_total = 0usize;

    for index in 0..raw_segments.len() {
        limits.check_deadline()?;
        let (segment_tokens, controls_before) = &raw_segments[index];
        let controls_after: &[String] = if index + 1 < raw_segments.len() {
            &raw_segments[index + 1].1
        } else {
            &trailing_controls
        };
        let (new_state, boundary_reason) =
            apply_group_boundaries_before_segment(state, controls_before, &mut group_states);
        state = new_state;
        let held_proofs = state.cwd_path_proofs.len()
            + state
                .stack
                .iter()
                .map(|entry| entry.cwd_path_proofs.len())
                .sum::<usize>();
        limits.admit_proofs(&mut proof_total, held_proofs)?;
        let mut segment_reason = state
            .reason_code
            .clone()
            .or_else(|| boundary_reason.map(str::to_owned))
            .or_else(|| control_sequence_reason(controls_before, false).map(str::to_owned));
        let mut operation = directory_operation(segment_tokens);
        if let Some(op) = operation.as_mut() {
            directory_change_present = true;
            let flow_before = last_flow_operator(controls_before).cloned();
            let previous_segment = segments.last();
            if matches!(flow_before.as_deref(), Some("&&") | Some("||"))
                && (previous_segment.is_none()
                    || previous_segment
                        .map(|s| s.directory_operation.is_none())
                        .unwrap_or(true)
                    || previous_segment.map(|s| !s.complete).unwrap_or(true)
                    || flow_before.as_deref() == Some("||"))
            {
                op.reason_code = Some(SHELL_CWD_UNRESOLVED_CONTROL_FLOW);
            }
            if segment_reason.is_none() {
                segment_reason = op.reason_code.map(str::to_owned);
            }
        }
        let mut segment = ShellExecutionSegment {
            tokens: segment_tokens.clone(),
            segment_index: index,
            control_before: controls_before.clone(),
            control_after: controls_after.to_vec(),
            effective_cwd: state.cwd.clone(),
            cwd_identity: state.cwd_identity.clone(),
            cwd_path_proofs: state.cwd_path_proofs.clone(),
            cwd_source: state.cwd_source.clone(),
            directory_stack: state.stack.iter().map(|e| e.cwd.clone()).collect(),
            complete: segment_reason.is_none(),
            reason_code: segment_reason.clone(),
            directory_operation: operation.as_ref().map(|o| o.name.clone()),
        };
        if let Some(op) = operation {
            let (next_state, operation_reason) = apply_directory_operation(
                &op,
                state,
                root.as_deref(),
                home_dir,
                controls_before,
                controls_after,
            );
            state = next_state;
            if let Some(or) = operation_reason {
                segment.complete = false;
                segment.reason_code = Some(or.clone());
                segment_reason = Some(or);
            }
        }
        segments.push(segment);
        if first_reason.is_none() && segment_reason.is_some() {
            first_reason = segment_reason;
        }
    }

    let (_trailing_state, trailing_boundary_reason) =
        apply_group_boundaries_before_segment(state, &trailing_controls, &mut group_states);
    let mut trailing_reason = trailing_boundary_reason
        .map(str::to_owned)
        .or_else(|| control_sequence_reason(&trailing_controls, true).map(str::to_owned));
    if trailing_reason.is_none() && trailing_controls.iter().any(|t| t == "(" || t == "{") {
        trailing_reason = Some(SHELL_CWD_UNRESOLVED_SYNTAX.to_owned());
    }
    if !group_states.is_empty() && trailing_reason.is_none() {
        trailing_reason = Some(SHELL_CWD_UNRESOLVED_SYNTAX.to_owned());
    }
    if first_reason.is_none() && trailing_reason.is_some() && directory_change_present {
        first_reason = trailing_reason.clone();
    }
    let mut complete = first_reason.is_none();
    if directory_change_present && trailing_reason.is_some() && !segments.is_empty() {
        if let Some(last) = segments.last_mut() {
            last.complete = false;
            last.reason_code = trailing_reason.clone();
        }
        complete = false;
    }
    Ok(ShellExecutionContext {
        command_text: command_text.to_owned(),
        initial_cwd,
        workspace_root: root,
        workspace_identity: root_identity,
        segments,
        complete,
        reason_code: first_reason,
        directory_change_present,
    })
}

/// `validate_shell_execution_segment` (:252-274).
pub fn validate_shell_execution_segment(
    context: &ShellExecutionContext,
    segment: &ShellExecutionSegment,
) -> (Option<PathBuf>, Option<String>) {
    validate_shell_execution_segment_bounded(context, segment, &ShellModelLimits::unbounded())
        .unwrap_or_else(|_| unreachable!("unbounded validation has no limit to exceed"))
}

/// Revalidation that stops between filesystem proof checks once the deadline
/// passes.
pub fn validate_shell_execution_segment_bounded(
    context: &ShellExecutionContext,
    segment: &ShellExecutionSegment,
    limits: &ShellModelLimits,
) -> Result<(Option<PathBuf>, Option<String>), ShellModelLimit> {
    limits.check_deadline()?;
    if !segment.complete || segment.effective_cwd.is_none() || segment.cwd_identity.is_none() {
        return Ok((
            None,
            Some(
                segment
                    .reason_code
                    .clone()
                    .or_else(|| context.reason_code.clone())
                    .unwrap_or_else(|| SHELL_CWD_PATH_CHANGED.to_owned()),
            ),
        ));
    }
    if context.workspace_root.is_none() || context.workspace_identity.is_none() {
        return Ok((
            None,
            Some(
                context
                    .reason_code
                    .clone()
                    .unwrap_or_else(|| SHELL_CWD_PATH_CHANGED.to_owned()),
            ),
        ));
    }
    let (root, root_identity, root_reason) =
        existing_directory(context.workspace_root.as_ref().unwrap());
    if root_reason.is_some() || root_identity != context.workspace_identity {
        return Ok((None, Some(SHELL_CWD_PATH_CHANGED.to_owned())));
    }
    let (current, current_identity, current_reason) =
        existing_directory(segment.effective_cwd.as_ref().unwrap());
    if current_reason.is_some() || current_identity != segment.cwd_identity {
        return Ok((None, Some(SHELL_CWD_PATH_CHANGED.to_owned())));
    }
    if root.is_none()
        || current.is_none()
        || !is_within(current.as_ref().unwrap(), root.as_ref().unwrap())
    {
        return Ok((None, Some(SHELL_CWD_WORKSPACE_ESCAPE.to_owned())));
    }
    for proof in &segment.cwd_path_proofs {
        limits.check_deadline()?;
        let (proof_current, proof_identity, proof_reason) = existing_directory(&proof.lexical_path);
        if proof_reason.is_some()
            || proof_current.as_deref() != Some(proof.resolved_path.as_path())
            || proof_identity.as_ref() != Some(&proof.identity)
        {
            return Ok((None, Some(SHELL_CWD_PATH_CHANGED.to_owned())));
        }
    }
    Ok((current, None))
}

/// `shell_execution_segment_hash` (:277-290).
#[allow(dead_code)]
pub fn shell_execution_segment_hash(
    context: &ShellExecutionContext,
    segment: &ShellExecutionSegment,
) -> String {
    let payload = json!({
        "schema": "shell-execution-context-v1",
        "command": context.command_text,
        "workspace_root": context.workspace_root.as_ref().map(|p| p.to_string_lossy().into_owned()),
        "workspace_identity": shell_path_identity_payload(context.workspace_identity.as_ref()),
        "segment": segment_payload(segment),
    });
    sha256_payload(&payload)
}

/// `shell_execution_context_hash` (:293-304).
pub fn shell_execution_context_hash(context: &ShellExecutionContext) -> String {
    let payload = json!({
        "schema": "shell-execution-context-v1",
        "command": context.command_text,
        "initial_cwd": context.initial_cwd.as_ref().map(|p| p.to_string_lossy().into_owned()),
        "workspace_root": context.workspace_root.as_ref().map(|p| p.to_string_lossy().into_owned()),
        "workspace_identity": shell_path_identity_payload(context.workspace_identity.as_ref()),
        "complete": context.complete,
        "reason_code": context.reason_code,
        "segments": context.segments.iter().map(segment_payload).collect::<Vec<_>>(),
    });
    sha256_payload(&payload)
}

/// `shell_execution_context_metadata` (:307-317).
#[allow(dead_code)]
pub fn shell_execution_context_metadata(context: &ShellExecutionContext) -> Value {
    let effective_cwds: Vec<String> = context
        .effective_cwds()
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    json!({
        "shell_execution_context_hash": context.context_hash(),
        "shell_execution_context_complete": context.complete,
        "shell_execution_context_reason_code": context.reason_code,
        "shell_execution_effective_cwds": effective_cwds,
        "effective_cwd": effective_cwds.last(),
    })
}

/// `_apply_group_boundaries_before_segment` (:320-345).
fn apply_group_boundaries_before_segment(
    mut state: ShellState,
    controls: &[String],
    group_states: &mut Vec<(String, Option<ShellState>)>,
) -> (ShellState, Option<&'static str>) {
    let mut reason: Option<&'static str> = None;
    for control in controls {
        match control.as_str() {
            "(" => group_states.push(("(".to_owned(), Some(state.clone()))),
            "{" => group_states.push(("{".to_owned(), None)),
            ")" => {
                if group_states.last().map(|(g, _)| g.as_str()) != Some("(") {
                    reason = Some(SHELL_CWD_UNRESOLVED_SYNTAX);
                } else if let Some((_g, Some(saved))) = group_states.pop() {
                    state = saved;
                }
            }
            "}" => {
                if group_states.last().map(|(g, _)| g.as_str()) != Some("{") {
                    reason = Some(SHELL_CWD_UNRESOLVED_SYNTAX);
                } else {
                    group_states.pop();
                }
            }
            _ => {}
        }
    }
    (state, reason)
}

/// `_apply_directory_operation` (:348-420).
fn apply_directory_operation(
    operation: &DirectoryOperation,
    mut state: ShellState,
    workspace_root: Option<&Path>,
    home_dir: Option<&Path>,
    controls_before: &[String],
    controls_after: &[String],
) -> (ShellState, Option<String>) {
    if let Some(rc) = operation.reason_code {
        state.cwd = None;
        state.cwd_identity = None;
        state.reason_code = Some(rc.to_owned());
        return (state, Some(rc.to_owned()));
    }
    if state.cwd.is_none() || state.cwd_identity.is_none() || workspace_root.is_none() {
        let reason = state
            .reason_code
            .clone()
            .unwrap_or_else(|| SHELL_CWD_UNRESOLVED_CONTROL_FLOW.to_owned());
        state.reason_code = Some(reason.clone());
        return (state, Some(reason));
    }
    let mut next_state: ShellState;
    if operation.name == "popd" {
        if state.stack.is_empty() {
            state.cwd = None;
            state.cwd_identity = None;
            state.reason_code = Some(SHELL_CWD_AMBIGUOUS_STACK.to_owned());
            return (state, Some(SHELL_CWD_AMBIGUOUS_STACK.to_owned()));
        }
        let stack_entry = state.stack.last().unwrap().clone();
        next_state = ShellState {
            cwd: Some(stack_entry.cwd),
            cwd_identity: Some(stack_entry.cwd_identity),
            cwd_path_proofs: stack_entry.cwd_path_proofs,
            cwd_source: "shell_popd".to_owned(),
            stack: state.stack[..state.stack.len() - 1].to_vec(),
            reason_code: state.reason_code.clone(),
        };
    } else {
        let Some(operand) = operation.operand.clone() else {
            state.cwd = None;
            state.cwd_identity = None;
            state.reason_code = Some(SHELL_CWD_UNRESOLVED_EXPRESSION.to_owned());
            return (state, Some(SHELL_CWD_UNRESOLVED_EXPRESSION.to_owned()));
        };
        let (destination, destination_identity, destination_proof, reason) =
            resolve_directory_operand(
                &operand,
                state.cwd.as_ref().unwrap(),
                workspace_root.unwrap(),
                home_dir,
            );
        if reason.is_some()
            || destination.is_none()
            || destination_identity.is_none()
            || destination_proof.is_none()
        {
            let failure_reason = reason.unwrap_or(SHELL_CWD_MISSING_DIRECTORY);
            state.cwd = None;
            state.cwd_identity = None;
            state.reason_code = Some(failure_reason.to_owned());
            return (state, Some(failure_reason.to_owned()));
        }
        let mut stack = state.stack.clone();
        if operation.name == "pushd" {
            if stack.len() >= MAX_DIRECTORY_STACK_DEPTH {
                state.cwd = None;
                state.cwd_identity = None;
                state.reason_code = Some(SHELL_CWD_STACK_LIMIT.to_owned());
                return (state, Some(SHELL_CWD_STACK_LIMIT.to_owned()));
            }
            stack.push(DirectoryStackEntry {
                cwd: state.cwd.clone().unwrap(),
                cwd_identity: state.cwd_identity.clone().unwrap(),
                cwd_path_proofs: state.cwd_path_proofs.clone(),
            });
        }
        let mut proofs = state.cwd_path_proofs.clone();
        proofs.push(destination_proof.unwrap());
        next_state = ShellState {
            cwd: destination,
            cwd_identity: destination_identity,
            cwd_path_proofs: proofs,
            cwd_source: format!("shell_{}", operation.name),
            stack,
            reason_code: state.reason_code.clone(),
        };
    }
    let flow_before = last_flow_operator(controls_before).cloned();
    let flow = last_flow_operator(controls_after).cloned();
    if matches!(flow_before.as_deref(), Some("|") | Some("|&")) {
        return (state, None);
    }
    if matches!(flow.as_deref(), Some("|") | Some("|&") | Some("&")) {
        return (state, None);
    }
    if flow.as_deref() == Some("||") {
        next_state.cwd = None;
        next_state.cwd_identity = None;
        next_state.reason_code = Some(SHELL_CWD_UNRESOLVED_CONTROL_FLOW.to_owned());
        return (
            next_state,
            Some(SHELL_CWD_UNRESOLVED_CONTROL_FLOW.to_owned()),
        );
    }
    (next_state, None)
}

/// `_segment_payload` (:423-444).
fn segment_payload(segment: &ShellExecutionSegment) -> Value {
    json!({
        "tokens": segment.tokens,
        "segment_index": segment.segment_index,
        "control_before": segment.control_before,
        "control_after": segment.control_after,
        "effective_cwd": segment.effective_cwd.as_ref().map(|p| p.to_string_lossy().into_owned()),
        "cwd_identity": shell_path_identity_payload(segment.cwd_identity.as_ref()),
        "cwd_path_proofs": segment.cwd_path_proofs.iter().map(|p| json!({
            "lexical_path": p.lexical_path.to_string_lossy(),
            "resolved_path": p.resolved_path.to_string_lossy(),
            "identity": shell_path_identity_payload(Some(&p.identity)),
        })).collect::<Vec<_>>(),
        "cwd_source": segment.cwd_source,
        "directory_stack": segment.directory_stack.iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>(),
        "complete": segment.complete,
        "reason_code": segment.reason_code,
        "directory_operation": segment.directory_operation,
    })
}

/// `_sha256_payload` (:447-454). Resident-side: canonical JSON + sha256,
/// `sha256:` prefix, strict `guard-context-unbound` fallback is unreachable
/// (this IS the resident worker).
fn sha256_payload(payload: &Value) -> String {
    let mut out = Vec::new();
    let _ = guard_contracts::write_canonical_json(payload, &mut out);
    format!("sha256:{:x}", Sha256::digest(&out))
}
