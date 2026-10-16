//! Shell working-directory half of the canonical request context.
//!
//! Converts between the wire DTOs and the native shell model in
//! `guard-command` so the resident, not Python, owns path resolution, symlink
//! and descriptor identity checks, and context hashing.

use std::path::{Path, PathBuf};

use guard_command::shell_execution_context::{
    model_shell_execution_context_bounded, shell_execution_context_hash,
    shell_execution_context_metadata, shell_execution_segment_hash,
    validate_shell_execution_segment_bounded, ShellExecutionContext, ShellExecutionSegment,
    ShellModelLimit, ShellModelLimits, ShellPathIdentity, ShellPathProof,
};
use guard_contracts::{
    ShellContextV1, ShellPathIdentityV1, ShellPathProofV1, ShellSegmentV1,
    MAX_REQUEST_CONTEXT_PATH_BYTES, MAX_REQUEST_CONTEXT_SEGMENTS,
    MAX_REQUEST_CONTEXT_SEGMENT_PROOFS, MAX_REQUEST_CONTEXT_TOTAL_PROOFS,
};
use serde_json::{json, Value};

use crate::request_context_op::{Budget, BUDGET_EXCEEDED};

const INVALID: &str = "native_request_context_shell_invalid";
const TOO_LARGE: &str = "native_request_context_shell_too_large";

fn limits(budget: &Budget) -> ShellModelLimits {
    ShellModelLimits {
        max_segments: MAX_REQUEST_CONTEXT_SEGMENTS,
        max_segment_proofs: MAX_REQUEST_CONTEXT_SEGMENT_PROOFS,
        max_total_proofs: MAX_REQUEST_CONTEXT_TOTAL_PROOFS,
        deadline: Some(budget.deadline()),
    }
}

fn limit_code(limit: ShellModelLimit) -> &'static str {
    match limit {
        ShellModelLimit::Deadline => BUDGET_EXCEEDED,
        ShellModelLimit::Segments | ShellModelLimit::Proofs => TOO_LARGE,
    }
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn identity_to_wire(identity: &ShellPathIdentity) -> ShellPathIdentityV1 {
    ShellPathIdentityV1 {
        device: identity.device,
        inode: identity.inode,
        mode: identity.mode,
        change_time_ns: identity.change_time_ns,
        creation_time_ns: identity.creation_time_ns,
    }
}

fn identity_from_wire(identity: &ShellPathIdentityV1) -> ShellPathIdentity {
    ShellPathIdentity {
        device: identity.device,
        inode: identity.inode,
        mode: identity.mode,
        change_time_ns: identity.change_time_ns,
        creation_time_ns: identity.creation_time_ns,
    }
}

fn segment_to_wire(segment: &ShellExecutionSegment) -> ShellSegmentV1 {
    ShellSegmentV1 {
        tokens: segment.tokens.clone(),
        segment_index: segment.segment_index as u64,
        control_before: segment.control_before.clone(),
        control_after: segment.control_after.clone(),
        effective_cwd: segment.effective_cwd.as_deref().map(path_text),
        cwd_identity: segment.cwd_identity.as_ref().map(identity_to_wire),
        cwd_path_proofs: segment
            .cwd_path_proofs
            .iter()
            .map(|proof| ShellPathProofV1 {
                lexical_path: path_text(&proof.lexical_path),
                resolved_path: path_text(&proof.resolved_path),
                identity: identity_to_wire(&proof.identity),
            })
            .collect(),
        cwd_source: segment.cwd_source.clone(),
        directory_stack: segment
            .directory_stack
            .iter()
            .map(|path| path_text(path))
            .collect(),
        complete: segment.complete,
        reason_code: segment.reason_code.clone(),
        directory_operation: segment.directory_operation.clone(),
    }
}

pub(crate) fn context_to_wire(context: &ShellExecutionContext) -> ShellContextV1 {
    ShellContextV1 {
        command_text: context.command_text.clone(),
        initial_cwd: context.initial_cwd.as_deref().map(path_text),
        workspace_root: context.workspace_root.as_deref().map(path_text),
        workspace_identity: context.workspace_identity.as_ref().map(identity_to_wire),
        segments: context.segments.iter().map(segment_to_wire).collect(),
        complete: context.complete,
        reason_code: context.reason_code.clone(),
        directory_change_present: context.directory_change_present,
    }
}

fn checked_path(text: &str) -> Result<PathBuf, &'static str> {
    if text.len() > MAX_REQUEST_CONTEXT_PATH_BYTES || text.contains('\0') {
        return Err(INVALID);
    }
    Ok(PathBuf::from(text))
}

fn optional_path(text: &Option<String>) -> Result<Option<PathBuf>, &'static str> {
    text.as_deref().map(checked_path).transpose()
}

fn segment_from_wire(segment: &ShellSegmentV1) -> Result<ShellExecutionSegment, &'static str> {
    let proofs = segment
        .cwd_path_proofs
        .iter()
        .map(|proof| {
            Ok(ShellPathProof {
                lexical_path: checked_path(&proof.lexical_path)?,
                resolved_path: checked_path(&proof.resolved_path)?,
                identity: identity_from_wire(&proof.identity),
            })
        })
        .collect::<Result<Vec<_>, &'static str>>()?;
    Ok(ShellExecutionSegment {
        tokens: segment.tokens.clone(),
        segment_index: usize::try_from(segment.segment_index).map_err(|_| INVALID)?,
        control_before: segment.control_before.clone(),
        control_after: segment.control_after.clone(),
        effective_cwd: optional_path(&segment.effective_cwd)?,
        cwd_identity: segment.cwd_identity.as_ref().map(identity_from_wire),
        cwd_path_proofs: proofs,
        cwd_source: segment.cwd_source.clone(),
        directory_stack: segment
            .directory_stack
            .iter()
            .map(|path| checked_path(path))
            .collect::<Result<Vec<_>, _>>()?,
        complete: segment.complete,
        reason_code: segment.reason_code.clone(),
        directory_operation: segment.directory_operation.clone(),
    })
}

/// Bound a caller-supplied context before any of it is converted or touched.
fn admit_wire_bounds(context: &ShellContextV1) -> Result<(), &'static str> {
    if context.segments.len() > MAX_REQUEST_CONTEXT_SEGMENTS {
        return Err(TOO_LARGE);
    }
    let mut total = 0usize;
    for segment in &context.segments {
        let held = segment.cwd_path_proofs.len();
        total = total.saturating_add(held);
        if held > MAX_REQUEST_CONTEXT_SEGMENT_PROOFS || total > MAX_REQUEST_CONTEXT_TOTAL_PROOFS {
            return Err(TOO_LARGE);
        }
    }
    Ok(())
}

pub(crate) fn context_from_wire(
    context: &ShellContextV1,
    budget: &Budget,
) -> Result<ShellExecutionContext, &'static str> {
    admit_wire_bounds(context)?;
    budget.check()?;
    Ok(ShellExecutionContext {
        command_text: context.command_text.clone(),
        initial_cwd: optional_path(&context.initial_cwd)?,
        workspace_root: optional_path(&context.workspace_root)?,
        workspace_identity: context.workspace_identity.as_ref().map(identity_from_wire),
        segments: context
            .segments
            .iter()
            .map(|segment| {
                budget.check()?;
                segment_from_wire(segment)
            })
            .collect::<Result<Vec<_>, _>>()?,
        complete: context.complete,
        reason_code: context.reason_code.clone(),
        directory_change_present: context.directory_change_present,
    })
}

/// Model the shell working directory. When the caller did not declare a cwd
/// the model runs from the caller's process cwd and reports that source, the
/// resident's own cwd is never consulted.
pub(crate) fn build_shell_context(
    script: &str,
    cwd: Option<&str>,
    fallback_cwd: Option<&str>,
    workspace: Option<&str>,
    home_dir: Option<&str>,
    budget: &Budget,
) -> Result<ShellExecutionContext, &'static str> {
    let declared = optional_path(&cwd.map(str::to_owned))?;
    let effective = match (&declared, fallback_cwd) {
        (Some(path), _) => path.clone(),
        (None, Some(fallback)) => checked_path(fallback)?,
        (None, None) => return Err("native_request_context_cwd_required"),
    };
    let workspace = optional_path(&workspace.map(str::to_owned))?;
    let home = optional_path(&home_dir.map(str::to_owned))?;
    let mut context = model_shell_execution_context_bounded(
        script,
        Some(&effective),
        workspace.as_deref(),
        home.as_deref(),
        &limits(budget),
    )
    .map_err(limit_code)?;
    if declared.is_none() {
        for segment in &mut context.segments {
            if segment.cwd_source == "workspace" {
                segment.cwd_source = "process".to_owned();
            }
        }
    }
    Ok(context)
}

/// Hashes and projections the resident derives for a modeled context.
pub(crate) fn context_report(
    context: &ShellExecutionContext,
    budget: &Budget,
) -> Result<Value, &'static str> {
    let mut segment_hashes = Vec::with_capacity(context.segments.len());
    for segment in &context.segments {
        budget.check()?;
        segment_hashes.push(shell_execution_segment_hash(context, segment));
    }
    budget.check()?;
    Ok(json!({
        "context": context_to_wire(context),
        "context_hash": shell_execution_context_hash(context),
        "segment_hashes": segment_hashes,
        "metadata": shell_execution_context_metadata(context),
    }))
}

/// Re-read the filesystem for one modeled segment.
pub(crate) fn validate_segment(
    context: &ShellContextV1,
    segment_index: u64,
    budget: &Budget,
) -> Result<Value, &'static str> {
    let index = usize::try_from(segment_index).map_err(|_| INVALID)?;
    if index >= context.segments.len() {
        return Err(INVALID);
    }
    let native = context_from_wire(context, budget)?;
    let segment = native.segments.get(index).ok_or(INVALID)?;
    let (cwd, reason) = validate_shell_execution_segment_bounded(&native, segment, &limits(budget))
        .map_err(limit_code)?;
    budget.check()?;
    Ok(json!({
        "effective_cwd": cwd.as_deref().map(path_text),
        "reason_code": reason,
        "context_hash": shell_execution_context_hash(&native),
        "segment_hash": shell_execution_segment_hash(&native, segment),
    }))
}

pub(crate) fn hash_context(
    context: &ShellContextV1,
    segment_index: Option<u64>,
    budget: &Budget,
) -> Result<Value, &'static str> {
    let index = segment_index
        .map(|index| usize::try_from(index).map_err(|_| INVALID))
        .transpose()?;
    if index.is_some_and(|index| index >= context.segments.len()) {
        return Err(INVALID);
    }
    let native = context_from_wire(context, budget)?;
    let segment_hash = match index {
        None => None,
        Some(index) => {
            let segment = native.segments.get(index).ok_or(INVALID)?;
            Some(shell_execution_segment_hash(&native, segment))
        }
    };
    budget.check()?;
    Ok(json!({
        "context_hash": shell_execution_context_hash(&native),
        "segment_hash": segment_hash,
        "metadata": shell_execution_context_metadata(&native),
    }))
}
