//! Whole-command developer execution contexts, including bounded verified
//! source edits (`source_edit_context.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::codex_output_fs as pyfs;
use crate::codex_output_py::PyPath;
use crate::sfrs_developer_graph::{
    low_risk_compound_developer_execution_context, starts_with_literal_cd, GraphInputs,
};
use crate::sfrs_developer_inspection::{
    read_only_lookup_primary_segment_is_safe, static_shell_segment_is_safe,
};
use crate::sfrs_gh_bindings::py_pattern;
use crate::sfrs_git_index::index_inspection_execution_context;
use crate::sfrs_shell_tokens::shell_segment_primary_command;
use crate::sfrs_source_edit::{
    bounded_edit_workspace_is_safe, bounded_in_place_sed_target, same_workspace_file,
};
use crate::sfrs_static_safety::{
    leading_literal_cd_workspace_root, without_safe_inspection_redirections,
};
use crate::shell_execution_context::{
    model_shell_execution_context, validate_shell_execution_segment, ShellExecutionContext,
};
use crate::shell_secret_read_support::search_concrete_file_operand_tokens;

static DELAYED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&py_pattern(
        r"(?s)\A\s*sleep\s+([1-9][0-9]{0,3})\s*&&\s*(.+)\z",
    ))
    .expect("delayed command pattern")
});

/// `_shell_execution_context_validation_reason`.
pub(crate) fn shell_execution_context_validation_reason(
    context: &ShellExecutionContext,
) -> Option<String> {
    if !context.complete {
        return context.reason_code.clone();
    }
    context
        .segments
        .iter()
        .find_map(|segment| validate_shell_execution_segment(context, segment).1)
}

/// `low_risk_compound_developer_execution_context`.
pub(crate) fn low_risk_developer_execution_context(
    command_text: &str,
    inputs: &GraphInputs,
) -> Option<ShellExecutionContext> {
    if let Some(captures) = DELAYED.captures(command_text) {
        if captures[1]
            .parse::<u32>()
            .is_ok_and(|seconds| seconds <= 3600)
        {
            let mut recovered =
                low_risk_compound_developer_execution_context(&captures[2], inputs)?;
            recovered.command_text = command_text.to_owned();
            return Some(recovered);
        }
    }
    low_risk_compound_developer_execution_context(command_text, inputs)
        .or_else(|| {
            index_inspection_execution_context(
                command_text,
                inputs.cwd,
                Some(inputs.home_dir),
                inputs.ctx,
            )
        })
        .or_else(|| bounded_verified_source_edit_execution_context(command_text, inputs))
}

/// `_bounded_verified_source_edit_execution_context`: one literal source
/// substitution followed by same-file verification.
pub(crate) fn bounded_verified_source_edit_execution_context(
    command_text: &str,
    inputs: &GraphInputs,
) -> Option<ShellExecutionContext> {
    let (home_dir, ctx) = (inputs.home_dir, inputs.ctx);
    if ["$(", "`", "<(", ">("]
        .iter()
        .any(|marker| command_text.contains(marker))
    {
        return None;
    }
    let modeled = command_text.replace("\\\r\n", " ").replace("\\\n", " ");
    let context =
        model_shell_execution_context(&modeled, Some(home_dir), Some(home_dir), Some(home_dir));
    let workspace_root = leading_literal_cd_workspace_root(&context, home_dir)?;
    let resolved_home = pyfs::resolve(&PyPath::new(&home_dir.to_string_lossy()))?.to_string();
    if workspace_root.to_string_lossy() == resolved_home
        || !bounded_edit_workspace_is_safe(&workspace_root, home_dir)
    {
        return None;
    }
    let context = model_shell_execution_context(
        &modeled,
        Some(&workspace_root),
        Some(&workspace_root),
        Some(home_dir),
    );
    if !starts_with_literal_cd(&context)
        || shell_execution_context_validation_reason(&context).is_some()
        || !matches!(context.segments.len(), 3 | 4)
    {
        return None;
    }
    let edit = &context.segments[1];
    let (edit_name, edit_index) = shell_segment_primary_command(&edit.tokens);
    let edit_index = edit_index?;
    if edit_name.as_deref() != Some("sed") || edit.control_before != ["&&"] {
        return None;
    }
    let edit_args = without_safe_inspection_redirections(&edit.tokens[edit_index + 1..])?;
    let target = bounded_in_place_sed_target(
        &edit_args,
        edit.effective_cwd.as_deref().unwrap_or(&workspace_root),
        &workspace_root,
    )?;
    let verification_segments = &context.segments[2..];
    let sequenced = |control: &[String]| control == ["&&"] || control == ["\n"];
    if verification_segments.len() == 2 {
        let label = &verification_segments[0];
        let (label_name, label_index) = shell_segment_primary_command(&label.tokens);
        let label_index = label_index?;
        if label_name.as_deref() != Some("echo") || !sequenced(&label.control_before) {
            return None;
        }
        let label_args = without_safe_inspection_redirections(&label.tokens[label_index + 1..])?;
        if !static_shell_segment_is_safe(&label_args) {
            return None;
        }
    }
    let verification = verification_segments.last()?;
    let (name, index) = shell_segment_primary_command(&verification.tokens);
    let (name, index) = (name?, index?);
    if !matches!(name.as_str(), "grep" | "egrep" | "fgrep")
        || !sequenced(&verification.control_before)
    {
        return None;
    }
    let args = without_safe_inspection_redirections(&verification.tokens[index + 1..])?;
    let verification_root: &Path = verification
        .effective_cwd
        .as_deref()
        .unwrap_or(&workspace_root);
    if !read_only_lookup_primary_segment_is_safe(&name, &args, Some(verification_root), ctx) {
        return None;
    }
    let targets = search_concrete_file_operand_tokens(&name, &args);
    if targets.len() != 1 || !same_workspace_file(&target, &targets[0], &workspace_root) {
        return None;
    }
    let mut result = context;
    result.command_text = command_text.to_owned();
    Some(result)
}
