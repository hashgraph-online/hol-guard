//! Safe Kubernetes and developer workflow recognition
//! (`secret_file_request_services/developer_routines.py`).
//!
//! Git inspection of one modeled segment and the trusted git binary belong to
//! the [`InspectionHost`](crate::codex_output_env::InspectionHost); a host
//! without them refuses.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::PyPath;
use crate::sfrs_constants::{
    READ_ONLY_LOOKUP_COMMANDS, READ_ONLY_LOOKUP_FILTERS, SAFE_STATIC_SHELL_COMMANDS,
};
use crate::sfrs_developer_graph::{
    compound_developer_effect_graph, git_segment, DeveloperShellEffect, GraphInputs,
};
use crate::sfrs_git_index::is_low_risk_git_index_inspection;
use crate::sfrs_git_routines::{git_log_has_execution_free_config, read_only_git_invocation};
use crate::sfrs_interpreter_scripts::is_python_interpreter_command;
use crate::sfrs_kubernetes_commands::kubernetes_read_only_inventory_args;
use crate::sfrs_routines_support::{
    git_status_has_execution_free_config, is_relative_to, resolve, resolve_strict,
    safe_git_status_cd_target, to_path,
};
use crate::sfrs_shell_tokens::{iter_shell_command_segments, shell_segment_primary_command};
use crate::sfrs_source_edit_context::shell_execution_context_validation_reason;
use crate::sfrs_static_safety::{
    leading_literal_cd_workspace_root, safe_cli_metadata_segment_is_safe, which_for_execution_cwd,
    without_safe_inspection_redirections,
};
use crate::shell_command_wrappers::is_trusted_absolute_command_path;
use crate::shell_execution_context::{
    model_shell_execution_context, ShellExecutionContext, ShellExecutionSegment,
};

fn contains_any(text: &str, markers: &[&str]) -> bool {
    markers.iter().any(|marker| text.contains(marker))
}

fn path_text(path: &Path) -> PyPath {
    PyPath::new(&path.to_string_lossy())
}

/// `_looks_like_safe_kubernetes_inventory_command`.
pub(crate) fn looks_like_safe_kubernetes_inventory_command(
    command_text: &str,
    parts: &[String],
    cwd: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    if contains_any(command_text, &["$(", "`", "<(", ">("]) {
        return false;
    }
    let segments = iter_shell_command_segments(parts);
    if segments.is_empty() {
        return false;
    }
    let base = cwd.map_or_else(|| ctx.process_cwd.clone(), path_text);
    let Some(mut effective_cwd) = resolve(&base, ctx).map(|path| to_path(&path)) else {
        return false;
    };
    let mut saw_inventory = false;
    for segment in &segments {
        let (command_name, command_index) = shell_segment_primary_command(segment);
        let (Some(command_name), Some(0)) = (command_name, command_index) else {
            return false;
        };
        let Some(args) = without_safe_inspection_redirections(&segment[1..]) else {
            return false;
        };
        if let Some(next_cwd) = safe_git_status_cd_target(&command_name, &args, &effective_cwd, ctx)
        {
            effective_cwd = next_cwd;
            continue;
        }
        let executable = &segment[0];
        if executable.contains('/') || executable.contains('\\') {
            return false;
        }
        if !kubernetes_read_only_inventory_args(&command_name, &args) {
            return false;
        }
        saw_inventory = true;
    }
    saw_inventory
}

/// `_looks_like_safe_compound_developer_inspection`: auto-relax only a command
/// with a complete bounded-observer effect graph.
pub(crate) fn looks_like_safe_compound_developer_inspection(
    command_text: &str,
    inputs: &GraphInputs,
) -> bool {
    let (home_dir, ctx) = (inputs.home_dir, inputs.ctx);
    let Some(graph) = compound_developer_effect_graph(command_text, inputs)
        .filter(|graph| graph.context.complete)
    else {
        return is_low_risk_git_index_inspection(command_text, inputs.cwd, Some(home_dir), ctx);
    };
    use DeveloperShellEffect::{
        Directory, LocalRead, RemoteRead, StaticOutput, StreamFilter, SyntaxCheck,
    };
    if graph.segments.iter().any(|segment| {
        !matches!(
            segment.effect,
            Directory | LocalRead | RemoteRead | StreamFilter | StaticOutput | SyntaxCheck
        )
    }) {
        return false;
    }
    let effects: HashMap<usize, DeveloperShellEffect> = graph
        .segments
        .iter()
        .map(|segment| (segment.index, segment.effect))
        .collect();
    for (index, segment) in graph.context.segments.iter().enumerate() {
        let (command_name, command_index) = shell_segment_primary_command(&segment.tokens);
        let Some(command_index) = command_index else {
            return false;
        };
        let name = command_name.as_deref().unwrap_or("");
        let segment_cwd = segment.effective_cwd.as_deref().unwrap_or(home_dir);
        let args = without_safe_inspection_redirections(&segment.tokens[command_index + 1..]);
        if let Some(args) = &args {
            if safe_cli_metadata_segment_is_safe(
                name,
                args,
                segment_cwd,
                &segment.tokens[command_index],
                command_index,
                ctx,
                inputs.managed_bin_dirs,
            ) {
                continue;
            }
        }
        if name != "git" {
            let effect = effects.get(&index).copied();
            let allowed = match effect {
                Some(Directory) => segment.directory_operation.is_some(),
                Some(RemoteRead) => name == "gh",
                Some(LocalRead) => {
                    READ_ONLY_LOOKUP_COMMANDS.contains(&name)
                        || name == "wc"
                        || is_python_interpreter_command(name)
                }
                Some(StreamFilter) => {
                    READ_ONLY_LOOKUP_FILTERS.contains(&name) || matches!(name, "jq" | "sort")
                }
                Some(StaticOutput) => SAFE_STATIC_SHELL_COMMANDS.contains(&name),
                Some(SyntaxCheck) => true,
                None => false,
            };
            if allowed {
                continue;
            }
            return false;
        }
        let Some(args) = args else {
            return false;
        };
        if !git_segment_is_silently_verified(segment, &args, segment_cwd, ctx) {
            return false;
        }
    }
    true
}

/// `_git_segment_is_silently_verified`.
fn git_segment_is_silently_verified(
    segment: &ShellExecutionSegment,
    args: &[String],
    cwd: &Path,
    ctx: &Ctx,
) -> bool {
    let invocation = read_only_git_invocation(args, cwd, ctx);
    let git_binary = ctx.host.trusted_git_binary(&cwd.to_string_lossy());
    let (Some((operation, git_cwd)), Some(git_binary)) = (invocation, git_binary) else {
        return false;
    };
    match operation.as_str() {
        "status" => git_status_has_execution_free_config(Some(&git_cwd), ctx),
        "log" => git_log_has_execution_free_config(&git_cwd, Some(&git_binary), ctx),
        "fetch" | "ls-remote" => {
            !segment
                .control_before
                .iter()
                .chain(&segment.control_after)
                .any(|control| control == "|")
                && ctx.host.git_inspection_segment(&git_segment(segment), None)
        }
        "blame" | "branch" | "diff" | "show" | "worktree" => {
            ctx.host.git_inspection_segment(&git_segment(segment), None)
        }
        other => matches!(other, "ls-files" | "rev-parse"),
    }
}

/// `_looks_like_safe_cli_metadata_command`.
pub(crate) fn looks_like_safe_cli_metadata_command(
    command_text: &str,
    parts: &[String],
    cwd: Option<&Path>,
    ctx: &Ctx,
    managed_bin_dirs: &[PathBuf],
) -> bool {
    if contains_any(
        command_text,
        &["$(", "`", "<(", ">(", ";", "&", "|", "<", ">"],
    ) {
        return false;
    }
    let segments = iter_shell_command_segments(parts);
    if segments.len() != 1 {
        return false;
    }
    let segment = &segments[0];
    let (Some(command_name), Some(0)) = shell_segment_primary_command(segment) else {
        return false;
    };
    if segment[0].contains('/') || segment[0].contains('\\') {
        return false;
    }
    let base = cwd.map_or_else(
        || ctx.process_cwd.to_string(),
        |p| p.to_string_lossy().into(),
    );
    safe_cli_metadata_segment_is_safe(
        &command_name,
        &segment[1..],
        Path::new(&base),
        &segment[0],
        0,
        ctx,
        managed_bin_dirs,
    )
}

/// `_safe_dependency_symlink_execution_context`: one non-overwriting workspace
/// dependency link.
pub(crate) fn safe_dependency_symlink_execution_context(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: &Path,
    ctx: &Ctx,
) -> Option<ShellExecutionContext> {
    let initial_root = cwd.unwrap_or(home_dir);
    let mut context = model_shell_execution_context(
        command_text,
        Some(initial_root),
        Some(initial_root),
        Some(home_dir),
    );
    let workspace_root = leading_literal_cd_workspace_root(&context, home_dir);
    if let Some(root) = &workspace_root {
        let resolved_initial = resolve(&path_text(initial_root), ctx)?;
        if root.to_string_lossy() != resolved_initial.to_string() {
            context =
                model_shell_execution_context(command_text, Some(root), Some(root), Some(home_dir));
        }
    }
    if shell_execution_context_validation_reason(&context).is_some()
        || !matches!(context.segments.len(), 2 | 3)
    {
        return None;
    }
    let (directory, link, marker_segments) = (
        &context.segments[0],
        &context.segments[1],
        &context.segments[2..],
    );
    if directory.directory_operation.as_deref() != Some("cd")
        || !directory.control_before.is_empty()
        || link.control_before != ["&&"]
    {
        return None;
    }
    let (link_name, link_index) = shell_segment_primary_command(&link.tokens);
    let (Some("ln"), Some(link_index)) = (link_name.as_deref(), link_index) else {
        return None;
    };
    let link_args = without_safe_inspection_redirections(&link.tokens[link_index + 1..])?;
    if link_args.first().map(String::as_str) != Some("-s") || link_args.len() != 3 {
        return None;
    }
    if let Some(marker) = marker_segments.first() {
        let (marker_name, marker_index) = shell_segment_primary_command(&marker.tokens);
        let (Some("echo"), Some(marker_index)) = (marker_name.as_deref(), marker_index) else {
            return None;
        };
        let separator_ok = marker.control_before == [";"] || marker.control_before == ["&&"];
        let echoed = without_safe_inspection_redirections(&marker.tokens[marker_index + 1..]);
        if !separator_ok || echoed != Some(vec!["linked".to_owned()]) {
            return None;
        }
    }
    let (source_text, destination_text) = (&link_args[1], &link_args[2]);
    if contains_any(source_text, &["$", "`", "\0"])
        || contains_any(destination_text, &["$", "`", "\0"])
        || !matches!(
            destination_text.as_str(),
            "." | "node_modules" | "./node_modules"
        )
    {
        return None;
    }
    let mut source = ctx.expanduser(source_text)?;
    if !source.is_absolute() {
        let base = link
            .effective_cwd
            .as_deref()
            .or(workspace_root.as_deref())
            .unwrap_or(initial_root);
        source = path_text(base).join(&source.to_string());
    }
    let destination_root = path_text(link.effective_cwd.as_deref()?);
    let resolved_home = resolve_strict(&path_text(home_dir), ctx)?;
    let resolved_workspace = resolve_strict(
        &path_text(workspace_root.as_deref().unwrap_or(initial_root)),
        ctx,
    )?;
    let resolved_source = resolve_strict(&source, ctx)?;
    let destination = if destination_text == "." {
        destination_root.join(resolved_source.name())
    } else {
        destination_root.join(destination_text)
    };
    let ln_path = which_for_execution_cwd("ln", &to_path(&destination_root), ctx)?;
    let resolved_ln = resolve_strict(&PyPath::new(&ln_path), ctx)?;
    if !is_relative_to(&resolved_source, &resolved_home) {
        return None;
    }
    let resolved_parent = resolve_strict(&destination.parent(), ctx)?;
    if !is_relative_to(&resolved_parent, &resolved_workspace) {
        return None;
    }
    let has_marker = [".git", "package.json", "pyproject.toml"]
        .iter()
        .any(|marker| pyfs::exists(&resolved_workspace.join(marker)) == Ok(true));
    let trusted = is_trusted_absolute_command_path(
        Path::new(&resolved_ln.to_string()),
        Some(Path::new(&resolved_workspace.to_string())),
        Some(home_dir),
    );
    let sibling_manifest =
        pyfs::is_file(&resolved_source.parent().join("package.json")) == Ok(true);
    (trusted
        && has_marker
        && resolved_source.name() == "node_modules"
        && pyfs::is_symlink(&source) == Ok(false)
        && pyfs::is_dir(&resolved_source) == Ok(true)
        && sibling_manifest
        && pyfs::exists(&destination) == Ok(false)
        && pyfs::is_symlink(&destination) == Ok(false)
        && resolved_parent == resolved_workspace)
        .then_some(context)
}
