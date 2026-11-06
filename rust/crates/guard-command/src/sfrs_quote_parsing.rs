//! Working-directory and runner-chain parsing
//! (`secret_file_request_services/shell_quote_parsing.py`). Executable
//! trust and local package evidence stay with the resident through
//! [`InspectionHost`].
//!
//! [`InspectionHost`]: crate::codex_output_env::InspectionHost

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::Path;

use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::env_wrapper::parse_env_wrapper;
use crate::sfrs_constants::GH_PR_OPTION_VALUE_FLAGS;
use crate::sfrs_developer_graph::starts_with_literal_cd;
use crate::sfrs_developer_inspection::static_shell_segment_is_safe;
use crate::sfrs_quote_tokens::QuotedToken;
use crate::sfrs_shell_tokens::{shell_segment_primary_command, wrapper_option_tokens_consumed};
use crate::sfrs_source_edit::{
    bounded_edit_workspace_is_safe, bounded_in_place_sed_target, py_path, resolve_strict,
};
use crate::sfrs_source_edit_context::shell_execution_context_validation_reason;
use crate::sfrs_static_safety::{
    leading_literal_cd_workspace_root, shell_token_escapes_root,
    shell_token_has_command_substitution, without_safe_inspection_redirections,
};
use crate::sfrs_substitution::{shell_command_substitution_payloads, shell_segment_env_index};
use crate::shell_execution_context::{model_shell_execution_context, ShellExecutionContext};

fn resolved_text(path: &Path) -> String {
    pyfs::resolve(&py_path(path)).map_or_else(
        || path.to_string_lossy().into_owned(),
        |resolved| resolved.to_string(),
    )
}

fn model(command_text: &str, root: &Path, home_dir: &Path) -> ShellExecutionContext {
    model_shell_execution_context(command_text, Some(root), Some(root), Some(home_dir))
}

fn with_command_text(mut context: ShellExecutionContext, text: &str) -> ShellExecutionContext {
    context.command_text = text.to_owned();
    context
}

/// `_bounded_current_workspace_source_edit_execution_context`.
pub(crate) fn bounded_current_workspace_source_edit_execution_context(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: &Path,
) -> Option<ShellExecutionContext> {
    let cwd = cwd?;
    if ["$(", "`", "<(", ">("]
        .iter()
        .any(|marker| command_text.contains(marker))
    {
        return None;
    }
    let workspace_root = resolve_strict(&py_path(cwd))?;
    let workspace = std::path::PathBuf::from(workspace_root.to_string());
    if workspace_root.to_string() == resolved_text(home_dir)
        || !bounded_edit_workspace_is_safe(&workspace, home_dir)
    {
        return None;
    }
    let modeled = command_text.replace("\\\r\n", " ").replace("\\\n", " ");
    let context = model(&modeled, &workspace, home_dir);
    if shell_execution_context_validation_reason(&context).is_some()
        || context.directory_change_present
        || !matches!(context.segments.len(), 1 | 2)
    {
        return None;
    }
    let edit = &context.segments[0];
    let (edit_name, edit_index) = shell_segment_primary_command(&edit.tokens);
    let edit_index = edit_index?;
    if edit_name.as_deref() != Some("sed") || !edit.control_before.is_empty() {
        return None;
    }
    let edit_args = without_safe_inspection_redirections(&edit.tokens[edit_index + 1..])?;
    bounded_in_place_sed_target(&edit_args, &workspace, &workspace)?;
    if context.segments.len() == 1 {
        return Some(with_command_text(context, command_text));
    }
    let label = &context.segments[1];
    let (label_name, label_index) = shell_segment_primary_command(&label.tokens);
    let label_index = label_index?;
    if label_name.as_deref() != Some("echo") || label.control_before != ["&&"] {
        return None;
    }
    let label_args = without_safe_inspection_redirections(&label.tokens[label_index + 1..])?;
    if !static_shell_segment_is_safe(&label_args) {
        return None;
    }
    Some(with_command_text(context, command_text))
}

fn filter_count_is_bounded(count: &str) -> bool {
    let Some(digits) = count.strip_prefix('-') else {
        return false;
    };
    !digits.is_empty()
        && digits.chars().all(|c| c.is_ascii_digit())
        && digits.parse::<u32>().is_ok_and(|n| (1..=1000).contains(&n))
}

/// `literal_cd_execution_context`.
pub(crate) fn literal_cd_execution_context(
    command_text: &str,
    home_dir: &Path,
    ctx: &Ctx,
) -> Option<ShellExecutionContext> {
    let mut context = model(command_text, home_dir, home_dir);
    if let Some(workspace_root) = leading_literal_cd_workspace_root(&context, home_dir) {
        if workspace_root.to_string_lossy() != resolved_text(home_dir) {
            context = model(command_text, &workspace_root, home_dir);
        }
    }
    if !starts_with_literal_cd(&context)
        || shell_execution_context_validation_reason(&context).is_some()
    {
        return None;
    }
    if !matches!(context.segments.len(), 2 | 3) {
        return bounded_local_runner_chain_is_safe(&context, home_dir, ctx).then_some(context);
    }
    let runner = &context.segments[1];
    let (name, index) = shell_segment_primary_command(&runner.tokens);
    let index = match (name.as_deref(), index) {
        (Some("bunx" | "npx"), Some(index)) => index,
        _ => return bounded_local_runner_chain_is_safe(&context, home_dir, ctx).then_some(context),
    };
    let mut args = without_safe_inspection_redirections(&runner.tokens[index + 1..])?;
    while args
        .first()
        .is_some_and(|arg| matches!(arg.as_str(), "--bun" | "--no" | "--no-install"))
    {
        args.remove(0);
    }
    let runner_name = args.first()?.clone();
    if !matches!(runner_name.as_str(), "eslint" | "jest" | "tsc" | "vitest") {
        return None;
    }
    let runner_cwd = runner.effective_cwd.as_deref();
    let arg_cwd = runner_cwd.unwrap_or(home_dir);
    let root = context.workspace_root.as_deref().unwrap_or(home_dir);
    if args[1..]
        .iter()
        .any(|arg| runner_argument_escapes_root(arg, arg_cwd, root))
    {
        return None;
    }
    let runner_cwd = py_path(runner_cwd?);
    let modules = runner_cwd.join("node_modules");
    let executable = resolve_strict(&modules.join(&format!(".bin/{runner_name}")))?;
    executable.relative_to(&resolve_strict(&modules)?)?;
    if context.segments.len() == 3 {
        let filter = &context.segments[2];
        let (filter_name, filter_index) = shell_segment_primary_command(&filter.tokens);
        let filter_index = filter_index?;
        if !matches!(filter_name.as_deref(), Some("head" | "tail")) {
            return None;
        }
        let filter_args = &filter.tokens[filter_index + 1..];
        if filter.control_before != ["|"]
            || filter_args.len() != 1
            || !filter_count_is_bounded(&filter_args[0])
        {
            return None;
        }
    }
    Some(context)
}

/// `_bounded_local_runner_chain_is_safe`.
pub(crate) fn bounded_local_runner_chain_is_safe(
    context: &ShellExecutionContext,
    home_dir: &Path,
    ctx: &Ctx,
) -> bool {
    let Some(workspace) = context.workspace_root.as_deref() else {
        return false;
    };
    if context.segments.is_empty() {
        return false;
    }
    let (workspace_text, home_text) = (
        workspace.to_string_lossy().into_owned(),
        home_dir.to_string_lossy().into_owned(),
    );
    let sequenced = |control: &[String]| control == ["&&"] || control == [";"] || control == ["\n"];
    let mut index = 1;
    let mut saw_runner = false;
    let mut bun_trusted: Option<bool> = None;
    while index < context.segments.len() {
        let segment = &context.segments[index];
        let (name, command_index) = shell_segment_primary_command(&segment.tokens);
        let (Some(name), Some(command_index)) = (name, command_index) else {
            return false;
        };
        if !sequenced(&segment.control_before) || command_index != 0 {
            return false;
        }
        let Some(args) = without_safe_inspection_redirections(&segment.tokens[1..]) else {
            return false;
        };
        if name == "echo" {
            if !static_shell_segment_is_safe(&args) {
                return false;
            }
            index += 1;
            continue;
        }
        if name != "bun" || args.len() != 2 || args[0] != "run" {
            return false;
        }
        let trusted = *bun_trusted.get_or_insert_with(|| {
            ctx.host
                .trusted_path_command("bun", &workspace_text, &home_text)
        });
        if !trusted
            || !ctx
                .host
                .bun_script_evidence_complete(&args, &workspace_text)
        {
            return false;
        }
        saw_runner = true;
        index += 1;
        if index < context.segments.len() && context.segments[index].control_before == ["|"] {
            let filter = &context.segments[index];
            let (filter_name, filter_index) = shell_segment_primary_command(&filter.tokens);
            if !matches!(filter_name.as_deref(), Some("head" | "tail"))
                || filter_index != Some(0)
                || !ctx.host.trusted_path_command(
                    filter_name.as_deref().unwrap_or_default(),
                    &workspace_text,
                    &home_text,
                )
            {
                return false;
            }
            let Some(filter_args) = without_safe_inspection_redirections(&filter.tokens[1..])
            else {
                return false;
            };
            if filter_args.len() != 1 || !filter_count_is_bounded(&filter_args[0]) {
                return false;
            }
            index += 1;
        }
    }
    saw_runner
}

/// `_runner_argument_escapes_root`.
pub(crate) fn runner_argument_escapes_root(arg: &str, cwd: &Path, root: &Path) -> bool {
    if shell_token_has_command_substitution(arg) || arg.contains('$') || arg.starts_with('~') {
        return true;
    }
    let candidate = match arg.split_once('=') {
        Some((_, value)) if arg.starts_with('-') => value,
        _ => arg,
    };
    if candidate.starts_with('~') || candidate.contains('$') {
        return true;
    }
    !candidate.is_empty() && shell_token_escapes_root(candidate, cwd, root)
}

/// `_gh_pr_env_split_string_payloads_with_substitution`.
pub(crate) fn gh_pr_env_split_string_payloads_with_substitution(
    segment: &[QuotedToken],
) -> Vec<String> {
    let plain: Vec<String> = segment.iter().map(|token| token.plain.clone()).collect();
    let Some(env_index) = shell_segment_env_index(&plain) else {
        return Vec::new();
    };
    let parsed = parse_env_wrapper(&plain[env_index + 1..], None, None);
    parsed
        .split_expansions
        .iter()
        .filter_map(|expansion| {
            let source = env_index + 1 + expansion.source_index;
            (source < segment.len()
                && !shell_command_substitution_payloads(&segment[source].raw).is_empty())
            .then(|| crate::codex_output_py::py_strip(&expansion.payload).to_owned())
        })
        .filter(|payload| !payload.is_empty())
        .collect()
}

/// `_skip_gh_pr_options`.
pub(crate) fn skip_gh_pr_options(segment: &[QuotedToken], mut index: usize) -> usize {
    while index < segment.len() {
        let plain = segment[index].plain.as_str();
        if plain == "--" {
            return index + 1;
        }
        if GH_PR_OPTION_VALUE_FLAGS.contains(&plain) {
            index += 2;
            continue;
        }
        let valued = GH_PR_OPTION_VALUE_FLAGS
            .iter()
            .any(|flag| plain.starts_with(&format!("{flag}=")));
        if valued || plain.starts_with('-') {
            index += 1;
            continue;
        }
        break;
    }
    index
}

/// `_skip_generic_shell_wrapper_options`.
pub(crate) fn skip_generic_shell_wrapper_options(
    command_name: &str,
    segment: &[QuotedToken],
    mut index: usize,
) -> usize {
    while index < segment.len() {
        let plain = segment[index].plain.as_str();
        if plain == "--" {
            return index + 1;
        }
        if !plain.starts_with('-') {
            break;
        }
        index += wrapper_option_tokens_consumed(command_name, plain);
    }
    index
}
