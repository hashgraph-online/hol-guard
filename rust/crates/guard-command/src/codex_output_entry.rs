//! Entry points for the Codex tool-output review: dispatches one wire action to
//! the matching review and owns the shell execution-context policy around it.

use std::path::{Path, PathBuf};

use guard_contracts::CodexToolOutputActionV1;
use sha2::{Digest, Sha256};

use crate::codex_output_commands::{
    is_focused_pytest_verification, is_read_only_git_metadata, may_read_local_content_tail,
    reads_environment_pipeline,
};
use crate::codex_output_env::Ctx;
use crate::codex_output_git_diff::git_diff_selection_identity;
use crate::codex_output_inspection_flow::{
    is_read_only_source_inspection, scan_targets_secret_like_source_name,
};
use crate::codex_output_py::{shlex_split, PyPath};
use crate::codex_output_search::Scope;
use crate::codex_output_source_paths::py_path;
use crate::codex_output_splitters::split_pipeline;
use crate::shell_execution_context::{
    model_shell_execution_context, validate_shell_execution_segment, ShellExecutionContext,
};

/// Verdict of one review: the boolean answer and an optional identity string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutputOutcome {
    pub allowed: bool,
    pub value: Option<String>,
}

impl ToolOutputOutcome {
    fn flag(allowed: bool) -> Self {
        Self {
            allowed,
            value: None,
        }
    }
}

fn scope_of<'a>(ctx: &'a Ctx<'a>, cwd: Option<&'a PyPath>, home: Option<&'a PyPath>) -> Scope<'a> {
    Scope { cwd, home, ctx }
}

/// `model_shell_execution_context(command, cwd=cwd, workspace_root=cwd)`.
fn model(ctx: &Ctx, command: &str, cwd: Option<&PyPath>) -> ShellExecutionContext {
    let base = match cwd {
        Some(path) if path.is_absolute() => path.clone(),
        Some(path) => ctx.process_cwd.join(&path.to_string()),
        None => ctx.process_cwd.clone(),
    };
    let base = PathBuf::from(base.to_string());
    model_shell_execution_context(
        command,
        Some(Path::new(&base)),
        Some(Path::new(&base)),
        None,
    )
}

/// The per-segment review of a directory-change context: `Err(())` when the
/// context or a segment cannot be proven, otherwise each non-directory segment
/// with its validated working directory.
fn contextual_segments(
    context: &ShellExecutionContext,
) -> Result<Vec<(usize, String, PyPath)>, ()> {
    if !context.complete {
        return Err(());
    }
    let mut result = Vec::new();
    for segment in &context.segments {
        if segment.directory_operation.is_some() {
            continue;
        }
        let (cwd, reason) = validate_shell_execution_segment(context, segment);
        match cwd {
            Some(cwd) if reason.is_none() => {
                result.push((segment.segment_index, segment.command_text(), py_path(&cwd)));
            }
            _ => return Err(()),
        }
    }
    Ok(result)
}

/// `_codex_command_targets_secret_like_source_name` (tool-output variant, which
/// applies the execution-context policy) and the plain scan (`exec_context`
/// false).
fn secret_like_source_name(
    ctx: &Ctx,
    command: &str,
    cwd: Option<&PyPath>,
    home: Option<&PyPath>,
    exec_context: bool,
    applied: bool,
) -> bool {
    if exec_context && !applied {
        let context = model(ctx, command, cwd);
        if context.directory_change_present {
            let Ok(segments) = contextual_segments(&context) else {
                return true;
            };
            return segments.iter().any(|(_, text, segment_cwd)| {
                secret_like_source_name(ctx, text, Some(segment_cwd), home, true, true)
            });
        }
    }
    scan_targets_secret_like_source_name(command, scope_of(ctx, cwd, home), &|segment| {
        secret_like_source_name(ctx, segment, cwd, home, exec_context, false)
    })
}

/// `_direct_codex_git_pathspec_identity`.
fn direct_git_pathspec_identity(command: &str, scope: Scope) -> Option<String> {
    let pipeline = split_pipeline(command).unwrap_or_default();
    let segment = pipeline.first().map(String::as_str).unwrap_or(command);
    let parts = shlex_split(segment)?;
    let first = parts.first()?;
    if PyPath::new(first).name() != "git" {
        return None;
    }
    git_diff_selection_identity(&parts[1..], scope)
}

/// The `codex-git-pathspec-context-v1` hash over several segment identities.
fn context_identity(identities: &[(usize, String)]) -> String {
    let items: Vec<String> = identities
        .iter()
        .map(|(index, identity)| format!("[{index},\"{identity}\"]"))
        .collect();
    let canonical = format!(
        "{{\"identities\":[{}],\"schema\":\"codex-git-pathspec-context-v1\"}}",
        items.join(",")
    );
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

/// `_codex_git_pathspec_identity_for_command`.
fn git_pathspec_identity(ctx: &Ctx, command: &str, cwd: Option<&PyPath>) -> Option<String> {
    let context = model(ctx, command, cwd);
    if !context.directory_change_present {
        return direct_git_pathspec_identity(command, scope_of(ctx, cwd, None));
    }
    let segments = contextual_segments(&context).ok()?;
    let identities: Vec<(usize, String)> = segments
        .iter()
        .filter_map(|(index, text, segment_cwd)| {
            direct_git_pathspec_identity(text, scope_of(ctx, Some(segment_cwd), None))
                .map(|identity| (*index, identity))
        })
        .collect();
    match identities.len() {
        0 => None,
        1 => identities.into_iter().next().map(|(_, identity)| identity),
        _ => Some(context_identity(&identities)),
    }
}

/// Run one wire action.
pub fn review_codex_tool_output(ctx: &Ctx, action: &CodexToolOutputActionV1) -> ToolOutputOutcome {
    use CodexToolOutputActionV1 as Action;
    match action {
        Action::ReadOnlyInspection(request) => {
            let (cwd, home) = (path_of(&request.cwd), path_of(&request.home_dir));
            ToolOutputOutcome::flag(is_read_only_source_inspection(
                &request.command,
                scope_of(ctx, cwd.as_ref(), home.as_ref()),
            ))
        }
        Action::PostToolReadOnly(request) => {
            let (cwd, home) = (path_of(&request.cwd), path_of(&request.home_dir));
            let scope = scope_of(ctx, cwd.as_ref(), home.as_ref());
            ToolOutputOutcome::flag(
                !request.commands.is_empty()
                    && request.commands.iter().all(|command| {
                        is_read_only_source_inspection(command, scope)
                            || is_read_only_git_metadata(command, scope.without_home())
                    }),
            )
        }
        Action::SecretLikeSourceName(request) => {
            let (cwd, home) = (path_of(&request.cwd), path_of(&request.home_dir));
            ToolOutputOutcome::flag(secret_like_source_name(
                ctx,
                &request.command,
                cwd.as_ref(),
                home.as_ref(),
                request.exec_context,
                false,
            ))
        }
        Action::GitPathspecIdentity(request) => {
            let cwd = path_of(&request.cwd);
            let value = git_pathspec_identity(ctx, &request.command, cwd.as_ref());
            ToolOutputOutcome {
                allowed: value.is_some(),
                value,
            }
        }
        Action::LocalContentTail(request) => {
            let cwd = path_of(&request.cwd);
            ToolOutputOutcome::flag(may_read_local_content_tail(
                &request.command,
                scope_of(ctx, cwd.as_ref(), None),
            ))
        }
        Action::ReadsEnvironmentPipeline(request) => {
            ToolOutputOutcome::flag(reads_environment_pipeline(&request.command))
        }
        Action::FocusedPytest(request) => {
            ToolOutputOutcome::flag(is_focused_pytest_verification(&request.command))
        }
        Action::GitMetadata(request) => {
            let cwd = path_of(&request.cwd);
            ToolOutputOutcome::flag(is_read_only_git_metadata(
                &request.command,
                scope_of(ctx, cwd.as_ref(), None),
            ))
        }
    }
}

fn path_of(value: &Option<String>) -> Option<PyPath> {
    value.as_deref().map(PyPath::new)
}

#[cfg(test)]
mod tests {
    use super::context_identity;

    #[test]
    fn context_identity_matches_the_recorded_python_hash() {
        let identities = vec![(1, "aa".repeat(32)), (3, "bb".repeat(32))];
        assert_eq!(
            context_identity(&identities),
            "bc531c8bb850ad6b0cd668e06e8198d739d13d1c2db4767f37905ced9af0c1db"
        );
    }
}
