//! Compound read-only source inspection flow for Codex tool-output: chains,
//! pipelines, directory-change contexts and the secret-like name scan.

use std::path::PathBuf;

use crate::codex_output_fs as pyfs;
use crate::codex_output_inspection::{
    has_external_source_search_target, is_bounded_read_only_filter, is_read_only_source_search,
    is_read_only_source_view, source_inspection_target_tokens,
};
use crate::codex_output_py::{py_strip, shlex_split, strip_quotes, PyPath};
use crate::codex_output_search::{target_is_source_like, Scope};
use crate::codex_output_source_paths::py_path;
use crate::codex_output_splitters::{has_unquoted_glob_metachar, split_chain, split_pipeline};
use crate::shell_execution_context::{
    model_shell_execution_context, validate_shell_execution_segment, ShellExecutionContext,
};

const SECRET_LIKE_SOURCE_NAME_STEMS: &[&str] = &[
    "auth",
    "credential",
    "credentials",
    "passwd",
    "password",
    "private-key",
    "private_key",
    "secret",
    "secrets",
    "token",
];

fn to_std(path: &PyPath) -> PathBuf {
    PathBuf::from(path.to_string())
}

fn absolute(scope: Scope, path: &PyPath) -> PyPath {
    if path.is_absolute() {
        path.clone()
    } else {
        scope.ctx.process_cwd.join(&path.to_string())
    }
}

/// `Path.resolve(strict=True)`: `None` when the path does not exist.
fn strict_resolve(scope: Scope, path: &PyPath) -> Option<PyPath> {
    let resolved = pyfs::resolve(&absolute(scope, path))?;
    matches!(pyfs::exists(&resolved), Ok(true)).then_some(resolved)
}

/// `_codex_literal_home_workspace_target`.
fn literal_home_workspace_target(tokens: &[String], home: &PyPath, scope: Scope) -> Option<PyPath> {
    if tokens.len() != 2 || strip_quotes(&tokens[0]).to_lowercase() != "cd" {
        return None;
    }
    let operand = strip_quotes(&tokens[1]);
    if operand.is_empty()
        || PyPath::new(operand).parts().iter().any(|part| part == "..")
        || ["$", "`", "\0"]
            .iter()
            .any(|marker| operand.contains(marker))
    {
        return None;
    }
    let mut candidate = match operand.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => PyPath::new(operand),
    };
    if !candidate.is_absolute() {
        candidate = home.join(&candidate.to_string());
    }
    let target = strict_resolve(scope, &candidate)?;
    let home_resolved = strict_resolve(scope, home)?;
    let relative = target.relative_to(&home_resolved)?;
    if relative.is_empty() || relative[0].starts_with('.') {
        return None;
    }
    let markers = [
        ".git",
        "package.json",
        "pyproject.toml",
        "Cargo.toml",
        "go.mod",
    ];
    markers
        .iter()
        .any(|marker| matches!(pyfs::exists(&target.join(marker)), Ok(true)))
        .then_some(target)
}

/// `_codex_contextual_source_inspection_is_read_only`.
fn contextual_is_read_only(
    context: &ShellExecutionContext,
    home: Option<&PyPath>,
    workspace_root: Option<&PyPath>,
    scope: Scope,
) -> bool {
    if !context.complete {
        return false;
    }
    let mut saw_inspection = false;
    let mut pipeline_open = false;
    for segment in &context.segments {
        if segment
            .control_before
            .iter()
            .chain(segment.control_after.iter())
            .any(|operator| operator == "||" || operator == "&")
        {
            return false;
        }
        if segment.directory_operation.is_some() {
            pipeline_open = false;
            continue;
        }
        if let Some(root) = workspace_root {
            let Some(segment_cwd) = &segment.effective_cwd else {
                return false;
            };
            let Some(resolved) = strict_resolve(scope, &py_path(segment_cwd)) else {
                return false;
            };
            let Some(root_resolved) = strict_resolve(scope, root) else {
                return false;
            };
            if resolved.relative_to(&root_resolved).is_none() {
                return false;
            }
        }
        let (segment_cwd, reason) = validate_shell_execution_segment(context, segment);
        let Some(segment_cwd) = segment_cwd.filter(|_| reason.is_none()) else {
            return false;
        };
        let command_text = segment.command_text();
        let cwd = py_path(&segment_cwd);
        let segment_scope = Scope {
            cwd: Some(&cwd),
            home,
            ctx: scope.ctx,
        };
        if pipeline_open {
            if !is_bounded_read_only_filter(&command_text) {
                return false;
            }
        } else if !(is_read_only_source_search(&command_text, segment_scope)
            || is_read_only_source_view(&command_text, segment_scope))
        {
            return false;
        }
        saw_inspection = true;
        pipeline_open = matches!(
            segment.control_operator().map(String::as_str),
            Some("|" | "|&")
        );
    }
    saw_inspection && !pipeline_open
}

fn model(
    command: &str,
    cwd: &PyPath,
    workspace: &PyPath,
    home: Option<&PyPath>,
) -> ShellExecutionContext {
    let cwd = to_std(cwd);
    let workspace = to_std(workspace);
    let home = home.map(to_std);
    model_shell_execution_context(command, Some(&cwd), Some(&workspace), home.as_deref())
}

/// `_codex_command_is_read_only_source_inspection`.
pub(crate) fn is_read_only_source_inspection(command_text: &str, scope: Scope) -> bool {
    let command = py_strip(command_text);
    if command.is_empty() || has_unquoted_glob_metachar(command) {
        return false;
    }
    if has_external_source_search_target(command, scope) {
        let Some(parts) = shlex_split(command) else {
            return false;
        };
        if parts.first().is_none_or(|first| first != "grep") {
            return false;
        }
        return is_read_only_source_search(command, scope);
    }
    let process_cwd = scope.ctx.process_cwd.clone();
    let base_cwd = scope
        .cwd
        .map(|cwd| absolute(scope, cwd))
        .unwrap_or(process_cwd);
    let context = model(command, &base_cwd, &base_cwd, None);
    if context.directory_change_present {
        if contextual_is_read_only(&context, scope.home, None, scope) {
            return true;
        }
        let Some(home) = scope.home else {
            return false;
        };
        let home_abs = absolute(scope, home);
        let home_context = model(command, &home_abs, &home_abs, Some(&home_abs));
        let Some(first) = home_context.segments.first() else {
            return false;
        };
        let workspace_target = literal_home_workspace_target(&first.tokens, &home_abs, scope);
        if !first.control_before.is_empty() || first.directory_operation.as_deref() != Some("cd") {
            return false;
        }
        let Some(workspace_target) = workspace_target else {
            return false;
        };
        return contextual_is_read_only(&home_context, Some(home), Some(&workspace_target), scope);
    }
    if let Some(segments) = split_chain(command) {
        let mut saw = false;
        for segment in &segments {
            if !is_read_only_source_inspection(segment, scope) {
                return false;
            }
            saw = true;
        }
        return saw;
    }
    let Some(segments) = split_pipeline(command) else {
        return is_read_only_source_search(command, scope)
            || is_read_only_source_view(command, scope);
    };
    let Some((first, filters)) = segments.split_first() else {
        return false;
    };
    if !(is_read_only_source_search(first, scope) || is_read_only_source_view(first, scope)) {
        return false;
    }
    filters
        .iter()
        .all(|segment| is_bounded_read_only_filter(segment))
}

fn stem_has_compound_secret_segment(stem: &str, split_compound: bool) -> bool {
    let lowered = stem.to_lowercase();
    if !split_compound {
        return false;
    }
    lowered.split(['-', '_']).any(|segment| {
        !segment.is_empty()
            && segment != lowered
            && SECRET_LIKE_SOURCE_NAME_STEMS.contains(&segment)
    })
}

/// `codex_scan_targets_secret_like_source_name`; `recurse` carries the caller's
/// own execution-context policy for chain and pipeline splits.
pub(crate) fn scan_targets_secret_like_source_name(
    command_text: &str,
    scope: Scope,
    recurse: &dyn Fn(&str) -> bool,
) -> bool {
    if let Some(segments) = split_chain(command_text) {
        return segments.iter().any(|segment| recurse(segment));
    }
    if let Some(segments) = split_pipeline(command_text).filter(|segments| !segments.is_empty()) {
        return recurse(&segments[0]);
    }
    let Some(parts) = shlex_split(command_text) else {
        return false;
    };
    for part in source_inspection_target_tokens(&parts) {
        let stripped = strip_quotes(py_strip(&part));
        if stripped.is_empty() {
            continue;
        }
        let name_full = PyPath::new(stripped).name().to_lowercase();
        let name = name_full.trim_start_matches('.').to_owned();
        let name_stem = PyPath::new(&name).stem().to_owned();
        let stem = if name_stem.is_empty() {
            name.clone()
        } else {
            name_stem
        };
        let exact = SECRET_LIKE_SOURCE_NAME_STEMS.contains(&stem.to_lowercase().as_str());
        let compound = stem_has_compound_secret_segment(&stem, scope.cwd.is_some());
        if !exact && !compound && !name.starts_with("id_") {
            continue;
        }
        if compound && scope.cwd.is_some() && target_is_source_like(stripped, scope, false) {
            continue;
        }
        return true;
    }
    false
}
