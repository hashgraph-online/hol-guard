//! Safe routine Git command recognition
//! (`secret_file_request_services/git_routines.py`).
//!
//! Git execution safety, the trusted binary and every bounded git run belong
//! to the [`InspectionHost`](crate::codex_output_env::InspectionHost): a host
//! without the service refuses, so each check fails closed.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::codex_output_env::{Ctx, GitCheck};
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::{py_strip, PyPath};
use crate::sfrs_developer_graph::git_segment;
use crate::sfrs_routines_support::{
    git_status_args_are_read_only, git_status_has_execution_free_config, is_relative_to, resolve,
    resolve_strict, safe_git_status_cd_target, to_path,
};
use crate::sfrs_shell_tokens::{iter_shell_command_segments, shell_segment_primary_command};
use crate::shell_execution_context::model_shell_execution_context;

const SUBSTITUTION_MARKERS: [&str; 4] = ["$(", "`", "<(", ">("];
const BRANCH_CONFIG_PATTERN: &str = r"^(core\.fsmonitor|filter\..*\.(clean|smudge|process)|submodule\..*\.update|submodule\.recurse)$";

fn contains_any(text: &str, markers: &[&str]) -> bool {
    markers.iter().any(|marker| text.contains(marker))
}

fn path_text(path: &Path) -> PyPath {
    PyPath::new(&path.to_string_lossy())
}

/// `_looks_like_safe_standalone_git_routine`.
pub(crate) fn looks_like_safe_standalone_git_routine(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    if contains_any(command_text, &["$(", "`", "<(", ">(", ";", "|", "\n"])
        || command_text.contains('&')
    {
        return false;
    }
    let Some(cwd) = cwd else {
        return false;
    };
    let Some(execution_cwd) = resolve(&path_text(cwd), ctx).map(|path| to_path(&path)) else {
        return false;
    };
    if ctx
        .host
        .git_object_existence_query(command_text, &execution_cwd.to_string_lossy())
    {
        return true;
    }
    let context = model_shell_execution_context(
        command_text,
        Some(&execution_cwd),
        Some(&execution_cwd),
        None,
    );
    let trusted_home = ctx
        .host
        .home_git_c_path(command_text)
        .and(home_dir)
        .map(|home| home.to_string_lossy().into_owned());
    let segments: Vec<_> = context.segments.iter().map(git_segment).collect();
    ctx.host
        .standalone_git_routine(&segments, context.complete, trusted_home.as_deref())
}

/// One `cd`/command walk shared by the status and branch-switch recognizers.
/// `visit` receives each non-`cd` segment's command name and arguments with the
/// effective cwd and returns whether to keep going.
fn walk_segments(
    parts: &[String],
    cwd: Option<&Path>,
    ctx: &Ctx,
    mut visit: impl FnMut(&str, &[String], &Path) -> bool,
) -> bool {
    let segments = iter_shell_command_segments(parts);
    if segments.is_empty() {
        return false;
    }
    let base = cwd.map_or_else(|| ctx.process_cwd.clone(), path_text);
    let Some(mut effective_cwd) = resolve(&base, ctx).map(|path| to_path(&path)) else {
        return false;
    };
    for segment in &segments {
        let (command_name, command_index) = shell_segment_primary_command(segment);
        let (Some(command_name), Some(0)) = (command_name, command_index) else {
            return false;
        };
        let executable = &segment[0];
        if executable.contains('/') || executable.contains('\\') {
            return false;
        }
        let args = &segment[1..];
        if let Some(next_cwd) = safe_git_status_cd_target(&command_name, args, &effective_cwd, ctx)
        {
            effective_cwd = next_cwd;
            continue;
        }
        if !visit(&command_name, args, &effective_cwd) {
            return false;
        }
    }
    true
}

/// `_looks_like_safe_git_status_command`.
pub(crate) fn looks_like_safe_git_status_command(
    command_text: &str,
    parts: &[String],
    cwd: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    if contains_any(command_text, &SUBSTITUTION_MARKERS) {
        return false;
    }
    let mut saw_status = false;
    let walked = walk_segments(parts, cwd, ctx, |name, args, effective_cwd| {
        if name != "git"
            || !git_status_args_are_read_only(args, ctx)
            || !git_status_has_execution_free_config(Some(effective_cwd), ctx)
        {
            return false;
        }
        saw_status = true;
        true
    });
    walked && saw_status
}

/// `_looks_like_safe_git_branch_switch_command`.
pub(crate) fn looks_like_safe_git_branch_switch_command(
    command_text: &str,
    parts: &[String],
    cwd: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    if contains_any(command_text, &["$(", "`", "<(", ">(", ";", "|", "<", ">"])
        || command_text.replace("&&", "").contains('&')
    {
        return false;
    }
    let mut saw_switch = false;
    let walked = walk_segments(parts, cwd, ctx, |name, args, effective_cwd| {
        if name != "git" || saw_switch || !git_local_branch_switch_is_safe(args, effective_cwd, ctx)
        {
            return false;
        }
        saw_switch = true;
        true
    });
    walked && saw_switch
}

/// `_git_local_branch_switch_is_safe`.
pub(crate) fn git_local_branch_switch_is_safe(args: &[String], cwd: &Path, ctx: &Ctx) -> bool {
    if args.len() != 2 || !matches!(args[0].as_str(), "checkout" | "switch") {
        return false;
    }
    let branch = &args[1];
    if branch.is_empty() || branch.starts_with('-') || branch == "." || branch == ".." {
        return false;
    }
    let Some(git_path) = ctx.host.git_executable() else {
        return false;
    };
    let (Some(resolved_git), Some(execution_cwd)) = (
        resolve(&PyPath::new(&git_path), ctx),
        resolve(&path_text(cwd), ctx),
    ) else {
        return false;
    };
    let (git, cwd_text) = (resolved_git.to_string(), execution_cwd.to_string());
    let host = ctx.host;
    if !host.git_binary_trusted(&git, &cwd_text) {
        return false;
    }
    let probe = |args: &[&str]| {
        let owned: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        host.git_probe(&git, &owned, &cwd_text)
    };
    let verify = format!("refs/heads/{branch}^{{commit}}");
    let (Some(branch_result), Some(execution_config), Some(hook_result), Some(git_dir_result)) = (
        probe(&["rev-parse", "--verify", "--quiet", &verify]),
        probe(&["config", "--null", "--get-regexp", BRANCH_CONFIG_PATTERN]),
        probe(&["rev-parse", "--git-path", "hooks/post-checkout"]),
        probe(&["rev-parse", "--absolute-git-dir"]),
    ) else {
        return false;
    };
    if branch_result.code != 0 || !matches!(execution_config.code, 0 | 1) {
        return false;
    }
    if execution_config.code == 0
        && !git_checkout_execution_config_is_safe(
            &execution_config.stdout,
            &to_path(&execution_cwd),
            ctx,
        )
    {
        return false;
    }
    if execution_config.code == 1 && !execution_config.stdout.is_empty() {
        return false;
    }
    if hook_result.code != 0 || git_dir_result.code != 0 {
        return false;
    }
    let hook_text = PyPath::new(py_strip(&hook_result.stdout));
    let hook_path = if hook_text.is_absolute() {
        hook_text
    } else {
        execution_cwd.join(&hook_text.to_string())
    };
    let Some(hook_path) = pyfs::resolve(&hook_path) else {
        return false;
    };
    let Some(git_dir) = resolve_strict(&PyPath::new(py_strip(&git_dir_result.stdout)), ctx) else {
        return false;
    };
    if is_relative_to(&hook_path, &execution_cwd) && !is_relative_to(&hook_path, &git_dir) {
        return false;
    }
    match pyfs::exists(&hook_path) {
        Err(()) => false,
        Ok(false) => true,
        Ok(true) => !crate::sfrs_gh_pyshim::is_executable(&hook_path.to_string()),
    }
}

/// `_git_checkout_execution_config_is_safe`.
pub(crate) fn git_checkout_execution_config_is_safe(
    config_output: &str,
    cwd: &Path,
    ctx: &Ctx,
) -> bool {
    let mut entries: HashMap<String, String> = HashMap::new();
    for entry in config_output.split('\0') {
        if entry.is_empty() {
            continue;
        }
        let Some((key, value)) = entry.split_once('\n') else {
            return false;
        };
        entries.insert(casefold(key), value.to_owned());
    }
    if entries.is_empty() {
        return true;
    }
    if let Some(fsmonitor) = entries.remove("core.fsmonitor") {
        if !matches!(
            casefold(py_strip(&fsmonitor)).as_str(),
            "0" | "false" | "no" | "off"
        ) {
            return false;
        }
    }
    if entries.is_empty() {
        return true;
    }
    let allowed = |key: &str| match key {
        "filter.lfs.clean" => Some("git-lfs clean -- %f"),
        "filter.lfs.smudge" => Some("git-lfs smudge -- %f"),
        "filter.lfs.process" => Some("git-lfs filter-process"),
        _ => None,
    };
    if entries
        .iter()
        .any(|(key, value)| allowed(key) != Some(value.as_str()))
    {
        return false;
    }
    ctx.host.git_lfs_trusted(&cwd.to_string_lossy())
}

fn casefold(text: &str) -> String {
    caseless::default_case_fold_str(text)
}

/// `_read_only_git_invocation`: the lower-cased operation and the git cwd.
pub(crate) fn read_only_git_invocation(
    args: &[String],
    cwd: &Path,
    ctx: &Ctx,
) -> Option<(String, PathBuf)> {
    let first = args.first()?;
    let mut operation_index = 0;
    let mut git_cwd = cwd.to_path_buf();
    if first == "-C" {
        if args.len() < 3 {
            return None;
        }
        let target = ctx.expanduser(&args[1])?;
        let target = if target.is_absolute() {
            target
        } else {
            path_text(cwd).join(&target.to_string())
        };
        let target = resolve_strict(&target, ctx)?;
        let root = resolve(&path_text(cwd), ctx)?;
        if !is_relative_to(&target, &root) || pyfs::is_dir(&target) != Ok(true) {
            return None;
        }
        git_cwd = to_path(&target);
        operation_index = 2;
    } else if first.starts_with('-') {
        return None;
    }
    Some((casefold(&args[operation_index]), git_cwd))
}

/// `_git_log_has_execution_free_config`.
pub(crate) fn git_log_has_execution_free_config(
    cwd: &Path,
    git_binary: Option<&str>,
    ctx: &Ctx,
) -> bool {
    let host = ctx.host;
    for key in ["GIT_PAGER", "PAGER"] {
        let value = host.env(key).unwrap_or_default();
        if !matches!(py_strip(&value), "" | "cat") {
            return false;
        }
    }
    if !host.git_safety(GitCheck::ConfigEnvironmentClean, None, &[]) {
        return false;
    }
    let Some(execution_cwd) = resolve(&path_text(cwd), ctx) else {
        return false;
    };
    let cwd_text = execution_cwd.to_string();
    let Some(git) = git_binary
        .map(str::to_owned)
        .or_else(|| host.trusted_git_binary(&cwd_text))
    else {
        return false;
    };
    for key in ["core.pager", "pager.log"] {
        let arguments = ["config", "--null", "--get-all", key].map(str::to_owned);
        let Some(result) = host.git_probe(&git, &arguments, &cwd_text) else {
            return false;
        };
        if result.code == 1 && result.stdout.is_empty() {
            continue;
        }
        if result.code != 0 {
            return false;
        }
        let values = result
            .stdout
            .split('\0')
            .map(py_strip)
            .filter(|value| !value.is_empty());
        if values.into_iter().any(|value| value != "cat") {
            return false;
        }
    }
    true
}
