//! Read-only `git diff` review for the Codex tool-output inspection.

use std::sync::OnceLock;

use regex::Regex;

use crate::codex_output_args::SAFE_GIT_GLOBAL_BOOLEAN_FLAGS;
use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::codex_output_git_config::repo_diff_helpers_are_unconfigured;
use crate::codex_output_pathspecs::{
    literal_file_selection, literal_pathspec_path, resolve_git_pathspecs, GLOBAL_MODES,
};
use crate::codex_output_py::PyPath;
use crate::codex_output_search::{target_is_source_like, Scope};

const VALUE_OPTIONS: &[&str] = &[
    "--diff-filter",
    "--inter-hunk-context",
    "--line-prefix",
    "--output-indicator-context",
    "--output-indicator-new",
    "--output-indicator-old",
    "--src-prefix",
    "--dst-prefix",
    "--stat-width",
    "--stat-name-width",
    "--stat-graph-width",
    "--unified",
    "-G",
    "-S",
    "-U",
    "--word-diff-regex",
];
const OPTIONAL_VALUE_OPTIONS: &[&str] = &[
    "--color",
    "--color-moved",
    "--find-copies",
    "--find-renames",
    "--ignore-submodules",
    "--submodule",
    "--word-diff",
];
const BOOLEAN_OPTIONS: &[&str] = &[
    "--binary",
    "--cached",
    "--check",
    "--compact-summary",
    "--exit-code",
    "--find-copies-harder",
    "--full-index",
    "--ignore-all-space",
    "--ignore-blank-lines",
    "--ignore-cr-at-eol",
    "--ignore-space-at-eol",
    "--ignore-space-change",
    "--minimal",
    "--name-only",
    "--name-status",
    "--no-ext-diff",
    "--no-textconv",
    "--numstat",
    "--patch",
    "--patch-with-raw",
    "--pickaxe-all",
    "--pickaxe-regex",
    "--raw",
    "--relative",
    "--shortstat",
    "--stat",
    "--summary",
    "--staged",
];
const DISALLOWED_OPTIONS: &[&str] = &["--ext-diff", "--no-index", "--output", "--textconv"];

fn with_value(arg: &str, options: &[&str]) -> bool {
    options.iter().any(|option| {
        arg.strip_prefix(option)
            .is_some_and(|rest| rest.starts_with('='))
    })
}

/// Working directory, as `Path(arg)` joined like Python.
fn chdir(effective: Option<&PyPath>, directory: &str) -> PyPath {
    let directory = PyPath::new(directory);
    match effective {
        Some(base) if !directory.is_absolute() => base.join(&directory.to_string()),
        _ => directory,
    }
}

/// `_git_diff_invocation`: diff args, effective working directory and global
/// pathspec modes.
pub(crate) fn git_diff_invocation(
    args: &[String],
    cwd: Option<&PyPath>,
) -> Option<(Vec<String>, Option<PyPath>, Vec<String>)> {
    let mut index = 0;
    let mut effective = cwd.cloned();
    let mut modes: Vec<String> = Vec::new();
    while index < args.len() {
        let arg = &args[index];
        if arg == "diff" {
            return Some((args[index + 1..].to_vec(), effective, modes));
        }
        if arg == "-C" {
            let directory = args.get(index + 1)?;
            effective = Some(chdir(effective.as_ref(), directory));
            index += 2;
            continue;
        }
        if arg.starts_with("-C") && arg.chars().count() > 2 {
            effective = Some(chdir(effective.as_ref(), &arg[2..]));
            index += 1;
            continue;
        }
        if GLOBAL_MODES.contains(&arg.as_str()) {
            modes.push(arg.clone());
            index += 1;
            continue;
        }
        if SAFE_GIT_GLOBAL_BOOLEAN_FLAGS.contains(&arg.as_str()) {
            index += 1;
            continue;
        }
        return None;
    }
    None
}

fn operand_is_revision(value: &str) -> bool {
    static HEX: OnceLock<Regex> = OnceLock::new();
    let hex = HEX.get_or_init(|| Regex::new(r"^[0-9a-fA-F]{7,64}$").expect("static pattern"));
    let mut chars = value.chars();
    let ref_like = chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'));
    value == "HEAD"
        || value == "@"
        || ["HEAD~", "HEAD^", "@{", "refs/"]
            .iter()
            .any(|prefix| value.starts_with(prefix))
        || value.contains("..")
        || hex.is_match(value)
        || ref_like
}

fn is_unified_option(arg: &str) -> bool {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"^-U\d{1,6}$").expect("static pattern"))
        .is_match(arg)
}

fn is_pickaxe_option(arg: &str) -> bool {
    (arg.starts_with("-G") || arg.starts_with("-S"))
        && arg.chars().count() > 2
        && !arg[2..].contains('\n')
}

/// `_git_diff_pathspecs`.
pub(crate) fn git_diff_pathspecs(args: &[String], cwd: Option<&PyPath>) -> Option<Vec<String>> {
    let mut paths = Vec::new();
    let mut index = 0;
    let mut after_separator = false;
    while index < args.len() {
        let arg = &args[index];
        if after_separator {
            paths.push(arg.clone());
            index += 1;
            continue;
        }
        if arg == "--" {
            after_separator = true;
            index += 1;
            continue;
        }
        if DISALLOWED_OPTIONS.contains(&arg.as_str()) || with_value(arg, DISALLOWED_OPTIONS) {
            return None;
        }
        if OPTIONAL_VALUE_OPTIONS.contains(&arg.as_str()) || with_value(arg, OPTIONAL_VALUE_OPTIONS)
        {
            index += 1;
            continue;
        }
        if VALUE_OPTIONS.contains(&arg.as_str()) {
            if args.get(index + 1).is_none_or(|next| next.starts_with('-')) {
                return None;
            }
            index += 2;
            continue;
        }
        if with_value(arg, VALUE_OPTIONS)
            || BOOLEAN_OPTIONS.contains(&arg.as_str())
            || is_unified_option(arg)
            || is_pickaxe_option(arg)
        {
            index += 1;
            continue;
        }
        if arg.starts_with('-') {
            return None;
        }
        if arg.starts_with(':') || arg.chars().any(|c| matches!(c, '*' | '?' | '[')) {
            return None;
        }
        if let Some(base) = cwd {
            if pyfs::exists(&base.join(arg)).unwrap_or(true) {
                return None;
            }
        }
        if operand_is_revision(arg) {
            index += 1;
            continue;
        }
        return None;
    }
    Some(paths)
}

/// `_git_diff_external_helpers_are_disabled_or_unconfigured`.
fn external_helpers_are_disabled_or_unconfigured(
    args: &[String],
    ctx: &Ctx,
    cwd: Option<&PyPath>,
) -> bool {
    let end = args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len());
    let active = &args[..end];
    if active.iter().any(|arg| arg == "--no-ext-diff")
        && active.iter().any(|arg| arg == "--no-textconv")
    {
        return true;
    }
    repo_diff_helpers_are_unconfigured(ctx, cwd)
}

fn absolute(ctx: &Ctx, path: Option<PyPath>) -> Option<PyPath> {
    path.map(|value| {
        if value.is_absolute() {
            value
        } else {
            ctx.process_cwd.join(&value.to_string())
        }
    })
}

/// `_codex_git_diff_targets_are_source_like`.
pub(crate) fn git_diff_targets_are_source_like(args: &[String], scope: Scope) -> bool {
    let Some((diff_args, effective, modes)) = git_diff_invocation(args, scope.cwd) else {
        return false;
    };
    let effective = absolute(scope.ctx, effective);
    let Some(targets) = git_diff_pathspecs(&diff_args, effective.as_ref()) else {
        return false;
    };
    if let Some(base) = &effective {
        for target in &targets {
            let Some(literal) = literal_pathspec_path(target) else {
                continue;
            };
            match pyfs::is_dir(&base.join(literal)) {
                Ok(false) => {}
                _ => return false,
            }
        }
    }
    let (selected, policy_root): (Vec<PyPath>, Option<PyPath>) =
        match literal_file_selection(&targets, effective.as_ref()) {
            Some(selection) => (selection, effective.clone()),
            None => {
                let resolution =
                    resolve_git_pathspecs(scope.ctx, &targets, effective.as_ref(), &modes);
                match resolution.repository_root {
                    Some(root) if resolution.complete && !resolution.resolved_paths.is_empty() => {
                        (resolution.resolved_paths, Some(root))
                    }
                    _ => return false,
                }
            }
        };
    let target_scope = Scope {
        cwd: policy_root.as_ref(),
        home: scope.home,
        ctx: scope.ctx,
    };
    !selected.is_empty()
        && selected
            .iter()
            .all(|target| target_is_source_like(&target.to_string(), target_scope, false))
        && external_helpers_are_disabled_or_unconfigured(&diff_args, scope.ctx, effective.as_ref())
}

/// `_codex_git_diff_selection_identity`.
pub(crate) fn git_diff_selection_identity(args: &[String], scope: Scope) -> Option<String> {
    let (diff_args, effective, modes) = git_diff_invocation(args, scope.cwd)?;
    let effective = absolute(scope.ctx, effective);
    let pathspecs = git_diff_pathspecs(&diff_args, effective.as_ref())?;
    resolve_git_pathspecs(scope.ctx, &pathspecs, effective.as_ref(), &modes).selection_identity
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn invocation_and_pathspecs_follow_python() {
        let (rest, cwd, modes) = git_diff_invocation(
            &v(&[
                "--no-pager",
                "-C",
                "sub",
                "--literal-pathspecs",
                "diff",
                "--stat",
                "--",
                "a.py",
            ]),
            None,
        )
        .expect("invocation");
        assert_eq!(rest, v(&["--stat", "--", "a.py"]));
        assert_eq!(cwd.expect("cwd").to_string(), "sub");
        assert_eq!(modes, v(&["--literal-pathspecs"]));
        assert!(git_diff_invocation(&v(&["log"]), None).is_none());
        assert_eq!(
            git_diff_pathspecs(&v(&["--stat", "HEAD~1", "--", "a.py"]), None),
            Some(v(&["a.py"]))
        );
        assert_eq!(git_diff_pathspecs(&v(&["--output=x"]), None), None);
        assert_eq!(
            git_diff_pathspecs(&v(&["-U3", "main"]), None),
            Some(Vec::new())
        );
        assert_eq!(git_diff_pathspecs(&v(&["-G", "-x"]), None), None);
        assert_eq!(git_diff_pathspecs(&v(&["some file"]), None), None);
    }
}
