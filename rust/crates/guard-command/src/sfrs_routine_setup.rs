//! Strict benign proofs for routine agent setup commands
//! (`routine_setup_commands.py`).
//!
//! Git execution safety, the trusted git binary, bounded git probes and
//! trusted `PATH` commands are [`InspectionHost`](crate::codex_output_env::InspectionHost)
//! services; a host without them refuses.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::{py_strip, shlex_split, PyPath};
use crate::sfrs_gh_bindings::py_pattern;
use crate::sfrs_routines_support::{absolute, is_relative_to, resolve_strict};

const RG_FLAGS: [&str; 6] = [
    "-F",
    "-i",
    "-n",
    "--fixed-strings",
    "--ignore-case",
    "--line-number",
];
const SUBSTITUTION_MARKERS: [&str; 7] = ["$(", "`", "<(", ">(", "\0", "\r", "\n"];
const OPERATORS: [&str; 7] = ["|", "||", "&&", "&", ";", "<", ">"];

fn pattern(text: &str) -> Regex {
    Regex::new(&py_pattern(text)).expect("routine setup pattern is a constant")
}

pub(crate) static BRANCH: LazyLock<Regex> =
    LazyLock::new(|| pattern(r"\A[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\z"));
pub(crate) static REF: LazyLock<Regex> =
    LazyLock::new(|| pattern(r"\A(?:origin/[A-Za-z0-9][A-Za-z0-9._/-]{0,127}|[0-9a-f]{7,40})\z"));
static FULL_SHA: LazyLock<Regex> = LazyLock::new(|| pattern(r"\A[0-9a-f]{40}\z"));
static OUTPUT_TAIL: LazyLock<Regex> =
    LazyLock::new(|| pattern(r"\A(?P<command>.+?)\s+2>&1\s*\|\s*tail\s+-[1-9][0-9]*\z"));
static DIRECTORY: LazyLock<Regex> =
    LazyLock::new(|| pattern(r"\Acd\s+(?P<directory>[^\s;&|<>]+)\s+&&\s+(?P<command>.+)\z"));
static PATH_OPERAND: LazyLock<Regex> = LazyLock::new(|| pattern(r"\A[A-Za-z0-9._/~+-]+\z"));
static REDIRECTION: LazyLock<Regex> = LazyLock::new(|| pattern(r"\A\d*(?:>|<|>>|<<|>&|<&).+\z"));

fn contains_any(text: &str, markers: &[&str]) -> bool {
    markers.iter().any(|marker| text.contains(marker))
}

fn path_text(path: &Path) -> PyPath {
    PyPath::new(&path.to_string_lossy())
}

/// `is_safe_git_worktree_add`: one new branch or detached worktree under a
/// bounded developer root.
pub(crate) fn is_safe_git_worktree_add(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: &Path,
    ctx: &Ctx,
) -> bool {
    let Some((command_text, execution_cwd)) =
        resolved_worktree_command(command_text, cwd, home_dir, ctx)
    else {
        return false;
    };
    let Some(tokens) = literal_tokens(&command_text) else {
        return false;
    };
    let word = |index: usize| tokens.get(index).map(String::as_str);
    let (branch, destination_text, reference): (Option<&str>, &str, &str) =
        if tokens.len() == 7 && tokens[..4] == ["git", "worktree", "add", "-b"] {
            (Some(&tokens[4]), &tokens[5], &tokens[6])
        } else if tokens.len() == 7
            && tokens[..3] == ["git", "worktree", "add"]
            && word(4) == Some("-b")
        {
            (Some(&tokens[5]), &tokens[3], &tokens[6])
        } else if tokens.len() == 6 && tokens[..4] == ["git", "worktree", "add", "--detach"] {
            if !FULL_SHA.is_match(&tokens[5]) {
                return false;
            }
            (None, &tokens[4], &tokens[5])
        } else {
            return false;
        };
    if branch.is_some_and(|name| !safe_git_name(name, &BRANCH)) {
        return false;
    }
    if !safe_path_operand(destination_text) || !safe_git_name(reference, &REF) {
        return false;
    }
    let destination = absolute_destination(destination_text, &execution_cwd, home_dir, ctx);
    match (pyfs::exists(&destination), pyfs::is_symlink(&destination)) {
        (Ok(false), Ok(false)) => {}
        _ => return false,
    }
    if !safe_worktree_parent(&destination, home_dir, ctx) {
        return false;
    }
    let cwd_text = execution_cwd.to_string();
    let Some(git) = ctx.host.trusted_git_binary(&cwd_text) else {
        return false;
    };
    if !ctx.host.git_worktree_add_config(&git, &cwd_text, reference)
        || !git_ref_exists(&git, &cwd_text, reference, ctx)
    {
        return false;
    }
    branch.is_none_or(|name| !git_branch_exists(&git, &cwd_text, name, ctx))
}

/// `_resolved_worktree_command`: the command text and strict execution cwd.
fn resolved_worktree_command(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: &Path,
    ctx: &Ctx,
) -> Option<(String, PyPath)> {
    let cwd = cwd?;
    if contains_any(command_text, &["$", "`", "<(", ">(", "\0", "\r", "\n"]) {
        return None;
    }
    let mut stripped = py_strip(command_text).to_owned();
    let mut piped_to_tail = false;
    if let Some(captures) = OUTPUT_TAIL.captures(&stripped) {
        piped_to_tail = true;
        stripped = captures["command"].to_owned();
    }
    let mut execution_cwd = path_text(cwd);
    let directory = DIRECTORY
        .captures(&stripped)
        .map(|found| (found["directory"].to_owned(), found["command"].to_owned()));
    if let Some((directory, command)) = directory {
        if !safe_path_operand(&directory) {
            return None;
        }
        execution_cwd = expand_path(&directory, &path_text(cwd), home_dir);
        stripped = command;
    }
    let execution_cwd = resolve_strict(&execution_cwd, ctx)?;
    if piped_to_tail
        && !ctx.host.trusted_path_command(
            "tail",
            &execution_cwd.to_string(),
            &home_dir.to_string_lossy(),
        )
    {
        return None;
    }
    Some((stripped, execution_cwd))
}

/// `_safe_path_operand` (also `_safe_cd_operand`).
pub(crate) fn safe_path_operand(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && (!value.starts_with('~') || value.starts_with("~/"))
        && !value.starts_with("~//")
        && PATH_OPERAND.is_match(value)
}

/// `is_safe_codex_memory_registry_search`: one bounded ripgrep search of the
/// Codex memory registry.
pub(crate) fn is_safe_codex_memory_registry_search(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: &Path,
    ctx: &Ctx,
) -> bool {
    let Some(tokens) = literal_tokens(command_text) else {
        return false;
    };
    let Some(cwd) = cwd else {
        return false;
    };
    if tokens.len() < 3 || tokens[0] != "rg" {
        return false;
    }
    let mut operands: Vec<&str> = Vec::new();
    let mut after_options = false;
    for token in &tokens[1..] {
        if !after_options && token == "--" {
            after_options = true;
            continue;
        }
        if !after_options && token.starts_with('-') {
            if !RG_FLAGS.contains(&token.as_str()) {
                return false;
            }
            continue;
        }
        operands.push(token);
    }
    if operands.len() != 2 || contains_any(operands[0], &["\0", "\r", "\n"]) {
        return false;
    }
    let target = expand_path(operands[1], &path_text(cwd), home_dir);
    let home = path_text(home_dir);
    let expected = home.join(".codex").join("memories").join("MEMORY.md");
    if absolute(&target, ctx) != absolute(&expected, ctx)
        || path_has_symlink_below_home(&expected, &home, ctx)
        || pyfs::is_symlink(&target) != Ok(false)
        || pyfs::is_file(&target) != Ok(true)
    {
        return false;
    }
    match std::fs::metadata(target.to_string()) {
        Ok(metadata) if metadata.len() <= 4 * 1024 * 1024 => {}
        _ => return false,
    }
    ctx.host
        .trusted_path_command("rg", &cwd.to_string_lossy(), &home_dir.to_string_lossy())
        && ctx
            .host
            .env("RIPGREP_CONFIG_PATH")
            .is_none_or(|value| py_strip(&value).is_empty())
}

/// `_path_has_symlink_below_home`.
pub(crate) fn path_has_symlink_below_home(path: &PyPath, home: &PyPath, ctx: &Ctx) -> bool {
    let (path, home) = (absolute(path, ctx), absolute(home, ctx));
    let Some(relative_parts) = path.relative_to(&home) else {
        return true;
    };
    let mut candidate = home;
    for part in relative_parts {
        candidate = candidate.join(&part);
        if pyfs::is_symlink(&candidate) != Ok(false) {
            return true;
        }
    }
    false
}

/// `_literal_tokens`.
pub(crate) fn literal_tokens(command_text: &str) -> Option<Vec<String>> {
    if contains_any(command_text, &SUBSTITUTION_MARKERS) {
        return None;
    }
    let tokens = shlex_split(command_text)?;
    tokens
        .iter()
        .all(|token| !OPERATORS.contains(&token.as_str()) && !REDIRECTION.is_match(token))
        .then_some(tokens)
}

/// `_safe_git_name`.
pub(crate) fn safe_git_name(value: &str, pattern: &Regex) -> bool {
    pattern.is_match(value)
        && !value.contains("..")
        && !value.contains("@{")
        && !value.contains("//")
        && !value.ends_with(['/', '.'])
        && !value.ends_with(".lock")
        && value
            .split('/')
            .all(|component| !matches!(component, "" | "." | ".."))
}

/// `_absolute_destination`.
pub(crate) fn absolute_destination(
    value: &str,
    cwd: &PyPath,
    home_dir: &Path,
    ctx: &Ctx,
) -> PyPath {
    let candidate = match value.strip_prefix("~/") {
        Some(rest) => path_text(home_dir).join(rest),
        None => PyPath::new(value),
    };
    let candidate = if candidate.is_absolute() {
        candidate
    } else {
        cwd.join(&candidate.to_string())
    };
    absolute(&candidate, ctx)
}

/// `_safe_worktree_parent`.
pub(crate) fn safe_worktree_parent(destination: &PyPath, home_dir: &Path, ctx: &Ctx) -> bool {
    let parent = destination.parent();
    let home_root = path_text(home_dir).join("CascadeProjects");
    let (Some(resolved_parent), Some(tmp_root), Some(home_root)) = (
        resolve_strict(&parent, ctx),
        resolve_strict(&PyPath::new("/tmp"), ctx),
        resolve_strict(&home_root, ctx),
    ) else {
        return false;
    };
    if pyfs::is_dir(&resolved_parent) != Ok(true) {
        return false;
    }
    [tmp_root, home_root]
        .iter()
        .any(|root| is_relative_to(&resolved_parent, root))
}

/// `_git_ref_exists`.
pub(crate) fn git_ref_exists(git: &str, cwd: &str, reference: &str, ctx: &Ctx) -> bool {
    let args = ["rev-parse", "--verify", "--quiet"]
        .map(str::to_owned)
        .into_iter()
        .chain([format!("{reference}^{{commit}}")])
        .collect::<Vec<_>>();
    let Some(result) = ctx.host.git_probe(git, &args, cwd) else {
        return false;
    };
    result.code == 0
        && FULL_SHA.is_match(result.stdout.strip_suffix('\n').unwrap_or(&result.stdout))
}

/// `_git_branch_exists`: an unanswerable probe counts as an existing branch.
pub(crate) fn git_branch_exists(git: &str, cwd: &str, branch: &str, ctx: &Ctx) -> bool {
    let args = ["show-ref", "--verify", "--quiet"]
        .map(str::to_owned)
        .into_iter()
        .chain([format!("refs/heads/{branch}")])
        .collect::<Vec<_>>();
    let Some(result) = ctx.host.git_probe(git, &args, cwd) else {
        return true;
    };
    result.code != 1 || !result.stdout.is_empty() || !result.stderr.is_empty()
}

/// `_expand_path`.
pub(crate) fn expand_path(value: &str, cwd: &PyPath, home_dir: &Path) -> PyPath {
    if let Some(rest) = value.strip_prefix("~/") {
        return path_text(home_dir).join(rest);
    }
    let path = PyPath::new(value);
    if path.is_absolute() {
        path
    } else {
        cwd.join(value)
    }
}
