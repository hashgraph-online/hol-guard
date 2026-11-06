//! One modeled Git segment: argument shape plus the environment facts that
//! prove the invocation cannot execute configured helpers.

use std::path::{Path, PathBuf};

use guard_contracts::CompoundGitSegmentV1;

use crate::compound_git_args as args;
use crate::compound_git_facts::GitFacts;
use crate::compound_git_paths::{is_relative_to, resolve};

const SHOW_CONFIG_PATTERN: &str = r"^(diff\..*\.(command|textconv)|diff\.external)$";

/// The resolved execution directory and the directory Git runs against.
pub(crate) fn invocation_cwds(
    segment: &CompoundGitSegmentV1,
    repository_path: Option<&str>,
    home_dir: Option<&Path>,
) -> Option<(PathBuf, PathBuf)> {
    let execution_cwd = resolve(Path::new(segment.effective_cwd.as_deref()?))?;
    let repository_cwd = match repository_path {
        None => execution_cwd.clone(),
        Some(path) => {
            let requested = match path.strip_prefix("~/") {
                Some(tail) => resolve(home_dir?)?.join(tail),
                None => PathBuf::from(path),
            };
            resolve(&execution_cwd.join(requested))?
        }
    };
    let mut roots = vec![execution_cwd.clone()];
    if let Some(home) = home_dir {
        roots.push(resolve(home)?);
    }
    (repository_cwd.is_dir()
        && roots
            .iter()
            .any(|root| is_relative_to(&repository_cwd, root)))
    .then_some((execution_cwd, repository_cwd))
}

/// Whether Git log-family output cannot invoke an executable pager.
pub(crate) fn log_config_is_execution_free(
    facts: &dyn GitFacts,
    cwd: &Path,
    git: &Path,
    pager_key: &str,
) -> bool {
    if let Some(git_pager) = facts.env("GIT_PAGER") {
        return matches!(git_pager, "" | "cat") && facts.routing_environment_is_clean();
    }
    if !matches!(facts.env("PAGER").unwrap_or(""), "" | "cat") {
        return false;
    }
    if !facts.routing_environment_is_clean() {
        return false;
    }
    for key in ["core.pager", pager_key] {
        let Some(output) = facts.probe(git, cwd, &["config", "--null", "--get-all", key]) else {
            return false;
        };
        if output.code == Some(1) && output.stdout.is_empty() {
            continue;
        }
        if output.code != Some(0) {
            return false;
        }
        let Some(text) = output.text() else {
            return false;
        };
        if text
            .split('\0')
            .any(|value| !value.is_empty() && value != "cat")
        {
            return false;
        }
    }
    true
}

/// Whether `git diff`/`show`/`blame` cannot run an external diff or textconv.
pub(crate) fn show_config_is_execution_free(
    facts: &dyn GitFacts,
    segment: &CompoundGitSegmentV1,
    repository_path: Option<&str>,
) -> bool {
    if segment.effective_cwd.is_none() {
        return false;
    }
    if !facts
        .env("GIT_EXTERNAL_DIFF")
        .unwrap_or("")
        .trim()
        .is_empty()
        || !facts.routing_environment_is_clean()
    {
        return false;
    }
    let Some((execution_cwd, repository_cwd)) = invocation_cwds(segment, repository_path, None)
    else {
        return false;
    };
    let Some(git) = facts.trusted_git(&execution_cwd) else {
        return false;
    };
    facts
        .probe(
            &git,
            &repository_cwd,
            &["config", "--null", "--get-regexp", SHOW_CONFIG_PATTERN],
        )
        .is_some_and(|output| output.code == Some(1) && output.stdout.is_empty())
}

/// One bounded Git refresh or inspection segment.
pub(crate) fn is_low_risk_git_inspection_segment(
    facts: &dyn GitFacts,
    segment: &CompoundGitSegmentV1,
    home_dir: Option<&Path>,
) -> bool {
    let Some(tokens) = args::without_stderr_merge(&segment.tokens) else {
        return false;
    };
    if tokens.len() < 2 {
        return false;
    }
    let mut operation_index = 1;
    let mut repository_path = None;
    if tokens[1] == "-C" {
        if tokens.len() < 4 || !args::safe_git_c_repository_path(tokens[2], home_dir.is_some()) {
            return false;
        }
        repository_path = Some(tokens[2]);
        operation_index = 3;
    }
    let Some((execution_cwd, repository_cwd)) = invocation_cwds(segment, repository_path, home_dir)
    else {
        return false;
    };
    let Some(git) = facts.trusted_git(&execution_cwd) else {
        return false;
    };
    let operation = tokens[operation_index];
    let rest = &tokens[operation_index + 1..];
    let log_config = |key: &str| log_config_is_execution_free(facts, &repository_cwd, &git, key);
    let show_config = || show_config_is_execution_free(facts, segment, repository_path);
    match operation {
        "fetch" => args::safe_fetch_args(rest) && facts.fetch_origin_is_safe(&repository_cwd, &git),
        "ls-remote" => {
            args::safe_ls_remote_args(rest) && facts.fetch_origin_is_safe(&repository_cwd, &git)
        }
        "log" => args::safe_bounded_log_args(rest) && log_config("pager.log"),
        "blame" => args::safe_blame_args(rest) && show_config() && log_config("pager.blame"),
        "status" => {
            rest.iter().all(|arg| args::safe_status_arg(arg))
                && facts.status_is_safe(&repository_cwd, &git)
        }
        "branch" => args::safe_branch_args(rest) && log_config("pager.branch"),
        "rev-parse" => args::safe_rev_parse_args(rest),
        "diff" => args::safe_diff_args(rest) && show_config(),
        "ls-files" => args::safe_ls_files_args(rest),
        "show" => args::safe_show_args(rest) && show_config(),
        "worktree" => rest == ["list", "--porcelain"],
        _ => false,
    }
}

/// One current-branch push to a verified GitHub origin.
pub(crate) fn is_low_risk_git_push_segment(
    facts: &dyn GitFacts,
    segment: &CompoundGitSegmentV1,
) -> bool {
    let Some(tokens) = args::without_stderr_merge(&segment.tokens) else {
        return false;
    };
    if tokens.len() != 5
        || tokens[0] != "git"
        || tokens[1] != "push"
        || !matches!(tokens[2], "-u" | "--set-upstream")
        || tokens[3] != "origin"
        || !args::safe_ref(tokens[4])
    {
        return false;
    }
    let Some((execution_cwd, repository_cwd)) = invocation_cwds(segment, None, None) else {
        return false;
    };
    facts
        .trusted_git(&execution_cwd)
        .is_some_and(|git| facts.push_origin_is_safe(&repository_cwd, &git, tokens[4]))
}
