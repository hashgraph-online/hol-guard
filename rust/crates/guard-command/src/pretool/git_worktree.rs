use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

#[path = "git_worktree_hooks.rs"]
mod hooks;
#[path = "git_worktree_config.rs"]
mod sources;
#[path = "git_worktree_tracking.rs"]
mod tracking;

use hooks::{hooks_are_inert, repository_hooks_inert};
use sources::{expand_config_path, safe_worktree_config, ConfigFacts};

/// The whole configuration listing, every entry of which the screen below
/// judges. Long-lived repositories collect a `branch.<name>` section for each
/// branch a worktree was ever created on, so a busy checkout's listing runs to
/// hundreds of kilobytes; a smaller cap turned every later `worktree add` in
/// such a repository into a review. This matches the session probe's bound.
const CONFIG_LIMIT: u64 = 8 * 1024 * 1024;
const WORKTREE_PROBE_LIMIT: u64 = 8 * 1024;

#[allow(clippy::too_many_arguments)]
pub(super) fn worktree_add_execution_free(
    executable: &str,
    leading: &[String],
    destination: &Path,
    branch: Option<&str>,
    reference: Option<&str>,
    attach: bool,
    reference_may_move: bool,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<bool> {
    let probe_deadline = Instant::now() + super::git_probe::PROBE_BUDGET;
    let deadline = deadline.unwrap_or(probe_deadline).min(probe_deadline);
    if Instant::now() >= deadline || !destination.is_absolute() {
        return None;
    }
    let (base, _binary, cwd, git_home) =
        prepared_git_command(executable, context, execution_environment)?;
    let home = fs::canonicalize(Path::new(context.home_dir?)).ok()?;
    if !destination.starts_with(&home)
        && !destination
            .parent()
            .is_some_and(|parent| super::worktree_add::fresh_temporary_parent(parent, context))
    {
        return Some(false);
    }
    match fs::symlink_metadata(destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => return Some(false),
        Err(_) => return None,
    }
    let (status, output) = git_query(
        &base,
        leading,
        [
            "--no-pager",
            "config",
            "--includes",
            "--show-scope",
            "--null",
            "--get-regexp",
            "^.*$",
        ],
        deadline,
        CONFIG_LIMIT,
    )?;
    if !(status.success() || status.code() == Some(1) && output.is_empty()) {
        return None;
    }
    let Some(facts) = safe_worktree_config(&output, &git_home)? else {
        return Some(false);
    };
    let [git_dir, common_dir] = git_paths(
        &base,
        leading,
        ["--absolute-git-dir", "--git-common-dir"],
        &cwd,
        deadline,
    )?;
    if !hooks_are_inert(&git_dir.join("hooks"), &|_| false)
        || !hooks_are_inert(&common_dir.join("hooks"), &|_| false)
    {
        return Some(false);
    }
    if !facts
        .hook_dirs
        .iter()
        .all(|directory| hooks_are_inert(directory, &|_| false))
    {
        return Some(false);
    }
    // Without `-b` no branch is created, so there is no name that could
    // already exist.
    if let Some(branch) = branch {
        let branch_ref = format!("refs/heads/{branch}");
        let (status, output) = git_query_with_args(
            &base,
            leading,
            &["show-ref", "--verify", "--quiet", &branch_ref],
            deadline,
            WORKTREE_PROBE_LIMIT,
        )?;
        if status.success() {
            return Some(false);
        }
        if status.code() != Some(1) || !output.is_empty() {
            return None;
        }
    }
    let branch_ref: String;
    let tracking_ref: String;
    let mut reference = reference.unwrap_or("HEAD");
    let mut local_branch = false;
    // Without `-b` or `--detach`, `git worktree add <path> <name>` checks
    // out `refs/heads/<name>` when that branch exists (Git never treats
    // `HEAD` as a branch name here), whatever the name would otherwise
    // resolve to. Read that branch's tip so the tree proven is the tree
    // checked out. Otherwise Git detaches at the commit the name resolves
    // to, which the `rev-parse` below resolves the same way. A name that
    // resolves to nothing makes Git create a branch of that name from the one
    // remote-tracking branch that matches it, so that ref is proven instead.
    // With no such branch Git stops before writing anything, unless a fetch
    // earlier in the same command creates one first.
    if attach && reference != "HEAD" {
        branch_ref = format!("refs/heads/{reference}");
        let (status, output) = git_query_with_args(
            &base,
            leading,
            &["show-ref", "--verify", "--quiet", &branch_ref],
            deadline,
            WORKTREE_PROBE_LIMIT,
        )?;
        if status.success() {
            reference = branch_ref.as_str();
            local_branch = true;
        } else if status.code() != Some(1) || !output.is_empty() {
            return None;
        }
    }
    let commit_ref = format!("{reference}^{{commit}}");
    let (mut status, mut output) = git_query_with_args(
        &base,
        leading,
        &["rev-parse", "--verify", "--quiet", &commit_ref],
        deadline,
        WORKTREE_PROBE_LIMIT,
    )?;
    if attach && !local_branch && reference != "HEAD" && !status.success() {
        tracking_ref =
            match tracking::resolve(&base, leading, reference, &facts, &common_dir, deadline)? {
                tracking::Tracking::Unique(found) => found,
                tracking::Tracking::Missing => {
                    return Some(
                        !reference_may_move && status.code() == Some(1) && output.is_empty(),
                    )
                }
                tracking::Tracking::Unproven => return Some(false),
            };
        reference = tracking_ref.as_str();
        let commit_ref = format!("{reference}^{{commit}}");
        (status, output) = git_query_with_args(
            &base,
            leading,
            &["rev-parse", "--verify", "--quiet", &commit_ref],
            deadline,
            WORKTREE_PROBE_LIMIT,
        )?;
    }
    if !status.success() || output.is_empty() {
        return Some(false);
    }
    // A hook manager's repository-relative hooks directory also runs from the
    // new tree, which the commit being checked out decides.
    if let Some(hooks_path) = facts.repository_hooks_path.as_deref() {
        // A fetch earlier in the same command can move the reference.
        if reference_may_move {
            return Some(false);
        }
        if !repository_hooks_inert(&base, leading, hooks_path, commit_id(&output)?, deadline)? {
            return Some(false);
        }
    }
    if !facts.filters {
        return Some(true);
    }
    // A fetch earlier in the same command can move the reference, so the
    // tree checked out is not the one read here. Only the filter the user's
    // own `git lfs install` wrote may then be configured; the repository
    // already may not name LFS programs or filters of its own.
    if reference_may_move {
        return Some(facts.only_standard_lfs);
    }
    let commit = commit_id(&output)?;
    let attribute_sources_free = no_filter_attributes(
        &base,
        leading,
        commit,
        &common_dir,
        &facts,
        &git_home,
        execution_environment?,
        deadline,
    )?;
    Some(attribute_sources_free)
}

const ATTRIBUTES_LIMIT: u64 = 1024 * 1024;
const MAX_TREE_ATTRIBUTE_FILES: usize = 16;

fn mentions_filter(bytes: &[u8]) -> bool {
    bytes
        .windows(6)
        .any(|window| window.eq_ignore_ascii_case(b"filter"))
}

/// A global filter driver only runs for paths whose attributes assign
/// `filter=`. Prove no attribute source of this checkout mentions `filter`:
/// the checked-out tree's `.gitattributes` files, `info/attributes`, and the
/// global attributes file. `None` is doubt and keeps review.
#[allow(clippy::too_many_arguments)]
fn no_filter_attributes(
    base: &Command,
    leading: &[String],
    commit: &str,
    common_dir: &Path,
    facts: &ConfigFacts,
    git_home: &Path,
    environment: &guard_contracts::GuardExecutionEnvironmentV1,
    deadline: Instant,
) -> Option<bool> {
    if facts.attribute_source_override {
        return Some(false);
    }
    // Tree `.gitattributes` files.
    let (status, listing) = git_query_with_args(
        base,
        leading,
        &["ls-tree", "-r", "-z", "--name-only", commit],
        deadline,
        super::git_probe::LISTING_LIMIT,
    )?;
    if !status.success() {
        return None;
    }
    let mut seen = 0;
    for path in listing
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let name = path.rsplit(|byte| *byte == b'/').next().unwrap_or(path);
        if name != b".gitattributes" {
            continue;
        }
        seen += 1;
        if seen > MAX_TREE_ATTRIBUTE_FILES {
            return None;
        }
        let object = format!("{commit}:{}", std::str::from_utf8(path).ok()?);
        let (status, content) = git_query_with_args(
            base,
            leading,
            &["cat-file", "blob", &object],
            deadline,
            ATTRIBUTES_LIMIT,
        )?;
        if !status.success() {
            return None;
        }
        if mentions_filter(&content) {
            return Some(false);
        }
    }
    // Repository-wide and user-wide attribute files.
    let global = match facts.attributes_file.as_deref() {
        Some(value) => expand_config_path(value, git_home)?,
        None => match environment.xdg_config_home.as_deref() {
            Some(directory) => Path::new(directory).join("git/attributes"),
            None => git_home.join(".config/git/attributes"),
        },
    };
    // Git also reads the system attributes file.
    let system = sources::system_attribute_files(base, leading, deadline)?;
    for file in [common_dir.join("info/attributes"), global]
        .into_iter()
        .chain(system)
    {
        if attributes_file_mentions_filter(&file)? {
            return Some(false);
        }
    }
    Some(true)
}

fn attributes_file_mentions_filter(path: &Path) -> Option<bool> {
    use std::io::Read;
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some(false),
        Err(_) => return None,
    };
    if !metadata.is_file() || metadata.len() > ATTRIBUTES_LIMIT {
        return None;
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(ATTRIBUTES_LIMIT + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= ATTRIBUTES_LIMIT).then(|| mentions_filter(&bytes))
}

pub(super) fn trusted_pipeline_command(
    executable: &str,
    context: super::PathContext<'_>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let Some(declared_home) = context.home_dir.map(Path::new) else {
        return false;
    };
    let Some(declared_cwd) = context.cwd.map(Path::new) else {
        return false;
    };
    let (Ok(home), Ok(cwd)) = (
        fs::canonicalize(declared_home),
        fs::canonicalize(declared_cwd),
    ) else {
        return false;
    };
    let Some(environment) = execution_environment else {
        return false;
    };
    if !home.is_dir()
        || !cwd.is_dir()
        || !super::git_config::clean_environment(Some(environment), &home, &cwd)
        || environment
            .home
            .as_deref()
            .and_then(|path| fs::canonicalize(path).ok())
            != Some(home.clone())
    {
        return false;
    }
    super::git_config::trusted_command(executable, &home, &cwd, Some(environment)).is_some()
}

fn prepared_git_command(
    executable: &str,
    context: super::PathContext<'_>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<(Command, PathBuf, PathBuf, PathBuf)> {
    let declared_home = Path::new(context.home_dir?);
    let declared_cwd = Path::new(context.cwd?);
    if !declared_home.is_absolute() || !declared_cwd.is_absolute() {
        return None;
    }
    let home = fs::canonicalize(declared_home).ok()?;
    let cwd = fs::canonicalize(declared_cwd).ok()?;
    let environment = execution_environment?;
    if !home.is_dir()
        || !cwd.is_dir()
        || !super::git_config::clean_environment(Some(environment), &home, &cwd)
    {
        return None;
    }
    let binary =
        super::git_config::trusted_command(executable, &home, &cwd, execution_environment)?;
    let mut command = Command::new(&binary);
    command.env_clear();
    #[cfg(windows)]
    for key in ["SYSTEMROOT", "WINDIR"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    let git_home = Path::new(environment.home.as_deref()?).to_path_buf();
    if !git_home.is_absolute() || fs::canonicalize(&git_home).ok()? != home {
        return None;
    }
    // Probe the configuration the agent's Git will read: the system file
    // unless the session disables it, and the session's XDG directory.
    // `safe_worktree_config` then judges every scope.
    if environment.git_config_no_system {
        command.env("GIT_CONFIG_NOSYSTEM", "1");
    }
    if let Some(directory) = environment.xdg_config_home.as_deref() {
        command.env("XDG_CONFIG_HOME", directory);
    }
    command
        .current_dir(&cwd)
        .env("HOME", &git_home)
        .env("USERPROFILE", &git_home);
    Some((command, binary, cwd, git_home))
}

fn git_query<const N: usize>(
    base: &Command,
    leading: &[String],
    arguments: [&str; N],
    deadline: Instant,
    limit: u64,
) -> Option<(std::process::ExitStatus, Vec<u8>)> {
    let mut command = super::git_probe::copy_command(base)?;
    command.args(leading).args(arguments);
    super::git_probe::output(&mut command, deadline, limit)
}

fn git_query_with_args(
    base: &Command,
    leading: &[String],
    arguments: &[&str],
    deadline: Instant,
    limit: u64,
) -> Option<(std::process::ExitStatus, Vec<u8>)> {
    let mut command = super::git_probe::copy_command(base)?;
    command.args(leading).args(arguments);
    super::git_probe::output(&mut command, deadline, limit)
}

/// One `rev-parse` answers every request, one line each, in order. A path
/// that itself held a line break shifts the count, so the answer is refused.
fn git_paths<const N: usize>(
    base: &Command,
    leading: &[String],
    requests: [&str; N],
    cwd: &Path,
    deadline: Instant,
) -> Option<[PathBuf; N]> {
    let mut arguments = vec!["rev-parse"];
    arguments.extend(requests);
    let (status, output) =
        git_query_with_args(base, leading, &arguments, deadline, 4096 * N as u64)?;
    if !status.success() {
        return None;
    }
    let rendered = std::str::from_utf8(&output).ok()?;
    let rendered = rendered.strip_suffix('\n').unwrap_or(rendered);
    let paths = rendered
        .split('\n')
        .map(|line| {
            let line = line.trim();
            if line.is_empty() || line.contains(['\0', '\r']) {
                return None;
            }
            let path = Path::new(line);
            fs::canonicalize(if path.is_absolute() {
                path.to_path_buf()
            } else {
                cwd.join(path)
            })
            .ok()
        })
        .collect::<Option<Vec<_>>>()?;
    paths.try_into().ok()
}

fn commit_id(output: &[u8]) -> Option<&str> {
    let commit = std::str::from_utf8(output).ok()?.trim();
    (commit.len() >= 40
        && commit.len() <= 64
        && commit.bytes().all(|byte| byte.is_ascii_hexdigit()))
    .then_some(commit)
}
