use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const CONFIG_LIMIT: u64 = 65_536;
const WORKTREE_PROBE_LIMIT: u64 = 8 * 1024;

#[allow(clippy::too_many_arguments)]
pub(super) fn worktree_add_execution_free(
    executable: &str,
    leading: &[String],
    destination: &Path,
    branch: &str,
    reference: Option<&str>,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<bool> {
    let probe_deadline = Instant::now() + Duration::from_secs(2);
    let deadline = deadline.unwrap_or(probe_deadline).min(probe_deadline);
    if Instant::now() >= deadline || !destination.is_absolute() {
        return None;
    }
    let (base, _binary, cwd, _git_home) =
        prepared_git_command(executable, context, execution_environment)?;
    let home = fs::canonicalize(Path::new(context.home_dir?)).ok()?;
    if !destination.starts_with(&home) {
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
    if !safe_worktree_config(&output)? {
        return Some(false);
    }
    let git_dir = git_path(
        &base,
        leading,
        &["rev-parse", "--absolute-git-dir"],
        &cwd,
        deadline,
    )?;
    let common_dir = git_path(
        &base,
        leading,
        &["rev-parse", "--git-common-dir"],
        &cwd,
        deadline,
    )?;
    if !hooks_are_inert(&git_dir.join("hooks")) || !hooks_are_inert(&common_dir.join("hooks")) {
        return Some(false);
    }
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
    let reference = reference.unwrap_or("HEAD");
    let commit_ref = format!("{reference}^{{commit}}");
    let (status, output) = git_query_with_args(
        &base,
        leading,
        &["rev-parse", "--verify", "--quiet", &commit_ref],
        deadline,
        WORKTREE_PROBE_LIMIT,
    )?;
    Some(status.success() && !output.is_empty())
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
        || !environment.git_config_no_system
        || environment.xdg_config_home.is_some()
        || !super::git_config::clean_environment(Some(environment))
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
    if !environment.git_config_no_system
        || environment.xdg_config_home.is_some()
        || !home.is_dir()
        || !cwd.is_dir()
        || !super::git_config::clean_environment(Some(environment))
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
    command
        .current_dir(&cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
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

fn git_path(
    base: &Command,
    leading: &[String],
    arguments: &[&str],
    cwd: &Path,
    deadline: Instant,
) -> Option<PathBuf> {
    let (status, output) = git_query_with_args(base, leading, arguments, deadline, 4096)?;
    if !status.success() {
        return None;
    }
    let rendered = std::str::from_utf8(&output).ok()?.trim();
    if rendered.is_empty() || rendered.contains(['\0', '\n', '\r']) {
        return None;
    }
    let path = Path::new(rendered);
    fs::canonicalize(if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    })
    .ok()
}

fn safe_worktree_config(output: &[u8]) -> Option<bool> {
    let output = std::str::from_utf8(output).ok()?;
    let mut records = output.split('\0');
    while let Some(scope) = records.next() {
        if scope.is_empty() {
            continue;
        }
        let record = records.next()?;
        let (key, value) = record.split_once('\n')?;
        let key = key.to_ascii_lowercase();
        if key == "core.bare" && super::git_config::enabled_boolean(value) {
            return Some(false);
        }
        // `worktree add` and each probe below use built-in commands, local
        // refs, and no diff/editor operation. A global credential helper is
        // not consulted for this local-ref operation; retain the deny floor
        // for repository-scoped helpers and execution-capable settings.
        if key == "core.hookspath"
            || key == "core.worktree"
            || key == "core.fsmonitor"
            || key == "core.sshcommand"
            || key == "core.gitproxy"
            || key == "core.askpass"
            || key == "core.pager"
            || key.starts_with("hook.")
            || key.starts_with("pager.")
            || key.starts_with("filter.")
            || (key.starts_with("credential.") && scope != "global")
            || key.starts_with("include")
            || key.starts_with("extensions.")
            || key.starts_with("submodule.")
            || key.ends_with(".promisor")
            || key.ends_with(".partialclonefilter")
            || key.ends_with(".uploadpack")
            || key.ends_with(".receivepack")
        {
            return Some(false);
        }
    }
    Some(true)
}

fn hooks_are_inert(path: &Path) -> bool {
    const EXECUTABLE_HOOKS: &[&str] = &[
        "post-checkout",
        "post-index-change",
        "reference-transaction",
    ];
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
        Err(_) => return false,
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return false;
    }
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(_) => return false,
    };
    for (count, entry) in entries.enumerate() {
        if count >= 256 {
            return false;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => return false,
        };
        let metadata = match fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(_) => return false,
        };
        if metadata.file_type().is_symlink() {
            return false;
        }
        if EXECUTABLE_HOOKS.contains(&entry.file_name().to_string_lossy().as_ref())
            && metadata.is_file()
            && hook_is_executable(&metadata)
        {
            return false;
        }
    }
    true
}

#[cfg(unix)]
fn hook_is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn hook_is_executable(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
}
