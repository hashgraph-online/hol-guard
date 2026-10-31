//! Native planning for protected read-only Git inspections (`git-readonly-v1`).
//!
//! The plan names the trusted Git executable, the directory Git's own `-C`
//! walk lands in, and the linked worktree metadata Git has to read. It never
//! grants the checkout a linked worktree points back to.
use super::*;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::Component;

/// Proves a resolved Git executable the way the execution-safety checks do:
/// `(git, cwd, account home, groups)`.
pub type GitBinaryTrust = fn(&Path, &Path, &Path, &[u32]) -> bool;

const INVALID_COMMAND: &str = "git_restricted_invalid_command";
const INVALID_METADATA: &str = "git_restricted_invalid_metadata";
const SANDBOX_UNAVAILABLE: &str = "git_restricted_sandbox_unavailable";

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Input {
    command: Vec<String>,
    workspace: PathBuf,
    cwd: PathBuf,
    home: Option<PathBuf>,
    platform: String,
    backend_executable: Option<PathBuf>,
    search_path: String,
    account_home: PathBuf,
    groups: Vec<u32>,
    source: std::collections::BTreeMap<String, String>,
}

/// `prepare_git`: the whole plan, checked in the order the sink always has:
/// argv, workspace, cwd, `-C` walk, backend, executable, trust, read roots.
pub fn prepare_git(input: &Value, trusted: GitBinaryTrust) -> Value {
    let result = serde_json::from_value::<Input>(input.clone())
        .map_err(|_| {
            RestrictedPytestError::new(INVALID_COMMAND, "Invalid restricted execution request.")
        })
        .and_then(|input| prepare(&input, trusted));
    match result {
        Ok(value) => json!({ "value": value }),
        Err(error) => crate::restricted_command::error_reply(error),
    }
}

/// `git_environment`: the sandbox environment with every host Git, pager and
/// config-home setting removed and Git told never to prompt, lock or fetch.
pub(super) fn evaluate(operation: &str, input: &Value) -> Option<Value> {
    if operation != "git_environment" {
        return None;
    }
    let Ok(input) = serde_json::from_value::<Input>(input.clone()) else {
        return Some(crate::restricted_command::error_reply(
            RestrictedPytestError::new(INVALID_COMMAND, "Invalid restricted execution request."),
        ));
    };
    let mut environment = input.source;
    environment.retain(|key, _| {
        !key.starts_with("GIT_") && !matches!(key.as_str(), "PAGER" | "XDG_CONFIG_HOME")
    });
    for (key, value) in [
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_NO_LAZY_FETCH", "1"),
    ] {
        environment.insert(key.to_owned(), value.to_owned());
    }
    Some(json!({ "value": environment }))
}

fn prepare(input: &Input, trusted: GitBinaryTrust) -> Result<Value, RestrictedPytestError> {
    let argv = normalized_command(&input.command)?;
    // The same grammar the hook reads the command with names the operation
    // here, so a read it contains is a read this sink can plan.
    let reading = crate::contained_git::read_only_invocation(&argv).ok_or_else(|| {
        RestrictedPytestError::new(
            INVALID_COMMAND,
            "Protected Git requires direct read-only argv.",
        )
    })?;
    let root = validation::resolve_workspace_with_home(&input.workspace, input.home.as_deref())?;
    let start = if input.cwd.as_os_str().is_empty() {
        root.clone()
    } else {
        input.cwd.clone()
    };
    let mut directory = resolve_cwd(&start, &root)?;
    // Git's own -C would move the run out from under the roots this plan
    // grants, so the sink walks the same path and starts the run there. Each
    // one is resolved against the last, as Git resolves them, and each has to
    // land inside the approved workspace on its own.
    for named in &reading.directories {
        let step = Path::new(named);
        let next = if step.is_absolute() {
            step.to_path_buf()
        } else {
            directory.join(step)
        };
        directory = resolve_cwd(&next, &root)?;
    }
    let (backend, backend_executable) = select_backend(
        &input.platform,
        input.backend_executable.as_deref(),
        &input.search_path,
    )?;
    if !matches!(backend, "macos-seatbelt" | "linux-bubblewrap") {
        return Err(RestrictedPytestError::new(
            SANDBOX_UNAVAILABLE,
            "Protected Git filtering is unavailable.",
        ));
    }
    let executable = resolve_executable(&argv[0], &directory, &input.search_path)?;
    if !trusted(&executable, &directory, &input.account_home, &input.groups) {
        return Err(RestrictedPytestError::new(
            INVALID_COMMAND,
            "Git does not resolve to a trusted executable.",
        ));
    }
    let read_only_roots = repository_read_roots(&root, &directory).ok_or_else(|| {
        RestrictedPytestError::new(
            INVALID_METADATA,
            "Git metadata could not be safely resolved.",
        )
    })?;
    // The reading writes each helper screen ahead of the caller's own words, so
    // an option-shaped pathname cannot push one past '--'.
    let mut command = vec![
        executable.to_string_lossy().into_owned(),
        "--no-pager".to_owned(),
        "-c".to_owned(),
        "core.fsmonitor=false".to_owned(),
        reading.operation,
    ];
    command.extend(reading.arguments);
    Ok(json!({
        "profile_version": "git-readonly-v1",
        "backend": backend,
        "backend_executable": backend_executable,
        "workspace": root,
        "cwd": directory,
        "executable": executable,
        "command": command,
        "allowed_executables": [executable],
        "read_only_roots": read_only_roots,
        "denied_capabilities": [
            "workspace-write",
            "workspace-credential-read",
            "network",
            "unapproved-process-exec",
            "host-secret-environment",
            "host-home-read",
        ],
    }))
}

/// One `gitdir:` or `commondir` pointer: a regular file, at most 4 KiB, no NUL.
fn metadata_pointer(path: &Path) -> Option<String> {
    if fs::symlink_metadata(path).ok()?.file_type().is_symlink() {
        return None;
    }
    let mut data = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(4097)
        .read_to_end(&mut data)
        .ok()?;
    if data.len() > 4096 || data.contains(&0) {
        return None;
    }
    Some(String::from_utf8(data).ok()?.trim().to_owned())
}

/// Resolve only Git's linked metadata, never grant its parent checkout. A
/// plain `.git` directory inside the workspace is already readable; a linked
/// worktree's pointer has to name a worktree of an owned, unshared repository.
fn repository_read_roots(workspace: &Path, cwd: &Path) -> Option<Vec<PathBuf>> {
    let mut directory = cwd.to_path_buf();
    while !directory.join(".git").exists() {
        if directory == workspace {
            return Some(Vec::new());
        }
        if !directory.pop() {
            return None;
        }
    }
    let pointer = directory.join(".git");
    let link = fs::symlink_metadata(&pointer).ok()?;
    if pointer.is_dir() && !link.file_type().is_symlink() {
        return Some(Vec::new());
    }
    let text = metadata_pointer(&pointer)?;
    let target = text
        .strip_prefix("gitdir: ")
        .filter(|_| !text.contains('\n'))?;
    let target = Path::new(target);
    let gitdir = if target.is_absolute() {
        target.to_path_buf()
    } else {
        directory.join(target)
    }
    .canonicalize()
    .ok()?;
    if !gitdir.is_dir() {
        return None;
    }
    let common_pointer = gitdir.join("commondir");
    let common = if common_pointer.exists() {
        let common = gitdir
            .join(metadata_pointer(&common_pointer)?)
            .canonicalize()
            .ok()?;
        let parts: Vec<Component<'_>> = gitdir.strip_prefix(&common).ok()?.components().collect();
        if parts.len() != 2 || parts[0] != Component::Normal(OsStr::new("worktrees")) {
            return None;
        }
        common
    } else {
        gitdir.clone()
    };
    if !common
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| name.ends_with(".git"))
        || !common.join("objects").is_dir()
        || !common.join("refs").is_dir()
    {
        return None;
    }
    let uid = nix::unistd::getuid().as_raw();
    for root in [&gitdir, &common] {
        let metadata = fs::metadata(root).ok()?;
        if ![0, uid].contains(&metadata.uid()) || metadata.mode() & 0o022 != 0 {
            return None;
        }
    }
    let mut roots = vec![gitdir];
    if roots[0] != common {
        roots.push(common);
    }
    Some(roots)
}

#[cfg(test)]
#[path = "git_plan_tests.rs"]
mod tests;
