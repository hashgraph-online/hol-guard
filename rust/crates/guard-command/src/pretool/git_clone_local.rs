//! `git clone` of a local repository into a directory that does not exist yet.
//!
//! Copying a repository the user already has writes a new repository and
//! checks one of its branches out. What could run while that happens is what
//! a worktree checkout could run: a filter the configuration names, a hook,
//! or a template directory whose hooks the new repository would keep. The
//! same execution-free proof answers for all three, read in the repository
//! being copied, because that is where the agent's Git reads the
//! configuration and attributes the new checkout uses.
//!
//! A clone of a local checkout below the home directory or an owned
//! temporary directory, into a fresh directory below the same roots, writes
//! only that new copy. A URL or `file://` transport, a source anywhere else,
//! a template, a configuration override, submodules and every other option
//! keep their review.

use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::path::{Path, PathBuf};
use std::time::Instant;

pub(crate) const REASON: &str = "native_exact_safe_git_clone_local";

const MAX_PATH_BYTES: usize = 4096;

struct LocalClone<'a> {
    leading: Vec<String>,
    source: &'a str,
    destination: &'a str,
    branch: Option<&'a str>,
}

pub(in crate::pretool) fn exact_safe_command(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<(&'static str, &'static str)> {
    let [segment] = model.segments.as_slice() else {
        return None;
    };
    if model.confidence != "exact" || model.path_overridden || !model.wrapper_chain.is_empty() {
        return None;
    }
    proven(segment, context, deadline, execution_environment)?;
    Some((
        REASON,
        "The Rust command authority proved this Git command copies a local repository into a directory that does not exist yet under the user's home or temporary directory, with no template, hook or filter that could run.",
    ))
}

/// The copy a proven `git clone` would create, or `None` when anything about
/// the command, the repository being copied or the new directory is left
/// uncertain.
fn proven(
    segment: &CommandSegmentV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<PathBuf> {
    let executable = segment.executable.as_deref()?;
    if super::executable_basename(executable) != "git"
        || segment.pipeline_index != 0
        || segment.path_overridden
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
        || segment.text.contains(['>', '<', '$', '`', '\n', '\r'])
        || !super::directory_targets::drive_targets_quoted(segment)
        || !super::directory_targets::home_targets_unquoted(segment)
    {
        return None;
    }
    let spec = parse(segment)?;
    let source = resolved_source(spec.source, context)?;
    let destination = super::worktree_add::fresh_destination(
        spec.destination,
        context,
        super::worktree_add::MissingParents::Required,
    )?;
    // Git reads the configuration, hooks and attributes of the repository
    // being copied, so the proof runs there rather than in the agent's cwd.
    let source_context = super::PathContext {
        cwd: Some(source.to_str()?),
        ..context
    };
    let probe = super::git_session_probe::Probe::new(
        executable,
        &spec.leading,
        source_context,
        deadline,
        execution_environment,
    )?;
    let (effective, _repository) = probe.config()?;
    // A configured template directory hands the new repository hooks that
    // later commands in it would run; a conditional include could set one.
    let templated = effective.keys().any(|key| {
        let key = key.to_ascii_lowercase();
        key == "init.templatedir" || key.starts_with("includeif.")
    });
    if templated {
        return None;
    }
    // `--branch` names the branch Git checks out, and without it Git checks
    // out whatever the source's `HEAD` points at. Neither creates a branch
    // in the repository being copied, so the proof names none.
    let reference = spec.branch.map(|name| format!("refs/heads/{name}"));
    super::git_worktree::worktree_add_execution_free(
        executable,
        &spec.leading,
        &destination,
        None,
        reference.as_deref(),
        false,
        false,
        source_context,
        deadline,
        execution_environment,
    )?
    .then_some(destination)
}

/// The repository `git clone` would copy: an existing repository of its own,
/// below the home directory or an owned temporary directory, under a name no
/// credential store is kept under.
fn resolved_source(value: &str, context: super::PathContext<'_>) -> Option<PathBuf> {
    let home = std::fs::canonicalize(Path::new(context.home_dir?)).ok()?;
    // The shell expands an unquoted `~/` from its own HOME, so the spelling
    // is proved only when that HOME is the declared one.
    let expanded;
    let value = if value.starts_with("~/") {
        if cfg!(windows) || !context.shell_home_matches {
            return None;
        }
        expanded = super::read_paths::expand_home_read_path(value, context.home_dir)?;
        expanded.as_str()
    } else {
        value
    };
    let supplied = Path::new(value);
    let spelled = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        Path::new(context.cwd?).join(supplied)
    };
    let source = std::fs::canonicalize(spelled).ok()?;
    // The source already exists, so every directory down to it has to be
    // the owner's and writable by no one else. A fresh checkout's parent is
    // enough for a directory being created, which is what
    // `temporary_checkout_parent` answers for: a repository sitting in the
    // sticky shared root is one another user may still be able to rewrite
    // between this proof and the clone.
    let contained =
        source.starts_with(&home) || super::git_routes::owned_temporary_directory(&source, context);
    (source.is_dir()
        && own_repository_data(&source)
        && contained
        && !guard_secure_fs::credential_named_path(&source))
    .then_some(source)
}

/// Whether the repository data `git clone` would read is the source's own:
/// a `.git` directory, or the bare repository itself.
///
/// Git clones a repository, not a directory, and it follows whatever the
/// repository points at. A `.git` file names another Git directory, which a
/// linked worktree uses and which can sit anywhere; a link in its place does
/// the same; and `objects/info/alternates` sends the object read to a store
/// outside the copy. None of those is below the roots this proof bounds the
/// source to, so each keeps its review.
fn own_repository_data(source: &Path) -> bool {
    let git = source.join(".git");
    let objects = match std::fs::symlink_metadata(&git) {
        Ok(metadata) if metadata.is_dir() => git.join("objects"),
        Ok(_) => return false,
        Err(_) if source.join("HEAD").is_file() => source.join("objects"),
        Err(_) => return false,
    };
    std::fs::symlink_metadata(&objects).is_ok_and(|metadata| metadata.is_dir())
        && !objects.join("info/alternates").exists()
        && !objects.join("info/http-alternates").exists()
}

fn parse(segment: &CommandSegmentV1) -> Option<LocalClone<'_>> {
    let arguments = &segment.arguments;
    let mut index = 0;
    let mut leading = Vec::new();
    while let Some(flag @ ("-P" | "--no-pager" | "--no-optional-locks")) =
        arguments.get(index).map(String::as_str)
    {
        leading.push(flag.to_owned());
        index += 1;
    }
    if arguments.get(index).map(String::as_str) != Some("clone") {
        return None;
    }
    index += 1;
    let mut branch: Option<&str> = None;
    let mut operands: Vec<&str> = Vec::new();
    while let Some(argument) = arguments.get(index) {
        match argument.as_str() {
            // Options that change how much of the repository is copied, and
            // whether a tree is checked out at all. None of them names a
            // program, a template or another repository.
            "-q" | "--quiet" | "-v" | "--verbose" | "-n" | "--no-checkout" | "-l" | "--local"
            | "--no-hardlinks" | "--single-branch" | "--no-single-branch" | "--no-tags" => {
                index += 1;
            }
            "-b" | "--branch" => {
                let name = arguments.get(index + 1)?.as_str();
                if branch.replace(name).is_some() {
                    return None;
                }
                index += 2;
            }
            value => {
                if let Some(name) = value.strip_prefix("--branch=") {
                    if branch.replace(name).is_some() {
                        return None;
                    }
                } else if value.starts_with('-') {
                    return None;
                } else {
                    operands.push(value);
                }
                index += 1;
            }
        }
    }
    let &[source, destination] = operands.as_slice() else {
        return None;
    };
    (branch.is_none_or(super::worktree_add::valid_branch_name)
        && local_path_text(source)
        && local_path_text(destination))
    .then_some(LocalClone {
        leading,
        source,
        destination,
        branch,
    })
}

/// A path spelling, never a remote one: `:` separates a host from its path in
/// every remote form Git accepts, `ssh://host/repo` and `host:repo` alike.
fn local_path_text(value: &str) -> bool {
    value.len() <= MAX_PATH_BYTES
        && !value.contains(':')
        && super::worktree_add::valid_destination_text(value)
}
