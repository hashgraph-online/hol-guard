//! `git init` of a new directory under the user's own temporary directory.
//!
//! Initializing a repository copies Git's template directory into it, and a
//! configured `init.templateDir` can copy in hooks that later commands there
//! would run. A target that does not exist yet, directly inside a temporary
//! directory only the user can write, or directly in the sticky shared root
//! or the user's private macOS temporary directory, gets a repository with
//! Git's own samples and touches nothing else. A configured template directory, a
//! conditional include that could set one for the new repository, a target
//! that already exists and every other `init` option keep their review.

use super::git_remote_config::GitConfig;
use crate::CanonicalCommandV1;
use std::path::{Component, Path};
use std::time::Instant;

pub(crate) const REASON: &str = "native_exact_safe_git_init_target";

/// The target of `init [-q] [-b NAME] TARGET`, given the arguments after
/// `init`; `None` for every other form.
pub(crate) fn target(arguments: &[String]) -> Option<&str> {
    let mut target = None;
    let mut options = Vec::new();
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if argument == "-b" {
            options.push(argument.clone());
            index += 1;
            options.push(arguments.get(index)?.clone());
        } else if argument.starts_with('-') {
            options.push(argument.clone());
        } else if target.replace(argument.as_str()).is_some() {
            return None;
        }
        index += 1;
    }
    let target = target.filter(|value| !value.is_empty() && *value != ".")?;
    crate::pretool::init_arguments(&options).map(|_| target)
}

/// An absolute target without parent components; a relative target names
/// a directory the compatibility layer cannot place.
pub(crate) fn absolute_target(target: &str) -> bool {
    let path = Path::new(target);
    path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, Component::ParentDir))
}

/// A lone `git init` of a fresh directory below an owned temporary
/// directory, or directly in a temporary root, with no template directory
/// configured. The same parents `git worktree add` may check out into.
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
    fresh(segment, context, deadline, execution_environment)?;
    Some((
        REASON,
        "The Rust command authority proved this Git command creates a new repository in a fresh directory under the user's own temporary directory, with no configured template.",
    ))
}

/// The effective and repository configuration the session's Git reads for
/// one `git init` step of the form above, or `None` when the step is not
/// that form or a template directory could apply.
pub(in crate::pretool) fn fresh(
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<(GitConfig, GitConfig)> {
    let executable = segment.executable.as_deref()?;
    if super::executable_basename(executable) != "git"
        || segment.pipeline_index != 0
        || segment.path_overridden
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
        || segment.text.contains(['>', '<', '$', '`', '~', '\n', '\r'])
        || !super::directory_targets::drive_targets_quoted(segment)
        || !super::directory_targets::home_targets_unquoted(segment)
        || segment.arguments.first().map(String::as_str) != Some("init")
    {
        return None;
    }
    let target = Path::new(target(&segment.arguments[1..])?);
    let target = if target.is_absolute() {
        target.to_path_buf()
    } else {
        Path::new(context.cwd?).join(target)
    };
    let Some(Component::Normal(name)) = target.components().next_back() else {
        return None;
    };
    let parent = std::fs::canonicalize(target.parent()?).ok()?;
    let fresh = |path: &Path| {
        std::fs::symlink_metadata(path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    };
    if name.to_string_lossy().starts_with('.')
        || !super::git_routes::temporary_checkout_parent(&parent, context)
        || !fresh(target.as_path())
        || !fresh(parent.join(name).as_path())
    {
        return None;
    }
    let probe = super::git_session_probe::Probe::new(
        executable,
        &[],
        context,
        deadline,
        execution_environment,
    )?;
    let (effective, repository) = probe.config()?;
    let git_dir = parent.join(name).join(".git");
    let templated = effective.keys().any(|key| {
        key.eq_ignore_ascii_case("init.templatedir")
            || super::git_conditional_include::could_apply(key, &git_dir, context.home_dir)
    });
    (!templated).then_some((effective, repository))
}
