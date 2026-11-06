//! Where the steps of a local Git write chain run.
//!
//! A chain proves its writes in one directory: the shell's own, the one a
//! leading `cd` enters, or the one every Git step names with a leading
//! `git -C <dir>`. Git enters that directory before it reads any
//! configuration, so `git -C <dir> commit` is judged as `cd <dir> && git
//! commit`: the directory must pass the same proof as the `cd` target, and
//! must also be a repository the Git read route proof accepts (the workspace,
//! a registered worktree of it, or a repository with its own `.git` directory
//! below home). The proofs then see each Git step without its `-C <dir>`
//! pair, run from that directory. In a chain that also has a `cd`, names two
//! directories, or has a Git step without `-C`, a write behind `-C` keeps the
//! review.
//!
//! A `;` or `||` after a verified `cd` chain runs what follows whether or not
//! the `cd` succeeded, so the steps after it may run in either directory.
//! Those steps must be reads proven in both.

use super::super::directory_targets;
use super::super::worktree_add::{separator_between, verified_worktree_cwd_context};
use crate::{CanonicalCommandV1, CommandSegmentV1};

pub(super) enum Route {
    /// Every step runs in the shell's directory.
    Here,
    /// The `cd` at `index` enters `cwd`. Steps from `either` on may also run
    /// in the shell's directory.
    Cd {
        index: usize,
        cwd: String,
        either: Option<usize>,
    },
    /// Every Git step enters `cwd` with `-C`; `model` drops those pairs.
    Chdir {
        cwd: String,
        model: Box<CanonicalCommandV1>,
    },
}

impl Route {
    pub(super) fn cwd(&self) -> Option<&str> {
        match self {
            Route::Here => None,
            Route::Cd { cwd, .. } | Route::Chdir { cwd, .. } => Some(cwd.as_str()),
        }
    }

    /// The command the proofs read: without the `-C <dir>` pairs.
    pub(super) fn model<'a>(&'a self, original: &'a CanonicalCommandV1) -> &'a CanonicalCommandV1 {
        match self {
            Route::Chdir { model, .. } => model.as_ref(),
            _ => original,
        }
    }

    pub(super) fn cd_index(&self) -> Option<usize> {
        match self {
            Route::Cd { index, .. } => Some(*index),
            _ => None,
        }
    }

    /// Whether the step at `index` may run in the shell's directory or in
    /// the one the `cd` entered.
    pub(super) fn either(&self, index: usize) -> bool {
        matches!(self, Route::Cd { either: Some(split), .. } if index >= *split)
    }

    /// Whether the step at `index` only removes links in the root of the
    /// linked worktree the command's leading `cd` enters (see `sibling`).
    pub(super) fn unlinks(
        &self,
        model: &CanonicalCommandV1,
        index: usize,
        shell: super::super::PathContext<'_>,
    ) -> bool {
        matches!(
            self,
            Route::Cd {
                index: 0,
                either: None,
                ..
            }
        ) && directory_targets::sibling::entered_link_removal(model, index, shell)
    }

    /// Whether only the Git steps run in the route's directory.
    pub(super) fn chdir(&self) -> bool {
        matches!(self, Route::Chdir { .. })
    }
}

pub(super) fn route(
    model: &CanonicalCommandV1,
    context: super::super::PathContext<'_>,
) -> Option<Route> {
    let chdir = model
        .segments
        .iter()
        .any(|segment| leading_chdir(segment).is_some());
    let cd = model
        .segments
        .iter()
        .position(|segment| segment.executable.as_deref() == Some("cd"));
    // A chain that `-C` cannot route keeps the plain proofs, which refuse a
    // write behind `-C` and judge a read by its own route.
    match cd {
        Some(index) => cd_route(model, index, context),
        None if chdir => Some(chdir_route(model, context).unwrap_or(Route::Here)),
        None => Some(Route::Here),
    }
}

/// The directory `git -C <dir> ...` names as its first option.
fn leading_chdir(segment: &CommandSegmentV1) -> Option<&str> {
    match segment.arguments.as_slice() {
        [flag, directory, ..] if flag == "-C" && segment.executable.as_deref() == Some("git") => {
            Some(directory.as_str())
        }
        _ => None,
    }
}

fn cd_route(
    model: &CanonicalCommandV1,
    index: usize,
    context: super::super::PathContext<'_>,
) -> Option<Route> {
    if let Some(proof) = verified_worktree_cwd_context(model, index, context) {
        return Some(Route::Cd {
            index: proof.cd_index,
            cwd: proof.cwd,
            either: None,
        });
    }
    let separator = |right: usize| {
        separator_between(model, right - 1, right).map(|separator| separator.trim().to_owned())
    };
    let count = model.segments.len();
    let split = (index + 1..count)
        .find(|right| matches!(separator(*right).as_deref(), Some(";" | "||")))?;
    if !(split..count)
        .all(|right| matches!(separator(right).as_deref(), Some("&&" | "|" | ";" | "||")))
        || model.segments[split..]
            .iter()
            .any(|segment| segment.executable.as_deref() == Some("cd"))
    {
        return None;
    }
    // Up to the `;` or `||` every step runs only after the `cd` succeeded.
    let mut before = model.clone();
    before.segments.truncate(split);
    let proof = verified_worktree_cwd_context(&before, index, context)?;
    Some(Route::Cd {
        index: proof.cd_index,
        cwd: proof.cwd,
        either: Some(split),
    })
}

fn chdir_route(
    model: &CanonicalCommandV1,
    context: super::super::PathContext<'_>,
) -> Option<Route> {
    let mut entered: Option<String> = None;
    let mut rewritten = model.clone();
    for (index, segment) in model.segments.iter().enumerate() {
        if segment.executable.as_deref() != Some("git") {
            continue;
        }
        let target = leading_chdir(segment)?;
        if !directory_targets::drive_targets_quoted(segment)
            || !directory_targets::home_targets_unquoted(segment)
            || !super::super::git_routes::git_route_within_workspace(target, context)
        {
            return None;
        }
        let cwd = directory_targets::verified_cwd_target(target, context)?;
        if *entered.get_or_insert_with(|| cwd.clone()) != cwd {
            return None;
        }
        let offset = segment.tokens.len().checked_sub(segment.arguments.len())?;
        if segment.tokens.get(offset).map(String::as_str) != Some("-C") {
            return None;
        }
        let plain = &mut rewritten.segments[index];
        plain.arguments.drain(..2);
        plain.tokens.drain(offset..offset + 2);
    }
    Some(Route::Chdir {
        cwd: entered?,
        model: Box::new(rewritten),
    })
}
