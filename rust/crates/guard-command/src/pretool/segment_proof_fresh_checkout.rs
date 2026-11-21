//! The checkouts a `git worktree add` creates while the command it belongs to
//! still runs, and the reads of the same command they answer for.
//!
//! A `git worktree add` writes a tree that was not there when the command
//! started. [`fresh_checkout`] records it only when the add passes the proof
//! it would pass as a command of its own, which refuses every configuration,
//! hook and filter that could put something other than the named ref there.
//! A later step is then screened against the destinations the command
//! creates ([`reads_outside_fresh_checkouts`]). A listing of a destination
//! itself ([`listing_of_fresh_checkouts`]) is screened apart: it prints the
//! names the add writes there and opens none of them, so it reveals nothing
//! the add it rides on does not already put on disk.

use super::super::{read_paths, worktree_add, PathContext};
use crate::{CanonicalCommandV1, CommandSegmentV1};

/// The checkout a `git worktree add` segment creates, when that segment would
/// pass as a command of its own.
///
/// The proof reads the destination before anything runs and admits it only
/// when nothing is there, so the add writes below a path no other step of the
/// command can already name. It also reads the repository the checkout comes
/// from: its hooks, its configuration and the ref the add names, so no code
/// the repository supplies runs while the command does. Together those make
/// the add's writes bounded by its own destination, which
/// [`reads_outside_fresh_checkouts`] screens the later reads against. Any
/// other tree-writing step is read as it was before: it may change whatever a
/// later step opens.
pub(super) fn fresh_checkout(
    model: &CanonicalCommandV1,
    index: usize,
    context: PathContext<'_>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<(std::path::PathBuf, String)> {
    let segment = model.segments.get(index)?;
    if !worktree_add::proven_alone(
        model,
        index,
        context,
        None,
        execution_environment,
        // A `git fetch` earlier in the same command moves the reference the
        // add names, so the tree it writes is not the one a proof of the add
        // on its own would read.
        index > 0,
    ) {
        return None;
    }
    let (destination, chdir) = worktree_add::planned(segment, context)?;
    let repository = chdir.or_else(|| context.cwd.map(str::to_owned))?;
    Some((destination, repository))
}

/// Whether this step only lists a checkout a proven `git worktree add` of
/// the same command creates, which is a name the add writes and no file it
/// writes there.
///
/// `git worktree add` fills its destination with the tree of the ref it
/// names, and the user's allow already covers writing it. A listing of that
/// destination prints the names now in it and opens none of them, so it adds
/// nothing to what the add already does.
///
/// Opening a file there is a different matter and keeps its review. The ref
/// decides the mode of every entry it writes, so a name that is an ordinary
/// file in the repository's own working tree can be a symbolic link in the
/// tree the add checks out, pointing anywhere on the host. A fetch earlier in
/// the same command can move the ref between the proof and the add as well,
/// so neither the repository's working tree nor the ref as it reads now
/// answers for what the read would open.
///
/// Every operand must name a new checkout exactly. A path below one is a name
/// the ref decides, so it may be a link out of the checkout; a step that also
/// reads elsewhere keeps the screen [`reads_outside_fresh_checkouts`] gives
/// it. The flags are screened as the same listing of the repository the
/// checkout comes from, a directory that is already there.
pub(super) fn listing_of_fresh_checkouts(
    segment: &CommandSegmentV1,
    context: PathContext<'_>,
    checkouts: &[(std::path::PathBuf, String)],
) -> bool {
    if checkouts.is_empty()
        || segment.pipeline_index != 0
        || segment.path_overridden
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
        || segment.text.contains([
            '>', '<', '$', '`', '|', '&', ';', '\n', '\r', '*', '?', '[', '{', '~', '\\', '\'', '"',
        ])
    {
        return false;
    }
    let listing = segment
        .executable
        .as_deref()
        .map(super::super::executable_basename)
        == Some("ls");
    if !listing {
        return false;
    }
    let mut named = false;
    let mut screened = Vec::with_capacity(segment.arguments.len());
    for argument in &segment.arguments {
        if argument.starts_with('-') {
            // The repository the flags are screened against is not the tree
            // the add writes. A recursive walk of the checkout, or one that
            // follows its links, reads names the ref decides, so both are
            // refused here however they are spelled.
            if super::super::listing_reads::is_recursive_flag(argument)
                || super::super::listing_reads::follows_links(argument)
            {
                return false;
            }
            screened.push(argument.clone());
            continue;
        }
        // The spelling must be the one the shell passes, so the word screened
        // here stands exactly where the operand does.
        if !segment.tokens.iter().any(|token| token == argument) {
            return false;
        }
        let Some(target) = read_target(argument, context) else {
            return false;
        };
        // Two adds in one command can name the same destination, and only
        // one of them creates it. The screen then has no single repository to
        // stand in for the listing, so it refuses.
        let mut matched = checkouts
            .iter()
            .filter(|(destination, _)| *destination == target);
        let Some((_, source)) = matched.next() else {
            return false;
        };
        if matched.next().is_some() {
            return false;
        }
        screened.push(source.clone());
        named = true;
    }
    named && super::super::safe_reads::safe_listing_arguments(&screened, context)
}

/// The absolute path `value` names before anything runs, with `~` expanded
/// and a relative spelling taken against the working directory.
///
/// Only a leading `./` or `../` run is resolved. A `..` after a named
/// directory would be read here as the directory above the name, while the
/// shell reads it as the directory above whatever that name links to, so
/// such a spelling gets no answer at all.
fn read_target(value: &str, context: PathContext<'_>) -> Option<std::path::PathBuf> {
    use std::path::Component;
    let expanded = read_paths::expand_home_read_path(value, context.home_dir)
        .unwrap_or_else(|| value.to_owned());
    let supplied = std::path::Path::new(&expanded);
    let mut resolved = if supplied.is_absolute() {
        std::path::PathBuf::new()
    } else {
        std::path::PathBuf::from(context.cwd?)
    };
    let mut named = false;
    for component in supplied.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => resolved.push(component.as_os_str()),
            Component::CurDir if !named => {}
            Component::ParentDir if !named && resolved.pop() => {}
            Component::Normal(part) => {
                named = true;
                resolved.push(part);
            }
            _ => return None,
        }
    }
    named.then_some(resolved)
}

/// Whether every path this step names is a file that is already there, out of
/// reach of the checkouts an earlier `git worktree add` of the same command
/// creates.
///
/// A path that resolves now names a file the add does not write: the add's
/// own destination is empty until it runs, and the proof behind it refused
/// anything that would run repository code. A path inside the new checkout
/// reads whatever the ref supplies, and a path that resolves nowhere may be
/// one the add creates, including through a link planted beforehand that
/// dangles until the checkout exists. A directory that holds a checkout is
/// no better: a recursive step named on it walks into the tree the add
/// writes, and the proof of that step ran before anything was there. All of
/// them keep their review.
pub(super) fn reads_outside_fresh_checkouts(
    segment: &CommandSegmentV1,
    context: PathContext<'_>,
    checkouts: &[(std::path::PathBuf, String)],
) -> bool {
    checkouts.is_empty()
        || segment.arguments.iter().all(|argument| {
            argument.starts_with('-') || resolves_outside(argument, context, checkouts)
        })
}

fn resolves_outside(
    value: &str,
    context: PathContext<'_>,
    checkouts: &[(std::path::PathBuf, String)],
) -> bool {
    let expanded = read_paths::expand_home_read_path(value, context.home_dir)
        .unwrap_or_else(|| value.to_owned());
    let supplied = std::path::Path::new(&expanded);
    let target = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        let Some(cwd) = context.cwd else {
            return false;
        };
        std::path::Path::new(cwd).join(supplied)
    };
    std::fs::canonicalize(target).is_ok_and(|resolved| {
        checkouts.iter().all(|(checkout, _)| {
            planned_path(checkout).is_some_and(|checkout| {
                // A directory that holds a checkout is read by a recursive
                // step as surely as the checkout itself, and the walk behind
                // such a step was proved before the add wrote anything there.
                !resolved.starts_with(&checkout) && !checkout.starts_with(&resolved)
            })
        })
    })
}

/// The canonical path a destination takes once the add creates it: its
/// nearest existing ancestor resolved, with the components below it appended.
/// Nothing is at the destination while this screen runs, and an ancestor that
/// is a symbolic link would otherwise leave the comparison above answering
/// for a different path than the one the add writes.
fn planned_path(destination: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut missing = Vec::new();
    let mut current = destination;
    loop {
        if let Ok(resolved) = std::fs::canonicalize(current) {
            let mut resolved = resolved;
            for part in missing.iter().rev() {
                resolved.push(part);
            }
            return Some(resolved);
        }
        missing.push(current.file_name()?);
        current = current.parent()?;
    }
}
