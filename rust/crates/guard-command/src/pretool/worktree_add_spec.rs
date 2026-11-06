//! Reading a `git worktree add` segment into the checkout it describes.
//!
//! Only the shapes the proof reads whole become a spec. An option the
//! parse does not model, a second `-b`, a name Git would munge or a
//! destination the text screens refuse all leave none, so the command
//! keeps its review rather than being proved against a different tree.

use crate::CommandSegmentV1;

use super::{valid_branch_name, valid_destination_text, valid_local_reference};

pub(super) struct WorktreeAdd<'a> {
    pub(super) leading: Vec<String>,
    /// The single `-C <dir>` value, applied by changing the proof's cwd
    /// (as Git does) instead of being passed on to the probes.
    pub(super) chdir: Option<&'a str>,
    /// `None` for the detached form, which creates no branch.
    pub(super) branch: Option<&'a str>,
    /// The destination as Git receives it, with a `$HOME` or `${HOME}` head
    /// written as the `~` the directory proofs already read.
    pub(super) destination: std::borrow::Cow<'a, str>,
    pub(super) reference: Option<&'a str>,
    /// Neither `-b` nor `--detach`: Git checks out the local branch the
    /// reference names when one exists, and detaches otherwise.
    pub(super) attach: bool,
}

/// Whether Git would take the destination's last component as the branch name
/// it creates for `git worktree add <path>`. `valid_destination_text` has
/// already ruled out a backslash, so `/` is the only separator left to read.
fn implied_branch(destination: &str) -> bool {
    destination
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .is_some_and(valid_branch_name)
}

pub(super) fn parse(segment: &CommandSegmentV1) -> Option<WorktreeAdd<'_>> {
    let arguments = if segment
        .arguments
        .last()
        .is_some_and(|argument| argument == "2>&1")
    {
        &segment.arguments[..segment.arguments.len() - 1]
    } else {
        &segment.arguments
    };
    let mut index = 0;
    let mut leading = Vec::new();
    let mut chdir = None;
    loop {
        match arguments.get(index).map(String::as_str) {
            Some(flag @ ("-P" | "--no-pager" | "--no-optional-locks")) => {
                leading.push(flag.to_owned());
                index += 1;
            }
            Some("-C") if chdir.is_none() => {
                let value = arguments.get(index + 1)?.as_str();
                if value.is_empty()
                    || value.starts_with('-')
                    || value.contains(['\0', '\n', '\r'])
                    || value.len() > super::MAX_DESTINATION_BYTES
                {
                    return None;
                }
                chdir = Some(value);
                index += 2;
            }
            _ => break,
        }
    }
    if arguments.get(index).map(String::as_str) != Some("worktree") {
        return None;
    }
    index += 1;
    if arguments.get(index).map(String::as_str) != Some("add") {
        return None;
    }
    index += 1;
    let mut branch = None;
    let mut detach = false;
    let mut destination = None;
    let mut reference = None;
    while let Some(argument) = arguments.get(index) {
        match argument.as_str() {
            "-q" | "--quiet" => index += 1,
            "-d" | "--detach" => {
                detach = true;
                index += 1;
            }
            // Git's option parser permutes, so the branch may be named after
            // the destination and the start point as readily as before them.
            // The spelling says nothing about what the checkout does; only a
            // second `-b` would leave the branch in doubt.
            "-b" if branch.is_none() => {
                branch = Some(arguments.get(index + 1)?.as_str());
                index += 2;
            }
            _ if argument.starts_with('-') => return None,
            _ if destination.is_none() => {
                destination = Some(argument.as_str());
                index += 1;
            }
            _ if reference.is_none() => {
                reference = Some(argument.as_str());
                index += 1;
            }
            _ => return None,
        }
    }
    // `$HOME` and `${HOME}` name the directory `~` names. The quoting screen
    // below covers both spellings, so the rewritten word carries no reach the
    // tilde does not already have.
    let destination = destination?;
    let destination = match super::directory_targets::home_variable::tilde_spelling(destination) {
        Some(spelling) => std::borrow::Cow::Owned(spelling),
        None => std::borrow::Cow::Borrowed(destination),
    };
    if !valid_destination_text(&destination) {
        return None;
    }
    // A quoted or escaped `~` stays a literal directory name.
    if destination.starts_with('~') && !super::directory_targets::home_targets_unquoted(segment) {
        return None;
    }
    // With neither a reference nor `--detach` Git checks out `HEAD` and names
    // the branch it creates after the destination's last component. Git would
    // munge a name it cannot use as written, so a name it would not take
    // keeps review; the proof reads the name Git would write.
    match branch {
        Some(value) if detach || !valid_branch_name(value) => return None,
        None if !detach && reference.is_none() && !implied_branch(&destination) => return None,
        _ => {}
    }
    // A bare name such as `main` or `feat/x` is accepted in every form.
    // Without `-b` and `--detach` Git checks out the existing branch of that
    // name (or detaches at what the name resolves to); with either flag it
    // starts from the commit the name resolves to, exactly as the probe's
    // `rev-parse` resolves it. The tree proven is the tree checked out.
    let attach = branch.is_none() && !detach;
    if reference.is_some_and(|value| !(valid_local_reference(value) || valid_branch_name(value))) {
        return None;
    }
    Some(WorktreeAdd {
        leading,
        chdir,
        branch,
        destination,
        reference,
        attach,
    })
}
