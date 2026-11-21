//! `gh repo create` with public or internal visibility, or with `--push`,
//! stays at review: publishing a repository discloses the workspace, and gh's
//! own push runs outside the proof that admits a plain `git push`. Agents
//! asked to "put it on GitHub" usually reach for `--public --push` and, given
//! only the generic reason, stop. When the same command made private and
//! without `--push` would run without review, say so. A private create
//! chained with the push to the remote it adds is named too: that push can
//! only be proven once the remote exists.

use crate::github_command_capabilities::private_repo_create;
use crate::{CanonicalCommandV1, CommandSegmentV1};

/// Options the private alternative drops; `--private` replaces the first two.
const DROPPED: &[&str] = &["--public", "--internal", "--push"];

/// Whether `gh` arguments create a private repository in the user's own
/// account. That publishes nothing and pushes nothing: the workspace reaches
/// the new repository only through a separate, separately proven `git push`.
pub(super) fn private_create(arguments: &[String]) -> bool {
    matches!(arguments, [repo, create, rest @ ..]
        if repo == "repo" && create == "create" && private_repo_create(rest))
}

/// A review reason naming the private alternative, or `None` when it does not
/// apply. In a chain, the other steps are named as separate commands, since
/// repeating the whole chain with `--private` would still go to review.
pub(super) fn private_alternative_reason(model: &CanonicalCommandV1) -> Option<String> {
    if model.confidence != "exact" || model.path_overridden || !model.wrapper_chain.is_empty() {
        return None;
    }
    let reason_tail = |push: &str| {
        format!(
            "Creating it private runs without review: repeat that `gh repo create` with `--private` in place of `--public`, `--internal` or `--push`{push}. If the user wants it public, tell them they can change its visibility."
        )
    };
    if let [segment] = model.segments.as_slice() {
        let push = private_alternative(segment)?;
        return Some(format!(
            "HOL Guard requires review because this `gh repo create` publishes the repository or pushes with gh itself. {}",
            reason_tail(push)
        ));
    }
    // Split into separate commands, steps after a `cd` would run elsewhere.
    if model
        .segments
        .iter()
        .any(|segment| matches!(segment.executable.as_deref(), Some("cd" | "pushd")))
    {
        return None;
    }
    let mut creates = model
        .segments
        .iter()
        .enumerate()
        .filter_map(|(index, segment)| private_alternative(segment).map(|push| (index, push)));
    let (index, push) = creates.next()?;
    if creates.next().is_some() {
        return None;
    }
    Some(format!(
        "HOL Guard requires review because step {} of this command runs a `gh repo create` that publishes the repository or pushes with gh itself. Run the other steps as separate commands. {}",
        index + 1,
        reason_tail(push)
    ))
}

/// The push hint for a public, internal or pushing `gh repo create` segment
/// whose private form would run without review, or `None`.
fn private_alternative(segment: &CommandSegmentV1) -> Option<&'static str> {
    let executable = segment.executable.as_deref()?;
    let [repo, create, tail @ ..] = segment.arguments.as_slice() else {
        return None;
    };
    if repo != "repo"
        || create != "create"
        || !segment.environment_names.is_empty()
        || super::executable_basename(executable) != "gh"
    {
        return None;
    }
    // Already private and not pushing: there is nothing different to suggest.
    if tail.iter().any(|argument| argument == "--private")
        && !tail
            .iter()
            .any(|argument| DROPPED.contains(&argument.as_str()))
    {
        return None;
    }
    let mut alternative: Vec<String> = tail
        .iter()
        .filter(|argument| !DROPPED.contains(&argument.as_str()))
        .cloned()
        .collect();
    if !alternative.iter().any(|argument| argument == "--private") {
        alternative.push("--private".to_owned());
    }
    if !private_repo_create(&alternative) {
        return None;
    }
    Some(if tail.iter().any(|argument| argument == "--push") {
        ", then push with `git push -u origin <branch>` as a separate command"
    } else {
        ""
    })
}

/// A review reason for a chain whose `git push origin <branch>` pushes to the
/// remote an earlier private `gh repo create --source` step adds, or `None`.
///
/// The push proof checks the URL, credential helpers and hooks of the remote
/// the push uses, and that remote does not exist until gh creates it. Its URL
/// depends on gh's default host (`GH_HOST`, or the only host gh is signed in
/// to) and that host's `git_protocol`, which gh's own configuration records.
/// So the chain keeps its review, and the reason says how to get the same
/// proof: run the steps separately, so the push is checked once the remote
/// exists.
pub(super) fn created_remote_push_reason(model: &CanonicalCommandV1) -> Option<String> {
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || model
            .segments
            .iter()
            .any(|segment| matches!(segment.executable.as_deref(), Some("cd" | "pushd")))
    {
        return None;
    }
    let create = only_step(model, adds_origin)?;
    let push = only_step(model, super::git_push::chained)?;
    if push < create {
        return None;
    }
    Some(format!(
        "HOL Guard requires review because step {} of this command (`git push`) pushes to the remote that step {} (`gh repo create`) adds, and Guard cannot check a remote before it exists. Run the steps as separate commands, in order: once the `gh repo create` command has added the remote, the `git push` command is checked on its own against that remote's URL, credentials and hooks.",
        push + 1,
        create + 1,
    ))
}

/// The index of the one step matching `matches`, or `None` for none or several.
fn only_step(model: &CanonicalCommandV1, matches: fn(&CommandSegmentV1) -> bool) -> Option<usize> {
    let mut found = (0..model.segments.len()).filter(|index| matches(&model.segments[*index]));
    match (found.next(), found.next()) {
        (Some(index), None) => Some(index),
        _ => None,
    }
}

/// Whether `segment` is a private `gh repo create` that adds the current
/// directory's remote as `origin`, the remote a chained push uses.
fn adds_origin(segment: &CommandSegmentV1) -> bool {
    const FLAGS: &[&str] = &[
        "--private",
        "--add-readme",
        "--disable-issues",
        "--disable-wiki",
    ];
    if segment.executable.as_deref() != Some("gh")
        || !segment.environment_names.is_empty()
        || !private_create(&segment.arguments)
    {
        return false;
    }
    let mut source = false;
    let mut remote = "origin";
    // `private_create` admitted the shape: every option other than `FLAGS`
    // takes a value, attached after `=` or as the next argument.
    let mut arguments = segment.arguments.iter().skip(2);
    while let Some(argument) = arguments.next() {
        if !argument.starts_with('-') || FLAGS.contains(&argument.as_str()) {
            continue;
        }
        let (option, value) = match argument.split_once('=') {
            Some((option, value)) => (option, Some(value)),
            None => (argument.as_str(), arguments.next().map(String::as_str)),
        };
        match option {
            "--source" | "-s" => source = true,
            "--remote" | "-r" => remote = value.unwrap_or_default(),
            _ => {}
        }
    }
    source && remote == "origin"
}

#[cfg(test)]
#[path = "repo_create_reason_tests.rs"]
mod tests;
