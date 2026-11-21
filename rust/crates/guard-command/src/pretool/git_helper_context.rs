use super::{exact_safe_command_with_context, executable_basename, git_config, PathContext};
use crate::CanonicalCommandV1;

pub(super) fn git_helper_context_required(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> bool {
    if !exact_safe_command_with_context(model, true, context) {
        return false;
    }
    // A proven read prefix holds no Git segment; judge from its `cd` onward.
    let rest = super::segment_proof::after_read_prefix(model, context);
    let model = rest.as_ref().unwrap_or(model);
    // A relative `-C` after a verified `cd` resolves against the destination.
    let destination = super::segment_proof::git_read_cwd_compound_context(model, context);
    let context = PathContext {
        cwd: destination.as_deref().or(context.cwd),
        ..context
    };
    (0..model.segments.len()).any(|index| {
        let child = super::fanout_reads::git_xargs_child(model, index);
        segment_runs_helpers(child.as_ref().unwrap_or(&model.segments[index]), context)
    })
}

/// Whether this segment's one `-C` route lands where Git discovers no
/// repository.
///
/// Only the leading option block is read, so a `-C` that belongs to a
/// subcommand (`git diff -C`, where it asks for copy detection) is never
/// mistaken for a route, and a segment carrying more than one `-C` keeps the
/// helper screen: the second is resolved against the first, which this does
/// not model.
///
/// The route only says Git finds no repository. Git still reads its global
/// and system configuration, and an inline `-c` adds to it, so the segment
/// counts only when it carries no `-c` and its operation is one the
/// inspection proof admits without a repository: `diff` on paths, `grep`,
/// `apply` and `hash-object` keep running there and open files.
pub(super) fn routes_to_no_repository(
    segment: &crate::CommandSegmentV1,
    context: PathContext<'_>,
) -> bool {
    segment
        .executable
        .as_deref()
        .is_some_and(|executable| executable_basename(executable) == "git")
        && arguments_route_to_no_repository(&segment.arguments, context)
}

/// [`routes_to_no_repository`] for a segment's arguments alone, for the
/// proofs that already know the segment runs Git and hold its arguments.
pub(super) fn arguments_route_to_no_repository(
    arguments: &[String],
    context: PathContext<'_>,
) -> bool {
    let mut index = 0;
    let mut route = None;
    while let Some(argument) = arguments.get(index) {
        if argument == "-C" {
            if route.is_some() {
                return false;
            }
            let Some(target) = arguments.get(index + 1) else {
                return false;
            };
            route = Some(target.as_str());
            index += 2;
            continue;
        }
        if argument == "-c" {
            return false;
        }
        if !argument.starts_with('-') {
            break;
        }
        index += 1;
    }
    route.is_some_and(|target| super::git_routes::git_route_without_repository(target, context))
        && crate::command_compatibility::git_inspection_arguments(arguments, context).is_some()
}

/// Whether a Git segment's operation can start a configured helper.
fn segment_runs_helpers(original: &crate::CommandSegmentV1, context: PathContext<'_>) -> bool {
    let stripped = super::segment_proof::without_stderr_merge(original);
    let segment = stripped.as_ref().unwrap_or(original);
    if routes_to_no_repository(segment, context) {
        // Git's setup dies on a `-C` target that holds no repository, before
        // it reads a pager, textconv, diff or filter setting, so there is no
        // configuration to probe and nothing a helper could run in.
        return false;
    }
    segment.executable.as_deref().is_some_and(|executable| {
        executable_basename(executable) == "git"
            // Leading `-C`/`-P` options precede the subcommand.
            && crate::command_compatibility::git_inspection_arguments(&segment.arguments, context)
                .is_some_and(|arguments| {
                    let option_end = arguments
                        .iter()
                        .position(|argument| argument == "--")
                        .unwrap_or(arguments.len());
                    let active_options = &arguments[1..option_end];
                    match arguments[0].as_str() {
                        "diff" | "diff-files" | "diff-index" | "diff-tree" | "log" | "show" => {
                            !(active_options
                                .iter()
                                .any(|argument| argument == "--no-ext-diff")
                                && active_options
                                    .iter()
                                    .any(|argument| argument == "--no-textconv"))
                        }
                        // A clean filter is the only helper hash-object runs.
                        "hash-object" => {
                            !super::git_hash_object::filters_disabled(&arguments[1..])
                        }
                        // The probe screens the printed entries for credentials.
                        "config" => super::git_config_reads::read_form(&arguments[1..]).is_some(),
                        // These do not page by default, but pager.<name> can, and
                        // an object read can fetch from a partial clone's promisor.
                        // `cherry` prints commit names through no helper of its
                        // own, so the pager is the whole of what it can start.
                        "cherry" | "merge-base" | "ls-tree" | "cat-file" | "show-ref"
                        | "for-each-ref" | "rev-list" => true,
                        // blame and reflog page by default; describe honors
                        // pager.describe when it is set.
                        "blame" | "annotate" | "describe" | "reflog" => true,
                        // grep pages by default through pager.grep or core.pager.
                        "grep" => true,
                        // None of these starts a pager of its own, runs a
                        // configured driver or opens a working-tree file, but
                        // an explicit pager.<name> key can still name a
                        // program, so the probe clears that first. The
                        // `symbolic-ref` spellings that write a ref never
                        // reach here: the inspection proof screens them.
                        "name-rev" | "show-branch" | "check-ref-format" | "symbolic-ref" => true,
                        // The stdin filters and `var` print without opening a
                        // working-tree file, but an explicit `pager.<name>`
                        // key can still name a program, so the probe clears
                        // that first. The `check-mailmap` and
                        // `interpret-trailers` spellings that open a file the
                        // caller names never reach here: the inspection proof
                        // screens them.
                        "var" | "patch-id" | "stripspace" | "check-mailmap"
                        | "interpret-trailers" => true,
                        // A stash listing is a log that pages under
                        // pager.stash, and `stash show` runs the diff drivers.
                        "stash" => true,
                        // A shortlog pages under pager.shortlog, a count and
                        // an attribute check page under their own pager.<name>,
                        // and every listing reads the repository's
                        // configuration.
                        "shortlog" | "check-ignore" | "count-objects" | "check-attr"
                        | "sparse-checkout" => true,
                        // A bisect log replays through the pager, a note
                        // prints through it too, and a replacement listing
                        // reads the repository's configuration to print the
                        // refs; all three honor core.pager.
                        "bisect" | "notes" | "replace" => true,
                        // Finding the untracked paths refreshes the index,
                        // which starts a configured core.fsmonitor.
                        "clean" => true,
                        // Reading the files the patch names refreshes the
                        // index, which starts a configured core.fsmonitor.
                        "apply" => true,
                        // A status line is printed from the superproject,
                        // whose index it reads, so a configured
                        // core.fsmonitor there can start. The read forms are
                        // the only ones that reach here, because the proof
                        // that admits the subcommand screens them first.
                        "submodule" => true,
                        _ => false,
                    }
                })
    })
}

/// What the configuration probe answered for a command's Git reads.
///
/// `Refused` and `Unanswered` both leave a read unproven, but for different
/// reasons. A refusal has something behind it: a helper the probe read out of
/// the configuration, or a segment whose own shape the proof does not model.
/// An unanswered probe found nothing against the read at all -- it could not
/// look. Only the second is a question a user's explicit Allow answers.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum HelperProof {
    /// Every Git read here starts no configured helper.
    Inert,
    /// A probe could not answer for some read, and nothing was found against
    /// any read in the command.
    Unanswered,
    /// A helper was read out of the configuration, or a read's own shape is
    /// one this proof does not clear.
    Refused,
}

/// Only a harness-stamped execution environment can prove which configuration
/// the agent's own Git process will read.
pub(super) fn git_helpers_proven_inert(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
    deadline: Option<std::time::Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    helper_proof(model, context, deadline, execution_environment) == HelperProof::Inert
}

/// Whether the helper-context review this command earned came from probes that
/// could not answer rather than from a helper one of them found.
///
/// A loaded host, a configuration the probe could not read or a spent budget
/// leaves what a read would start an open question with nothing found against
/// it. The user who allowed that read answered it: run it as this checkout
/// configures it. A helper the probe did read out of the configuration is a
/// program Guard cannot see, so that review stands however much the user
/// allowed.
pub(super) fn probe_left_helpers_unproven(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
    deadline: Option<std::time::Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    git_helper_context_required(model, context)
        && helper_proof(model, context, deadline, execution_environment) == HelperProof::Unanswered
}

fn helper_proof(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
    deadline: Option<std::time::Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> HelperProof {
    let Some(environment) = execution_environment else {
        // Without a stamped environment Guard cannot say which configuration
        // the agent's Git process reads at all. That is a layout it cannot
        // see rather than a question left open, so no allow answers it.
        return HelperProof::Refused;
    };
    let rest = super::segment_proof::after_read_prefix(model, context);
    let model = rest.as_ref().unwrap_or(model);
    // `cd <dir>; <rest>` and `cd <dir> && <head>; <tail>` leave their later
    // reads running in the new directory when the `cd` succeeded and in the
    // original one when it failed. Inspect each read in every directory it
    // can run in, the split the Git execution-context floor already makes,
    // and keep the strongest answer any of them produced.
    if let Some((cwd, rest)) = super::safe_reads::leading_semicolon_cd(model, context) {
        let moved = PathContext {
            cwd: Some(&cwd),
            ..context
        };
        let moved_proof = segments_proof(&rest, moved, deadline, environment);
        return moved_proof.max(segments_proof(&rest, context, deadline, environment));
    }
    if let Some((cwd, rest, tail)) = super::safe_reads::leading_and_cd(model, context) {
        let moved = PathContext {
            cwd: Some(&cwd),
            ..context
        };
        let moved_proof = segments_proof(&rest, moved, deadline, environment);
        return moved_proof.max(segments_proof(&tail, context, deadline, environment));
    }
    // After a verified `cd`, the Git process reads configuration from the new
    // directory, so the probe must run there rather than in the reported cwd.
    let destination = super::segment_proof::git_read_cwd_compound_context(model, context);
    let context = PathContext {
        cwd: destination.as_deref().or(context.cwd),
        ..context
    };
    segments_proof(model, context, deadline, environment)
}

/// What every Git read in `model` answered when it runs in `context`: the
/// strongest of the segments' own proofs, so one refusal refuses the command
/// and one unanswered probe leaves it unanswered.
fn segments_proof(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
    deadline: Option<std::time::Instant>,
    environment: &guard_contracts::GuardExecutionEnvironmentV1,
) -> HelperProof {
    model
        .segments
        .iter()
        .enumerate()
        .map(|(index, segment)| {
            segment_proof(model, index, segment, context, deadline, environment)
        })
        .max()
        .unwrap_or(HelperProof::Inert)
}

fn segment_proof(
    model: &CanonicalCommandV1,
    index: usize,
    original: &crate::CommandSegmentV1,
    context: PathContext<'_>,
    deadline: Option<std::time::Instant>,
    environment: &guard_contracts::GuardExecutionEnvironmentV1,
) -> HelperProof {
    // `git merge-base ... | xargs git log` runs its Git read as the child.
    let child = super::fanout_reads::git_xargs_child(model, index);
    let original = child.as_ref().unwrap_or(original);
    // A trailing `2>&1` is a redirect, not a Git argument.
    let stripped = super::segment_proof::without_stderr_merge(original);
    let segment = stripped.as_ref().unwrap_or(original);
    let Some(executable) = segment.executable.as_deref() else {
        return HelperProof::Inert;
    };
    // The exact-safe proof already cleared Git reads that start no helper,
    // such as `rev-parse`, so only helper reads need the probe.
    if executable_basename(executable) != "git" || !segment_runs_helpers(segment, context) {
        return HelperProof::Inert;
    }
    if !segment.environment_names.is_empty()
        || !super::directory_targets::drive_targets_quoted(segment)
        || !super::directory_targets::home_targets_unquoted(segment)
    {
        // A name that changes what Git runs, or a target whose quoting this
        // proof does not model, is a shape Guard cannot read rather than a
        // question the probe left open.
        return HelperProof::Refused;
    }
    let piped = stdout_piped(model, index);
    match git_config::execution_free(
        executable,
        &segment.arguments,
        context,
        deadline,
        Some(environment),
        piped,
    ) {
        Some(true) => HelperProof::Inert,
        Some(false) => {
            // Only a refusal has a cause worth telling apart, and both calls
            // go through one probe memo, so this starts no second Git
            // process. Every way the probe refuses before it reaches the
            // configuration -- a home or working directory it cannot resolve,
            // an environment it cannot vouch for, a Git binary it does not
            // trust -- is a program or a layout Guard cannot see, so it stays
            // a refusal.
            if git_config::trusted_launch(executable, context, Some(environment))
                && git_config::probe_unanswered(
                    executable,
                    &segment.arguments,
                    context,
                    deadline,
                    Some(environment),
                    piped,
                )
            {
                HelperProof::Unanswered
            } else {
                HelperProof::Refused
            }
        }
        // An operation the probe does not model reaches here only when this
        // segment runs helpers, which the exact-safe proof did not clear on
        // its own, so there is nothing left to prove it inert.
        None => HelperProof::Refused,
    }
}

/// Git starts a pager only when its standard output is a terminal. The parser
/// rejects stdout redirection, so a following pipeline stage proves a pipe.
pub(super) fn stdout_piped(model: &CanonicalCommandV1, index: usize) -> bool {
    match (model.segments.get(index), model.segments.get(index + 1)) {
        (Some(segment), Some(next)) => next.pipeline_index == segment.pipeline_index + 1,
        _ => false,
    }
}

#[cfg(test)]
#[path = "git_helper_context_tests.rs"]
mod tests;
