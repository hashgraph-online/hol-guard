//! A plain `origin` refresh, or a pull of one that fast-forwards or merges
//! the fetched branch. It runs only Git built-ins once the effective
//! configuration proves `origin` is a GitHub HTTPS or SSH remote with no program,
//! proxy or URL rewrite in the way, every credential helper resolves to a
//! trusted executable, and no hook Git would start for the fetch can run.
//!
//! `git merge --ff-only origin/<branch>`, alone or after the refresh, is the
//! pull split in two. It reaches no remote, so it needs only the work tree
//! half of the pull proof: what a fast-forward checkout could start.

use super::git_remote_config as config;
use super::git_session_probe::Probe;
use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::time::Instant;

#[path = "git_remote_proof.rs"]
mod proof;

#[path = "git_remote_pull.rs"]
pub(super) mod pull;

use proof::{
    every_remote_is_origin, fast_forward_inert, lfs_endpoint_overridden, lfsconfig_absent,
    tracks_origin, transport_proven,
};
use pull::Operation;

/// The allow reason for a proven refresh, or `None`. The fetch may sit in a
/// chain after a verified `cd` and beside segments that are benign on their
/// own, such as `git fetch origin main && git log origin/main --oneline -2`.
pub(super) fn exact_safe_command(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<(&'static str, &'static str)> {
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || model.segments.is_empty()
    {
        return None;
    }
    let cwd_proof = model
        .segments
        .iter()
        .position(|segment| segment.executable.as_deref() == Some("cd"))
        .and_then(|cd_index| {
            super::worktree_add::verified_worktree_cwd_context(model, cd_index, context)
        });
    let context = super::PathContext {
        cwd: cwd_proof
            .as_ref()
            .map(|proof| proof.cwd.as_str())
            .or(context.cwd),
        ..context
    };
    let mut fetch_seen = false;
    // One proven fast-forward merge may follow or stand in for the fetch;
    // after it, the checkout may hold files the chain did not see.
    let mut merged = false;
    // A pull already fast-forwards; no merge pairs with it.
    let mut pulled = false;
    // Whether the current pipeline starts with the proven fetch, as in
    // `git fetch origin main 2>&1 | tail -2`.
    let mut fetch_pipeline = false;
    // The pull or fast-forward merge that rewrote the work tree, if one did.
    // A commit it checks out may become configuration a later Git read obeys,
    // which the proof of that read never saw.
    let mut rewrote: Option<usize> = None;
    for (index, segment) in model.segments.iter().enumerate() {
        if segment.pipeline_index == 0 {
            fetch_pipeline = false;
        }
        if segment.executable.as_deref() == Some("cd") {
            if cwd_proof
                .as_ref()
                .is_none_or(|proof| proof.cd_index != index)
            {
                return None;
            }
            continue;
        }
        let stripped = super::segment_proof::without_stderr_merge(segment);
        let candidate = stripped.as_ref().unwrap_or(segment);
        if let Some((leading, operation)) = parse(candidate, context) {
            let merge = operation.upstream.is_some_and(|shape| !shape.fetches);
            // Only a change to the checkout bars a later operation: a pull or
            // a fast-forward merge may leave files the proofs still to come
            // never saw. A fetch writes refs and objects alone, so it may
            // stand before a pull, a merge or another fetch.
            if merged
                || pulled
                || !proven(
                    candidate,
                    leading,
                    operation,
                    context,
                    deadline,
                    execution_environment,
                )
            {
                return None;
            }
            if merge {
                merged = true;
            } else {
                fetch_seen = true;
                pulled |= operation.upstream.is_some();
            }
            if operation.upstream.is_some() {
                rewrote = Some(index);
            }
            fetch_pipeline = true;
            continue;
        }
        // Only a bounded `head`/`tail` of stdin may read the fetch's output.
        if fetch_pipeline
            && !(segment
                .executable
                .as_deref()
                .is_some_and(|value| matches!(super::executable_basename(value), "head" | "tail"))
                && super::safe_reads::safe_head_tail_stdin_arguments(&segment.arguments)
                && super::git_worktree::trusted_pipeline_command(
                    segment.executable.as_deref().unwrap_or_default(),
                    context,
                    execution_environment,
                ))
        {
            return None;
        }
        // A merge may check out a link to a file outside the checkout, which
        // a read screened before it ran would then follow. Git reads take
        // blobs from objects and never follow one.
        if ((merged && !fetch_pipeline)
            || !super::segment_proof::exact_safe_segment_with_context(
                model, segment, false, context,
            ))
            && !proven_read(model, index, context, deadline, execution_environment)
        {
            return None;
        }
        // A fast-forward earlier in the chain may check out a file an include
        // names, which this read would then obey; the refresh answers for the
        // read only when no include reaches into the work tree.
        if let Some(prior) = rewrote {
            if super::executable_basename(segment.executable.as_deref().unwrap_or_default())
                == "git"
                && !verified_refresh(
                    &model.segments[prior],
                    segment,
                    context,
                    deadline,
                    execution_environment,
                )
            {
                return None;
            }
        }
    }
    (fetch_seen || merged).then_some((
        "native_exact_safe_git_origin_refresh",
        "The Rust command authority proved this fetch, pull or fast-forward of an origin branch starts no hook, filter or transport program, and any fetch reaches only a GitHub origin with trusted credential helpers and plain refspecs.",
    ))
}

/// Lifts the generic review the declarative `command.git.merge` rule puts on
/// every merge once this module proves the chain a fast-forward of origin. A
/// permission the user disabled, a sandbox route and a sensitive target keep
/// their own verdicts, and a chain without such a merge is left as it is.
pub(super) fn settle_fast_forward(
    result: &mut guard_contracts::PreToolResultV1,
    model: Option<&CanonicalCommandV1>,
    controls: Option<&crate::native_command_controls::CompiledNativeCommandControls>,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) {
    let Some(model) = model else {
        return;
    };
    if result.minimum_action != "review"
        || !matches!(
            result.reason_code.as_str(),
            "native_command_review_required" | "native_command_extension_review"
        )
        || result.action.action_type != guard_contracts::PreToolActionTypeV1::Command
        || result.action.sensitive_target
    {
        return;
    }
    let merges = model.segments.iter().any(|segment| {
        let stripped = super::segment_proof::without_stderr_merge(segment);
        matches!(
            parse(stripped.as_ref().unwrap_or(segment), context),
            Some((_, Operation { upstream: Some(shape), .. })) if !shape.fetches
        )
    });
    // Only the merge rule's own review is lifted: another rule that asks for
    // more than allow, a permission the user keeps under review or an
    // uncertain match keeps its verdict. A `git status` or `git log` beside
    // the merge asks for nothing of its own, so it does not hold the proof
    // back. Neither does the ruleless permission a Git plumbing read records
    // (`git rev-parse`, `git merge-base`, `git show-ref`): it declares no
    // floor, and exists so a disabled Git extension or permission can still
    // block the read.
    let Some(extensions) = result.command_extensions.as_ref() else {
        return;
    };
    if !merges
        || extensions.binding.uncertainty_count != 0
        || extensions.evaluation_error.is_some()
        || !extensions
            .permission_observations
            .iter()
            .all(|observation| {
                observation.uncertainty_reasons.is_empty()
                    && controls.is_some_and(|controls| {
                        controls.permission_settles_at_allow(
                            &observation.extension_id,
                            &observation.permission_id,
                        )
                    })
            })
        || !extensions.observations.iter().all(|observation| {
            observation.uncertainty_reasons.is_empty()
                && (matches!(
                    observation.rule_id.as_str(),
                    "command.git.merge" | "command.git.fetch" | "command.git.pull"
                ) || controls
                    .is_some_and(|controls| controls.rule_settles_at_allow(&observation.rule_id)))
        })
    {
        return;
    }
    let Some((reason_code, reason)) =
        exact_safe_command(model, context, deadline, execution_environment)
    else {
        return;
    };
    result.minimum_action = "allow".into();
    result.policy_action = "allow".into();
    result.decision = "allow".into();
    result.explicitly_benign = true;
    result.reason_code = reason_code.into();
    result.reason = reason.into();
}

/// A Git read the configuration probe proves starts no pager, diff driver or
/// textconv helper. A fetch writes refs, never configuration, so the proof
/// holds on either side of it.
pub(super) fn proven_read(
    model: &CanonicalCommandV1,
    index: usize,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let segment = &model.segments[index];
    segment.executable.as_deref() == Some("git")
        && segment.environment_names.is_empty()
        && !segment.path_overridden
        && segment.wrapper_chain.is_empty()
        && !super::sensitive_command(&segment.text)
        && super::git_reads::safe_git_arguments(&segment.arguments, true, context)
        && super::directory_targets::drive_targets_quoted(segment)
        && super::directory_targets::home_targets_unquoted(segment)
        && super::git_config::execution_free(
            "git",
            &segment.arguments,
            context,
            deadline,
            execution_environment,
            super::git_helper_context::stdout_piped(model, index),
        ) == Some(true)
}

fn proven(
    segment: &CommandSegmentV1,
    leading: &[String],
    operation: Operation,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    // The one argument after `merge` that is not an option names its target.
    let target = operation
        .upstream
        .filter(|shape| !shape.fetches)
        .and_then(|_| {
            segment
                .arguments
                .iter()
                .rev()
                .find(|argument| !argument.starts_with('-'))
        })
        .map(String::as_str);
    let proven = super::git_probe::memoized(memo_key(segment, context), || {
        Some(prove(
            segment.executable.as_deref()?,
            leading,
            operation,
            target,
            context,
            deadline,
            execution_environment,
        ))
    });
    proven == Some(true)
}

/// Whether `segment` is an `origin` fetch this proof establishes now. The
/// worktree proof accepts one before the `worktree add` it refreshes.
pub(super) fn proven_fetch(
    segment: &CommandSegmentV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let stripped = super::segment_proof::without_stderr_merge(segment);
    let segment = stripped.as_ref().unwrap_or(segment);
    matches!(
        parse(segment, context),
        Some((leading, operation))
            if operation.upstream.is_none()
                && proven(segment, leading, operation, context, deadline, execution_environment)
    )
}

/// Whether this evaluation already proved `segment` as a safe `origin`
/// operation; the compatibility layer uses it to drop the unverified-fetch
/// review it would otherwise record. A trailing `2>&1` is the same operation.
pub(super) fn verified(segment: &CommandSegmentV1, context: super::PathContext<'_>) -> bool {
    let stripped = super::segment_proof::without_stderr_merge(segment);
    let segment = stripped.as_ref().unwrap_or(segment);
    parse(segment, context).is_some() && super::git_probe::proven(&memo_key(segment, context))
}

/// Whether this evaluation proved `segment` as an `origin` refresh that
/// settles a later Git read in the same command. A fetch writes only refs and
/// objects, so it settles one outright. A pull's fast-forward also rewrites
/// tracked files, and the one route by which a tracked file becomes
/// configuration the later read obeys is an include that names it, so a pull
/// settles the read when no include reaches into the work tree.
pub(super) fn verified_refresh(
    segment: &CommandSegmentV1,
    later: &CommandSegmentV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let stripped = super::segment_proof::without_stderr_merge(segment);
    let segment = stripped.as_ref().unwrap_or(segment);
    let Some((leading, operation)) = parse(segment, context) else {
        return false;
    };
    if !super::git_probe::proven(&memo_key(segment, context)) {
        return false;
    }
    if operation.upstream.is_none() {
        return true;
    }
    let Some(route) = read_route(later, context) else {
        return false;
    };
    let mut key = memo_key(segment, context);
    key.0.push_str(":settles:");
    key.0.push_str(&route.to_string_lossy());
    super::git_probe::memoized(key, || {
        let executable = segment.executable.as_deref()?;
        let probe = Probe::new(
            executable,
            leading,
            context,
            deadline,
            execution_environment,
        )?;
        Some(work_tree_settles(&probe, &route))
    })
    .unwrap_or(false)
}

/// The directory the later read runs Git in: the segment's working directory
/// folded through its leading `-C` routes, as Git folds them. `None` when a
/// leading option could send the read somewhere this cannot name, which
/// `--git-dir` and `--work-tree` do.
fn read_route(
    later: &CommandSegmentV1,
    context: super::PathContext<'_>,
) -> Option<std::path::PathBuf> {
    let mut route = std::path::PathBuf::from(context.cwd?);
    let mut arguments = later.arguments.iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-P" | "--no-pager" | "--no-optional-locks" | "--literal-pathspecs" => {}
            // A relative path joins what came before it; an absolute one
            // replaces it, which `PathBuf::push` already does.
            "-C" => route.push(arguments.next()?),
            "-c" => {
                arguments.next()?;
            }
            _ if argument.starts_with('-') => return None,
            // The subcommand: every later word is its own.
            _ => break,
        }
    }
    std::fs::canonicalize(route).ok()
}

/// Whether the later read, routed to `route`, reads only what this checkout
/// already proved: it runs at this very top level, and no configuration
/// include names a file the work tree holds, so no commit the fast-forward
/// checks out can become configuration. A relative include, or one whose
/// location this cannot resolve, counts as reaching the work tree.
fn work_tree_settles(probe: &Probe, route: &std::path::Path) -> bool {
    let Some((effective, _)) = probe.config() else {
        return false;
    };
    let Some(toplevel) = probe
        .text(&["rev-parse", "--show-toplevel"])
        .and_then(|toplevel| std::fs::canonicalize(toplevel).ok())
    else {
        return false;
    };
    // The fetched commit may add a directory Git reads as a repository of its
    // own: `safe.bareRepository=all`, Git's default, finds one anywhere below
    // the checkout, and a read routed into it would take its configuration.
    // Only a read that runs at this very top level is answered for.
    if toplevel != route {
        return false;
    }
    !effective.iter().any(|(key, values)| {
        (key == "include.path" || (key.starts_with("includeif.") && key.ends_with(".path")))
            && values
                .iter()
                .any(|value| include_reaches_tree(value, &probe.home, &toplevel))
    })
}

fn include_reaches_tree(value: &str, home: &std::path::Path, toplevel: &std::path::Path) -> bool {
    let path = match value.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None if std::path::Path::new(value).is_absolute() => std::path::PathBuf::from(value),
        None => return true,
    };
    !super::git_hook_files::outside_checkout(&path, toplevel)
}

fn memo_key(
    segment: &CommandSegmentV1,
    context: super::PathContext<'_>,
) -> super::git_probe::MemoKey {
    (
        format!(
            "\0origin:{}",
            segment.executable.as_deref().unwrap_or_default()
        ),
        segment.arguments.clone(),
        context.home_dir.map(str::to_owned),
        context.cwd.map(str::to_owned),
        false,
    )
}

/// The leading `-C` routes of a refresh, with `None` for a fetch or the
/// shape of a pull or fast-forward merge.
fn parse<'a>(
    segment: &'a CommandSegmentV1,
    context: super::PathContext<'_>,
) -> Option<(&'a [String], Operation)> {
    let executable = segment.executable.as_deref()?;
    if executable != "git"
        || segment.pipeline_index != 0
        || segment.path_overridden
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
        || segment
            .text
            .contains(['>', '<', '$', '`', '|', '&', ';', '\n', '\r'])
        || !super::directory_targets::drive_targets_quoted(segment)
        || !super::directory_targets::home_targets_unquoted(segment)
    {
        return None;
    }
    let arguments = segment.arguments.as_slice();
    let remaining = crate::command_compatibility::git_routed_arguments(arguments, context)?;
    let leading = &arguments[..arguments.len() - remaining.len()];
    if !leading
        .chunks(2)
        .all(|pair| matches!(pair, [flag, _] if flag == "-C"))
    {
        return None;
    }
    let (command, rest) = remaining.split_first()?;
    match command.as_str() {
        "fetch" => crate::command_compatibility::git_fetch_every_remote(rest).map(|every_remote| {
            (
                leading,
                Operation {
                    upstream: None,
                    every_remote,
                },
            )
        }),
        "pull" => Some((leading, Operation::upstream(pull::shaped(rest)?))),
        "merge" => Some((
            leading,
            Operation::upstream(pull::fast_forward_merge(rest)?),
        )),
        _ => None,
    }
}

fn prove(
    executable: &str,
    leading: &[String],
    operation: Operation,
    target: Option<&str>,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let Some(probe) = Probe::new(
        executable,
        leading,
        context,
        deadline,
        execution_environment,
    ) else {
        return false;
    };
    let Some((effective, repository)) = probe.config() else {
        return false;
    };
    if let Some(shape) = operation.upstream.filter(|shape| !shape.fetches) {
        // Git LFS smudges the pointers a fast-forward checks out from the
        // endpoint it derives from origin, with the credentials Git hands it,
        // so with LFS on the merge needs the fetch's transport proof too.
        let lfs = effective.keys().any(|key| key.starts_with("filter.lfs."));
        return target.is_some_and(|target| tracks_origin(&probe, target))
            && (!lfs
                || (transport_proven(&effective, &repository, &probe)
                    && !lfs_endpoint_overridden(&effective)
                    && target.is_some_and(|target| lfsconfig_absent(&probe, target))))
            && fast_forward_inert(&effective, &repository, shape, &probe);
    }
    // Initialized submodules are fetched on demand with their own config
    // and hooks, which this probe does not read.
    transport_proven(&effective, &repository, &probe)
        && (!operation.every_remote || every_remote_is_origin(&effective, &probe))
        && !effective.keys().any(|key| key.starts_with("submodule."))
        && probe.hooks_inert_in_a_stable_tree([
            "pre-auto-gc",
            "reference-transaction",
            "post-fetch",
        ])
        && operation
            .upstream
            .is_none_or(|shape| pull::pull_inert(&effective, &repository, shape, &probe))
}

#[cfg(test)]
#[path = "git_remote_ops_tests.rs"]
mod tests;
