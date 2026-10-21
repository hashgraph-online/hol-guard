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

#[path = "git_remote_pull.rs"]
pub(super) mod pull;

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
        if let Some((leading, upstream)) = parse(candidate, context) {
            let merge = upstream.is_some_and(|shape| !shape.fetches);
            // Only `git fetch origin` then `git merge --ff-only origin/main`
            // pair; a pull, a second fetch or a second merge stands alone.
            let repeated = if merge {
                merged || pulled
            } else {
                fetch_seen || merged
            };
            if repeated
                || !proven(
                    candidate,
                    leading,
                    upstream,
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
                pulled |= upstream.is_some();
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
            Some((_, Some(shape))) if !shape.fetches
        )
    });
    // Only the merge rule's own review is lifted: another rule, a permission
    // the user keeps under review or an uncertain match keeps its verdict.
    let Some(extensions) = result.command_extensions.as_ref() else {
        return;
    };
    if !merges
        || extensions.binding.uncertainty_count != 0
        || extensions.evaluation_error.is_some()
        || !extensions.permission_observations.is_empty()
        || !extensions.observations.iter().all(|observation| {
            observation.uncertainty_reasons.is_empty()
                && matches!(
                    observation.rule_id.as_str(),
                    "command.git.merge" | "command.git.fetch" | "command.git.pull"
                )
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
    upstream: Option<pull::Pull>,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    // The one argument after `merge` that is not an option names its target.
    let target = upstream
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
            upstream,
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
        Some((leading, None))
            if proven(segment, leading, None, context, deadline, execution_environment)
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

/// Whether this evaluation already proved `segment` as a safe `origin` fetch.
/// A fetch writes only refs and objects, never the configuration a later Git
/// read in the same command depends on; a pull also updates the work tree.
pub(super) fn verified_fetch(segment: &CommandSegmentV1, context: super::PathContext<'_>) -> bool {
    let stripped = super::segment_proof::without_stderr_merge(segment);
    let segment = stripped.as_ref().unwrap_or(segment);
    parse(segment, context).is_some_and(|(_, upstream)| upstream.is_none())
        && super::git_probe::proven(&memo_key(segment, context))
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
) -> Option<(&'a [String], Option<pull::Pull>)> {
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
        "fetch" => {
            crate::command_compatibility::git_fetch_origin_shaped(rest).then_some((leading, None))
        }
        "pull" => Some((leading, Some(pull::shaped(rest)?))),
        "merge" => Some((leading, Some(pull::fast_forward_merge(rest)?))),
        _ => None,
    }
}

fn prove(
    executable: &str,
    leading: &[String],
    upstream: Option<pull::Pull>,
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
    if let Some(shape) = upstream.filter(|shape| !shape.fetches) {
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
        && !effective.keys().any(|key| key.starts_with("submodule."))
        && probe.hooks_inert_in_a_stable_tree([
            "pre-auto-gc",
            "reference-transaction",
            "post-fetch",
        ])
        && upstream.is_none_or(|shape| pull::pull_inert(&effective, &repository, shape, &probe))
}

/// Git LFS takes its endpoint from `lfs.url`, `lfs.pushurl` or
/// `remote.<name>.lfsurl`, and how it authenticates there from
/// `lfs.<url>.access`, rather than from origin's URL.
fn lfs_endpoint_overridden(effective: &config::GitConfig) -> bool {
    effective.keys().any(|key| {
        let key = key.to_ascii_lowercase();
        key == "lfs.url"
            || key == "lfs.pushurl"
            || (key.starts_with("remote.") && key.ends_with(".lfsurl"))
            || (key.starts_with("lfs.") && key.ends_with(".access"))
    })
}

/// No `.lfsconfig` names those keys from the work tree, the current commit
/// or the commit the fast-forward checks out. A probe that fails counts as
/// one being there.
fn lfsconfig_absent(probe: &Probe, target: &str) -> bool {
    let Some(top) = probe.text(&["rev-parse", "--show-toplevel"]) else {
        return false;
    };
    if std::fs::symlink_metadata(std::path::Path::new(&top).join(".lfsconfig")).is_ok() {
        return false;
    }
    ["HEAD", target].iter().all(|commit| {
        probe
            .output(&[
                "ls-tree",
                "--full-tree",
                "--name-only",
                "--end-of-options",
                commit,
                "--",
                ".lfsconfig",
            ])
            .is_some_and(|listed| listed.iter().all(u8::is_ascii_whitespace))
    })
}

/// The network half of the proof: every origin URL reaches GitHub, no
/// configuration routes the transport through a program, credential helpers
/// are trusted, and no `pager.fetch` names a program for the fetch's output.
fn transport_proven(
    effective: &config::GitConfig,
    repository: &config::GitConfig,
    probe: &Probe,
) -> bool {
    let urls = effective
        .get("remote.origin.url")
        .map_or(&[][..], Vec::as_slice);
    !urls.is_empty()
        && urls.iter().all(|url| {
            config::rewritten_remote_url(effective, url.trim())
                .is_some_and(|url| config::safe_github_remote_url(&url))
        })
        && !config::fetch_config_routes_execution(effective)
        && probe.credential_helpers_trusted(&config::credential_helpers(effective))
        && !config::config_weakens_transport(effective)
        && !config::repository_config_routes_transport(repository)
        && !pull::pager_enabled(effective, "fetch")
}

/// Whether Git resolves the merge target to origin's remote-tracking ref,
/// rather than a ref such as a tag or local branch spelled `origin/<branch>`
/// that Git would pick first.
fn tracks_origin(probe: &Probe, target: &str) -> bool {
    let Some(full) = probe.text(&[
        "rev-parse",
        "--verify",
        "--quiet",
        "--symbolic-full-name",
        target,
    ]) else {
        return false;
    };
    if target.starts_with("origin/") {
        full == format!("refs/remotes/{target}")
    } else {
        full.starts_with("refs/remotes/origin/")
    }
}

/// The work tree half of the pull proof, for a fast-forward merge that
/// fetches nothing: the checkout, ref update and automatic maintenance start
/// no program. A partial clone would fetch the blobs it checks out from a
/// remote this proof has not read, submodules carry their own hooks, and a
/// virtual file system names a program Git runs on every index read.
fn fast_forward_inert(
    effective: &config::GitConfig,
    repository: &config::GitConfig,
    shape: pull::Pull,
    probe: &Probe,
) -> bool {
    !effective.iter().any(|(key, values)| {
        matches!(
            key.as_str(),
            "extensions.partialclone" | "core.virtualfilesystem"
        ) || key.starts_with("submodule.")
            || (key.starts_with("remote.")
                && key.ends_with(".promisor")
                && values.iter().any(|value| !pull::disabled(value)))
    }) && probe.hooks_inert(["reference-transaction", "pre-auto-gc"])
        && pull::pull_inert(effective, repository, shape, probe)
}
