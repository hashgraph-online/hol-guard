//! A plain `origin` refresh, or a pull of one that fast-forwards or merges
//! the fetched branch. It runs only Git built-ins once the effective
//! configuration proves `origin` is a GitHub HTTPS remote with no program,
//! proxy or URL rewrite in the way, every credential helper resolves to a
//! trusted executable, and no hook Git would start for the fetch can run.

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
            if fetch_seen
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
            fetch_seen = true;
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
        if !super::segment_proof::exact_safe_segment_with_context(model, segment, false, context)
            && !proven_read(model, index, context, deadline, execution_environment)
        {
            return None;
        }
    }
    fetch_seen.then_some((
        "native_exact_safe_git_origin_refresh",
        "The Rust command authority proved this fetch or pull reaches only a GitHub HTTPS origin with trusted credential helpers, plain refspecs and no hooks, filters or transport programs.",
    ))
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
    let proven = super::git_probe::memoized(memo_key(segment, context), || {
        Some(prove(
            segment.executable.as_deref()?,
            leading,
            upstream,
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
/// shape of a pull.
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
        _ => None,
    }
}

fn prove(
    executable: &str,
    leading: &[String],
    upstream: Option<pull::Pull>,
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
    let urls = effective
        .get("remote.origin.url")
        .map_or(&[][..], Vec::as_slice);
    if urls.is_empty()
        || !urls.iter().all(|url| {
            config::rewritten_remote_url(&effective, url.trim())
                .is_some_and(|url| config::safe_github_https_remote_url(&url))
        })
        || config::fetch_config_routes_execution(&effective)
        || !probe.credential_helpers_trusted(&config::credential_helpers(&effective))
    {
        return false;
    }
    // Initialized submodules are fetched on demand with their own config
    // and hooks, which this probe does not read.
    !config::config_weakens_transport(&effective)
        && !config::repository_config_routes_transport(&repository)
        && !effective.keys().any(|key| key.starts_with("submodule."))
        && probe.hooks_inert(["pre-auto-gc", "reference-transaction", "post-fetch"])
        && upstream.is_none_or(|shape| pull::pull_inert(&effective, &repository, shape, &probe))
}
