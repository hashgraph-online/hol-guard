//! A plain `origin` refresh. It runs only Git built-ins once the effective
//! configuration proves `origin` is a GitHub HTTPS remote with no program,
//! proxy or URL rewrite in the way, every credential helper resolves to a
//! trusted executable, and no hook Git would start for the fetch can run.

use super::git_remote_config as config;
use super::git_session_probe::Probe;
use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::time::Instant;

/// The allow reason for a proven refresh, or `None`.
pub(super) fn exact_safe_command(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<(&'static str, &'static str)> {
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || model.segments.len() != 1
    {
        return None;
    }
    let segment = &model.segments[0];
    let leading = parse(segment, context)?;
    let proven = super::git_probe::memoized(memo_key(segment, context), || {
        Some(prove(
            segment.executable.as_deref()?,
            leading,
            context,
            deadline,
            execution_environment,
        ))
    });
    (proven == Some(true)).then_some((
        "native_exact_safe_git_origin_refresh",
        "The Rust command authority proved this fetch reaches only a GitHub HTTPS origin with trusted credential helpers, plain refspecs and no hooks or transport programs.",
    ))
}

/// Whether this evaluation already proved `segment` as a safe `origin`
/// operation; the compatibility layer uses it to drop the unverified-fetch
/// review it would otherwise record.
pub(super) fn verified(segment: &CommandSegmentV1, context: super::PathContext<'_>) -> bool {
    parse(segment, context).is_some() && super::git_probe::proven(&memo_key(segment, context))
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

fn parse<'a>(
    segment: &'a CommandSegmentV1,
    context: super::PathContext<'_>,
) -> Option<&'a [String]> {
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
    (command == "fetch" && crate::command_compatibility::git_fetch_origin_shaped(rest))
        .then_some(leading)
}

fn prove(
    executable: &str,
    leading: &[String],
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
        && probe.hooks_inert(&["pre-auto-gc", "reference-transaction", "post-fetch"])
}
