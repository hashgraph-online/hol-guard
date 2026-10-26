//! Frozen, script-free installs from a committed lockfile: `bun install
//! --frozen-lockfile --ignore-scripts`, `pnpm install --frozen-lockfile
//! --ignore-scripts` and `npm ci --ignore-scripts`. Each one installs exactly
//! what the lockfile pins, fails rather than resolve anything new, and runs no
//! lifecycle script, so the packages land as files in `node_modules` and no
//! package code runs. The lockfile must name only registry packages with an
//! integrity hash or workspace links, so no git host, tarball URL or local
//! path is fetched, and no project or user configuration may move the
//! registry or load a hook. An install without `--ignore-scripts`, with a
//! package operand, or anywhere these facts cannot be shown stays reviewed.

#[path = "lockfile_install_scan.rs"]
mod scan;

use crate::{CanonicalCommandV1, CommandSegmentV1};
use guard_contracts::{GuardExecutionEnvironmentV1, PreToolActionTypeV1, PreToolResultV1};
use std::path::Path;
use std::time::Instant;

pub(crate) const REASON: &str = "native_exact_safe_lockfile_install";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Manager {
    Bun,
    Pnpm,
    Npm,
}

/// Turn the package review of a proven frozen install into an allow.
pub(super) fn settle(
    result: &mut PreToolResultV1,
    model: Option<&CanonicalCommandV1>,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) {
    if result.reason_code != "native_package_review"
        || result.minimum_action != "review"
        || !matches!(
            result.action.action_type,
            PreToolActionTypeV1::Command | PreToolActionTypeV1::Package
        )
        || result.action.sensitive_target
    {
        return;
    }
    let Some(model) = model else {
        return;
    };
    if !evidence_clean(result, model) {
        return;
    }
    let Some(xdg_config_home) = environment_inert(execution_environment) else {
        return;
    };
    let Some((manager, directory)) = install(model, context) else {
        return;
    };
    // The session proof trusted the loader paths outside the session's own
    // directory; the install writes in `directory`, so they must avoid it too.
    if execution_environment.is_some_and(|environment| {
        environment.library_search_paths.keys().any(|name| {
            !super::npm_environment::trusted_stamped_loader(
                environment,
                name,
                context.home_dir,
                &[directory.as_str()],
            )
        })
    }) {
        return;
    }
    let context = super::PathContext {
        cwd: Some(directory.as_str()),
        ..context
    };
    if !scan::directory_ready(manager, context, xdg_config_home.as_deref(), deadline) {
        if let Some(hint) = scan::present_lockfile_hint(manager, Path::new(&directory)) {
            result.reason.push(' ');
            result.reason.push_str(&hint);
        }
        return;
    }
    result.minimum_action = "allow".into();
    result.policy_action = "allow".into();
    result.decision = "allow".into();
    result.explicitly_benign = true;
    result.reason_code = REASON.into();
    result.reason = concat!(
        "The Rust command authority proved this install only fetches the registry packages ",
        "its lockfile pins, changes nothing else, and runs no install script.",
    )
    .into();
}

/// The package-protection permission is the only thing the extensions saw.
fn evidence_clean(result: &PreToolResultV1, model: &CanonicalCommandV1) -> bool {
    let Some(extensions) = result.command_extensions.as_ref() else {
        return false;
    };
    model.confidence == "exact"
        && !model.path_overridden
        && model.wrapper_chain.is_empty()
        && extensions.binding.uncertainty_count == 0
        && extensions.evaluation_error.is_none()
        && extensions.observations.is_empty()
        && extensions
            .permission_observations
            .iter()
            .all(|observation| {
                observation.extension_id == "command.package.node"
                    && observation.permission_id
                        == "command.package.node.permission.package-protection"
                    && observation.uncertainty_reasons.is_empty()
            })
}

/// No inherited variable may move the registry or the configuration the
/// managers read, or add arguments. An npm cache or output setting is inert.
/// npm's own selectors are checked through the path context. `BUN_INSTALL`
/// and `PNPM_HOME` only say where the tool lives, so they stay allowed.
/// Returns the XDG configuration directory, whose pnpm and Bun files are
/// checked like the ones in home.
fn environment_inert(
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> Option<Option<String>> {
    let selector = |name: &str| {
        let upper = name.to_ascii_uppercase();
        let configuration = [
            "BUN_CONFIG_",
            "PNPM_CONFIG_",
            "NPM_CONFIG_",
            "COREPACK_NPM_",
        ]
        .iter()
        .any(|prefix| upper.starts_with(prefix));
        (configuration && !super::npm_environment::inert_npm_config_name(name))
            || upper == "BUN_OPTIONS"
    };
    match execution_environment {
        Some(environment) => (environment.has_valid_shape()
            && !environment
                .environment_names
                .iter()
                .any(|name| selector(name)))
        .then(|| environment.xdg_config_home.clone()),
        None => (!std::env::vars_os()
            .any(|(name, value)| !value.is_empty() && selector(&name.to_string_lossy())))
        .then(|| {
            std::env::var("XDG_CONFIG_HOME")
                .ok()
                .filter(|value| !value.is_empty())
        }),
    }
}

/// The manager and the directory it installs in, when the command is an
/// optional verified `cd`, the install, then only commands that are safe on
/// their own, such as `| tail`. Running first means nothing earlier in the
/// command can rewrite the configuration checked here. Bun's `--cwd <dir>`
/// moves the install the way a leading `cd` would, so its directory is proved
/// the same way, and never on top of a `cd`.
fn install(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> Option<(Manager, String)> {
    if !context.npm_config_inert || !context.shell_home_matches {
        return None;
    }
    let leading_cd = model.segments.first()?.executable.as_deref() == Some("cd");
    let shell_directory = if leading_cd {
        super::segment_proof::verified_cwd_compound_context(model, context)?
    } else {
        context.cwd?.to_owned()
    };
    let start = usize::from(leading_cd);
    let (manager, moved) = install_form(model.segments.get(start)?)?;
    let directory = match moved {
        None => shell_directory.clone(),
        Some(target) if !leading_cd => {
            super::directory_targets::verified_cwd_target(&target, context)?
        }
        Some(_) => return None,
    };
    // Later commands still run where the shell is, not where `--cwd` points.
    let context = super::PathContext {
        cwd: Some(shell_directory.as_str()),
        ..context
    };
    model.segments[start + 1..]
        .iter()
        .all(|segment| {
            segment.executable.as_deref() != Some("cd")
                && super::segment_proof::exact_safe_segment_with_context(
                    model, segment, false, context,
                )
        })
        .then_some((manager, directory))
}

/// The manager, and the directory a Bun `--cwd` names, for an install with
/// the required flags and only known optional ones.
fn install_form(original: &CommandSegmentV1) -> Option<(Manager, Option<String>)> {
    let stripped = super::segment_proof::without_stderr_merge(original);
    let segment = stripped.as_ref().unwrap_or(original);
    if segment.pipeline_index != 0
        || segment.path_overridden
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
        || segment.text.contains(['>', '<', '$', '`', '\n', '\r'])
    {
        return None;
    }
    let manager = match segment.executable.as_deref()? {
        "bun" => Manager::Bun,
        "pnpm" => Manager::Pnpm,
        "npm" => Manager::Npm,
        _ => return None,
    };
    let (verb, rest) = segment.arguments.split_first()?;
    let mut flags: Vec<&str> = Vec::new();
    let mut moved = None;
    let mut rest = rest.iter();
    while let Some(argument) = rest.next() {
        let target = match argument.strip_prefix("--cwd=") {
            Some(target) => target,
            None if argument == "--cwd" => rest.next()?.as_str(),
            None => {
                flags.push(argument.as_str());
                continue;
            }
        };
        // Only Bun reads `--cwd`, and a second one would be ambiguous.
        if manager != Manager::Bun || target.is_empty() || moved.is_some() {
            return None;
        }
        moved = Some(target.to_owned());
    }
    let (verbs, required, optional): (&[&str], &[&str], &[&str]) = match manager {
        Manager::Bun => (
            &["install", "i"],
            &["--frozen-lockfile", "--ignore-scripts"],
            &[
                "--silent",
                "--no-progress",
                "--no-summary",
                "--production",
                "--verbose",
            ],
        ),
        Manager::Pnpm => (
            &["install", "i"],
            &["--frozen-lockfile", "--ignore-scripts"],
            &[
                "--silent",
                "--prefer-offline",
                "--offline",
                "--prod",
                "--reporter=append-only",
                "--reporter=silent",
                "--reporter=default",
                "--loglevel=error",
                "--loglevel=warn",
                "--ignore-pnpmfile",
            ],
        ),
        Manager::Npm => (
            &["ci", "clean-install"],
            &["--ignore-scripts"],
            &[
                "--no-audit",
                "--no-fund",
                "--silent",
                "--quiet",
                "--prefer-offline",
                "--offline",
                "--omit=dev",
                "--omit=optional",
                "--allow-git=none",
                "--loglevel=error",
                "--loglevel=warn",
                "--loglevel=silent",
                "--progress=false",
            ],
        ),
    };
    (verbs.contains(&verb.as_str())
        && required.iter().all(|flag| flags.contains(flag))
        && flags
            .iter()
            .all(|flag| required.contains(flag) || optional.contains(flag)))
    .then_some((manager, moved))
}
