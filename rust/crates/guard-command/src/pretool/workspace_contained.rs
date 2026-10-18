//! General workspace containment for confidently parsed local commands.
//!
//! A command no narrower profile claims runs inside the macOS workspace
//! sandbox (no network, no home, credentials denied, `.git` execution config
//! and agent/editor paths write-denied) instead of becoming a review prompt.
//! The sandbox, not this classifier, is the security boundary; this module only
//! refuses shapes whose effect the sandbox cannot bound.
use super::PathContext;
use crate::native_command_controls::CompiledNativeCommandControls;
use crate::CanonicalCommandV1;
use guard_contracts::{GuardExecutionEnvironmentV1, PreToolActionTypeV1, PreToolResultV1};
use std::path::Path;

#[cfg(unix)]
use crate::restricted_pytest::{linux_workspace_sandbox_available, workspace_admissible};

/// The workspace sandbox runs on macOS and Linux; Windows never admits a workspace.
#[cfg(not(unix))]
fn workspace_admissible(_cwd: &Path, _home: Option<&Path>) -> Option<std::path::PathBuf> {
    None
}
#[cfg(not(unix))]
fn linux_workspace_sandbox_available() -> bool {
    false
}

pub(crate) const REASON: &str = "native_workspace_containment_required";
/// A generic review left in place because the sandbox could not run the
/// program; the local CLI it launches can be set up on this device instead.
pub(crate) const OUTSIDE_ROOTS_REASON: &str =
    "native_workspace_containment_executable_outside_roots";
#[cfg(unix)]
pub(crate) const PROFILE: &str = "workspace-contained-v1";

#[path = "workspace_contained_cd.rs"]
mod cd;
#[path = "workspace_contained_chmod.rs"]
mod chmod;
#[path = "workspace_contained_git.rs"]
mod git_metadata;
#[path = "workspace_contained_home_cd.rs"]
pub(super) mod home_cd;
#[path = "workspace_git_keeps_work.rs"]
mod keeps_work;
#[path = "workspace_contained_kill.rs"]
mod kill;
#[path = "workspace_contained_launch.rs"]
mod launch;
#[path = "workspace_contained_links.rs"]
mod links;
#[path = "workspace_contained_package.rs"]
pub(super) mod package;
#[path = "workspace_contained_reach.rs"]
mod reach;
#[path = "workspace_contained_removal.rs"]
mod removal;
#[path = "workspace_contained_runner.rs"]
pub(super) mod runner;
#[path = "workspace_contained_script.rs"]
mod script;
#[path = "workspace_contained_settings.rs"]
mod settings;
#[path = "workspace_contained_sibling.rs"]
mod sibling;

pub(super) use keeps_work::keeping_arguments;
pub(super) use reach::PRIVATE_TEMP_WITH_FALLBACK;
pub(super) use reach::{private_temp_expansions_only, rebinds_private_temp};
pub(super) use settings::carry_settings;

/// Clients whose only purpose is the network the sandbox withholds.
const NETWORK_CLIENTS: &[&str] = &[
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "ftp", "tftp", "telnet",
    "rsync", "nmap", "aria2c", "http", "https", "xh",
];

// Privilege and permission changes. This is an exclusion, not an allowlist.
const PRIVILEGE_DENY: &[&str] = &[
    "sudo",
    "doas",
    "su",
    "login",
    "chmod",
    "chown",
    "chgrp",
    "chflags",
    "xattr",
    "setfacl",
    "launchctl",
    "crontab",
    "at",
    "security",
    "osascript",
    "open",
    "defaults",
    "dscl",
    "spctl",
    "csrutil",
    "kill",
    "killall",
    "pkill",
];
// The sandbox cannot undo losing uncommitted work, so these stay at review.
const UNRECOVERABLE_RULES: &[&str] = &[
    "command.git.hard-reset",
    "command.git.force-clean",
    "command.git.clean",
    "command.git.reset",
    "command.git.local-branch-delete",
    "command.git.stash",
    "command.git.checkout",
    "command.git.restore",
    "command.git.switch",
    "command.git.unsafe-read",
];
// Remote changes: with no network, containing them only hides a consent prompt.
const REMOTE_RULES: &[&str] = &["command.git.force-push", "command.git.remote-branch-delete"];
const CONTAINABLE_RISKS: &[&str] = &["local_secret_read", "destructive_shell"];
const EXTENSION_REVIEW: &str = "native_command_extension_review";
/// What the sandbox executes for one authorized command.
pub(crate) struct Shape {
    /// Arguments for a trusted `git init`, run before the sandbox starts
    /// because `git init` always rewrites the write-denied `.git/config`.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub bootstrap: Option<Vec<String>>,
    /// Text run before `git init`, which runs only if it succeeds (`&&`).
    pub prefix: Option<String>,
    /// Text for `sh -c`; `None` runs the original bytes unchanged.
    pub remainder: Option<String>,
    /// Character span of the `git init` segment in the classified text.
    pub init_span: Option<(usize, usize)>,
    /// Canonical scripts outside the workspace the sandbox may read, each
    /// only as that one file.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub read_files: Vec<std::path::PathBuf>,
}

/// Shell-state builtins: before `git init` they run in a separate shell.
pub(super) const SHELL_STATE: &[&str] = &[
    "cd", "pushd", "popd", "export", "unset", "set", "shopt", "source", ".", "alias", "unalias",
    "declare", "typeset", "local", "readonly", "eval", "exec", "umask", "trap", "ulimit", "hash",
    "shift", "read", "getopts", "builtin", "enable", "exit", "return", "function",
];

fn branch_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
}

/// The canonical arguments of a `git init` creating a repository in the current
/// directory, or None for any other form (template, git dir, target, unknown options).
pub(crate) fn init_arguments(arguments: &[String]) -> Option<Vec<String>> {
    let mut result = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "-q" | "--quiet" => result.push("-q".to_owned()),
            "." => {}
            "-b" => {
                index += 1;
                let name = arguments.get(index).filter(|name| branch_name(name))?;
                result.extend(["-b".to_owned(), name.clone()]);
            }
            value => {
                let name = value
                    .strip_prefix("--initial-branch=")
                    .filter(|name| branch_name(name))?;
                result.extend(["-b".to_owned(), name.to_owned()]);
            }
        }
        index += 1;
    }
    Some(result)
}

/// Shape checks shared by classification and the launch plan. `original`,
/// the exact text to run, is needed only to slice off a bootstrapped `git init`.
pub(crate) fn command_shape(
    model: &CanonicalCommandV1,
    workspace: &Path,
    original: Option<&str>,
) -> Option<Shape> {
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || model.segments.is_empty()
        || !cd::stand_ins_only_entered(model)
    {
        return None;
    }
    let mut bootstrap = None;
    let mut read_files = Vec::new();
    if links::unbounded_linked_writes(model, workspace) {
        return None;
    }
    let linked = super::worktree_writes::linked_worktree_common_dir(workspace).is_some();
    let temp_fixed = !reach::rebinds_private_temp(&model.normalized_text);
    // `~` is the private home the launcher seeds only while nothing rebinds it.
    let home_fixed = !model.normalized_text.contains("HOME");
    for (index, segment) in model.segments.iter().enumerate() {
        // A bare private assignment starts no program.
        if segment.executable.is_none() && cd::assigns_private(model, segment) {
            continue;
        }
        let executable = segment.executable.as_deref()?;
        if executable.contains('$')
            || !segment.wrapper_chain.is_empty()
            || segment.path_overridden
            // Redirecting Git's repository or configuration roots would move
            // the write-denied paths this profile relies on.
            || segment
                .environment_names
                .iter()
                .any(|name| name.to_ascii_uppercase().starts_with("GIT_"))
        {
            return None;
        }
        let name = super::executable_basename(executable);
        // A scratch script outside the workspace is read as that one file.
        let script = script::outside_script(segment, workspace);
        // The sandbox has no network, so a network client would only fail,
        // and it reaches no directory outside the workspace.
        if NETWORK_CLIENTS.contains(&name)
            || reach::reaches_outside(
                segment,
                name,
                workspace,
                temp_fixed,
                home_fixed,
                script.as_ref().map(|(operand, _)| operand.as_str()),
            )
            || (matches!(name, "cd" | "pushd")
                && !matches!(segment.arguments.as_slice(),
                    [target] if cd::bounded(target, workspace, temp_fixed)))
        {
            return None;
        }
        if let Some((_, path)) = script {
            // One script only: a second grant would let the first read it.
            if read_files.first().is_some_and(|first| *first != path) {
                return None;
            }
            if !read_files.contains(&path) {
                read_files.push(path);
            }
        }
        if PRIVILEGE_DENY.contains(&name)
            && !(name == "chmod" && chmod::plain_mode(&segment.arguments))
            && !(name == "kill" && kill::jobs_only(&segment.arguments))
        {
            return None;
        }
        // A linked worktree keeps its index, refs and objects in the shared
        // Git directory outside the workspace, which the sandbox cannot
        // reach, so Git there would only fail. It keeps its review unless
        // `git_local_writes` proves the write starts no program.
        if name == "git" && linked {
            return None;
        }
        if name == "git" && git_metadata::writes_denied_metadata(&segment.arguments) {
            return None;
        }
        if name == "git" && git_metadata::initializes(&segment.arguments) {
            if bootstrap.is_some() || segment.arguments.first().map(String::as_str) != Some("init")
            {
                return None;
            }
            // An existing `.git` is never re-initialized: that is a config write.
            if std::fs::symlink_metadata(workspace.join(".git")).is_ok() {
                return None;
            }
            bootstrap = Some((index, init_arguments(&segment.arguments[1..])?));
        }
    }
    let Some((init, arguments)) = bootstrap else {
        return Some(Shape {
            bootstrap: None,
            prefix: None,
            remainder: None,
            init_span: None,
            read_files,
        });
    };
    if model.segments[..init].iter().any(|segment| {
        segment
            .executable
            .as_deref()
            .is_none_or(|value| SHELL_STATE.contains(&super::executable_basename(value)))
    }) {
        return None;
    }
    let text = original?;
    if text.trim() != model.normalized_text || model.normalized_text != model.normalized_text.trim()
    {
        return None;
    }
    let span = &model.segments[init].span;
    let (prefix, remainder) = split_at_init(&model.normalized_text, span.start, span.end)?;
    Some(Shape {
        bootstrap: Some(arguments),
        prefix,
        remainder: Some(remainder),
        init_span: Some((span.start, span.end)),
        read_files,
    })
}

/// The text before and after the `git init` segment at character span
/// `start..end`. Only `&&` may precede it, so a failed prefix still stops it;
/// only an unconditional sequence may follow it, so the rest can run alone.
pub(crate) fn split_at_init(
    text: &str,
    start: usize,
    end: usize,
) -> Option<(Option<String>, String)> {
    let head: String = text.chars().take(start).collect();
    let head = head.trim();
    let prefix = if head.is_empty() {
        None
    } else {
        let prefix = head.strip_suffix("&&")?.trim();
        if prefix.is_empty() || prefix.ends_with(['&', '|', ';']) {
            return None;
        }
        Some(prefix.to_owned())
    };
    let tail: String = text.chars().skip(end).collect();
    let tail = tail.trim_start_matches([' ', '\t']);
    let rest = if tail.is_empty() {
        ""
    } else {
        tail.strip_prefix("&&")
            .or_else(|| tail.strip_prefix(';'))
            .or_else(|| tail.strip_prefix('\n'))?
    };
    Some((prefix, rest.trim().to_owned()))
}

fn extensions_contain(
    result: &PreToolResultV1,
    controls: &CompiledNativeCommandControls,
    model: &CanonicalCommandV1,
    package: bool,
) -> bool {
    // Without the loaded extension program there is no risk evidence: keep review.
    let Some(extensions) = result.command_extensions.as_ref() else {
        return false;
    };
    extensions.binding.uncertainty_count == removal::accepted_uncertainty(extensions, model)
        && extensions.evaluation_error.is_none()
        // A package-firewall permission marks package-manager use (or a Bun
        // image evaluating code), not a proven risk; a disabled one blocked.
        && extensions.permission_observations.iter().all(|observation| {
            (package || super::restricted_tests::bun_inline_eval(model))
                && observation.mcp_tool.is_none()
                && package::PACKAGE_EXTENSIONS.contains(&observation.extension_id.as_str())
                && observation.uncertainty_reasons.is_empty()
        })
        && extensions.observations.iter().all(|observation| {
            (observation.uncertainty_reasons.is_empty() || removal::accepted(observation, model))
                && (!UNRECOVERABLE_RULES.contains(&observation.rule_id.as_str())
                    || keeps_work::keeps_work(observation, model))
                && !REMOTE_RULES.contains(&observation.rule_id.as_str())
                && controls
                    .rule_risk_classes(&observation.rule_id)
                    .is_some_and(|classes| {
                        classes
                            .iter()
                            .all(|class| CONTAINABLE_RISKS.contains(&class.as_str()))
                    })
        })
}

/// Whether this host runs the workspace sandbox for this harness hook: macOS
/// Seatbelt, or a Linux bubblewrap that passed the overlay probe.
pub(super) fn host_eligible(harness: &str, event: &str) -> bool {
    event == "PreToolUse"
        && matches!(
            harness,
            "omp" | "oh-my-pi" | "pi" | "zcode" | "claude-code" | "codex"
        )
        && sandbox_available()
}

pub(super) fn sandbox_available() -> bool {
    cfg!(target_os = "macos") || linux_workspace_sandbox_available()
}

/// Whether a redirect in `command` names a path outside `workspace`.
pub(super) fn redirect_leaves(command: &str, workspace: &Path) -> bool {
    reach::redirect_targets(command).any(|target| reach::outside(target, "", workspace))
}

/// The workspace the sandbox would confine for this session, if any.
pub(super) fn admitted_workspace(context: PathContext<'_>) -> Option<std::path::PathBuf> {
    workspace_admissible(Path::new(context.cwd?), context.home_dir.map(Path::new))
}

/// Convert a generic review into a workspace sandbox requirement when every
/// condition holds. `pre_floor` is the reason and action before the Git
/// execution-context floor ran.
#[allow(clippy::too_many_arguments)]
pub(super) fn convert(
    result: &mut PreToolResultV1,
    pre_floor: &(String, String),
    model: Option<&CanonicalCommandV1>,
    controls: Option<&CompiledNativeCommandControls>,
    context: PathContext<'_>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
    harness: &str,
    event: &str,
    command_text: Option<&str>,
) {
    if !host_eligible(harness, event)
        || !matches!(
            result.action.action_type,
            PreToolActionTypeV1::Command | PreToolActionTypeV1::Package
        )
        || result.action.sensitive_target
    {
        return;
    }
    let package = result.action.action_type == PreToolActionTypeV1::Package;
    let floor_reason = if package {
        "native_package_review"
    } else {
        "native_command_review_required"
    };
    // An extension rule can raise an otherwise allowed command such as
    // `rm notes.txt` to review; `extensions_contain` still requires every
    // matched rule to carry only risks the sandbox bounds.
    let reviewable =
        |reason: &str| reason == floor_reason || (!package && reason == EXTENSION_REVIEW);
    let generic = reviewable(result.reason_code.as_str()) && result.minimum_action == "review";
    // The Git floor existed because unsandboxed helpers could run; inside the
    // sandbox the configuration is write-denied and helpers stay contained.
    let git_floor = result.reason_code == "native_git_execution_context_review"
        && pre_floor.1 == "review"
        && (reviewable(pre_floor.0.as_str()) || pre_floor.0 == "native_git_helper_context_review");
    if !generic && !git_floor {
        return;
    }
    let (Some(model), Some(controls), Some(cwd)) = (model, controls, context.cwd) else {
        return;
    };
    let (launch_context, sent_text) = (context, command_text);
    // The sink expands a leading `cd ~/<dir>` itself and runs the rest from
    // the directory it reaches, so the checks below see that directory.
    let home = home_cd::as_absolute_cd(model, context);
    let model = home.as_ref().map_or(model, |list| &list.model);
    let command_text = home
        .as_ref()
        .map_or(command_text, |list| Some(list.text.as_str()));
    // The home spelling and the directory it expands to are the same command
    // written two ways, so the screens that answer for what the agent issued
    // answer for the expanded spelling too. The package projection below is a
    // different list the sink synthesizes, which those screens never read.
    let issued = model;
    let projected = super::contained_wrapper::package_dir::as_cd_list(model, context);
    let model = projected.as_ref().map_or(model, |list| &list.model);
    let command_text = projected
        .as_ref()
        .map_or(command_text, |list| Some(list.text.as_str()));
    // After `cd <sibling root> &&` the sink runs the rest from that root, so
    // the rest is checked with the root as its workspace and working directory.
    // One command after a `cd` elsewhere in a sibling runs whole from its root.
    let sibling = sibling::sibling_run(model, context);
    let root = match &sibling {
        Some((root, _)) => root.to_str(),
        None => Some(cwd),
    };
    let Some(root) = root else {
        return;
    };
    let Some(workspace) = workspace_admissible(Path::new(root), context.home_dir.map(Path::new))
    else {
        return;
    };
    let rest = sibling.as_ref().and_then(|(_, rest)| rest.as_ref());
    let shaped = rest.unwrap_or(model);
    let context = PathContext {
        cwd: Some(root),
        ..context
    };
    // `npx vite` with vite installed runs `node_modules/.bin/vite`. `npx` and
    // `bunx` arrive as commands rather than package actions, so a runner is
    // held to every package check below whichever way it arrived.
    let runners = runner::installed_tools(shaped, &workspace);
    let package = package || runners.is_some();
    // A package-firewall permission records which manager ran. It is evidence
    // the command is a manager's, not that the work it does leaves the
    // workspace, so a manager running a local verb answers for the
    // observation too. A command with no manager in it proves nothing about
    // the permission, so it keeps the admission it has.
    let local_work = package::local_package_work(model, runners.is_some(), &workspace);
    let manager_work = local_work && package::names_a_manager(model);
    if !extensions_contain(result, controls, issued, package || manager_work)
        || (package && !local_work)
    {
        return;
    }
    // Installs, one-shot executions and lockfile syncs stay with supply-chain
    // admission even when the verb check above missed their spelling.
    if package
        && command_text.is_none_or(|text| {
            crate::package_intent_parser::parse_package_intent(
                text,
                Some(&workspace),
                context.home_dir.map(Path::new),
                None,
                None,
            )
            .is_some_and(|intent| {
                !runners
                    .as_deref()
                    .is_some_and(|tools| runner::intent_only_runs(&intent, tools))
            })
        })
    {
        return;
    }
    if super::workspace_git_environment::session_git_variables(execution_environment)
        .and_then(|variables| {
            super::workspace_git_config::workspace_write_denials(
                &workspace,
                context.home_dir.map(Path::new),
                &variables,
            )
        })
        .is_none()
        || command_shape(shaped, &workspace, command_text.filter(|_| rest.is_none())).is_none()
        || removal::destroys_workspace(result, issued, &workspace)
        || removal::loses_work(result, issued, context, execution_environment)
    {
        return;
    }
    // Last, so a check above that keeps the review keeps its own reason.
    if super::script_content::keeps_network_review(result, issued, sent_text, launch_context) {
        return;
    }
    if launch::outside(shaped, &workspace, context, execution_environment) {
        // Nothing marks a generic review as unrecognised any more plainly, so
        // only that one is renamed; any other reason already says more.
        if result.reason_code == floor_reason && !package {
            result.reason_code = OUTSIDE_ROOTS_REASON.into();
            result.reason = concat!(
                "HOL Guard's workspace sandbox cannot run this program, ",
                "so it was not started there.",
            )
            .into();
        }
        return;
    }
    mark_contained(result);
}

pub(crate) fn mark_contained(result: &mut PreToolResultV1) {
    result.minimum_action = "sandbox-required".into();
    result.policy_action = "sandbox-required".into();
    result.decision = "deny".into();
    result.explicitly_benign = false;
    result.reason_code = REASON.into();
    result.reason = concat!(
        "HOL Guard runs this command in a protected workspace sandbox ",
        "(no network, no home access, no PTY or Docker socket). Every program it ",
        "starts, including children of an interpreter, runs contained and can write ",
        "only the workspace, $TMPDIR and a private scratch $HOME; only commands ",
        "Guard proves safe run ",
        "directly, outside the sandbox.",
    )
    .into();
}
