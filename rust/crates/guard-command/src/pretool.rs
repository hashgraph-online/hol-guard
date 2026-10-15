use crate::{parse_command, powershell_floors as ps, CanonicalCommandV1, CommandModelRequestV1};
use guard_secure_fs::sensitive_path_family;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Caller roots have explicit names; individual proofs still verify them on disk.
#[derive(Clone, Copy, Debug, Default)]
pub struct PathContext<'a> {
    pub home_dir: Option<&'a str>,
    pub cwd: Option<&'a str>,
    pub cdpath_unset: bool,
    /// No inherited `RUSTUP_TOOLCHAIN` or `RUSTUP_HOME` can change which
    /// toolchain the rustup proxy runs. Literal contexts leave this false.
    pub rustup_override_absent: bool,
    /// No inherited npm or Node variable can move npm's registry, config
    /// files or loaded code. Literal contexts leave this false.
    pub npm_config_inert: bool,
    /// The shell expands `~` to `home_dir`: its HOME names the same
    /// directory. Literal contexts leave this false.
    pub shell_home_matches: bool,
    /// No inherited `RIPGREP_CONFIG_PATH` can prepend options such as
    /// `--pre`, `--hidden` or extra search paths to an `rg` command that
    /// omits `--no-config`. Literal contexts leave this false.
    pub ripgrep_config_absent: bool,
}

mod contained_wrapper;
pub(crate) mod curl_reads;
pub(crate) mod docker_reads;
mod docker_start;
mod doctl_reads;
pub(crate) mod kubectl_reads;
pub(crate) mod port_probes;
mod workspace_contained;
#[cfg(unix)]
pub(crate) use workspace_contained::PROFILE as WORKSPACE_PROFILE;
pub(crate) use workspace_contained::{command_shape, init_arguments, Shape};
pub(crate) mod directory_targets;
pub(crate) mod workspace_git_config;
pub(crate) mod workspace_git_environment;
pub(crate) use directory_targets::safe_directory_target;
mod awk_reads;
mod base64_reads;
mod brew_reads;
mod bun_eval;
mod chain_temporary;
mod compound_reason;
mod fanout_reads;
mod find_reads;
mod for_loop_unroll;
pub(crate) mod git_branch_listing;
mod git_config;
pub(crate) mod git_config_reads;
pub(crate) mod git_grep;
pub(crate) mod git_hash_object;
pub(crate) mod git_init_target;
pub(crate) mod git_object_reads;
mod git_read_floor;
mod git_reads;
mod git_ref_listings;
mod git_rev_list;
mod git_search_text;
mod repo_create_reason;
use git_reads::safe_git_arguments;
mod git_helper_context;
mod git_local_writes;
mod git_probe;
mod git_push;
mod git_remote_config;
mod git_remote_ops;
mod git_routes;
mod git_session_probe;
mod git_worktree;
pub(crate) mod github_conversation;
mod guard_diagnostics;
mod listing_reads;
mod lookup_reads;
mod metadata_reads;
mod npm_environment;
mod npm_reads;
mod postgres_reads;
mod pytest_contained;
mod tool_bin_listing;
mod trailing_group;
mod trusted_location;
pub(crate) use git_routes::{git_dir_route_within_scope, git_route_within_workspace};
mod apply_patch_writes;
mod lockfile_install;
mod omp_hashline_writes;
mod pure_expression;
mod read_paths;
mod source_reads;
use source_reads::{plain_source_code_path, sensitive_command_input, source_file_read_segment};
mod recursive_copy;
mod restricted_tests;
mod rust_toolchain;
mod rustfmt_writes;
mod safe_links;
pub(crate) mod safe_reads;
mod safe_scalar;
mod safe_writes;
mod search;
mod search_scope;
mod search_scope_filter;
mod search_scope_glob;
mod search_scope_ignore;
mod secret_aliases;
pub(crate) mod sed_edits;
mod segment_proof;
mod shell_script;
mod stderr_merge;
mod stdin_filters;
mod symlink_writes;
mod version_probes;
#[cfg(test)]
#[path = "pretool/workspace_contained_runner_tests.rs"]
mod workspace_contained_runner_tests;
#[cfg(test)]
#[path = "pretool/workspace_contained_sibling_tests.rs"]
mod workspace_contained_sibling_tests;
#[cfg(test)]
#[path = "pretool/workspace_contained_tests.rs"]
mod workspace_contained_tests;
mod worktree_add;
mod worktree_maintenance;
mod worktree_writes;
mod wrangler_reads;

pub mod generic;
mod package_scripts_disabled;
pub use package_scripts_disabled::no_script_install_command;

pub use generic::bounded_task_metadata_output;
pub use generic::evaluate_pre_tool_envelope;
pub use generic::evaluate_pre_tool_envelope_with_context;
pub use generic::evaluate_pre_tool_envelope_with_execution_context;
pub use generic::evaluate_pre_tool_envelope_with_extensions;
pub use git_push::{install_git_push_verdict, GitPushRequest, GitPushVerdict};
pub(crate) use segment_proof::{benign_command_segments, without_stderr_merge};
pub(crate) use worktree_add::new_checkout_route;
pub(crate) use worktree_add::verified_leading_cd;

/// Whether this evaluation already proved `segment` as a safe `origin`
/// refresh or feature push.
pub(crate) fn verified_origin_operation(
    segment: &crate::CommandSegmentV1,
    context: PathContext<'_>,
) -> bool {
    git_remote_ops::verified(segment, context)
}

fn executable_basename(executable: &str) -> &str {
    executable.rsplit(['/', '\\']).next().unwrap_or(executable)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreToolDecisionV1 {
    pub decision: String,
    pub minimum_action: String,
    pub reason_code: String,
    pub reason: String,
    pub explicitly_benign: bool,
    pub command_model: CanonicalCommandV1,
}

fn pretool_decision(
    command_model: CanonicalCommandV1,
    minimum_action: &str,
    reason_code: &str,
    reason: &str,
) -> PreToolDecisionV1 {
    let explicitly_benign = minimum_action == "allow";
    PreToolDecisionV1 {
        decision: if explicitly_benign {
            "allow".to_owned()
        } else {
            "deny".to_owned()
        },
        minimum_action: minimum_action.to_owned(),
        reason_code: reason_code.to_owned(),
        reason: reason.to_owned(),
        explicitly_benign,
        command_model,
    }
}

pub(super) fn normalized_haystack(value: &str) -> String {
    value.to_ascii_lowercase().replace('\\', "/")
}

/// Floors no extension permission can settle: Guard self-protection, secret
/// exfiltration, and Git configuration that runs a program Guard cannot read.
pub(crate) fn fixed_command_floor(model: &CanonicalCommandV1) -> bool {
    model
        .segments
        .iter()
        .any(crate::command_compatibility::git_runs_configured_program)
        || crate::command_critical_floors::guard_control_block_in_launcher_text(
            &model.normalized_text,
        )
        || crate::command_critical_floors::guard_control_block_in_command(
            &crate::canonical_command::CanonicalCommand::from_v1(model),
        )
        || ps::sensitive_exfiltration(model, sensitive_command, exfiltration_command)
        || model.segments.iter().any(names_guard_outside_message)
}

/// A Git alias, hook or config value can carry a program the parser never
/// models; any argument naming Guard, other than a commit message, keeps the
/// native decision.
fn names_guard_outside_message(segment: &crate::CommandSegmentV1) -> bool {
    let mut message_value = false;
    segment.arguments.iter().any(|argument| {
        let is_message = std::mem::take(&mut message_value);
        message_value = matches!(argument.as_str(), "-m" | "--message");
        let lowered = argument.to_ascii_lowercase();
        let attached_message = lowered.starts_with("--message=")
            || (lowered.starts_with("-m") && !lowered.starts_with("--"));
        !(is_message || attached_message)
            && ["hol-guard", "plugin-guard", ".hol-guard"]
                .iter()
                .any(|needle| lowered.contains(needle))
    })
}

pub(super) fn sensitive_command(value: &str) -> bool {
    credential_keyword_text(value) || sensitive_location_text(value)
}

/// Credential words such as `password` or `api_key`, anywhere in `value`
/// except a plain source-file path.
pub(super) fn credential_keyword_text(value: &str) -> bool {
    let lowered = normalized_haystack(value);
    let keyword_needles = [
        "aws_secret_access_key",
        "private_key",
        "api key",
        "api_key",
        "api-key",
        "password",
        "secret",
    ];
    !plain_source_code_path(value)
        && keyword_needles
            .iter()
            .any(|needle| lowered.contains(needle))
}

/// Credential locations and environment reads: `.env`, `~/.ssh`,
/// `process.env` and the like.
fn sensitive_location_text(value: &str) -> bool {
    let lowered = normalized_haystack(value);
    let needles = [
        "/.ssh/",
        "~/.ssh",
        "/.aws/credentials",
        "~/.aws/credentials",
        "/.docker/config.json",
        "~/.docker/config.json",
        "/.kube/config",
        "~/.kube/config",
        "/.git-credentials",
        "~/.git-credentials",
        "/.npmrc",
        "~/.npmrc",
        "/.pypirc",
        "~/.pypirc",
        "/.netrc",
        "~/.netrc",
        ".authrc",
        ".envrc",
        "/.env",
        "~/.env",
        "id_rsa",
        "id_ed25519",
        ".env",
    ];
    needles.iter().any(|needle| lowered.contains(needle))
        || crate::environment_secret_dump::printenv_may_print_secret(&lowered)
        || lowered.contains("os.environ")
        || lowered.contains("process.env")
}

fn sensitive_path_argument(value: &str) -> bool {
    sensitive_path_argument_with_credentials(value, false)
}

fn sensitive_read_path_argument(value: &str) -> bool {
    sensitive_path_argument_with_credentials(value, true)
}

fn sensitive_path_argument_with_credentials(value: &str, include_credential_names: bool) -> bool {
    let normalized = normalized_haystack(value);
    let candidates = [
        normalized.as_str(),
        normalized.split_once('=').map_or("", |(_, tail)| tail),
        normalized.rsplit_once(':').map_or("", |(_, tail)| tail),
    ];
    candidates.iter().any(|candidate| {
        let relative = candidate.strip_prefix("./").unwrap_or(candidate);
        sensitive_path_family(Path::new(relative)).is_some()
            || (include_credential_names
                && (guard_secure_fs::credential_named_path(Path::new(relative))
                    || search::glob_can_select_sensitive_path(relative)))
            || relative == ".git/config"
            || relative.ends_with("/.git/config")
    })
}

fn destructive_command(value: &str) -> bool {
    let lowered = normalized_haystack(value);
    let rm_force = lowered.contains("rm -rf") || lowered.contains("rm -fr");
    let rm_root = [" /", " -- /", " $home", " ~", " --/"]
        .iter()
        .any(|needle| lowered.contains(needle));
    if rm_force && rm_root {
        return true;
    }
    let basename_tokens: Vec<&str> = lowered
        .split(|character: char| character.is_ascii_whitespace() || character == '=')
        .filter(|token| !token.is_empty())
        .collect();
    basename_tokens.iter().any(|token| {
        matches!(
            executable_basename(token),
            "shred" | "mkfs" | "mkfs.ext4" | "shutdown" | "reboot" | "wipefs"
        )
    }) || lowered.contains(" of=/dev/")
        || lowered.contains("of=/dev/")
}

fn exfiltration_command(value: &str) -> bool {
    let lowered = normalized_haystack(value);
    let network = ["curl", "wget", "nc ", "netcat", "scp ", "rsync "];
    let upload = [
        " -d ",
        " --data",
        " --upload-file",
        " -t ",
        "@-",
        "@~",
        "@/",
    ];
    network.iter().any(|needle| lowered.contains(needle))
        && upload.iter().any(|needle| lowered.contains(needle))
}

fn safe_gh_arguments(arguments: &[String], text: &str) -> bool {
    matches!(arguments, [auth, status, flag]
        if auth == "auth" && status == "status" && matches!(flag.as_str(), "--help" | "-h"))
        || repo_create_reason::private_create(arguments)
        || crate::command_compatibility::github_arguments_are_read_only(arguments, text)
}

fn exact_safe_command(model: &CanonicalCommandV1, allow_git_helper_context: bool) -> bool {
    exact_safe_command_with_context(
        model,
        allow_git_helper_context,
        crate::pretool::PathContext::default(),
    )
}

fn exact_safe_command_with_context(
    model: &CanonicalCommandV1,
    allow_git_helper_context: bool,
    context: PathContext<'_>,
) -> bool {
    if model.confidence != "exact"
        || model.path_overridden
        || model.segments.is_empty()
        || !model.wrapper_chain.is_empty()
    {
        return false;
    }
    if !safe_scalar::bounded_total_sleep(model)
        || !chain_temporary::absent_reads_bounded(model, context)
    {
        return false;
    }
    if segment_proof::exact_safe_cwd_compound(model, allow_git_helper_context, context)
        || safe_reads::exact_safe_sequence(model, allow_git_helper_context, context)
    {
        return true;
    }
    if let Some(rest) = segment_proof::after_read_prefix(model, context) {
        return segment_proof::exact_safe_cwd_compound(&rest, allow_git_helper_context, context);
    }
    if let Some(rest) =
        git_read_floor::after_safe_git_read_prefix(model, allow_git_helper_context, context)
    {
        return segment_proof::exact_safe_cwd_compound(&rest, allow_git_helper_context, context);
    }
    model.segments.iter().all(|segment| {
        segment_proof::exact_safe_segment_with_context(
            model,
            segment,
            allow_git_helper_context,
            context,
        )
    })
}

fn exact_destructive_tool_introspection(model: &CanonicalCommandV1) -> bool {
    if model.confidence != "exact"
        || model.path_overridden
        || model.segments.is_empty()
        || !model.wrapper_chain.is_empty()
    {
        return false;
    }
    model.segments.iter().all(|segment| {
        let Some(executable) = segment.executable.as_deref() else {
            return false;
        };
        matches!(
            executable_basename(executable),
            "shred" | "mkfs" | "mkfs.ext4" | "shutdown" | "reboot" | "wipefs"
        ) && matches!(segment.arguments.as_slice(), [argument] if matches!(argument.as_str(), "--help" | "--version"))
    })
}

pub fn evaluate_pre_tool(request: &CommandModelRequestV1) -> Result<PreToolDecisionV1, String> {
    evaluate_pre_tool_with_context(request, None, None)
}

pub(super) fn evaluate_pre_tool_with_context(
    request: &CommandModelRequestV1,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> Result<PreToolDecisionV1, String> {
    evaluate_pre_tool_with_execution_context(request, home_dir, cwd, None, None)
}

pub(super) fn evaluate_pre_tool_with_execution_context(
    request: &CommandModelRequestV1,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    deadline: Option<std::time::Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Result<PreToolDecisionV1, String> {
    let decision =
        evaluate_single_command(request, home_dir, cwd, deadline, execution_environment)?;
    if request.dialect != "posix" || decision.minimum_action != "review" {
        return Ok(decision);
    }
    // A loop over literal words is its unrolled command list. The unrolled
    // form goes through the same proofs and replaces the loop's decision: an
    // allow there admits the loop, a block is never softened, and a review
    // carries the unrolled model so later layers judge modeled commands.
    let Some(unrolled) = for_loop_unroll::unroll(&request.command) else {
        return Ok(ungrouped_decision(
            request,
            decision,
            home_dir,
            cwd,
            deadline,
            execution_environment,
        ));
    };
    let unrolled_request = CommandModelRequestV1 {
        command: unrolled,
        ..request.clone()
    };
    match evaluate_single_command(
        &unrolled_request,
        home_dir,
        cwd,
        deadline,
        execution_environment,
    ) {
        Ok(unrolled)
            if matches!(
                unrolled.minimum_action.as_str(),
                "allow" | "review" | "block"
            ) =>
        {
            Ok(unrolled)
        }
        _ => Ok(decision),
    }
}

/// A trailing subshell group is its command list. Only an allow or a block
/// for that list replaces the grouped review, so an approval still binds the
/// exact text the agent sent.
fn ungrouped_decision(
    request: &CommandModelRequestV1,
    decision: PreToolDecisionV1,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    deadline: Option<std::time::Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> PreToolDecisionV1 {
    let Some(command) = trailing_group::unwrap(&request.command) else {
        return decision;
    };
    let ungrouped = CommandModelRequestV1 {
        command,
        ..request.clone()
    };
    match evaluate_single_command(&ungrouped, home_dir, cwd, deadline, execution_environment) {
        Ok(plain) if matches!(plain.minimum_action.as_str(), "allow" | "block") => plain,
        _ => decision,
    }
}

fn evaluate_single_command(
    request: &CommandModelRequestV1,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    deadline: Option<std::time::Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Result<PreToolDecisionV1, String> {
    let model = parse_command(request)?;
    let normalized = model.normalized_text.as_str();
    let context = PathContext::for_session(home_dir, cwd, execution_environment);
    if shell_script::contains_credential_post(&model, context) {
        return Ok(pretool_decision(
            model,
            "block",
            "native_secret_exfiltration",
            "HOL Guard blocked a local script that combines credential access with outbound posting.",
        ));
    }
    if exact_safe_command_with_context(&model, false, context)
        && model.segments.iter().all(|segment| {
            segment
                .executable
                .as_deref()
                .is_some_and(|executable| matches!(executable_basename(executable), "rg" | "grep"))
        })
    {
        return Ok(pretool_decision(
            model,
            "allow",
            "native_exact_safe_command",
            "The Rust command authority proved this bounded source search explicitly benign.",
        ));
    }
    if exact_destructive_tool_introspection(&model) {
        return Ok(pretool_decision(
            model,
            "allow",
            "native_exact_introspection_command",
            "The Rust command authority proved this command only inspects tool metadata.",
        ));
    }
    let destructive_remote_sync = model.segments.iter().any(|segment| {
        segment.executable.as_deref().is_some_and(|executable| {
            matches!(executable_basename(executable), "gh" | "gh.exe")
        }) && matches!(segment.arguments.as_slice(), [repo, sync, ..] if repo == "repo" && sync == "sync")
            && segment.arguments.iter().take_while(|arg| arg.as_str() != "--")
                .any(|arg| arg == "--force")
            && !segment.arguments.iter().any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    });
    if destructive_remote_sync || ps::destructive(&model, destructive_command) {
        return Ok(pretool_decision(
            model,
            "block",
            "native_destructive_command",
            "HOL Guard blocked a destructive command before execution.",
        ));
    }
    if crate::command_critical_floors::guard_control_block_in_launcher_text(normalized)
        || crate::command_critical_floors::guard_control_block_in_command(
            &crate::canonical_command::CanonicalCommand::from_v1(&model),
        )
    {
        return Ok(pretool_decision(
            model,
            "block",
            "native_guard_self_protection",
            "HOL Guard blocked a command that would remove or weaken Guard protection. Run it yourself in a terminal.",
        ));
    }
    if ps::sensitive_exfiltration(&model, sensitive_command, exfiltration_command) {
        return Ok(pretool_decision(
            model,
            "block",
            "native_secret_exfiltration",
            "HOL Guard blocked a command that combines sensitive data access with network transfer.",
        ));
    }
    if model
        .wrapper_chain
        .iter()
        .any(|wrapper| wrapper != "timeout")
    {
        return Ok(pretool_decision(
            model,
            "require-reapproval",
            "native_privileged_wrapper_reapproval",
            "HOL Guard requires fresh approval for the privileged execution context.",
        ));
    }
    if bun_eval::exact_safe_command(&model, context, execution_environment) {
        return Ok(pretool_decision(
            model,
            "allow",
            "native_exact_safe_command",
            "The Rust command authority proved this Bun program only prints constants and no preload can run first.",
        ));
    }
    if worktree_add::exact_safe_command(&model, context, deadline, execution_environment) {
        return Ok(pretool_decision(
            model,
            "allow",
            "native_exact_safe_worktree_add",
            "The Rust command authority proved this bounded worktree creation has a fresh contained destination, a local ref, and no executable Git routes.",
        ));
    }
    if let Some((reason_code, reason)) =
        git_remote_ops::exact_safe_command(&model, context, deadline, execution_environment)
            .or_else(|| {
                let environment = execution_environment;
                git_config_reads::writes::exact_safe_command(&model, context, deadline, environment)
            })
            .or_else(|| {
                let environment = execution_environment;
                git_init_target::exact_safe_command(&model, context, deadline, environment)
            })
    {
        return Ok(pretool_decision(model, "allow", reason_code, reason));
    }
    if worktree_maintenance::exact_safe_command(&model, context, deadline, execution_environment) {
        return Ok(pretool_decision(
            model,
            "allow",
            "native_exact_safe_worktree_maintenance",
            "The Rust command authority proved this worktree maintenance targets an unlocked linked worktree of the routed checkout without force or executable Git routes.",
        ));
    }
    if git_push::exact_safe_command(&model, context, deadline, execution_environment) {
        return Ok(pretool_decision(
            model,
            "allow",
            "native_exact_safe_git_push",
            "The Rust command authority proved this push sends the checked-out branch to a credential-free GitHub HTTPS origin through trusted Git, credential helpers and hooks.",
        ));
    }
    if exact_safe_command_with_context(&model, false, context)
        && !bun_eval::node_inline_preload_configured(&model, execution_environment)
    {
        let reason_code = docker_start::proven_reason_code(&model)
            .unwrap_or_else(|| curl_reads::proven_reason_code(&model));
        return Ok(pretool_decision(
            model,
            "allow",
            reason_code,
            "The Rust command authority proved this bounded command explicitly benign.",
        ));
    }
    if git_search_text::sensitive_beyond_patterns(
        normalized,
        git_search_text::command_without_patterns(&model),
    ) || secret_aliases::names_secret_alias(&model, context)
    {
        return Ok(pretool_decision(
            model,
            "review",
            "native_sensitive_access_review",
            "HOL Guard requires review before this command can access sensitive local data.",
        ));
    }
    if model.path_overridden {
        return Ok(pretool_decision(
            model,
            "review",
            "native_path_override_review",
            "HOL Guard requires review because this command overrides executable resolution.",
        ));
    }
    if git_helper_context::git_helper_context_required(&model, context) {
        if git_helper_context::git_helpers_proven_inert(
            &model,
            context,
            deadline,
            execution_environment,
        ) {
            return Ok(pretool_decision(
                model,
                "allow",
                "native_exact_safe_command",
                "The Rust command authority verified that the effective Git configuration defines no diff, textconv, pager, or filter helper for this read.",
            ));
        }
        return Ok(pretool_decision(
            model,
            "review",
            "native_git_helper_context_review",
            "HOL Guard is checking repository Git-helper configuration before allowing this read-only command.",
        ));
    }
    let reason = repo_create_reason::private_alternative_reason(&model)
        .or_else(|| repo_create_reason::created_remote_push_reason(&model))
        .or_else(|| fanout_reads::whitespace_split_reason(&model))
        .or_else(|| compound_reason::unproven_steps_reason(&model, context))
        .or_else(|| worktree_add::outside_home_reason(&model, context));
    Ok(pretool_decision(
        model,
        "review",
        "native_command_review_required",
        reason.as_deref().unwrap_or(
            "HOL Guard requires review because this command could not be confirmed read-only. Splitting it into simpler commands can let the read-only parts run without review.",
        ),
    ))
}

#[cfg(test)]
#[path = "pretool/for_loop_tests.rs"]
mod for_loop_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_benign_probes;
#[cfg(test)]
mod tests_fanout_reads;
#[cfg(test)]
mod tests_listing_find_probes;
