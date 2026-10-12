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
    /// The shell expands `~` to `home_dir`: its HOME names the same
    /// directory. Literal contexts leave this false.
    pub shell_home_matches: bool,
}

mod contained_wrapper;
pub(crate) mod directory_targets;
pub(crate) use directory_targets::safe_directory_target;
mod base64_reads;
mod bun_eval;
mod find_reads;
pub(crate) mod git_branch_listing;
mod git_config;
pub(crate) mod git_config_reads;
pub(crate) mod git_hash_object;
mod git_read_floor;
mod git_reads;
use git_reads::safe_git_arguments;
mod git_helper_context;
mod git_probe;
mod git_push;
mod git_routes;
mod git_worktree;
mod guard_diagnostics;
mod listing_reads;
mod lookup_reads;
mod metadata_reads;
mod pytest_contained;
mod trusted_location;
pub(crate) use git_routes::git_route_within_workspace;
mod apply_patch_writes;
mod pure_expression;
mod read_paths;
mod source_reads;
use source_reads::{plain_source_code_path, sensitive_command_input, source_file_read_segment};
mod recursive_copy;
mod restricted_tests;
mod rust_toolchain;
mod safe_links;
mod safe_reads;
mod safe_scalar;
mod safe_writes;
mod search;
mod search_scope;
mod search_scope_filter;
mod search_scope_glob;
mod search_scope_ignore;
mod segment_proof;
mod shell_script;
mod stdin_filters;
mod version_probes;
mod worktree_add;
mod worktree_writes;
mod wrangler_reads;

pub mod generic;

pub use generic::bounded_task_metadata_output;
pub use generic::evaluate_pre_tool_envelope;
pub use generic::evaluate_pre_tool_envelope_with_context;
pub use generic::evaluate_pre_tool_envelope_with_execution_context;
pub use generic::evaluate_pre_tool_envelope_with_extensions;
pub use git_push::{install_git_push_verdict, GitPushRequest, GitPushVerdict};
pub(crate) use segment_proof::benign_command_segments;

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

pub(super) fn sensitive_command(value: &str) -> bool {
    let lowered = normalized_haystack(value);
    let keywords_apply = !plain_source_code_path(value);
    let keyword_needles = [
        "aws_secret_access_key",
        "private_key",
        "api key",
        "api_key",
        "api-key",
        "password",
        "secret",
    ];
    if keywords_apply
        && keyword_needles
            .iter()
            .any(|needle| lowered.contains(needle))
    {
        return true;
    }
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
        || lowered.contains("printenv")
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
    if !safe_scalar::bounded_total_sleep(model) {
        return false;
    }
    if segment_proof::exact_safe_cwd_compound(model, allow_git_helper_context, context) {
        return true;
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
        return Ok(pretool_decision(
            model,
            "allow",
            "native_exact_safe_command",
            "The Rust command authority proved this bounded command explicitly benign.",
        ));
    }
    if sensitive_command(normalized) {
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
    Ok(pretool_decision(
        model,
        "review",
        "native_command_review_required",
        "HOL Guard requires review because the Rust authority could not prove this command explicitly benign.",
    ))
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_benign_probes;
#[cfg(test)]
mod tests_listing_find_probes;
