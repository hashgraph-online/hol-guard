use crate::{parse_command, CanonicalCommandV1, CommandModelRequestV1};
use guard_secure_fs::sensitive_path_family;
use serde::{Deserialize, Serialize};
use std::path::Path;

mod safe_reads;
mod search;

use search::safe_search_arguments;

pub mod generic;

pub use generic::evaluate_pre_tool_envelope;
pub use generic::evaluate_pre_tool_envelope_with_extensions;

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
        "/.env",
        "~/.env",
        "id_rsa",
        "id_ed25519",
        "aws_secret_access_key",
        "private_key",
        ".env",
        "api key",
        "api_key",
        "api-key",
        "password",
        "secret",
    ];
    needles.iter().any(|needle| lowered.contains(needle))
        || lowered.contains("printenv")
        || lowered.contains("os.environ")
        || lowered.contains("process.env")
}

fn sensitive_path_argument(value: &str) -> bool {
    let normalized = normalized_haystack(value);
    let candidates = [
        normalized.as_str(),
        normalized.split_once('=').map_or("", |(_, tail)| tail),
        normalized.rsplit_once(':').map_or("", |(_, tail)| tail),
    ];
    candidates.iter().any(|candidate| {
        let relative = candidate.trim_start_matches("./");
        sensitive_path_family(Path::new(relative)).is_some()
            || relative == ".git/config"
            || relative.ends_with("/.git/config")
    })
}

fn has_argument(arguments: &[String], exact: &[&str], prefixes: &[&str]) -> bool {
    arguments.iter().any(|argument| {
        exact.contains(&argument.as_str())
            || prefixes.iter().any(|prefix| argument.starts_with(prefix))
    })
}

fn safe_git_arguments(arguments: &[String], allow_helper_context: bool) -> bool {
    let Some(subcommand) = arguments.first().map(String::as_str) else {
        return false;
    };
    if !matches!(
        subcommand,
        "status" | "diff" | "log" | "show" | "rev-parse" | "ls-files"
    ) {
        return false;
    }
    let option_end = arguments
        .iter()
        .position(|argument| argument == "--")
        .unwrap_or(arguments.len());
    let active_options = &arguments[1..option_end];
    if !allow_helper_context
        && matches!(subcommand, "diff" | "log" | "show")
        && !(active_options
            .iter()
            .any(|argument| argument == "--no-ext-diff")
            && active_options
                .iter()
                .any(|argument| argument == "--no-textconv"))
    {
        return false;
    }
    !has_argument(
        active_options,
        &["--ext-diff", "--textconv", "--output", "-o"],
        &["--output=", "--exec-path="],
    )
}

fn git_helper_context_required(model: &CanonicalCommandV1) -> bool {
    exact_safe_command(model, true)
        && model.segments.iter().any(|segment| {
            segment.executable.as_deref().is_some_and(|executable| {
                executable_basename(executable) == "git"
                    && segment.arguments.first().is_some_and(|subcommand| {
                        let option_end = segment
                            .arguments
                            .iter()
                            .position(|argument| argument == "--")
                            .unwrap_or(segment.arguments.len());
                        let active_options = &segment.arguments[1..option_end];
                        matches!(subcommand.as_str(), "diff" | "log" | "show")
                            && !(active_options
                                .iter()
                                .any(|argument| argument == "--no-ext-diff")
                                && active_options
                                    .iter()
                                    .any(|argument| argument == "--no-textconv"))
                    })
            })
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

fn exact_safe_command(model: &CanonicalCommandV1, allow_git_helper_context: bool) -> bool {
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
        let basename = executable_basename(executable);
        if sensitive_command(&segment.text)
            || (!matches!(basename, "rg" | "grep")
                && segment
                    .arguments
                    .iter()
                    .any(|argument| sensitive_path_argument(argument)))
            || !segment.environment_names.is_empty()
            || executable.contains(['/', '\\'])
        {
            return false;
        }
        match basename {
            "pwd" | "true" | "echo" | "printf" | "which" | "whoami" | "uname" | "stat" => true,
            "date" => safe_reads::safe_date_arguments(&segment.arguments),
            "ls" => safe_reads::safe_listing_arguments(&segment.arguments),
            "cat" => safe_reads::safe_plain_file_arguments(&segment.arguments),
            "head" | "tail" => safe_reads::safe_head_tail_arguments(&segment.arguments),
            "git" => safe_git_arguments(&segment.arguments, allow_git_helper_context),
            "rg" | "grep" => safe_search_arguments(basename, &segment.arguments),
            _ => false,
        }
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
    let model = parse_command(request)?;
    let normalized = model.normalized_text.as_str();
    if exact_destructive_tool_introspection(&model) {
        return Ok(pretool_decision(
            model,
            "allow",
            "native_exact_introspection_command",
            "The Rust command authority proved this command only inspects tool metadata.",
        ));
    }
    if destructive_command(normalized) {
        return Ok(pretool_decision(
            model,
            "block",
            "native_destructive_command",
            "HOL Guard blocked a destructive command before execution.",
        ));
    }
    if sensitive_command(normalized) && exfiltration_command(normalized) {
        return Ok(pretool_decision(
            model,
            "block",
            "native_secret_exfiltration",
            "HOL Guard blocked a command that combines sensitive data access with network transfer.",
        ));
    }
    if !model.wrapper_chain.is_empty() {
        return Ok(pretool_decision(
            model,
            "require-reapproval",
            "native_privileged_wrapper_reapproval",
            "HOL Guard requires fresh approval for the privileged execution context.",
        ));
    }
    if exact_safe_command(&model, false) {
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
    if git_helper_context_required(&model) {
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
