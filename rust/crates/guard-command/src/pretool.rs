use crate::{parse_command, CanonicalCommandV1, CommandModelRequestV1};
use guard_secure_fs::sensitive_path_family;
use serde::{Deserialize, Serialize};
use std::path::Path;

mod search;

use search::safe_search_arguments;

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

fn normalized_haystack(value: &str) -> String {
    value.to_ascii_lowercase().replace('\\', "/")
}

fn sensitive_command(value: &str) -> bool {
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

fn safe_git_arguments(arguments: &[String]) -> bool {
    let Some(subcommand) = arguments.first().map(String::as_str) else {
        return false;
    };
    if !matches!(
        subcommand,
        "status" | "diff" | "log" | "show" | "rev-parse" | "ls-files"
    ) {
        return false;
    }
    !has_argument(
        &arguments[1..],
        &["--ext-diff", "--textconv", "--output", "-o"],
        &["--output=", "--exec-path="],
    )
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

fn exact_safe_command(model: &CanonicalCommandV1) -> bool {
    if model.confidence != "exact" || model.path_overridden || model.segments.is_empty() {
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
            "git" => safe_git_arguments(&segment.arguments),
            "rg" | "grep" => safe_search_arguments(basename, &segment.arguments),
            _ => false,
        }
    })
}

pub fn evaluate_pre_tool(request: &CommandModelRequestV1) -> Result<PreToolDecisionV1, String> {
    let model = parse_command(request)?;
    let normalized = model.normalized_text.as_str();
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
    if exact_safe_command(&model) {
        return Ok(pretool_decision(
            model,
            "allow",
            "native_exact_safe_command",
            "The Rust command authority proved this bounded command explicitly benign.",
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
mod tests {
    use super::*;

    fn request(command: &str) -> CommandModelRequestV1 {
        CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        }
    }

    #[test]
    fn blocks_destructive_and_device_commands() {
        for command in [
            "rm -rf /",
            "rm -rf -- /",
            "shred ~/.ssh/id_ed25519",
            "dd if=/dev/zero of=/dev/sda",
            "mkfs.ext4 /dev/sda1",
            "shutdown -h now",
            "reboot",
            "wipefs -a /dev/sda",
        ] {
            let decision = evaluate_pre_tool(&request(command)).unwrap();
            assert_eq!(decision.decision, "deny", "{command}");
            assert_eq!(decision.minimum_action, "block", "{command}");
        }
    }

    #[test]
    fn reviews_home_relative_secret_paths() {
        let decision = evaluate_pre_tool(&request("cat ~/.npmrc")).unwrap();
        assert_eq!(decision.decision, "deny");
        assert_eq!(decision.minimum_action, "review");
        assert_eq!(decision.reason_code, "native_sensitive_access_review");
    }

    #[test]
    fn allows_bounded_exact_commands() {
        for command in [
            "pwd",
            "whoami",
            "uname -a",
            "git status --short",
            "git rev-parse --show-toplevel",
            "git diff --check",
            "rg -n authority src",
            "rg -g*.ts authority src",
            "rg --glob '*.{ts,tsx}' authority src",
            "rg -e '.env.local' src",
            "grep -n authority README.md",
            "grep -eerror README.md",
            "grep -e 'terraform.tfvars' README.md",
            "grep -d skip authority README.md",
            "stat README.md",
        ] {
            let decision = evaluate_pre_tool(&request(command)).unwrap();
            assert_eq!(decision.decision, "allow", "{command}");
            assert!(decision.explicitly_benign, "{command}");
        }
    }

    #[test]
    fn reviews_only_materially_risky_variants_of_safe_commands() {
        for command in [
            "rg --pre /opt/guard-test/payload authority src",
            "rg --hostname-bin=/opt/guard-test/payload --hyperlink-format='file://{host}{path}' TOKEN src",
            "rg --hidden authority .",
            "rg -uuu authority .",
            "rg -L authority .",
            "rg --no-ignore-files authority .",
            "rg --glob '*.env' TOKEN .",
            "rg --glob '*.{env,ts}' TOKEN .",
            "rg --glob 'nested/*.env' TOKEN .",
            "rg --glob 'nested/[.]env' TOKEN .",
            r"rg --glob 'nested/[\.]env' TOKEN .",
            "rg --glob 'nested/{safe,.env}' TOKEN .",
            "rg TOKEN .env.local",
            "rg --glob 'nested/[.]env.local' TOKEN .",
            "rg --glob 'nested/[.]env.production' TOKEN .",
            "rg --glob 'nested/[.]e[n]v.production' TOKEN .",
            "rg --glob 'nested/[.]e*v.production' TOKEN .",
            "rg --glob 'my-private-[k]ey-prod.pem' TOKEN .",
            "rg --glob 'my-private-[ak]ey-prod.pem' TOKEN .",
            "rg --glob 'my-pr[i]vate-[k]ey-prod.pem' TOKEN .",
            "rg --type-add 'secret:.env' -tsecret TOKEN .",
            "rg TOKEN .aws/config",
            "rg TOKEN terraform.tfvars",
            "rg TOKEN wallet.key",
            "rg TOKEN .gnupg/private-keys-v1.d/key",
            "rg authority .env",
            "grep authority .npmrc",
            "grep TOKEN .*",
            "grep TOKEN '.[a-z]*'",
            "grep TOKEN nested/.*",
            "grep -R authority .",
            "grep -d recurse TOKEN .",
            "grep --directories=recurse TOKEN .",
            "/opt/guard-test/rg authority src",
            "FOO=bar git status --short",
            "GIT_EXTERNAL_DIFF=/opt/guard-test/payload git diff --ext-diff README.md",
            "git diff --output=/opt/guard-test/diff README.md",
            "git log -1 --output=/opt/guard-test/log",
            "git show HEAD:.env",
            "git show HEAD:.git/config",
        ] {
            let decision = evaluate_pre_tool(&request(command)).unwrap();
            assert_eq!(decision.decision, "deny", "{command}");
            assert_eq!(decision.minimum_action, "review", "{command}");
            assert!(!decision.explicitly_benign, "{command}");
        }
    }

    #[test]
    fn denies_uncertain_or_networked_commands() {
        for command in [
            "echo $(whoami)",
            "pwd && rm -rf /",
            "python -c 'print(1)'",
            "git push origin main",
            "PATH=/tmp:$PATH ls",
        ] {
            let decision = evaluate_pre_tool(&request(command)).unwrap();
            assert_eq!(decision.decision, "deny", "{command}");
            assert_ne!(decision.minimum_action, "allow", "{command}");
        }
    }
}
