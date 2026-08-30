use crate::{parse_command, CanonicalCommandV1, CommandModelRequestV1};
use serde::{Deserialize, Serialize};

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
        if sensitive_command(&segment.text) || !segment.environment_names.is_empty() {
            return false;
        }
        // The v1 native request does not bind a decision to the executable that
        // the harness will resolve, nor does it carry enough filesystem context
        // to prove external command identity and argument effects. Keep the
        // automatic allow surface to argument-free POSIX shell built-ins until
        // that evidence is part of the authority contract.
        matches!(executable, "pwd" | "true") && segment.arguments.is_empty()
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
        for command in ["pwd", "true", "pwd && true"] {
            let decision = evaluate_pre_tool(&request(command)).unwrap();
            assert_eq!(decision.decision, "allow", "{command}");
            assert!(decision.explicitly_benign, "{command}");
        }
    }

    #[test]
    fn reviews_commands_without_bound_identity_and_argument_evidence() {
        for command in [
            "whoami",
            "uname -a",
            "git status --short",
            "git rev-parse --show-toplevel",
            "git diff --check",
            "rg -n authority src",
            "grep -n authority README.md",
            "stat README.md",
            "./rg authority src",
            "/tmp/evil/rg authority src",
            "rg --pre /tmp/payload authority src",
            "GIT_EXTERNAL_DIFF=/tmp/payload git diff --ext-diff README.md SECURITY.md",
            "git diff --output=/tmp/diff",
            "git log -1 --format=%B --output=$HOME/.zshrc",
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
