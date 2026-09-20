//! Context-dependent classifiers keep a narrow exact subset and explicit uncertainty.
use super::{basename, CanonicalCommandV1, CommandSegmentV1, CompatibilityObservations};

fn sensitive(value: &str) -> bool {
    let value = value.to_ascii_lowercase().replace('\\', "/");
    [
        ".aws/",
        ".ssh/",
        ".docker/",
        ".kube/",
        ".env",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".git-credentials",
        "credential",
        "secret",
        "password",
        "api_key",
        "api-key",
        "token",
        "private_key",
    ]
    .iter()
    .any(|needle| value.contains(needle))
}

fn option(arguments: &[String], names: &[&str]) -> bool {
    arguments
        .iter()
        .take_while(|argument| argument.as_str() != "--")
        .any(|argument| {
            names.iter().any(|name| {
                argument == name
                    || argument
                        .strip_prefix(name)
                        .is_some_and(|tail| tail.starts_with('='))
            })
        })
}

fn docker(segment: &CommandSegmentV1, index: usize, output: &mut CompatibilityObservations) {
    let arguments = &segment.arguments;
    if arguments.len() == 1
        && matches!(
            arguments[0].as_str(),
            "--version" | "--help" | "-h" | "version" | "help"
        )
    {
        return;
    }
    // Python has additional option-value, Compose, Buildx, exported environment
    // and credential-context logic. Do not silently turn those into no-match.
    let direct_sensitive = arguments
        .first()
        .is_some_and(|value| matches!(value.as_str(), "login" | "push" | "run"))
        && !option(arguments, &["--help", "-h"]);
    output.rule(
        "command.container-runtime.docker-sensitive",
        index,
        !direct_sensitive,
    );
}

fn kubernetes(segment: &CommandSegmentV1, index: usize, output: &mut CompatibilityObservations) {
    let arguments = &segment.arguments;
    if arguments.len() == 1
        && matches!(
            arguments[0].as_str(),
            "--help" | "version" | "api-resources"
        )
    {
        return;
    }
    let direct_resource = arguments.get(1).is_some_and(|resource| {
        resource.split(',').any(|part| {
            let head = part.split('/').next().unwrap_or("");
            matches!(head, "secret" | "secrets")
        })
    });
    let direct_secret = arguments
        .first()
        .is_some_and(|subcommand| matches!(subcommand.as_str(), "get" | "describe" | "edit"))
        && direct_resource;
    let token = arguments.first().is_some_and(|value| value == "create")
        && arguments.get(1).is_some_and(|value| value == "token");
    let extract = basename(segment) == "oc"
        && arguments.first().is_some_and(|value| value == "extract")
        && direct_resource;
    if (direct_secret || token || extract) && !option(arguments, &["--help", "-h"]) {
        output.rule("command.kubernetes-secrets.secret-read", index, false);
    } else {
        // Named-context, exec/cp, --raw, JSONPath, token/volume and stdin forms
        // need the richer context classifier; even a missing subcommand is not
        // evidence of absence of this capability.
        output.rule("command.kubernetes-secrets.secret-read", index, true);
    }
}

pub(super) fn observe(
    command: &CanonicalCommandV1,
    segment: &CommandSegmentV1,
    index: usize,
    output: &mut CompatibilityObservations,
) {
    let executable = basename(segment);
    let arguments = &segment.arguments;
    if executable == "docker" {
        docker(segment, index, output);
    }
    if matches!(executable.as_str(), "kubectl" | "oc") {
        kubernetes(segment, index, output);
    }
    let normalized = segment.text.to_ascii_lowercase().replace('\\', "/");
    let literal_printer = matches!(executable.as_str(), "echo" | "printf");
    if !literal_printer && normalized.contains(".docker/config.json") {
        output.rule(
            "command.container-runtime.docker-config-access",
            index,
            true,
        );
    }
    if matches!(
        executable.as_str(),
        "curl" | "wget" | "nc" | "netcat" | "scp" | "rsync" | "sftp" | "ftp"
    ) {
        let upload = !matches!(executable.as_str(), "curl" | "wget")
            || arguments.iter().any(|value| {
                value.starts_with('@')
                    || value.starts_with("--data")
                    || value.starts_with("--upload")
                    || value.starts_with("--post")
                    || value.starts_with("-T")
                    || value.starts_with("-d")
                    || value.starts_with("--config")
                    || value == "-K"
            });
        let pipeline = command
            .segments
            .iter()
            .filter(|other| other.execution_context == segment.execution_context)
            .count()
            > 1;
        if upload || pipeline {
            output.rule("command.data-protection.file-upload", index, true);
        }
        if sensitive(&command.normalized_text) {
            output.rule(
                "command.data-protection.credential-exfiltration",
                index,
                true,
            );
        }
    }
    if matches!(executable.as_str(), "printenv" | "env") {
        if arguments.is_empty() || arguments.iter().any(|value| sensitive(value)) {
            output.rule(
                "command.shell-mutations.process-environment-secret-read",
                index,
                false,
            );
        } else if executable == "env"
            || arguments.len() != 1
            || !matches!(
                arguments[0].as_str(),
                "PATH" | "HOME" | "PWD" | "SHELL" | "LANG" | "TERM" | "--help" | "--version"
            )
        {
            output.rule(
                "command.shell-mutations.process-environment-secret-read",
                index,
                true,
            );
        }
    }
    let interpreter = executable.starts_with("python")
        || matches!(
            executable.as_str(),
            "node"
                | "nodejs"
                | "ruby"
                | "perl"
                | "php"
                | "lua"
                | "pwsh"
                | "powershell"
                | "sh"
                | "bash"
                | "zsh"
                | "fish"
        );
    if interpreter {
        // Interpreter programs can construct accesses that are absent from raw
        // tokens. No claim of complete environment/dataflow analysis is made.
        output.rule(
            "command.shell-mutations.process-environment-secret-read",
            index,
            true,
        );
    }
    let write_command = matches!(
        executable.as_str(),
        "cp" | "mv"
            | "tee"
            | "dd"
            | "install"
            | "touch"
            | "truncate"
            | "sed"
            | "awk"
            | "gawk"
            | "ln"
            | "chmod"
            | "chown"
            | "chgrp"
    );
    let redirect = segment.text.contains('>');
    if write_command || redirect || interpreter {
        if [".hol-guard", ".codex/", ".claude/", "hol-guard/config"]
            .iter()
            .any(|path| normalized.contains(path))
        {
            output.rule("command.shell-mutations.managed-config-write", index, true);
        }
        if sensitive(&segment.text) {
            output.rule("command.shell-mutations.sensitive-file-write", index, true);
        }
    }
    if matches!(
        executable.as_str(),
        "rm" | "rmdir"
            | "shred"
            | "wipefs"
            | "mkfs"
            | "mkfs.ext4"
            | "mkfs.xfs"
            | "shutdown"
            | "reboot"
            | "poweroff"
            | "halt"
            | "diskutil"
            | "dd"
            | "truncate"
    ) || (executable == "find"
        && option(
            arguments,
            &["-delete", "-exec", "-execdir", "-ok", "-okdir"],
        ))
        || (matches!(executable.as_str(), "sed" | "perl")
            && arguments.iter().any(|value| value.starts_with("-i")))
    {
        output.rule("command.shell-mutations.destructive-shell", index, true);
    }
    if executable == "gh"
        && matches!(arguments.first().map(String::as_str), Some("pr"))
        && matches!(
            arguments.get(1).map(String::as_str),
            Some("create" | "edit")
        )
        && (segment.text.contains("$(") || segment.text.contains('`'))
    {
        output.rule(
            "command.shell-mutations.github-body-substitution",
            index,
            true,
        );
    }
}
