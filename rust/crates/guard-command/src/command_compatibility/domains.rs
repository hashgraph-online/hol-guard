//! Context-dependent classifiers keep a narrow exact subset and explicit uncertainty.
use crate::is_contained_compile_check_arguments;

use super::{basename, CanonicalCommandV1, CommandSegmentV1, CompatibilityObservations};

#[path = "interpreter.rs"]
mod interpreter;
#[path = "redirects.rs"]
mod redirects;
use redirects::Redirect;

const SENSITIVE_PATHS: [&str; 9] = [
    ".aws/",
    ".ssh/",
    ".docker/",
    ".kube/",
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
];

/// A credential location named anywhere in the value, even inside prose.
fn sensitive_path(value: &str) -> bool {
    let value = value.to_ascii_lowercase().replace('\\', "/");
    SENSITIVE_PATHS.iter().any(|needle| value.contains(needle))
}

fn sensitive(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    sensitive_path(value)
        || [
            "credential",
            "secret",
            "password",
            "api_key",
            "api-key",
            "token",
            "private_key",
        ]
        .iter()
        .any(|needle| lowered.contains(needle))
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
    if matches!(arguments.get(..2), Some(prefix) if prefix == ["compose", "down"]) {
        let invalid_rmi = match &arguments[2..] {
            [option, value] if option == "--rmi" => !matches!(value.as_str(), "all" | "local"),
            [option] => option
                .strip_prefix("--rmi=")
                .is_some_and(|value| !matches!(value, "all" | "local")),
            _ => false,
        };
        if invalid_rmi {
            // Compose rejects this closed invocation before changing anything.
            // Additional options remain outside this proof (for example -v).
            return;
        }
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

/// `get`/`describe` with only well-known global and display options and a plain
/// resource list that names no Secret: this form cannot reveal Secret payloads.
fn plain_non_secret_read(arguments: &[String]) -> bool {
    const VALUE_OPTIONS: &[&str] = &[
        "--context",
        "--cluster",
        "--namespace",
        "--request-timeout",
        "-n",
        "--chunk-size",
        "--field-selector",
        "--label-columns",
        "--output",
        "--selector",
        "--sort-by",
        "-L",
        "-l",
        "-o",
    ];
    const FLAGS: &[&str] = &[
        "--all-namespaces",
        "--ignore-not-found",
        "--no-headers",
        "--show-kind",
        "--show-labels",
        "--show-managed-fields",
        "-A",
    ];
    let mut subcommand: Option<&str> = None;
    let mut resources: Vec<&str> = Vec::new();
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        index += 1;
        if let Some(name) = argument.strip_prefix("--").and(argument.split('=').next()) {
            let attached = argument.split_once('=').map(|(_, value)| value);
            if VALUE_OPTIONS.contains(&name) {
                let value = attached.or_else(|| arguments.get(index).map(String::as_str));
                if attached.is_none() {
                    index += 1;
                }
                if name == "--output" && !value.is_some_and(output_format_reads_no_file) {
                    return false;
                }
            } else if !FLAGS.contains(&name) || attached.is_some() {
                return false;
            }
        } else if argument.starts_with('-') {
            if VALUE_OPTIONS.contains(&argument.as_str()) {
                if argument == "-o"
                    && !arguments
                        .get(index)
                        .is_some_and(|value| output_format_reads_no_file(value))
                {
                    return false;
                }
                index += 1;
            } else if !FLAGS.contains(&argument.as_str()) {
                return false;
            }
        } else if subcommand.is_none() {
            subcommand = Some(argument);
        } else {
            // kubectl accepts several TYPE[/NAME] operands; every one must be checked.
            resources.push(argument);
        }
    }
    if !matches!(subcommand, Some("get" | "describe")) || resources.is_empty() {
        return false;
    }
    resources
        .iter()
        .flat_map(|resource| resource.split(','))
        .all(|part| {
            let head = part.split('/').next().unwrap_or("").to_ascii_lowercase();
            !head.is_empty()
                && head
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
                && !head.starts_with("secret")
                && !head.starts_with("sealedsecret")
        })
}

/// Output formats that render the fetched objects only. The `*-file` formats
/// (`go-template-file`, `jsonpath-file`, `custom-columns-file`, `template-file`)
/// read a local file and would print it, so they stay on review.
fn output_format_reads_no_file(value: &str) -> bool {
    matches!(value, "json" | "yaml" | "name" | "wide")
        || [
            "jsonpath=",
            "jsonpath-as-json=",
            "go-template=",
            "custom-columns=",
        ]
        .iter()
        .any(|prefix| value.starts_with(prefix))
}

fn kubernetes(
    command: &CanonicalCommandV1,
    segment: &CommandSegmentV1,
    index: usize,
    output: &mut CompatibilityObservations,
    context: crate::pretool::PathContext<'_>,
) {
    // The native proof's read-only queries name no Secret and load only a
    // trusted kubeconfig, so they cannot return Secret payloads either.
    if crate::pretool::kubectl_reads::proven_read_segment(command, segment, context) {
        return;
    }
    let arguments = &segment.arguments;
    if arguments.len() == 1
        && matches!(
            arguments[0].as_str(),
            "--help" | "version" | "api-resources"
        )
    {
        return;
    }
    if plain_non_secret_read(arguments) {
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
    context: crate::pretool::PathContext<'_>,
) {
    let executable = basename(segment);
    let arguments = &segment.arguments;
    // A proven container or image listing, or a start of an existing
    // container, grants no new host access and prints no container
    // environment, credential or Compose project data.
    if executable == "docker"
        && !crate::pretool::docker_reads::proven_segment(command, segment, context)
    {
        docker(segment, index, output);
    }
    if matches!(executable.as_str(), "kubectl" | "oc") {
        kubernetes(command, segment, index, output, context);
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
        // A proven read takes no option that sends stdin or a file, so a
        // pipe after it only filters the response. A zero-I/O loopback
        // `nc -z` probe reads no stdin and sends nothing.
        let proven_read = (executable == "curl"
            && crate::pretool::curl_reads::proven_read_segment(command, segment, context))
            || crate::pretool::port_probes::proven_probe_segment(command, segment, context);
        if (upload || pipeline) && !proven_read {
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
    if literal_printer && crate::environment_secret_dump::printer_expands_secret(&segment.text) {
        output.rule(
            "command.shell-mutations.process-environment-secret-read",
            index,
            false,
        );
    }
    if matches!(executable.as_str(), "printenv" | "env") {
        if arguments.is_empty() || arguments.iter().any(|value| sensitive(value)) {
            output.rule(
                "command.shell-mutations.process-environment-secret-read",
                index,
                false,
            );
        } else if executable == "env"
            || !(matches!(arguments.as_slice(), [only] if only == "--help" || only == "--version")
                || arguments
                    .iter()
                    .all(|name| super::environment::plain_printed_name(name)))
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
        // tokens. Only bounded literal/CLI forms remove this attribution; they
        // do not remove the independent pre-tool execution review requirement.
        if let Some(uncertain) = interpreter::environment_observation(&executable, arguments) {
            output.rule(
                "command.shell-mutations.process-environment-secret-read",
                index,
                uncertain,
            );
        }
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
    // A quoted `>` in a POSIX argument (a Markdown placeholder or arrow in a
    // comment body) writes nothing; interpreter code keeps the raw check.
    let redirect = if interpreter || command.dialect != "posix" {
        if segment.text.contains('>') {
            Redirect::Output
        } else {
            Redirect::None
        }
    } else {
        redirects::posix_redirect(&segment.text)
    };
    if write_command || redirect != Redirect::None || interpreter {
        if [".hol-guard", ".codex/", ".claude/", "hol-guard/config"]
            .iter()
            .any(|path| normalized.contains(path))
        {
            output.rule("command.shell-mutations.managed-config-write", index, true);
        }
        // An environment API such as os.environ is not a filesystem path.
        // Interpreter writes need an actual write operation as well as a
        // sensitive path; other interpreter uncertainty remains owned above.
        let interpreter_write = [
            "write(",
            "writetext(",
            "write_text(",
            "unlink(",
            "remove(",
            "rename(",
            "chmod(",
        ]
        .iter()
        .any(|operation| normalized.contains(operation));
        // A stderr merge or discard writes no file, but still shows the agent
        // what the command reads: any sensitive path operand keeps review.
        // Multi-word prose, such as a comment body, still counts when it names
        // a credential location, but words like "token" in it are just text.
        let output_write = write_command || redirect == Redirect::Output || interpreter_write;
        if (output_write && sensitive(&segment.text))
            || (redirect == Redirect::Stderr
                && segment.tokens.iter().any(|token| {
                    if token.contains(char::is_whitespace) {
                        sensitive_path(token)
                    } else {
                        sensitive(token)
                    }
                }))
        {
            output.rule("command.shell-mutations.sensitive-file-write", index, true);
        }
    }
    let introspection_only =
        matches!(arguments.as_slice(), [only] if matches!(only.as_str(), "--help" | "--version"));
    // A write probe's trailing `rm` removes only the file the same command
    // creates, which the native proof checked did not exist beforehand.
    let probe_cleanup = executable == "rm"
        && crate::pretool::safe_reads::proven_created_file_removal(command, segment, context);
    // Removing the links an agent placed at the root of a linked worktree
    // of the session's repository deletes no data, whether named from the
    // session's checkout or after a leading `cd` into that worktree.
    let link_cleanup = executable == "rm"
        && (crate::pretool::directory_targets::sibling::link_removal(segment, context)
            || crate::pretool::directory_targets::sibling::entered_link_removal(
                command, index, context,
            ));
    // A proven in-place substitution is the same bounded edit the agent's
    // edit tool makes on an ordinary workspace file.
    let proven_edit = executable == "sed"
        && crate::pretool::sed_edits::proven_in_place_segment(command, segment, context);
    if !introspection_only
        && !probe_cleanup
        && !link_cleanup
        && !proven_edit
        && (matches!(
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
            && !is_contained_compile_check_arguments(arguments)
            && crate::read_only_fanout::find_exec(arguments).is_none()
            && option(
                arguments,
                &["-delete", "-exec", "-execdir", "-ok", "-okdir"],
            ))
            || (matches!(executable.as_str(), "sed" | "perl")
                && arguments.iter().any(|value| value.starts_with("-i"))))
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
