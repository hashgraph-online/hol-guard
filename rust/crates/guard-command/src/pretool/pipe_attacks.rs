//! Pipelines that are attacks whatever the extension controls say: downloaded
//! content piped into a shell or interpreter (`curl … | sh`), and the process
//! environment piped to a network sender (`env | curl -d @- …`).
//!
//! These read the raw pipeline, because the shell or `env` at either end
//! leaves the command model uncertain, and an uncertain model only ever
//! reached a generic "could not match" stop. Each check only adds a block
//! with a reason that names the attack; a pipeline it cannot split keeps its
//! existing decision.

use crate::parser_segments::{shell_tokens, split_pipelines_including_background};
use crate::{assignment_name, executable_basename, CanonicalCommandV1};

#[path = "pipe_stdin_programs.rs"]
mod stdin_programs;
use stdin_programs::runs_stdin_program;

pub(super) const REMOTE_CODE: (&str, &str) = (
    "native_remote_code_execution",
    "HOL Guard blocked a command that pipes downloaded content into a shell or interpreter, which runs remote code without review. Download it to a file, inspect it, and ask the user before running it.",
);
pub(super) const ENVIRONMENT_EXFILTRATION: (&str, &str) = (
    "native_secret_exfiltration",
    "HOL Guard blocked a command that sends environment variables, which often hold secrets, over the network. Send only the specific non-secret values the request needs.",
);

const MAX_STEPS: usize = 64;

/// The attack `model` pipes, as `(reason_code, reason)`.
pub(super) fn pipe_attack(model: &CanonicalCommandV1) -> Option<(&'static str, &'static str)> {
    if model.dialect != "posix" || model.transport != "shell_string" {
        return None;
    }
    let raw = model.normalized_text.as_str();
    let preserve_backslash = cfg!(windows);
    let segments = split_pipelines_including_background(raw, preserve_backslash).ok()?;
    if segments.len() > MAX_STEPS {
        return None;
    }
    let chars: Vec<char> = raw.chars().collect();
    let mut steps = Vec::with_capacity(segments.len());
    for segment in segments {
        let text: String = chars[segment.start..segment.end].iter().collect();
        let tokens = shell_tokens(&text, preserve_backslash).ok()?;
        steps.push((segment.group_index, segment.pipeline_index, tokens));
    }
    for (index, (group, position, earlier)) in steps.iter().enumerate() {
        let earlier = program_words(earlier);
        for (_, _, later) in steps[index + 1..]
            .iter()
            .filter(|(other_group, other_position, _)| {
                other_group == group && other_position > position
            })
        {
            let later = program_words(later);
            if fetches(earlier) && runs_stdin_program(later) {
                return Some(REMOTE_CODE);
            }
            if dumps_environment(earlier) && sends_stdin(later) {
                return Some(ENVIRONMENT_EXFILTRATION);
            }
        }
    }
    None
}

/// The program and its arguments after assignments and launch wrappers.
fn program_words(tokens: &[String]) -> &[String] {
    let mut index = 0;
    while tokens
        .get(index)
        .is_some_and(|token| assignment_name(token).is_some())
    {
        index += 1;
    }
    while let Some(wrapper) = tokens.get(index).map(|token| executable_basename(token)) {
        let value_options: &[&str] = match wrapper {
            "sudo" | "doas" => &["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"],
            "env" => &["-u", "--unset", "-C", "--chdir"],
            "nice" => &["-n", "--adjustment"],
            "timeout" => &["-s", "--signal", "-k", "--kill-after"],
            "command" | "nohup" | "setsid" | "stdbuf" | "time" => &[],
            _ => break,
        };
        let start = index;
        index += 1;
        while let Some(token) = tokens.get(index) {
            if token == "--" {
                index += 1;
                break;
            }
            if value_options.contains(&token.as_str()) {
                index += 2;
            } else if token.starts_with('-')
                || (wrapper == "env" && assignment_name(token).is_some())
            {
                index += 1;
            } else {
                break;
            }
        }
        if wrapper == "timeout" && index < tokens.len() {
            index += 1;
        }
        if wrapper == "env" && index >= tokens.len() {
            // `env` with nothing to run prints the environment.
            return &tokens[start..];
        }
    }
    tokens.get(index..).unwrap_or_default()
}

fn program(words: &[String]) -> Option<&str> {
    words.first().map(|word| {
        let name = executable_basename(word);
        name.strip_suffix(".exe").unwrap_or(name)
    })
}

/// A download client. Its output flags are not trusted to keep the body off
/// the pipe: `-o` can name a link to standard output, and `-w`, `-D -` and
/// config files print to it as well.
fn fetches(words: &[String]) -> bool {
    matches!(
        program(words),
        Some("curl" | "wget" | "fetch" | "http" | "https" | "xh" | "xhs" | "curlie")
    )
}

/// A step that writes environment variables to its output.
fn dumps_environment(words: &[String]) -> bool {
    let arguments = words.get(1..).unwrap_or_default();
    match program(words) {
        Some("env") => env_prints_inherited_environment(arguments),
        // Named variables print only those values.
        Some("printenv") => arguments
            .iter()
            .all(|argument| matches!(argument.as_str(), "-0" | "--null")),
        Some("export") => arguments.iter().all(|argument| argument == "-p"),
        Some("declare" | "typeset") => arguments.iter().all(|argument| {
            argument.starts_with('-') && (argument.contains('x') || argument.contains('p'))
        }),
        Some("set") => arguments.is_empty(),
        _ => words.iter().any(|word| word.ends_with("/environ")),
    }
}

/// `env` with nothing to run prints the environment it inherited, adjusted
/// by any unsets and assignments, unless it starts from an empty one.
fn env_prints_inherited_environment(arguments: &[String]) -> bool {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        match argument.as_str() {
            "-i" | "-" | "--ignore-environment" => return false,
            "-u" | "--unset" => index += 1,
            "-0" | "--null" => {}
            other if other.starts_with("--unset=") => {}
            other if assignment_name(other).is_some() => {}
            _ => return false,
        }
        index += 1;
    }
    true
}

/// A network client that sends what it reads on standard input.
fn sends_stdin(words: &[String]) -> bool {
    let arguments = words.get(1..).unwrap_or_default();
    match program(words) {
        Some("curl") => arguments.iter().enumerate().any(|(index, argument)| {
            argument.contains("@-")
                || argument.contains("@/dev/stdin")
                || argument == "-T-"
                || argument == "--upload-file=-"
                || (matches!(argument.as_str(), "-T" | "--upload-file")
                    && arguments
                        .get(index + 1)
                        .is_some_and(|next| matches!(next.as_str(), "-" | "/dev/stdin")))
        }),
        Some("wget") => arguments
            .iter()
            .any(|argument| argument.contains("/dev/stdin")),
        Some(
            "nc" | "ncat" | "netcat" | "socat" | "telnet" | "ssh" | "http" | "https" | "xh" | "xhs"
            | "curlie",
        ) => true,
        // Other `openssl` commands hash or encode locally.
        Some("openssl") => arguments
            .first()
            .is_some_and(|command| command == "s_client"),
        _ => false,
    }
}

#[cfg(test)]
#[path = "pipe_attacks_tests.rs"]
mod tests;
