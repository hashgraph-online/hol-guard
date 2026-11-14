//! The risk groups a shell command falls in, for Cloud Review.
//!
//! A command ask carries the groups so a workspace can route it to the people
//! who answer that kind of action (deletes, deploys, packages, ...), the same
//! way a held cloud action is routed by the rules that held it. The names are
//! the ones Cloud uses for cloud actions.
//!
//! The groups are a routing hint, not an enforcement decision: nothing here
//! allows or blocks anything. A command Guard cannot place gets no group, and
//! Cloud shows it as "other". Recognition never narrows a group to a safer one.

#[path = "command_risk_groups_cloud.rs"]
mod cloud;
#[path = "command_risk_groups_http.rs"]
mod http;
#[path = "command_risk_groups_tools.rs"]
mod tools;
#[path = "command_risk_groups_words.rs"]
mod words;

use cloud::cloud_storage_groups;
use http::http_sends;
use tools::{
    deploy_groups, gh_groups, git_groups, has, is_remote_target, package_groups, sql_groups,
    subcommand,
};
use words::{body_substitutions, tokens, Token};

/// Cloud's group names, in Cloud's display order.
const GROUPS: [&str; 6] = [
    "deletes",
    "bulk_changes",
    "sending_and_sharing",
    "secrets",
    "code_and_deploys",
    "packages_and_scripts",
];

/// Commands that run another command without changing what it does.
const WRAPPERS: [&str; 11] = [
    "sudo", "doas", "env", "nohup", "time", "nice", "ionice", "command", "exec", "xargs", "timeout",
];

/// Shell words that open or continue a compound command; the simple command
/// after them is the one that runs (`if true; then rm -rf build; fi`).
const CONTROL_WORDS: [&str; 10] = [
    "if", "then", "else", "elif", "do", "while", "until", "!", "{", "case",
];

/// Programs that run the here-document they read as commands.
const STDIN_SHELLS: [&str; 8] = ["bash", "sh", "zsh", "dash", "ksh", "fish", "ssh", "eval"];

/// How deep `bash -c`, `eval`, `ssh` and `watch` payloads are followed.
const MAX_DEPTH: usize = 4;

/// ssh options that take the next word as their value.
const SSH_VALUE_FLAGS: &str = "BbcDEeFIiJLlmOoPpQRSWw";

const SECRET_PATH_MARKERS: [&str; 13] = [
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    ".pem",
    ".p12",
    ".key",
    ".aws/credentials",
    ".netrc",
    ".npmrc",
    ".pgpass",
    "credentials.json",
    ".kube/config",
    ".docker/config.json",
];

/// The groups of `command`, in Cloud's order, or none when nothing is known.
pub(crate) fn command_risk_groups(command: &str) -> Vec<&'static str> {
    let mut found = [false; GROUPS.len()];
    collect(command, 0, &mut found);
    GROUPS
        .iter()
        .zip(found)
        .filter_map(|(name, hit)| hit.then_some(*name))
        .collect()
}

fn collect(command: &str, depth: usize, found: &mut [bool; GROUPS.len()]) {
    for segment in segments(tokens(command)) {
        if depth < MAX_DEPTH {
            for inner in &segment.substitutions {
                collect(inner, depth + 1, found);
            }
        }
        let program = program_index(&segment.words);
        if depth < MAX_DEPTH {
            collect_heredocs(&segment, program.as_ref(), depth, found);
        }
        let index = match program {
            Some(Program::At(index)) => index,
            Some(Program::Split(inner)) => {
                if depth < MAX_DEPTH {
                    collect(&inner, depth + 1, found);
                }
                continue;
            }
            None => continue,
        };
        let name = program_name(&segment.words[index]);
        let raw_args = &segment.words[index + 1..];
        for group in segment_groups(&name, raw_args, &segment.redirects) {
            if let Some(at) = GROUPS.iter().position(|known| *known == group) {
                found[at] = true;
            }
        }
        if depth < MAX_DEPTH {
            if let Some(inner) = nested_command(&name, raw_args) {
                collect(&inner, depth + 1, found);
            }
        }
    }
}

/// A here-document is the command text when a shell or `ssh` reads it. For
/// any other reader it is input, and only an unquoted body's command
/// substitutions run.
fn collect_heredocs(
    segment: &Segment,
    program: Option<&Program>,
    depth: usize,
    found: &mut [bool; GROUPS.len()],
) {
    let runs_body = match program {
        Some(Program::At(index)) => {
            STDIN_SHELLS.contains(&program_name(&segment.words[*index]).as_str())
        }
        Some(Program::Split(inner)) => inner
            .split_whitespace()
            .next()
            .is_some_and(|first| STDIN_SHELLS.contains(&program_name(first).as_str())),
        None => false,
    };
    for (body, quoted) in &segment.heredocs {
        if runs_body {
            collect(body, depth + 1, found);
        } else if !quoted {
            for inner in body_substitutions(body) {
                collect(&inner, depth + 1, found);
            }
        }
    }
}

/// One simple command per segment, with redirection targets kept apart.
fn segments(tokens: Vec<Token>) -> Vec<Segment> {
    let mut out = Vec::new();
    let mut current = Segment::default();
    let mut redirect_next = false;
    for token in tokens {
        match token {
            Token::Boundary => {
                out.push(std::mem::take(&mut current));
                redirect_next = false;
            }
            Token::Redirect => redirect_next = true,
            Token::Word(word) if redirect_next => {
                current.redirects.push(word);
                redirect_next = false;
            }
            Token::Word(word) => current.words.push(word),
            Token::Substitution(inner) => current.substitutions.push(inner),
            Token::Heredoc { body, quoted } => current.heredocs.push((body, quoted)),
        }
    }
    out.push(current);
    out.into_iter()
        .filter(|segment| {
            !segment.words.is_empty()
                || !segment.substitutions.is_empty()
                || !segment.heredocs.is_empty()
        })
        .collect()
}

#[derive(Default)]
struct Segment {
    words: Vec<String>,
    redirects: Vec<String>,
    substitutions: Vec<String>,
    /// Here-document bodies, each with whether its delimiter was quoted.
    heredocs: Vec<(String, bool)>,
}

/// Where a segment's program is: a word, or the command line `env -S` splits.
enum Program {
    At(usize),
    Split(String),
}

fn program_name(word: &str) -> String {
    word.rsplit('/').next().unwrap_or(word).to_ascii_lowercase()
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// Wrapper options that take the next word as their value.
fn wrapper_flag_takes_value(wrapper: &str, flag: &str) -> bool {
    match wrapper {
        "sudo" => matches!(
            flag,
            "-u" | "-g"
                | "-C"
                | "-h"
                | "-p"
                | "-U"
                | "-r"
                | "-t"
                | "-D"
                | "-R"
                | "-T"
                | "--user"
                | "--group"
                | "--close-from"
                | "--host"
                | "--prompt"
                | "--other-user"
                | "--role"
                | "--type"
                | "--chdir"
                | "--chroot"
                | "--command-timeout"
        ),
        "doas" => matches!(flag, "-u" | "-C"),
        "env" => matches!(flag, "-u" | "-C" | "--unset" | "--chdir"),
        "nice" => matches!(flag, "-n" | "--adjustment"),
        "ionice" => matches!(flag, "-c" | "-n" | "-p" | "--class" | "--classdata"),
        "timeout" => matches!(flag, "-s" | "-k" | "--signal" | "--kill-after"),
        "exec" => flag == "-a",
        "time" => matches!(flag, "-f" | "-o" | "--format" | "--output"),
        "xargs" => matches!(
            flag,
            "-n" | "-I"
                | "-L"
                | "-P"
                | "-d"
                | "-s"
                | "-E"
                | "-a"
                | "--max-args"
                | "--max-procs"
                | "--max-lines"
                | "--max-chars"
                | "--delimiter"
                | "--arg-file"
        ),
        _ => false,
    }
}

/// The program word, past `NAME=value` words and wrappers with their options
/// (and the duration of `timeout`). `env -S` splits its value into the
/// command it runs, so that value is returned to be read as a command.
fn program_index(words: &[String]) -> Option<Program> {
    let mut index = 0;
    loop {
        let word = words.get(index)?;
        if is_assignment(word) || CONTROL_WORDS.contains(&word.as_str()) {
            index += 1;
            continue;
        }
        let wrapper = program_name(word);
        if !WRAPPERS.contains(&wrapper.as_str()) {
            return Some(Program::At(index));
        }
        index += 1;
        while let Some(next) = words.get(index) {
            if wrapper == "command" && matches!(next.as_str(), "-v" | "-V") {
                // `command -v rm` looks a program up without running it.
                return None;
            }
            if wrapper == "env" {
                if let Some(split) = env_split_string(next, &words[index + 1..]) {
                    return Some(Program::Split(split));
                }
            }
            if next.len() > 1 && next.starts_with('-') {
                index += if wrapper_flag_takes_value(&wrapper, next) {
                    2
                } else {
                    1
                };
            } else if is_assignment(next) {
                index += 1;
            } else {
                break;
            }
        }
        if wrapper == "timeout" {
            index += 1;
        }
    }
}

/// The command `env -S STRING`, `-SSTRING` or `--split-string=STRING` runs:
/// the string, split into words, followed by the remaining words, each kept
/// as one word as `env` passes them.
fn env_split_string(flag: &str, rest: &[String]) -> Option<String> {
    let (value, rest) = match flag {
        "-S" | "--split-string" => (rest.first()?.as_str(), rest.get(1..).unwrap_or(&[])),
        _ => (
            flag.strip_prefix("--split-string=")
                .or_else(|| flag.strip_prefix("-S"))
                .filter(|value| !value.is_empty())?,
            rest,
        ),
    };
    let mut command = value.to_string();
    for word in rest {
        command.push_str(" '");
        command.push_str(&word.replace('\'', "'\\''"));
        command.push('\'');
    }
    Some(command)
}

/// The command a shell, `eval`, `ssh` or `watch` runs, as one string. `eval`,
/// `ssh` and `watch` join their words with spaces, as they do when they run.
fn nested_command(name: &str, args: &[String]) -> Option<String> {
    let joined = |words: &[String]| Some(words.join(" ")).filter(|text| !text.trim().is_empty());
    match name {
        "bash" | "sh" | "zsh" | "dash" | "ksh" | "fish" => shell_payload(args),
        "eval" => joined(args),
        "ssh" => joined(args.get(ssh_host_index(args)? + 1..)?),
        "watch" => joined(&args[subcommand(args, &["-n", "--interval"])?.0..]),
        _ => None,
    }
}

/// The string after `-c` (also in `-lc`, `-ec`, ...), or a script and its
/// arguments.
fn shell_payload(args: &[String]) -> Option<String> {
    let mut reads_string = false;
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if matches!(arg.as_str(), "-o" | "+o" | "-O" | "+O") {
            index += 2;
        } else if arg == "--" {
            index += 1;
            break;
        } else if arg.starts_with('-') || arg.starts_with('+') {
            reads_string |= !arg.starts_with("--") && arg.contains('c');
            index += 1;
        } else {
            break;
        }
    }
    let rest = args.get(index..).filter(|rest| !rest.is_empty())?;
    if reads_string {
        rest.first().cloned()
    } else {
        Some(rest.join(" "))
    }
}

fn ssh_host_index(args: &[String]) -> Option<usize> {
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        let Some(flags) = arg.strip_prefix('-') else {
            return Some(index);
        };
        // In `-p 22` or `-tp 22` the value is the next word; in `-p22` it is attached.
        let value_next = flags
            .char_indices()
            .find(|(_, flag)| SSH_VALUE_FLAGS.contains(*flag))
            .is_some_and(|(at, _)| at + 1 == flags.len());
        index += if value_next { 2 } else { 1 };
    }
    None
}

fn names_secret(word: &str) -> bool {
    let lowered = word.to_ascii_lowercase();
    let file = lowered.rsplit('/').next().unwrap_or(&lowered);
    (file == ".env" || file.starts_with(".env."))
        || SECRET_PATH_MARKERS
            .iter()
            .any(|marker| lowered.contains(marker))
}

/// The file an upload argument names: `@path` in `-d @.env`, `-F file=@.env`
/// or `-F 'file=@.env;type=text/plain'`.
fn uploaded_file(arg: &str) -> &str {
    arg.split_once('@')
        .map_or(arg, |(_, path)| path.split(';').next().unwrap_or(path))
}

fn segment_groups(name: &str, raw_args: &[String], redirects: &[String]) -> Vec<&'static str> {
    let args: Vec<String> = raw_args
        .iter()
        .map(|arg| arg.to_ascii_lowercase())
        .collect();
    let mut groups = Vec::new();
    let sub = subcommand(&args, &[]).map(|(_, verb)| verb);
    match name {
        "rm" | "rmdir" | "unlink" | "shred" | "trash" | "srm" | "dropdb" | "dropuser" => {
            groups.push("deletes")
        }
        "find"
            if has(&args, "-delete")
                || args
                    .windows(2)
                    .any(|pair| pair[0] == "-exec" && pair[1] == "rm") =>
        {
            groups.push("deletes");
        }
        "git" => groups.extend(git_groups(&args)),
        "gh" => groups.extend(gh_groups(&args)),
        "aws" | "gsutil" | "gcloud" | "az" => groups.extend(cloud_storage_groups(name, &args)),
        "docker" | "podman" => {
            let words: Vec<&str> = args
                .iter()
                .filter(|arg| !arg.starts_with('-'))
                .map(String::as_str)
                .take(2)
                .collect();
            if matches!(
                words.as_slice(),
                ["rm" | "rmi" | "prune", ..] | [_, "rm" | "rmi" | "prune" | "remove"]
            ) {
                groups.push("deletes");
            }
            if matches!(words.as_slice(), ["push", ..] | [_, "push"]) {
                groups.push("sending_and_sharing");
            }
        }
        "redis-cli"
            if args
                .iter()
                .any(|arg| arg == "flushall" || arg == "flushdb" || arg == "del") =>
        {
            groups.push("deletes")
        }
        "psql" | "mysql" | "sqlite3" | "mongosh" | "clickhouse-client" => {
            groups.extend(sql_groups(&args))
        }
        "curl" | "wget" | "http" | "https" | "xh" if http_sends(name, raw_args) => {
            groups.push("sending_and_sharing")
        }
        "scp" | "rsync" | "sftp" | "ftp" if args.iter().any(|arg| is_remote_target(arg)) => {
            groups.push("sending_and_sharing")
        }
        "mail" | "mailx" | "sendmail" | "mutt" => groups.push("sending_and_sharing"),
        "printenv" => groups.push("secrets"),
        "security"
            if sub.is_some_and(|verb| verb.starts_with("find-") && verb.ends_with("-password")) =>
        {
            groups.push("secrets")
        }
        "op" | "vault" if matches!(sub, Some("read" | "get" | "kv")) => groups.push("secrets"),
        "make" | "just"
            if args
                .iter()
                .any(|arg| arg.contains("deploy") || arg.contains("release")) =>
        {
            groups.push("code_and_deploys")
        }
        _ => {}
    }
    groups.extend(package_groups(name, &args));
    groups.extend(deploy_groups(name, &args));
    if name.starts_with("deploy") {
        groups.push("code_and_deploys");
    }
    let reads_secret = matches!(
        name,
        "cat"
            | "less"
            | "more"
            | "head"
            | "tail"
            | "bat"
            | "grep"
            | "rg"
            | "cp"
            | "base64"
            | "xxd"
            | "strings"
            | "source"
            | "."
    ) && args.iter().any(|arg| names_secret(arg));
    let sends_secret = matches!(
        name,
        "scp" | "rsync" | "curl" | "wget" | "http" | "https" | "xh"
    ) && args
        .iter()
        .any(|arg| names_secret(arg) || names_secret(uploaded_file(arg)));
    if reads_secret || sends_secret || redirects.iter().any(|target| names_secret(target)) {
        groups.push("secrets");
    }
    groups
}

#[cfg(test)]
#[path = "command_risk_groups_tests.rs"]
mod tests;
