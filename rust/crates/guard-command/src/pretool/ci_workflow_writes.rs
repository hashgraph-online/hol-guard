//! A CI workflow runs on the forge with the repository's secrets, where Guard
//! never sees its steps execute. A file-tool write that plants a step
//! uploading a credential file to a network host is therefore the last point
//! Guard can review it, so such a write is not an ordinary workspace edit.
//!
//! Only the upload shape is screened. A workflow may call `curl` or read
//! `${{ secrets.* }}` for many ordinary reasons; what it should not do is send
//! a local credential file (`.env`, `~/.ssh/...`, `.npmrc`) as a request body.
//!
//! The screen reads the commands a step runs, not raw lines: backslash
//! continuations and folded (`>`) blocks are joined, whole-line comments are
//! skipped, and a network tool counts only where a command starts. The written
//! text comes from the file tools' body fields, a Codex `apply_patch` body, or
//! an Oh My Pi hashline `input`, so every route that proves an ordinary file
//! write is screened the same way.

use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

#[path = "ci_workflow_shell.rs"]
mod shell;
use shell::{inline_scripts, pipes_credential_read, simple_commands};

const BODY_KEYS: [&str; 4] = ["content", "contents", "new_string", "newString"];
const PATCH_KEYS: [&str; 3] = ["command", "input", "_input"];
const CREDENTIAL_FILE_NEEDLES: [&str; 14] = [
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    ".aws/credentials",
    ".docker/config.json",
    ".kube/config",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".envrc",
    ".authrc",
    ".config/gh/hosts.yml",
];
const NETWORK_TOOLS: [&str; 10] = [
    "curl", "wget", "http", "https", "xh", "scp", "rsync", "nc", "ncat", "socat",
];
/// Commands that pass a file's bytes on to the next pipeline stage.
const READERS: [&str; 9] = [
    "cat", "base64", "gzip", "xxd", "head", "tail", "tar", "zip", "openssl",
];
/// Prefix words that run the command after them.
const WRAPPERS: [&str; 8] = [
    "sudo", "env", "exec", "command", "time", "nohup", "nice", "timeout",
];
const SHELLS: [&str; 5] = ["sh", "bash", "zsh", "dash", "ksh"];
/// Shell keywords that open a clause and run the command after them, as in
/// `if true; then curl ...; fi`.
const CONTROL_WORDS: [&str; 9] = [
    "if", "then", "elif", "else", "do", "while", "until", "!", "{",
];

/// The file a network tool reads its request body from: `-d @path`,
/// `-F field=@path`, `--data-binary @path`, `-T path`, `--upload-file path`,
/// `--post-file=path` or `--body-file=path`.
static UPLOAD_OPERAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"@["']?(?P<at>[^\s"';|&)]+)"#,
        r#"|(?:\s|^)(?:-T|--upload-file|--post-file|--body-file)(?:=|\s+)["']?(?P<flag>[^\s"';|&)]+)"#,
        r#"|<\s*["']?(?P<redirect>[^\s"';|&)]+)"#,
    ))
    .expect("upload operand pattern compiles")
});

/// A credential file read inside a command or process substitution:
/// `$(cat .env)` or `@<(cat .env)`.
static SUBSTITUTED_READ: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?:\$\(|<\(|`)\s*(?:cat|base64|head|tail|xxd)\s+(?:-\S+\s+)*["']?(?P<file>[^\s"'`)]+)"#,
    )
    .expect("substituted read pattern compiles")
});

/// A script run by `bash -c '...'` or `eval "..."`, read whole before the line
/// is cut at the separators inside its quotes.
static INLINE_SCRIPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?:^|[\s;&|(`])(?P<shell>(?:\S*/)?"#,
        r#"(?:(?:sh|bash|zsh|dash|ksh)\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*c[A-Za-z]*|eval))\s+"#,
        r#"(?:'(?P<sq>[^']*)'|"(?P<dq>(?:[^"\\]|\\.)*)")"#,
    ))
    .expect("inline script pattern compiles")
});

/// A YAML list marker or mapping key ahead of a step's command.
static YAML_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:-\s+)*(?:[A-Za-z_][\w.-]*:\s+)?").expect("yaml prefix pattern compiles")
});

/// True for the configuration files a hosted CI service runs on push.
pub(super) fn ci_workflow_path(path: &str) -> bool {
    let lowered = path.replace('\\', "/").to_ascii_lowercase();
    let name = lowered.rsplit('/').next().unwrap_or_default();
    let yaml = name.ends_with(".yml") || name.ends_with(".yaml");
    let in_dir = |dir: &str| lowered.starts_with(dir) || lowered.contains(&format!("/{dir}"));
    (yaml
        && (in_dir(".github/workflows/")
            || in_dir(".gitea/workflows/")
            || in_dir(".forgejo/workflows/")
            || in_dir(".circleci/")))
        || matches!(
            name,
            ".gitlab-ci.yml" | "azure-pipelines.yml" | "bitbucket-pipelines.yml" | ".drone.yml"
        )
}

/// A local credential file: an SSH key, a cloud or registry credential file, or
/// a dotenv file. `.env.example` and its siblings are templates, not secrets.
fn credential_file_operand(operand: &str) -> bool {
    let lowered = operand.replace('\\', "/").to_ascii_lowercase();
    let name = lowered.rsplit('/').next().unwrap_or_default();
    let dotenv = name == ".env"
        || name.strip_prefix(".env.").is_some_and(|suffix| {
            !matches!(
                suffix,
                "example" | "sample" | "template" | "dist" | "defaults"
            )
        });
    dotenv
        || CREDENTIAL_FILE_NEEDLES
            .iter()
            .any(|needle| lowered.contains(needle))
}

/// `|`, `|-`, `|+` or `|2`: a YAML literal block opens on the next line.
fn literal_block_indicator(value: &str) -> bool {
    value
        .strip_prefix('|')
        .is_some_and(|rest| rest.chars().all(|c| matches!(c, '-' | '+' | '0'..='9')))
}

/// `cat .env |` or `npm test &&`: the shell reads the next line as the rest of
/// this command.
fn ends_with_operator(text: &str) -> bool {
    text.ends_with('|') || text.ends_with("&&")
}

/// The commands a workflow body runs, one per entry: backslash continuations
/// and folded block scalars are joined, and whole-line comments are dropped.
fn logical_lines(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut continuing = false;
    let mut folded: Option<usize> = None;
    for raw in body.lines() {
        let line = raw.trim_end_matches('\r');
        let indent = line.len() - line.trim_start().len();
        let text = line.trim();
        if let Some(key_indent) = folded {
            if text.is_empty() || (indent > key_indent && text.starts_with('#')) {
                continue;
            }
            if indent > key_indent {
                current.push(' ');
                current.push_str(text.trim_end_matches('\\'));
                continue;
            }
            folded = None;
            out.push(std::mem::take(&mut current));
        }
        if continuing {
            current.push(' ');
            current.push_str(text.trim_end_matches('\\'));
            continuing = text.ends_with('\\') || ends_with_operator(text);
            if !continuing {
                out.push(std::mem::take(&mut current));
            }
            continue;
        }
        if text.starts_with('#') {
            continue;
        }
        let value = YAML_PREFIX.replace(text, "");
        if matches!(value.as_ref(), ">" | ">-" | ">+") {
            folded = Some(indent);
            continue;
        }
        if literal_block_indicator(&value) {
            continue;
        }
        if let Some(head) = text.strip_suffix('\\') {
            current = head.to_owned();
            continuing = true;
        } else if ends_with_operator(text) {
            current = text.to_owned();
            continuing = true;
        } else {
            out.push(text.to_owned());
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// The command a segment runs, after env assignments and wrapper words, with
/// the words that follow it.
fn command_words(segment: &str) -> Vec<String> {
    let words: Vec<String> = segment
        .split_whitespace()
        .map(|word| word.trim_matches(['"', '\'']).to_owned())
        .filter(|word| !word.is_empty())
        .collect();
    let mut start = 0;
    let mut wrapper_in_use: Option<&str> = None;
    let mut option_value = false;
    while let Some(word) = words.get(start) {
        start += 1;
        if std::mem::take(&mut option_value) {
            continue;
        }
        let assignment = word.contains('=') && !word.starts_with('-');
        let control = CONTROL_WORDS.contains(&word.as_str());
        if WRAPPERS.contains(&basename(word)) {
            wrapper_in_use = Some(basename(word));
        } else if let Some(wrapper) = wrapper_in_use.filter(|_| word.starts_with('-')) {
            option_value = wrapper_option_takes_value(wrapper, word);
        } else if !(assignment || control || (wrapper_in_use.is_some() && duration(word))) {
            start -= 1;
            break;
        }
    }
    words[start..].to_vec()
}

/// `sudo -u root`, `env -u CI`, `timeout -s KILL`: the option's value is the
/// next word, not the command the wrapper runs.
fn wrapper_option_takes_value(wrapper: &str, option: &str) -> bool {
    let options: &[&str] = match wrapper {
        "sudo" => &[
            "-u",
            "-g",
            "-C",
            "-D",
            "-h",
            "-p",
            "-r",
            "-t",
            "-U",
            "-T",
            "--user",
            "--group",
            "--chdir",
            "--host",
            "--prompt",
            "--role",
            "--type",
            "--other-user",
            "--command-timeout",
            "--close-from",
        ],
        "env" => &["-u", "-C", "--unset", "--chdir"],
        "timeout" => &["-s", "-k", "--signal", "--kill-after"],
        "nice" => &["-n", "--adjustment"],
        "time" => &["-f", "-o", "--format", "--output"],
        _ => &[],
    };
    options.contains(&option)
}

/// A `nice` adjustment or a `timeout` duration such as `30`, `10s` or `1.5m`.
fn duration(word: &str) -> bool {
    let number = word.trim_end_matches(['s', 'm', 'h', 'd']);
    !number.is_empty()
        && number.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && number.bytes().any(|b| b.is_ascii_digit())
}

/// True when a network tool in this segment sends a credential file.
fn segment_uploads(segment: &str, depth: usize) -> bool {
    let words = command_words(segment);
    let Some(command) = words.first().map(|word| basename(word)) else {
        return false;
    };
    // `bash -c '...'` and `eval '...'` run their argument as a command.
    let inline = if SHELLS.contains(&command)
        && words
            .get(1)
            .is_some_and(|flag| flag.starts_with('-') && flag.ends_with('c'))
    {
        Some(words[2..].join(" "))
    } else if command == "eval" {
        Some(words[1..].join(" "))
    } else {
        None
    };
    if let Some(inner) = inline {
        return depth < 3 && command_uploads(&inner, depth + 1);
    }
    // `CMD=curl; bash -c "$CMD -d @.env ..."`: a command read from a variable
    // may be any tool, so its curl-style upload operands still count.
    let variable = command.starts_with('$');
    if !variable && !NETWORK_TOOLS.contains(&command) {
        return false;
    }
    let operands: &[&str] = if variable {
        &["at", "flag"]
    } else {
        &["at", "flag", "redirect"]
    };
    let operand = UPLOAD_OPERAND.captures_iter(segment).any(|captures| {
        operands
            .iter()
            .filter_map(|name| captures.name(name))
            .any(|operand| credential_file_operand(operand.as_str()))
    });
    // `scp`, `rsync`, `nc` and `socat` take the local file as a plain operand.
    operand
        || (!variable
            && !matches!(command, "curl" | "wget" | "http" | "https" | "xh")
            && words[1..]
                .iter()
                .filter(|word| !word.starts_with('-') && !word.contains(':'))
                .any(|word| credential_file_operand(word)))
}

/// True when a pipeline stage reads a credential file for a later stage.
fn reads_credential_file(segment: &str) -> bool {
    let words = command_words(segment);
    words
        .first()
        .is_some_and(|word| READERS.contains(&basename(word)))
        && words[1..]
            .iter()
            .filter(|word| !word.starts_with('-'))
            .any(|word| credential_file_operand(word))
}

/// True when this segment runs a network tool, or a command named by a
/// variable that sends its stdin as a body (`cat .env | "$CURL" -d @- ...`).
fn runs_network_tool(segment: &str) -> bool {
    command_words(segment).first().is_some_and(|word| {
        NETWORK_TOOLS.contains(&basename(word))
            || (word.starts_with('$')
                && (segment.contains("@-")
                    || segment.contains("-T -")
                    || segment.contains("--upload-file -")))
    })
}

/// True when this segment runs a command named by a variable and passes a
/// curl-style body or upload flag (`$CURL -d "$(cat .env)" ...`).
fn runs_variable_command(segment: &str) -> bool {
    command_words(segment).first().is_some_and(|word| {
        word.starts_with('$')
            && ["-d ", "--data", "-F ", "--form", "-T ", "--upload-file"]
                .iter()
                .any(|flag| segment.contains(flag))
    })
}

/// True when one command line sends a credential file to a network host.
fn command_uploads(line: &str, depth: usize) -> bool {
    let line = YAML_PREFIX.replace(line, "");
    let inline_uploads = depth < 3
        && inline_scripts(&line)
            .iter()
            .any(|script| command_uploads(script, depth + 1));
    if inline_uploads {
        return true;
    }
    let commands = simple_commands(&line);
    if commands
        .iter()
        .any(|command| segment_uploads(command, depth))
    {
        return true;
    }
    // `curl -d "$(cat .env)" ...`.
    pipes_credential_read(&line, 0)
        || (commands
            .iter()
            .any(|command| runs_network_tool(command) || runs_variable_command(command))
            && SUBSTITUTED_READ
                .captures_iter(&line)
                .filter_map(|captures| captures.name("file"))
                .any(|file| credential_file_operand(file.as_str())))
}

fn body_uploads_credential_file(body: &str) -> bool {
    logical_lines(body)
        .iter()
        .any(|line| command_uploads(line, 0))
}

fn written_bodies(input: &serde_json::Map<String, Value>) -> Vec<&str> {
    let mut bodies: Vec<&str> = BODY_KEYS
        .iter()
        .filter_map(|key| input.get(*key).and_then(Value::as_str))
        .collect();
    if let Some(edits) = input.get("edits").and_then(Value::as_array) {
        for edit in edits {
            bodies.extend(
                ["new_string", "newString"]
                    .iter()
                    .filter_map(|key| edit.get(*key).and_then(Value::as_str)),
            );
        }
    }
    bodies
}

/// The text a Codex `apply_patch` body or an Oh My Pi hashline edit adds to
/// each CI workflow file it names. Removed rows and context rows are left out:
/// only the rows the edit writes can plant a step.
fn patch_workflow_additions(patch: &str) -> Vec<String> {
    let mut additions: Vec<String> = Vec::new();
    let mut target: Option<usize> = None;
    let mut hashline = false;
    let mut in_put = false;
    for raw in patch.lines() {
        let line = raw.trim_end_matches('\r');
        let trimmed = line.trim();
        let header = trimmed
            .strip_prefix("*** Add File: ")
            .or_else(|| trimmed.strip_prefix("*** Update File: "))
            .or_else(|| trimmed.strip_prefix("*** Move to: "))
            .map(|path| (path, false))
            .or_else(|| {
                let body = line.strip_prefix('[')?.trim_end().strip_suffix(']')?;
                let path = body.rsplit_once('#').map_or(body, |(path, _)| path);
                Some((path, true))
            });
        if let Some((path, is_hashline)) = header {
            hashline = is_hashline;
            in_put = false;
            target = ci_workflow_path(path.trim()).then(|| {
                additions.push(String::new());
                additions.len() - 1
            });
            continue;
        }
        let Some(index) = target else {
            continue;
        };
        if hashline && (line.starts_with("PUT ") || line.starts_with("CUT ")) {
            in_put = line.starts_with("PUT ");
            continue;
        }
        let row = if let Some(added) = line.strip_prefix('+') {
            Some(added)
        } else if hashline && in_put && !line.starts_with('-') && !trimmed.starts_with("***") {
            Some(line)
        } else {
            None
        };
        if let Some(row) = row {
            additions[index].push_str(row);
            additions[index].push('\n');
        }
    }
    additions
}

/// True when a write that Guard proved ordinary adds a CI step that uploads a
/// credential file: through a file tool's body for a workflow `path`, or
/// through patch text that names a workflow file in its own headers.
pub(super) fn plants_credential_upload(paths: &[String], payload: &Value) -> bool {
    let Some(input) = payload.get("tool_input").and_then(Value::as_object) else {
        return false;
    };
    let direct = paths.iter().any(|path| ci_workflow_path(path))
        && written_bodies(input)
            .iter()
            .any(|body| body_uploads_credential_file(body));
    direct
        || PATCH_KEYS
            .iter()
            .filter_map(|key| input.get(*key).and_then(Value::as_str))
            .flat_map(patch_workflow_additions)
            .any(|added| body_uploads_credential_file(&added))
}

#[cfg(test)]
#[path = "ci_workflow_writes_tests.rs"]
mod tests;
