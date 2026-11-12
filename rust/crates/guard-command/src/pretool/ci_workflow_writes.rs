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

/// A credential file read inside a command substitution: `$(cat .env)`.
static SUBSTITUTED_READ: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?:\$\(|`)\s*(?:cat|base64|head|tail|xxd)\s+(?:-\S+\s+)*["']?(?P<file>[^\s"'`)]+)"#,
    )
    .expect("substituted read pattern compiles")
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
            continuing = text.ends_with('\\');
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
        if let Some(head) = text.strip_suffix('\\') {
            current = head.to_owned();
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
    let mut wrapped = false;
    while let Some(word) = words.get(start) {
        let assignment = word.contains('=') && !word.starts_with('-');
        let wrapper = WRAPPERS.contains(&basename(word));
        let control = CONTROL_WORDS.contains(&word.as_str());
        let wrapper_argument =
            wrapped && (word.starts_with('-') || word.bytes().all(|b| b.is_ascii_digit()));
        if !(assignment || wrapper || control || wrapper_argument) {
            break;
        }
        wrapped |= wrapper;
        start += 1;
    }
    words[start..].to_vec()
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
    if !NETWORK_TOOLS.contains(&command) {
        return false;
    }
    let operand = UPLOAD_OPERAND.captures_iter(segment).any(|captures| {
        ["at", "flag", "redirect"]
            .iter()
            .filter_map(|name| captures.name(name))
            .any(|operand| credential_file_operand(operand.as_str()))
    });
    // `scp`, `rsync`, `nc` and `socat` take the local file as a plain operand.
    operand
        || (!matches!(command, "curl" | "wget" | "http" | "https" | "xh")
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

/// True when this segment runs a network tool.
fn runs_network_tool(segment: &str) -> bool {
    command_words(segment)
        .first()
        .is_some_and(|word| NETWORK_TOOLS.contains(&basename(word)))
}

/// Every simple command in `text`, cut at each separator, pipe and group
/// delimiter. `||` separates commands and `|&` is a pipe.
fn simple_commands(text: &str) -> Vec<String> {
    text.replace("||", ";")
        .replace("|&", "|")
        .split(['\n', ';', '&', '(', ')', '`', '|'])
        .map(str::to_owned)
        .collect()
}

/// The pipelines of one command line, cut at `;`, `&&`, `||`, a lone `&` and
/// newlines. A `( … )`, `{ …; }`, `$( … )` or backtick group stays inside the
/// stage it belongs to, so `{ cat .env; } | curl …` is one pipeline, and the
/// `&` of a `2>&1` redirect is not a separator. Also returns the inner text of
/// every top-level group, whose own pipelines are checked separately.
fn top_level_pipelines(line: &str) -> (Vec<Vec<String>>, Vec<String>) {
    let chars: Vec<char> = line.chars().collect();
    let mut pipelines: Vec<Vec<String>> = Vec::new();
    let mut stages: Vec<String> = Vec::new();
    let mut stage = String::new();
    let mut groups: Vec<String> = Vec::new();
    let mut group = String::new();
    let mut closers: Vec<char> = Vec::new();
    let mut index = 0;
    while let Some(&ch) = chars.get(index) {
        let next = chars.get(index + 1).copied();
        let previous = index.checked_sub(1).map(|at| chars[at]);
        index += 1;
        if closers.last() == Some(&ch) {
            closers.pop();
            if closers.is_empty() {
                groups.push(std::mem::take(&mut group));
            } else {
                group.push(ch);
            }
            stage.push(ch);
            continue;
        }
        let opens = match ch {
            '(' => Some(')'),
            '`' => Some('`'),
            // `{ cmd; }` is a group; `${{ expr }}` and `${VAR}` are not.
            '{' if previous.is_none_or(|p| p.is_whitespace() || ";&|(".contains(p))
                && next.is_none_or(char::is_whitespace) =>
            {
                Some('}')
            }
            _ => None,
        };
        if !closers.is_empty() {
            group.push(ch);
        }
        if let Some(closer) = opens {
            closers.push(closer);
            stage.push(ch);
            continue;
        }
        if !closers.is_empty() {
            stage.push(ch);
            continue;
        }
        let ends_pipeline = match ch {
            '|' if next == Some('|') => {
                index += 1;
                true
            }
            '|' => {
                if next == Some('&') {
                    index += 1;
                }
                stages.push(std::mem::take(&mut stage));
                continue;
            }
            '&' if next == Some('&') => {
                index += 1;
                true
            }
            '&' if matches!(previous, Some('>' | '<')) || next == Some('>') => false,
            '&' | ';' | '\n' | ')' => true,
            _ => false,
        };
        if ends_pipeline {
            stages.push(std::mem::take(&mut stage));
            pipelines.push(std::mem::take(&mut stages));
        } else {
            stage.push(ch);
        }
    }
    if !closers.is_empty() {
        groups.push(group);
    }
    stages.push(stage);
    pipelines.push(stages);
    (pipelines, groups)
}

/// `cat .env | curl -d @- ...`: a credential read feeds a later network stage
/// of the same pipeline. A read that ends at `&&` or `;` sends nothing.
fn pipes_credential_read(line: &str, depth: usize) -> bool {
    if depth > 4 {
        return false;
    }
    let (pipelines, groups) = top_level_pipelines(line);
    pipelines.iter().any(|stages| {
        stages
            .iter()
            .rposition(|stage| simple_commands(stage).iter().any(|c| runs_network_tool(c)))
            .is_some_and(|network| {
                stages[..network].iter().any(|stage| {
                    simple_commands(stage)
                        .iter()
                        .any(|c| reads_credential_file(c))
                })
            })
    }) || groups
        .iter()
        .any(|inner| pipes_credential_read(inner, depth + 1))
}

/// True when one command line sends a credential file to a network host.
fn command_uploads(line: &str, depth: usize) -> bool {
    let line = YAML_PREFIX.replace(line, "");
    let commands = simple_commands(&line);
    if commands
        .iter()
        .any(|command| segment_uploads(command, depth))
    {
        return true;
    }
    // `curl -d "$(cat .env)" ...`.
    pipes_credential_read(&line, 0)
        || (commands.iter().any(|command| runs_network_tool(command))
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
