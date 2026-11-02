//! `local_cli_help` — the first-level commands a CLI's `--help` output names.
//!
//! A port of `runtime/local_cli_help.parse_cli_help_text` and its helpers. The
//! probing half of that module (running the program, bounding its output,
//! recursing into nested commands) stays in Python; only the parse is here,
//! beside [`crate::local_cli_identify`], which already derives the CLI identity
//! these commands hang from.
//!
//! A CLI whose help names no subcommands still has variations: its options.
//! [`options`] reads those, from the help text or, for a script whose help
//! printed nothing usable, from the script's own source.
//!
//! Help text is whatever a third-party program printed, so the parse reads it
//! as Python does, character for character: `str.splitlines` line boundaries,
//! `str.isspace` whitespace, `str.split` fields and character-counted slices.

use std::collections::HashSet;
use std::sync::LazyLock;

use guard_contracts::{
    LocalCliHelpCommandV1, LocalCliHelpParseRequestV1, LocalCliHelpParseResultV1,
    LOCAL_CLI_HELP_PARSE_MAX_BYTES, LOCAL_CLI_HELP_PARSE_REQUEST_SCHEMA,
    LOCAL_CLI_HELP_PARSE_RESULT_SCHEMA,
};
use regex::Regex;
use serde::Serialize;
use serde_json::json;

use crate::daemon_lifecycle_text::{py_isspace, py_splitlines, py_strip};
use crate::package_authority_op::request_digest_with_limit;

#[path = "local_cli_help_options.rs"]
mod options;
pub(crate) use options::is_option_name;
use options::HelpHandler;

/// Read the commands a `--help` text names, for the resident's Python caller.
pub(crate) fn evaluate_local_cli_help_parse_request(
    request: &LocalCliHelpParseRequestV1,
) -> Result<Vec<u8>, String> {
    // A request under another schema is not this op's to answer. Binding a v1
    // result to it would tell the caller its own contract was honoured.
    if request.schema != LOCAL_CLI_HELP_PARSE_REQUEST_SCHEMA {
        return Err("native_local_cli_help_parse_schema_mismatch".to_owned());
    }
    let request_sha256 = request_digest_with_limit(request, LOCAL_CLI_HELP_PARSE_MAX_BYTES)
        .map_err(|_| "native_local_cli_help_parse_too_large".to_owned())?;
    let commands: Vec<LocalCliHelpCommandV1> = commands_and_variations(
        &request.text,
        request.parent_id.as_deref(),
        &request.invocation,
        request.script_source,
    )
    .into_iter()
    .map(|command| LocalCliHelpCommandV1 {
        command_id: command.command_id,
        name: command.name,
        usage: command.usage,
        description: command.description,
        parent_id: command.parent_id,
    })
    .collect();
    let payload = if request.script_source {
        // What the source says about running it, so the caller decides from
        // the code whether `script --help` is safe to ask for at all.
        let facts = options::script_facts(&request.text, &request.invocation);
        let mut help = facts.help;
        // A parser that answers `<command> --help` speaks only for the
        // commands it runs. One the script dispatches itself gets `--help` as
        // an argument, so only the top-level `--help` is asked for.
        if help == HelpHandler::Framework
            && options::dispatches_by_hand(&request.text, &request.invocation)
        {
            help = HelpHandler::Script;
        }
        json!({
            "commands": commands,
            "help_handler": help.as_str(),
            "mcp_server": facts.mcp_server,
            "entry_point": facts.entry_point,
            "imports": facts.imports,
        })
    } else {
        json!({ "commands": commands })
    };
    crate::encode_response(&LocalCliHelpParseResultV1 {
        schema: LOCAL_CLI_HELP_PARSE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(payload),
    })
}

/// The subcommands a help text names, or, when it names none, the options
/// that make its calls different; a script source reports both. Options are
/// read only at the top level: a nested command's help is read for its
/// subcommands alone.
fn commands_and_variations(
    text: &str,
    parent_id: Option<&str>,
    invocation: &[String],
    script_source: bool,
) -> Vec<LocalCliCommand> {
    if script_source {
        // A script's code is full of `{a,b}` brace expansions that are not
        // choice sets, so only its comment text is read as help, and without
        // the whole-text choice-set fallback. Its code names options whether
        // or not its comments name commands, so both are kept.
        let mut commands = parse_help(
            &options::comment_lines(text, invocation),
            None,
            invocation,
            false,
        );
        for row in options::variations(text, invocation, true) {
            if !commands
                .iter()
                .any(|known| known.command_id == row.command_id)
            {
                commands.push(row);
            }
        }
        return commands;
    }
    let commands = parse_cli_help_text(text, parent_id, invocation);
    if commands.is_empty() && parent_id.is_none() {
        return options::variations(text, invocation, false);
    }
    commands
}

/// One command read out of help text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct LocalCliCommand {
    pub(crate) command_id: String,
    pub(crate) name: String,
    pub(crate) usage: String,
    pub(crate) description: String,
    pub(crate) parent_id: Option<String>,
}

static COMMAND_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9_-]{0,40}$").unwrap());

/// `\s` as Python reads it for `str` patterns: White_Space and the ASCII
/// information separators, which Rust's own `\s` leaves out.
const PY_SPACE: &str = r"[\s\x{1c}-\x{1f}]";

static SECTION_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    let headings = concat!(
        "commands|available commands|core commands|additional commands",
        "|management commands|general commands|positional arguments",
    );
    Regex::new(&format!("(?i)^(?:{headings}){PY_SPACE}*:?{PY_SPACE}*$")).unwrap()
});

static ARGPARSE_SET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"\{{([A-Za-z][A-Za-z0-9_-]*(?:{PY_SPACE}*,{PY_SPACE}*[A-Za-z][A-Za-z0-9_-]*)+)\}}"
    ))
    .unwrap()
});

static YARGS_GROUP_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Z][A-Z0-9 &/-]{0,40}:?$").unwrap());

static NON_COMMAND_GROUP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"EXAMPLE|OPTION|FLAG|POSITIONAL|ARGUMENT|USAGE").unwrap());

const SKIP_NAMES: [&str; 3] = ["help", "completion", "completions"];

fn is_skipped(name: &str) -> bool {
    let lowered = name.to_lowercase();
    SKIP_NAMES.contains(&lowered.as_str())
}

/// `str.split()` with no separator: fields between runs of whitespace.
fn py_split(text: &str) -> Vec<&str> {
    text.split(py_isspace)
        .filter(|part| !part.is_empty())
        .collect()
}

/// `str.split(maxsplit=n)` with no separator. The last field keeps whatever
/// followed it, trailing whitespace included.
fn py_split_maxsplit(text: &str, maxsplit: usize) -> Vec<&str> {
    let mut parts: Vec<&str> = Vec::new();
    let mut rest = text;
    loop {
        let trimmed = rest.trim_start_matches(py_isspace);
        if trimmed.is_empty() {
            return parts;
        }
        if parts.len() == maxsplit {
            parts.push(trimmed);
            return parts;
        }
        let end = trimmed.find(py_isspace).unwrap_or(trimmed.len());
        parts.push(&trimmed[..end]);
        rest = &trimmed[end..];
    }
}

/// Extract first-level commands from typical CLI `--help` output.
///
/// `invocation` is the program and parent command path (for example
/// `["wrangler", "d1"]`). Yargs-style help repeats it at the start of every
/// indented row and groups commands under uppercase headings such as
/// `ACCOUNT`. Under those headings only invocation-prefixed rows count; prose,
/// examples, options and positionals never do.
pub(crate) fn parse_cli_help_text(
    text: &str,
    parent_id: Option<&str>,
    invocation: &[String],
) -> Vec<LocalCliCommand> {
    parse_help(text, parent_id, invocation, true)
}

/// [`parse_cli_help_text`], with the last-resort scan of the whole text for an
/// argparse choice set made optional.
fn parse_help(
    text: &str,
    parent_id: Option<&str>,
    invocation: &[String],
    choice_set_fallback: bool,
) -> Vec<LocalCliCommand> {
    let mut found: Vec<LocalCliCommand> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut in_section = false;
    let mut prefixed_only = false;
    for raw_line in py_splitlines(text) {
        let stripped = py_strip(raw_line);
        if stripped.is_empty() {
            if in_section && raw_line.is_empty() {
                in_section = false;
            }
            continue;
        }
        if SECTION_HEADER.is_match(stripped) {
            in_section = true;
            prefixed_only = false;
            for name in argparse_names(stripped) {
                append_command(&mut found, &mut seen, &name, "", parent_id);
            }
            continue;
        }
        if !invocation.is_empty() && raw_line == stripped && YARGS_GROUP_HEADER.is_match(stripped) {
            in_section = !NON_COMMAND_GROUP.is_match(stripped);
            prefixed_only = true;
            continue;
        }
        if !in_section {
            continue;
        }
        let leading_space = raw_line.chars().next().is_some_and(py_isspace);
        let prefixed = if leading_space {
            strip_invocation(stripped, invocation)
        } else {
            None
        };
        if let Some(prefixed) = prefixed {
            if let Some((name, description)) = row_command(prefixed) {
                append_command(&mut found, &mut seen, &name, &description, parent_id);
            }
            continue;
        }
        if prefixed_only {
            continue;
        }
        for name in argparse_names(stripped) {
            append_command(&mut found, &mut seen, &name, "", parent_id);
        }
        let Some((name, description)) = row_command(stripped) else {
            if stripped.ends_with(':') && !stripped.starts_with('-') {
                in_section = false;
            }
            continue;
        };
        append_command(&mut found, &mut seen, &name, &description, parent_id);
    }
    if found.is_empty() && choice_set_fallback {
        for name in argparse_names(text) {
            append_command(&mut found, &mut seen, &name, "", parent_id);
        }
    }
    found
}

/// Drop the leading program-and-parent words a yargs row repeats, and return
/// the rest of the row. `None` when the row does not start with them.
fn strip_invocation<'a>(line: &'a str, invocation: &[String]) -> Option<&'a str> {
    let words: Vec<String> = invocation
        .iter()
        .filter(|word| !word.is_empty())
        .map(|word| word.to_lowercase())
        .collect();
    if words.is_empty() {
        return None;
    }
    let parts = py_split_maxsplit(line, words.len());
    if parts.len() <= words.len() {
        return None;
    }
    if parts[..words.len()]
        .iter()
        .zip(&words)
        .any(|(part, word)| part.to_lowercase() != *word)
    {
        return None;
    }
    Some(parts[words.len()])
}

/// A `name  description` row, when the first field can name a command.
fn row_command(line: &str) -> Option<(String, String)> {
    if line.starts_with('-') {
        return None;
    }
    let parts = py_split(line);
    let name = *parts.first()?;
    if !COMMAND_NAME.is_match(name) || is_skipped(name) {
        return None;
    }
    let rest: String = line.chars().skip(name.chars().count()).collect();
    let description: String = py_strip(&rest).chars().take(200).collect();
    Some((name.to_owned(), description))
}

/// The command names inside an argparse choice set such as `{add,remove}`.
fn argparse_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    for captures in ARGPARSE_SET.captures_iter(text) {
        for raw in captures[1].split(',') {
            let name = py_strip(raw);
            if COMMAND_NAME.is_match(name) && !is_skipped(name) {
                names.push(name.to_owned());
            }
        }
    }
    names
}

fn append_command(
    found: &mut Vec<LocalCliCommand>,
    seen: &mut HashSet<String>,
    name: &str,
    description: &str,
    parent_id: Option<&str>,
) {
    let command_id = match parent_id {
        None => name.to_owned(),
        Some(parent) => format!("{parent}.{name}"),
    };
    if seen.contains(&command_id) || is_skipped(name) {
        return;
    }
    if parent_id.is_none() && !COMMAND_NAME.is_match(name) {
        return;
    }
    seen.insert(command_id.clone());
    found.push(LocalCliCommand {
        command_id,
        name: name.to_owned(),
        usage: name.to_owned(),
        description: description.to_owned(),
        parent_id: parent_id.map(str::to_owned),
    });
}

#[cfg(test)]
#[path = "local_cli_help_tests.rs"]
mod tests;
