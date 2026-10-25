//! `local_cli_help` — the first-level commands a CLI's `--help` output names.
//!
//! A port of `runtime/local_cli_help.parse_cli_help_text` and its helpers. The
//! probing half of that module (running the program, bounding its output,
//! recursing into nested commands) stays in Python; only the parse is here,
//! beside [`crate::local_cli_identify`], which already derives the CLI identity
//! these commands hang from.
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
    let commands: Vec<LocalCliHelpCommandV1> = parse_cli_help_text(
        &request.text,
        request.parent_id.as_deref(),
        &request.invocation,
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
    crate::encode_response(&LocalCliHelpParseResultV1 {
        schema: LOCAL_CLI_HELP_PARSE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(json!({ "commands": commands })),
    })
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
    if found.is_empty() {
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
mod tests {
    use super::*;

    fn names(text: &str) -> Vec<String> {
        parse_cli_help_text(text, None, &[])
            .into_iter()
            .map(|command| command.name)
            .collect()
    }

    #[test]
    fn a_commands_section_names_its_rows() {
        let help = "Usage: tool [options]\n\nCommands:\n  build   Build it\n  ship    Ship it\n";
        let parsed = parse_cli_help_text(help, None, &[]);
        assert_eq!(names(help), vec!["build", "ship"]);
        assert_eq!(parsed[0].description, "Build it");
        assert_eq!(parsed[0].command_id, "build");
        assert_eq!(parsed[0].usage, "build");
        assert!(parsed[0].parent_id.is_none());
    }

    #[test]
    fn a_blank_line_closes_the_section() {
        let help = "Commands:\n  build   Build it\n\nnotacommand   prose\n";
        assert_eq!(names(help), vec!["build"]);
    }

    #[test]
    fn help_and_completion_rows_are_never_commands() {
        let help = "Commands:\n  help   Show help\n  completions  Shell completions\n  run  Run\n";
        assert_eq!(names(help), vec!["run"]);
    }

    #[test]
    fn an_argparse_choice_set_names_its_commands() {
        let help = "positional arguments:\n  {add,remove,list}\n";
        assert_eq!(names(help), vec!["add", "remove", "list"]);
    }

    #[test]
    fn a_choice_set_is_read_even_without_a_section() {
        assert_eq!(
            names("usage: tool {add,remove} ...\n"),
            vec!["add", "remove"]
        );
    }

    #[test]
    fn a_yargs_group_counts_only_invocation_prefixed_rows() {
        let help = concat!(
            "ACCOUNT\n",
            "  wrangler d1 create   Create a database\n",
            "  some prose that is not a row\n",
            "EXAMPLES\n",
            "  wrangler d1 execute  Should not count\n",
        );
        let invocation = vec!["wrangler".to_owned(), "d1".to_owned()];
        let parsed = parse_cli_help_text(help, None, &invocation);
        assert_eq!(
            parsed.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            vec!["create"]
        );
        assert_eq!(parsed[0].description, "Create a database");
    }

    #[test]
    fn a_parent_id_keys_every_command_under_it() {
        let help = "Commands:\n  create  Make one\n";
        let parsed = parse_cli_help_text(help, Some("d1"), &[]);
        assert_eq!(parsed[0].command_id, "d1.create");
        assert_eq!(parsed[0].parent_id.as_deref(), Some("d1"));
    }

    #[test]
    fn the_same_command_is_recorded_once() {
        let help = "Commands:\n  build  First\n  build  Second\n";
        let parsed = parse_cli_help_text(help, None, &[]);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].description, "First");
    }

    #[test]
    fn a_description_is_cut_at_two_hundred_characters() {
        let help = format!("Commands:\n  build  {}\n", "x".repeat(250));
        let parsed = parse_cli_help_text(&help, None, &[]);
        assert_eq!(parsed[0].description.chars().count(), 200);
    }

    #[test]
    fn an_option_row_is_not_a_command() {
        let help = "Commands:\n  --verbose  Be loud\n  build  Build it\n";
        assert_eq!(names(help), vec!["build"]);
    }

    #[test]
    fn a_one_word_header_closes_the_section() {
        let help = "Commands:\n  build  Build it\nOptions:\n  verbose  Say more\n";
        assert_eq!(names(help), vec!["build"]);
    }

    #[test]
    fn a_two_word_header_reads_as_a_row_and_keeps_the_section_open() {
        // `Other things:` splits into a name and a description, so the parse
        // cannot tell it from a command row. Python does the same.
        let help = "Commands:\n  build  Build it\nOther things:\n  ship  Ship it\n";
        assert_eq!(names(help), vec!["build", "Other", "ship"]);
    }

    /// Decisions recorded from the Python parser this module replaced. Each
    /// case was produced by handing the same text, parent and invocation to
    /// `runtime/local_cli_help.parse_cli_help_text`, so a disagreement here is
    /// a behaviour change, not a style difference.
    #[test]
    fn recorded_python_decisions_replay() {
        const FIXTURE: &str =
            include_str!("../../../../tests/fixtures/guard-local-cli-help-parse.v1.json");
        let document: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture parses");
        assert_eq!(
            document["schema"], "guard-local-cli-help-parse-parity.v1",
            "fixture schema moved"
        );
        let cases = document["cases"].as_array().expect("cases");
        assert!(cases.len() >= 20, "the fixture records too few cases");
        for case in cases {
            let name = case["name"].as_str().expect("case name");
            let invocation: Vec<String> = case["invocation"]
                .as_array()
                .expect("invocation")
                .iter()
                .map(|word| word.as_str().expect("invocation word").to_owned())
                .collect();
            let parsed = parse_cli_help_text(
                case["text"].as_str().expect("case text"),
                case["parent_id"].as_str(),
                &invocation,
            );
            assert_eq!(
                serde_json::to_value(&parsed).expect("commands serialise"),
                case["expected"],
                "case {name} disagrees with Python"
            );
        }
    }

    #[test]
    fn a_request_under_another_schema_is_refused() {
        let request = LocalCliHelpParseRequestV1 {
            schema: "guard-local-cli-help-parse-request.v2".to_owned(),
            request_id: "local-cli-help-parse-test".to_owned(),
            text: "Commands:\n  build  Build it\n".to_owned(),
            parent_id: None,
            invocation: Vec::new(),
        };
        assert_eq!(
            evaluate_local_cli_help_parse_request(&request),
            Err("native_local_cli_help_parse_schema_mismatch".to_owned())
        );

        // The same request under the declared schema still answers.
        let request = LocalCliHelpParseRequestV1 {
            schema: LOCAL_CLI_HELP_PARSE_REQUEST_SCHEMA.to_owned(),
            ..request
        };
        assert!(evaluate_local_cli_help_parse_request(&request).is_ok());
    }

    #[test]
    fn python_line_boundaries_and_whitespace_are_honoured() {
        // `\x1c` ends a line for `str.splitlines` and is whitespace for
        // `str.isspace`, so this row is indented and its section closes.
        let help = "Commands:\u{1c}\u{1f}build  Build it\u{1c}";
        assert_eq!(names(help), vec!["build"]);
    }
}
