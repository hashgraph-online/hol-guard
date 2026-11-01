//! The call variations a CLI with no subcommands still has: its options.
//!
//! `deploy.sh --dry-run` and `deploy.sh --force` do different things, and an
//! operator may allow one and block the other, so a tool whose `--help` names
//! no subcommands is not one command. This reads the options a help text
//! names, from its usage lines and option rows. For a script whose `--help`
//! printed nothing usable, or that Guard reads before running it, it reads
//! the script's own source the same way, with comment markers removed, and
//! adds the shell `case` arms, option parser calls (`add_argument`,
//! `.option`, `getopts`) and the JavaScript, Python and Ruby dispatch that
//! define them.
//!
//! The text is untrusted and nothing here runs it. Only names that pass
//! [`is_option_name`] are kept, and a source read never probes anything.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

use super::{is_skipped, LocalCliCommand, COMMAND_NAME};
use crate::daemon_lifecycle_text::{py_splitlines, py_strip};

#[path = "local_cli_help_source.rs"]
mod source;
use source::{source_line, ShellState};

#[path = "local_cli_help_script.rs"]
mod script;
use script::ScriptState;

#[path = "local_cli_help_script_facts.rs"]
mod facts;
pub(super) use facts::Facts;

/// Most option variations one read reports. The catalog keeps room for its
/// root and other rows and for subcommands a source read finds.
const MAX_OPTIONS: usize = 64;
/// Most subcommands a source read reports from `case "$1"` arms and the
/// dispatch of other languages.
const MAX_SOURCE_COMMANDS: usize = 32;
const DESCRIPTION_CHARS: usize = 200;
const VALUE_CHARS: usize = 40;
/// Asking for help or a version changes nothing, so neither is a variation.
const IGNORED: [&str; 3] = ["-h", "--help", "--version"];
/// The placeholder for a value a `case` arm or parser call reads but never names.
const VALUE_PLACEHOLDER: &str = "VALUE";

/// `--name` (a letter or digit, then up to 39 letters, digits, `_` or `-`) or
/// a single-letter `-x`. These are the only option spellings a catalog keeps.
pub(crate) fn is_option_name(text: &str) -> bool {
    let bytes = text.as_bytes();
    let word = |rest: &[u8]| {
        rest.first().is_some_and(u8::is_ascii_alphanumeric)
            && rest[1..]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    };
    match bytes {
        [b'-', b'-', rest @ ..] => (1..=40).contains(&rest.len()) && word(rest),
        [b'-', only] => only.is_ascii_alphanumeric(),
        _ => false,
    }
}

static USAGE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\busage:\s*(.*)$").unwrap());

/// `<<EOF`, `<<-'EOF'`, `<< "USAGE"` or Ruby's `<<~USAGE`: the lines up to
/// the marker are text.
static HEREDOC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"<<[-~]?\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?"#).unwrap());

/// Quotes that open a string spanning lines: a Python docstring or a
/// JavaScript template literal, where a script keeps its usage text.
const MULTILINE_QUOTES: [&str; 3] = ["\"\"\"", "'''", "`"];

/// `USAGE = `, `const HELP = ` or `__doc__ = ` before such a quote.
static STRING_TARGET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:(?:export\s+)?(?:const|let|var)\s+)?[A-Za-z_$][\w$.]*\s*=\s*$").unwrap()
});

/// One option in the order the text first named it.
struct Variation {
    name: String,
    value: Option<String>,
    description: String,
}

#[derive(Default)]
struct Found {
    options: Vec<Variation>,
    index: HashMap<String, usize>,
    commands: Vec<LocalCliCommand>,
}

impl Found {
    /// Record `name`, or fill in what an earlier mention of it left out.
    fn option(&mut self, name: &str, value: Option<&str>, description: &str) {
        if !is_option_name(name) || IGNORED.contains(&name) {
            return;
        }
        let value = value.and_then(clean_value);
        let description: String = py_strip(description)
            .chars()
            .take(DESCRIPTION_CHARS)
            .collect();
        if let Some(&at) = self.index.get(name) {
            let known = &mut self.options[at];
            if known.value.is_none() {
                known.value = value;
            }
            if known.description.is_empty() {
                known.description = description;
            }
            return;
        }
        if self.options.len() >= MAX_OPTIONS {
            return;
        }
        self.index.insert(name.to_owned(), self.options.len());
        self.options.push(Variation {
            name: name.to_owned(),
            value,
            description,
        });
    }

    /// Record a subcommand a source read names, once, up to the cap.
    fn command(&mut self, name: &str, description: &str) {
        let known = self.commands.iter().any(|command| command.name == name);
        if !COMMAND_NAME.is_match(name)
            || is_skipped(name)
            || known
            || self.commands.len() >= MAX_SOURCE_COMMANDS
        {
            return;
        }
        self.commands.push(LocalCliCommand {
            command_id: name.to_owned(),
            name: name.to_owned(),
            usage: name.to_owned(),
            description: py_strip(description)
                .chars()
                .take(DESCRIPTION_CHARS)
                .collect(),
            parent_id: None,
        });
    }

    /// Several spellings of one option: the first long one carries the
    /// description, and each other spelling points at it.
    fn aliases(&mut self, names: &[String], value: Option<&str>, description: &str) {
        let primary = names
            .iter()
            .find(|name| name.starts_with("--"))
            .or(names.first())
            .cloned();
        let Some(primary) = primary else {
            return;
        };
        self.option(&primary, value, description);
        let alias = format!("Same as {primary}.");
        for name in names.iter().filter(|name| **name != primary) {
            self.option(name, value, &alias);
        }
    }
}

/// A value placeholder as written, cut of the brackets around it.
fn clean_value(raw: &str) -> Option<String> {
    let value = raw.trim_matches(|c: char| matches!(c, '[' | ']' | '(' | ')' | ',' | '"' | '\''));
    let usable = !value.is_empty()
        && !value.starts_with('-')
        && value.chars().count() <= VALUE_CHARS
        && !value.chars().any(char::is_control)
        && !value.contains("...");
    usable.then(|| value.to_owned())
}

/// The options a help text or script source names, as catalog rows, after the
/// subcommands a source's `case "$1"` arms name.
pub(super) fn variations(
    text: &str,
    invocation: &[String],
    script_source: bool,
) -> Vec<LocalCliCommand> {
    let raw: Vec<&str> = py_splitlines(text);
    // Usage lines and option rows are read only from text a person reads: all
    // of a help text, and a script's comments and heredocs. A code line such
    // as `  --json state)` is an argument to some other program.
    let lines: Vec<Option<String>> = if script_source {
        source_text_lines(&raw)
    } else {
        raw.iter().map(|line| Some((*line).to_owned())).collect()
    };
    let mut found = Found::default();
    let mut shell = ShellState::default();
    let mut script = script_source.then(|| {
        let code: Vec<bool> = lines.iter().map(Option::is_none).collect();
        ScriptState::prepare(&raw, &code, &facts::facts(&raw, &lines))
    });
    let mut index = 0;
    while index < lines.len() {
        let Some(text_line) = &lines[index] else {
            source_line(py_strip(raw[index]), &raw[index..], &mut shell, &mut found);
            if let Some(script) = &mut script {
                script.line(raw[index], &raw[index..], &mut found);
            }
            index += 1;
            continue;
        };
        let line = py_strip(text_line);
        if let Some(captures) = USAGE.captures(line) {
            let mut usage = captures[1].to_owned();
            while let Some(Some(next)) = lines.get(index + 1) {
                if !usage_continues(next) {
                    break;
                }
                index += 1;
                usage.push(' ');
                usage.push_str(py_strip(next));
            }
            usage_options(&usage, &mut found);
        } else if line.starts_with('-') {
            option_row(line, &mut found);
        }
        index += 1;
    }
    let program = invocation.first().map(String::as_str).unwrap_or("");
    let mut rows = found.commands;
    rows.extend(found.options.into_iter().map(|option| {
        let usage = match &option.value {
            Some(value) => format!("{program} {} {value}", option.name),
            None => format!("{program} {}", option.name),
        };
        LocalCliCommand {
            command_id: option.name.clone(),
            name: option.name,
            usage: py_strip(&usage).to_owned(),
            description: option.description,
            parent_id: None,
        }
    }));
    rows
}

/// How a script source answers `--help`, and the local modules it imports.
pub(super) fn script_facts(text: &str) -> Facts {
    let raw = py_splitlines(text);
    facts::facts(&raw, &source_text_lines(&raw))
}

/// A script source's comment and heredoc text, one line per source line, with
/// code lines left blank so a section still ends where the code starts.
pub(super) fn comment_lines(text: &str) -> String {
    source_text_lines(&py_splitlines(text))
        .into_iter()
        .map(Option::unwrap_or_default)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Each source line's readable text, or `None` for a line of code. Comments
/// lose their marker; a heredoc's body (a `usage()` that `cat`s its text) and
/// a string that spans lines are read as written.
fn source_text_lines(raw: &[&str]) -> Vec<Option<String>> {
    let mut lines = Vec::with_capacity(raw.len());
    let mut heredoc_end: Option<String> = None;
    let mut string_end: Option<&str> = None;
    for line in raw {
        if let Some(end) = string_end {
            match line.find(end) {
                Some(at) => {
                    string_end = None;
                    lines.push(Some(line[..at].to_owned()));
                }
                None => lines.push(Some((*line).to_owned())),
            }
            continue;
        }
        if let Some(end) = &heredoc_end {
            if py_strip(line) == end {
                heredoc_end = None;
                lines.push(None);
            } else {
                lines.push(Some((*line).to_owned()));
            }
            continue;
        }
        let comment = comment_text(line);
        if comment.is_none() {
            if let Some((end, before, text)) = opened_string(line) {
                // A docstring or `USAGE = """Usage: ...` starts its text on
                // this line; a call such as `ArgumentParser(description="""`
                // keeps the line as code.
                string_end = Some(end);
                let only_string = before.trim().is_empty() || STRING_TARGET.is_match(before);
                lines.push(only_string.then(|| text.to_owned()));
                continue;
            }
            heredoc_end = HEREDOC
                .captures(line)
                .map(|captures| captures[1].to_owned());
        }
        lines.push(comment);
    }
    lines
}

/// The quote a code line leaves open, the code before it and the text after.
fn opened_string(line: &str) -> Option<(&'static str, &str, &str)> {
    MULTILINE_QUOTES.into_iter().find_map(|quote| {
        let opened = line.matches(quote).count() % 2 == 1;
        let at = line.rfind(quote)?;
        opened.then(|| (quote, &line[..at], &line[at + quote.len()..]))
    })
}

/// A comment line's text without its marker, keeping the indentation after
/// it so a wrapped usage line still reads as a continuation. `None` for code;
/// a shebang reads as an empty comment.
fn comment_text(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("#!") {
        return Some(String::new());
    }
    for marker in ["#", "//", "::", "/*", "* ", "*/"] {
        if let Some(rest) = trimmed.strip_prefix(marker) {
            return Some(rest.strip_prefix(' ').unwrap_or(rest).to_owned());
        }
    }
    if trimmed == "*" {
        return Some(String::new());
    }
    let lowered = trimmed.get(..4).map(str::to_ascii_lowercase);
    if lowered.as_deref() == Some("rem ") {
        return Some(trimmed[4..].to_owned());
    }
    None
}

/// A wrapped usage line: indented, and opening another optional group or
/// alternative rather than starting an option row or prose.
fn usage_continues(line: &str) -> bool {
    line.starts_with(|c: char| c.is_whitespace())
        && py_strip(line).starts_with(['[', '(', '|', '<'])
}

/// The options a usage synopsis names, and the value each one takes.
fn usage_options(usage: &str, found: &mut Found) {
    let mut pending: Option<String> = None;
    for token in usage.split_whitespace() {
        let token = token.trim_matches(|c: char| c == '"' || c == '\'');
        // `<name>` is the value itself; a bracket opens another group.
        let opens = token.starts_with(['[', '(', '{']);
        let core = token.trim_start_matches(['[', '(', '{', '|']);
        let closes = core.ends_with([']', ')', '}', '|', ',']);
        let core = core.trim_end_matches([']', ')', '}', '|', ',', '.']);
        if let Some(name) = pending.take() {
            if !opens && !core.starts_with('-') && !core.is_empty() {
                found.option(&name, Some(core), "");
                continue;
            }
        }
        let mut last = None;
        for part in core.split('|') {
            let (name, value) = match part.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (part, None),
            };
            if is_option_name(name) {
                found.option(name, value, "");
                last = value.is_none().then(|| name.to_owned());
            }
        }
        if !closes {
            pending = last;
        }
    }
}

/// An option row: spellings and an optional value, then the description
/// after a gap of two spaces or a tab. A row without that gap must be only
/// spellings and a value, so prose that starts with an option is not a row.
fn option_row(line: &str, found: &mut Found) {
    let (head, description) = match split_gap(line) {
        Some((head, description)) => (head, description),
        None => (line, ""),
    };
    let mut names: Vec<String> = Vec::new();
    let mut value: Option<String> = None;
    for token in head
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|t| !t.is_empty())
    {
        let (name, inline) = match token.split_once('=') {
            Some((name, inline)) => (name, Some(inline)),
            None => (token, None),
        };
        if is_option_name(name) {
            names.push(name.to_owned());
            if let Some(inline) = inline {
                value.get_or_insert_with(|| inline.to_owned());
            }
        } else if names.is_empty() || token.starts_with('-') {
            return;
        } else if value.is_none() {
            value = Some(token.to_owned());
        } else if value.as_deref() != Some(token) {
            // `-n NUM, --count NUM` repeats its value; anything else is prose.
            return;
        }
    }
    found.aliases(&names, value.as_deref(), description);
}

/// `line` split at its first run of two or more spaces, or a tab.
fn split_gap(line: &str) -> Option<(&str, &str)> {
    let bytes = line.as_bytes();
    let at = (0..bytes.len())
        .find(|&i| bytes[i] == b'\t' || (bytes[i] == b' ' && bytes.get(i + 1) == Some(&b' ')))?;
    Some((&line[..at], py_strip(&line[at..])))
}

#[cfg(test)]
#[path = "local_cli_help_options_tests.rs"]
mod tests;
