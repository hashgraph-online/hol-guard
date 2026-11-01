//! The subcommands a command-line framework declares in code:
//! `program.command('build')` (Commander, yargs, cac, sade),
//! `subparsers.add_parser("build")` (argparse) and `@cli.command()` (Click,
//! Typer, Cyclopts). Each is read only in a script that imports that
//! framework, and only on the first receiver it is seen on, so a nested
//! group's commands are not read as top-level ones.

use std::sync::LazyLock;

use regex::Regex;

use super::super::facts::Facts;
use super::super::source::{call_text, inside_quotes, HELP_KEYWORD, STRING_LITERAL};
use super::super::Found;
use crate::daemon_lifecycle_text::py_strip;

static COMMAND_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"([A-Za-z_$][\w$]*)?\s*\.command\s*\(\s*(?:"([^"\\]*)"|'([^'\\]*)'|`([^`\\$]*)`)"#)
        .unwrap()
});

static DESCRIPTION_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\.(?:description|describe|summary)\s*\(\s*(?:"([^"\\]*)"|'([^'\\]*)')"#).unwrap()
});

static ADD_PARSER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"([A-Za-z_]\w*)?\s*\.add_parser\s*\(\s*(?:"([^"\\]*)"|'([^'\\]*)')"#).unwrap()
});

static DECORATOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^@([A-Za-z_]\w*)\.(?:command|group)\b\s*(?:\((.*))?$").unwrap());

static NAME_KEYWORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\bname\s*=\s*(?:"([^"\\]*)"|'([^'\\]*)')"#).unwrap());

static PY_DEF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(").unwrap());

/// A decorator on the framework module itself makes the root command.
const DECORATOR_MODULES: [&str; 5] = ["click", "typer", "cyclopts", "rich_click", "asyncclick"];

pub(super) struct Frameworks {
    commander: Option<Option<String>>,
    argparse: Option<Option<String>>,
    decorator: Option<Option<String>>,
    /// A `@cli.command()` with no name: the `def` it decorates names it.
    pending_def: Option<String>,
}

impl Frameworks {
    /// `None` for a framework the script does not import; `Some(None)` until
    /// its first receiver is seen.
    pub(super) fn new(facts: &Facts) -> Self {
        let imported = |yes: bool| yes.then_some(None);
        Self {
            commander: imported(facts.commander),
            argparse: imported(facts.argparse),
            decorator: imported(facts.decorators),
            pending_def: None,
        }
    }

    pub(super) fn line(&mut self, line: &str, rest: &[&str], found: &mut Found) {
        let following = rest.get(1..).unwrap_or_default();
        if self.decorator.is_some() {
            self.decorated(line, following, found);
        }
        if self.commander.is_some() && !line.starts_with('@') {
            self.commands(line, following, found);
        }
        if let Some(captures) = ADD_PARSER.captures(line) {
            let receiver = captures.get(1).map_or("", |m| m.as_str());
            if owns(&mut self.argparse, receiver) {
                let name = captures
                    .get(2)
                    .or(captures.get(3))
                    .map_or("", |m| m.as_str());
                let after = captures.get(0).map_or(line.len(), |m| m.end());
                let call = call_text(&line[after..], following);
                found.command(name, &keyword(&HELP_KEYWORD, &call).unwrap_or_default());
            }
        }
    }

    fn commands(&mut self, line: &str, following: &[&str], found: &mut Found) {
        for captures in COMMAND_CALL.captures_iter(line) {
            let at = captures.get(0).map_or(0, |m| m.start());
            let receiver = captures.get(1).map_or("", |m| m.as_str());
            if inside_quotes(&line[..at]) || !owns(&mut self.commander, receiver) {
                continue;
            }
            let spec = (2..=4)
                .find_map(|group| captures.get(group))
                .map_or("", |m| m.as_str());
            let name = spec.split_whitespace().next().unwrap_or("");
            let after = captures.get(0).map_or(line.len(), |m| m.end());
            let call = call_text(&line[after..], following);
            let next = following.first().map_or("", |next| py_strip(next));
            let description = description_argument(&call)
                .or_else(|| keyword(&DESCRIPTION_CALL, line))
                .or_else(|| keyword(&DESCRIPTION_CALL, next).filter(|_| next.starts_with('.')))
                .unwrap_or_default();
            found.command(name, &description);
        }
    }

    fn decorated(&mut self, line: &str, following: &[&str], found: &mut Found) {
        if let Some(description) = self.pending_def.take() {
            if let Some(captures) = PY_DEF.captures(line) {
                let description = if description.is_empty() {
                    docstring(following.first().copied().unwrap_or(""))
                } else {
                    description
                };
                found.command(&captures[1].replace('_', "-"), &description);
                return;
            }
            if line.starts_with('@') && !DECORATOR.is_match(line) {
                // Another decorator stacked under it, such as `@click.option`.
                self.pending_def = Some(description);
                return;
            }
        }
        let Some(captures) = DECORATOR.captures(line) else {
            return;
        };
        let receiver = &captures[1];
        if DECORATOR_MODULES.contains(&receiver) || !owns(&mut self.decorator, receiver) {
            return;
        }
        let arguments = captures
            .get(2)
            .map_or(String::new(), |m| call_text(m.as_str(), following));
        let description = keyword(&HELP_KEYWORD, &arguments).unwrap_or_default();
        match keyword(&NAME_KEYWORD, &arguments).or_else(|| first_positional(&arguments)) {
            Some(name) => found.command(&name, &description),
            None => self.pending_def = Some(description),
        }
    }
}

/// Whether a framework call on `receiver` declares a top-level command: the
/// framework is imported, and this is the first receiver seen, or a chained
/// call (`.command(...)` on its own line) whose receiver is not written.
fn owns(slot: &mut Option<Option<String>>, receiver: &str) -> bool {
    let Some(owner) = slot else {
        return false;
    };
    receiver.is_empty() || owner.get_or_insert_with(|| receiver.to_owned()).as_str() == receiver
}

fn keyword(regex: &Regex, text: &str) -> Option<String> {
    regex
        .captures(text)
        .and_then(|captures| captures.get(1).or(captures.get(2)))
        .map(|m| m.as_str().to_owned())
}

/// The description a call passes after the name, as in
/// `.command('serve', 'Start the server')`: the first string literal before
/// the call closes. `rest` starts after the name.
fn description_argument(rest: &str) -> Option<String> {
    let mut depth = 1;
    let end = rest
        .char_indices()
        .find_map(|(at, c)| {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            (depth == 0).then_some(at)
        })
        .unwrap_or(rest.len());
    let captures = STRING_LITERAL.captures(&rest[..end])?;
    captures
        .get(1)
        .or(captures.get(2))
        .map(|m| m.as_str().to_owned())
}

/// The first string literal of a call that is not a keyword's value.
fn first_positional(arguments: &str) -> Option<String> {
    STRING_LITERAL
        .captures_iter(arguments)
        .find_map(|captures| {
            let start = captures.get(0)?.start();
            if arguments[..start].trim_end().ends_with('=') {
                return None;
            }
            captures
                .get(1)
                .or(captures.get(2))
                .map(|m| m.as_str().to_owned())
        })
}

/// A one-line `"""Build the site."""` docstring.
fn docstring(line: &str) -> String {
    let line = py_strip(line);
    for quote in ["\"\"\"", "'''"] {
        if let Some(rest) = line.strip_prefix(quote) {
            return py_strip(rest.split(quote).next().unwrap_or("")).to_owned();
        }
    }
    String::new()
}
