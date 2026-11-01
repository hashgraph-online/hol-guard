//! The code lines of a JavaScript, Python or Ruby script that name its
//! subcommands and options. A shell script's `case "$1"` arms are read in
//! [`super::source`]; this reads what the other languages write instead:
//!
//! * `switch (command) { case 'build': }`, Python's `match command:` with
//!   `case "build":`, and Ruby's `case command` with `when "build"`;
//! * comparisons such as `command === 'build'` or `sys.argv[1] == "build"`,
//!   and membership tests such as `command in ("build", "test")`;
//! * the subcommands a command-line framework declares, in [`frameworks`].
//!
//! `command` is the script's first argument, followed through the variables
//! that hold it (see [`values`]). Only a word compared against the first
//! argument is a subcommand. An option compared against any argument is an
//! option. Like the rest of the source read, nothing here runs the script.

use std::sync::LazyLock;

use regex::Regex;

use super::facts::Facts;
use super::source::inside_quotes;
use super::{Found, VALUE_PLACEHOLDER};
use crate::daemon_lifecycle_text::py_strip;

#[path = "local_cli_help_script_frameworks.rs"]
mod frameworks;
#[path = "local_cli_help_script_syntax.rs"]
mod syntax;
#[path = "local_cli_help_script_values.rs"]
mod values;

use frameworks::Frameworks;
use syntax::{bare, literal, literals};
use values::{Kind, Values};

const COMPARISON: &str = r"(?:===|!==|==|!=|\beq\b|\bne\b)";
const OPERAND: &str = r"([\w$.\[\]()]+)";
const LITERAL: &str = r#"(?:"([^"\\]*)"|'([^'\\]*)')"#;

static COMPARED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"{OPERAND}\s*{COMPARISON}\s*{LITERAL}")).unwrap());

static COMPARED_REVERSED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"{LITERAL}\s*{COMPARISON}\s*{OPERAND}")).unwrap());

/// `command in ("build", "test")`, or `in COMMANDS` for a list of words.
static IN_LIST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"{OPERAND}\s+(?:not\s+)?in\s+(\[[^\]]*\]|\([^)]*\)|\{{[^}}]*\}}|[A-Za-z_]\w*)"
    ))
    .unwrap()
});

/// `['build', 'test'].includes(command)`, `COMMANDS.has(command)` or Ruby's
/// `%w[build test].include?(command)`.
static INCLUDES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(\[[^\]]*\]|%w[\[(][^\])]*[\])]|[A-Za-z_$][\w$]*)\s*\)?",
        r"\s*\.(?:includes|has|include\?)\s*\(\s*([\w$.\[\]]+)\s*\)",
    ))
    .unwrap()
});

/// An option a script compares an argument against, whatever holds it:
/// `arg === '--force'`, `'-v' == a`, `args.includes('--json')`,
/// `"--quiet" in args` or `arg.startsWith('--target=')`.
static OPTION_TEST: LazyLock<Regex> = LazyLock::new(|| {
    let o = r"(-{1,2}[A-Za-z0-9][\w-]*)";
    Regex::new(&format!(
        concat!(
            r#"{c}\s*["']{o}["']"#,
            r#"|["']{o}["']\s*{c}"#,
            r#"|\.(?:includes|has|include\?|index)\(\s*["']{o}["']"#,
            r#"|["']{o}["']\s+(?:not\s+)?in\s+[A-Za-z_]"#,
            r#"|\.(?:startsWith|startswith|start_with\?)\(\s*["']{o}=["']"#,
        ),
        c = COMPARISON,
        o = o
    ))
    .unwrap()
});

/// A Node `parseArgs` option: `force: { type: 'boolean', short: 'f' }`.
static PARSE_ARGS_OPTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^["']?([A-Za-z][\w-]*)["']?\s*:\s*\{\s*type\s*:\s*["'](boolean|string)["']"#)
        .unwrap()
});

/// The first line of a `parseArgs` option written over several lines.
static OPEN_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^["']?[A-Za-z][\w-]*["']?\s*:\s*\{\s*$"#).unwrap());

/// Most lines one wrapped `parseArgs` option is joined across.
const OPTION_LINES: usize = 5;

static SHORT_KEYWORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\bshort\s*:\s*["']([A-Za-z0-9])["']"#).unwrap());

static SWITCH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bswitch\s*\((.+)\)\s*\{").unwrap());

static JS_CASE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bcase\s+(?:"([^"\\]*)"|'([^'\\]*)'|`([^`\\$]*)`)\s*:"#).unwrap()
});

static PY_MATCH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^match\s+(.+?)\s*:$").unwrap());

static PY_CASE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^case\s+(.+?)\s*(?:\bif\b.*)?:$").unwrap());

/// Ruby's `case command`. A colon makes it a Python or JavaScript `case`.
static RUBY_CASE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^case\s+([^\s:]+)$").unwrap());

static RUBY_WHEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^when\s+(.+?)(?:\s+then\b.*)?$").unwrap());

#[derive(Clone, Copy, PartialEq, Eq)]
enum Language {
    Js,
    Python,
    Ruby,
}

/// A `switch`, `match` or Ruby `case` the line being read is inside.
struct Block {
    language: Language,
    /// The brace depth inside a JavaScript `switch`; the indentation of a
    /// Python `match` or a Ruby `case`.
    at: usize,
    /// What it switches on: the first argument, the argument list (a Python
    /// `case ["build", *rest]:`), or something else.
    subject: Kind,
}

/// What the code read so far says about the line being read.
pub(super) struct ScriptState {
    values: Values,
    blocks: Vec<Block>,
    depth: usize,
    frameworks: Frameworks,
}

impl ScriptState {
    /// A state that knows which functions the script calls with its argument
    /// list, from a first pass over its code, so a parameter given that list
    /// is followed even when the call comes after the function.
    pub(super) fn prepare(raw: &[&str], code: &[bool], facts: &Facts) -> Self {
        let mut first = Self::new(Values::default(), facts);
        let mut scratch = Found::default();
        for (index, line) in raw.iter().enumerate() {
            if code.get(index).copied().unwrap_or(false) {
                first.line(line, &raw[index..], &mut scratch);
            }
        }
        Self::new(first.values.with_callees_only(), facts)
    }

    fn new(values: Values, facts: &Facts) -> Self {
        Self {
            values,
            blocks: Vec::new(),
            depth: 0,
            frameworks: Frameworks::new(facts),
        }
    }

    /// What one code line adds. `raw` is the line as written; `rest` starts
    /// at it, for calls that wrap.
    pub(super) fn line(&mut self, raw: &str, rest: &[&str], found: &mut Found) {
        let line = py_strip(raw);
        if line.is_empty() {
            return;
        }
        let indent = raw.len() - raw.trim_start().len();
        self.close_blocks(line, indent);
        let before = self.depth;
        self.values.track(line);
        self.block_arm(line, before, found);
        self.open_block(line, indent);
        let depth = before.saturating_add_signed(brace_balance(line));
        self.depth = depth;
        self.blocks
            .retain(|block| block.language != Language::Js || block.at <= depth);
        self.comparisons(line, found);
        self.frameworks.line(line, rest, found);
        options(line, rest, found);
        self.values.consume(line);
    }

    fn close_blocks(&mut self, line: &str, indent: usize) {
        while let Some(block) = self.blocks.last() {
            let ends = match block.language {
                Language::Js => false,
                Language::Python => indent <= block.at,
                Language::Ruby => indent <= block.at && (line == "end" || line.starts_with("end ")),
            };
            if !ends {
                break;
            }
            self.blocks.pop();
        }
    }

    fn open_block(&mut self, line: &str, indent: usize) {
        let (language, at, subject) = if let Some(captures) = SWITCH.captures(line) {
            let before = captures.get(0).map_or(0, |m| m.start());
            let at = self
                .depth
                .saturating_add_signed(brace_balance(&line[..before]))
                + 1;
            (Language::Js, at, captures[1].to_owned())
        } else if let Some(captures) = PY_MATCH.captures(without_comment(line)) {
            (Language::Python, indent, captures[1].to_owned())
        } else if let Some(captures) = RUBY_CASE.captures(without_comment(line)) {
            (Language::Ruby, indent, captures[1].to_owned())
        } else {
            return;
        };
        let subject = self.values.kind(&subject);
        self.blocks.push(Block {
            language,
            at,
            subject,
        });
    }

    /// A `case` or `when` arm of the block the line is inside.
    fn block_arm(&self, line: &str, depth: usize, found: &mut Found) {
        let Some(block) = self.blocks.last() else {
            return;
        };
        let comment = line_comment(line);
        match block.language {
            Language::Js if block.subject == Kind::First && depth == block.at => {
                for captures in JS_CASE.captures_iter(line) {
                    if let Some(name) = (1..=3).find_map(|group| captures.get(group)) {
                        found.hand_command(name.as_str(), comment);
                    }
                }
            }
            Language::Python => {
                let Some(captures) = PY_CASE.captures(without_comment(line)) else {
                    return;
                };
                let pattern = match block.subject {
                    Kind::First => captures[1].to_owned(),
                    Kind::List => match first_item(&captures[1]) {
                        Some(item) => item,
                        None => return,
                    },
                    Kind::Other => return,
                };
                for alternative in pattern.split('|') {
                    if let Some(name) = literal(alternative) {
                        found.hand_command(&name, comment);
                    }
                }
            }
            Language::Ruby if block.subject == Kind::First => {
                if let Some(captures) = RUBY_WHEN.captures(without_comment(line)) {
                    for name in literals(&captures[1]) {
                        found.hand_command(&name, comment);
                    }
                }
            }
            _ => {}
        }
    }

    /// Words compared against the first argument, and lists it is looked up in.
    fn comparisons(&self, line: &str, found: &mut Found) {
        let comment = line_comment(line);
        for captures in COMPARED.captures_iter(line) {
            if self.values.kind(operand(matched(captures.get(1)))) == Kind::First {
                found.hand_command(matched(captures.get(2).or(captures.get(3))), comment);
            }
        }
        for captures in COMPARED_REVERSED.captures_iter(line) {
            if self.values.kind(operand(matched(captures.get(3)))) == Kind::First {
                found.hand_command(matched(captures.get(1).or(captures.get(2))), comment);
            }
        }
        let listed = IN_LIST
            .captures_iter(line)
            .map(|captures| (matched(captures.get(1)), matched(captures.get(2))))
            .chain(
                INCLUDES
                    .captures_iter(line)
                    .map(|captures| (matched(captures.get(2)), matched(captures.get(1)))),
            );
        for (subject, list) in listed {
            if self.values.kind(operand(subject)) == Kind::First {
                for name in self.values.words(list) {
                    found.hand_command(&name, comment);
                }
            }
        }
    }
}

fn matched<'h>(m: Option<regex::Match<'h>>) -> &'h str {
    m.map_or("", |m| m.as_str())
}

/// Options a line compares an argument against, and Node `parseArgs` options.
fn options(line: &str, rest: &[&str], found: &mut Found) {
    for captures in OPTION_TEST.captures_iter(line) {
        if let Some(name) = (1..=5).find_map(|group| captures.get(group)) {
            found.option(name.as_str(), None, "");
        }
    }
    for captures in IN_LIST.captures_iter(line) {
        for word in literals(&captures[2]) {
            if word.starts_with('-') {
                found.option(&word, None, "");
            }
        }
    }
    let option = option_object(line, rest);
    if let Some(captures) = PARSE_ARGS_OPTION.captures(&option) {
        let value = (&captures[2] == "string").then_some(VALUE_PLACEHOLDER);
        let mut names = vec![format!("--{}", &captures[1])];
        if let Some(short) = SHORT_KEYWORD.captures(&option) {
            names.push(format!("-{}", &short[1]));
        }
        found.aliases(&names, value, "");
    }
}

/// A `parseArgs` option as one line: `force: {` joined with the lines after
/// it up to the one that closes it.
fn option_object(line: &str, rest: &[&str]) -> String {
    let mut text = line.to_owned();
    if !OPEN_OPTION.is_match(line) {
        return text;
    }
    for next in rest.iter().skip(1).take(OPTION_LINES) {
        let next = py_strip(next);
        text.push(' ');
        text.push_str(next);
        if next.contains('}') {
            break;
        }
    }
    text
}

/// A compared expression without the brackets and negation around it.
fn operand(text: &str) -> &str {
    let mut text = text.trim().trim_start_matches(['(', '!']);
    while text.ends_with(')') && text.matches('(').count() < text.matches(')').count() {
        text = &text[..text.len() - 1];
    }
    bare(text)
}

/// The net braces a line opens, outside strings and a trailing comment.
fn brace_balance(line: &str) -> isize {
    let mut depth = 0;
    let mut open: Option<char> = None;
    let mut escaped = false;
    let mut previous = ' ';
    for c in line.chars() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if let Some(quote) = open {
            if c == quote {
                open = None;
            }
        } else if matches!(c, '"' | '\'' | '`') {
            open = Some(c);
        } else if c == '/' && previous == '/' {
            break;
        } else if c == '{' {
            depth += 1;
        } else if c == '}' {
            depth -= 1;
        }
        previous = c;
    }
    depth
}

/// The text of a `// ...` or ` # ...` comment that ends a line.
fn line_comment(line: &str) -> &str {
    comment_at(line).map_or("", |(at, marker)| py_strip(&line[at + marker..]))
}

/// A line without the `// ...` or ` # ...` comment that ends it.
fn without_comment(line: &str) -> &str {
    comment_at(line).map_or(line, |(at, _)| py_strip(&line[..at]))
}

/// Where a trailing comment starts outside quotes, and its marker's length.
fn comment_at(line: &str) -> Option<(usize, usize)> {
    for marker in [" // ", " # "] {
        let mut from = 0;
        while let Some(at) = line[from..].find(marker) {
            let at = from + at;
            if !inside_quotes(&line[..at]) {
                return Some((at, marker.len()));
            }
            from = at + marker.len();
        }
    }
    None
}

/// The first item of a Python list pattern: `"build"` in `["build", *rest]`.
fn first_item(pattern: &str) -> Option<String> {
    let inner = pattern.trim().strip_prefix('[')?.strip_suffix(']')?;
    Some(inner.split(',').next()?.trim().to_owned())
}

#[cfg(test)]
#[path = "local_cli_help_script_tests.rs"]
mod tests;
