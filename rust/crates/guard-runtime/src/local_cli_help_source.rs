//! The code lines of a script source that name its variations: shell `case`
//! arms, option parser calls (`add_argument`, `.option`), arguments compared
//! against an option, and `getopts` letters. Like the rest of the source read,
//! nothing here runs the script.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

use super::{is_option_name, Found, VALUE_PLACEHOLDER};
use crate::daemon_lifecycle_text::py_strip;

static CASE_OPTION_ARM: LazyLock<Regex> = LazyLock::new(|| {
    let arm = r#"["']?-{1,2}[A-Za-z0-9][A-Za-z0-9_-]*(?:=\*?)?["']?"#;
    Regex::new(&format!(r"^\(?\s*({arm}(?:\s*\|\s*{arm})*)\s*\)(.*)$")).unwrap()
});

static CASE_WORD_ARM: LazyLock<Regex> = LazyLock::new(|| {
    let arm = r#"["']?[A-Za-z][A-Za-z0-9_-]{0,40}["']?"#;
    Regex::new(&format!(r"^\(?\s*({arm}(?:\s*\|\s*{arm})*)\s*\)(.*)$")).unwrap()
});

/// `case WORD in`, where a line starts or after `;`, `do`, `then` or `else`,
/// as in `while [ $# -gt 0 ]; do case "$1" in`.
static CASE_START: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|;\s*|\b(?:do|then|else)\s+)case\s+(.+?)\s+in(?:\s|$)").unwrap()
});

/// A positional parameter or a variable, bare or braced: `$1`, `"$@"`,
/// `${1:-}`, `$arg`.
static EXPANSION: LazyLock<Regex> = LazyLock::new(|| {
    let name = r"[1-9@*]|[A-Za-z_][A-Za-z0-9_]*";
    Regex::new(&format!(
        r"^\$(?:({name})|\{{({name})(?:[^A-Za-z0-9_}}][^}}]*)?\}})$"
    ))
    .unwrap()
});

/// `arg="$1"` or `local key=$1`: the value a shell variable is given.
static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:(?:local|declare|typeset|readonly|export)(?:\s+-[A-Za-z]+)*\s+)?([A-Za-z_][A-Za-z0-9_]*)=(\S*)")
        .unwrap()
});

/// `for arg in "$@"; do`, or `for arg; do`, which loops over the arguments.
static FOR_LOOP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^for\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s+in\s+(.+?))?\s*(?:;?\s*do\b.*)?$").unwrap()
});

/// An option a script compares an argument against: `case "--force":` in
/// JavaScript, `"--force" in sys.argv`, `argv.includes("--force")`, or a shell
/// test such as `[ "$1" = "--force" ]`.
static COMPARED_OPTION: LazyLock<Regex> = LazyLock::new(|| {
    let option = r"(-{1,2}[A-Za-z0-9][A-Za-z0-9_-]*)";
    Regex::new(&format!(
        concat!(
            r#"^case\s+["']{o}["']\s*:"#,
            r#"|["']{o}["']\s+in\s+(?:sys\.)?argv\b"#,
            r#"|argv\.includes\(\s*["']{o}["']"#,
            r#"|\$\{{?[A-Za-z0-9_@#]+\}}?"?\s*==?\s*["']{o}["']"#,
        ),
        o = option
    ))
    .unwrap()
});

static PARSER_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:add_argument|add_option|\.option)\s*\(").unwrap());

pub(super) static STRING_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""([^"\\]*)"|'([^'\\]*)'"#).unwrap());

pub(super) static HELP_KEYWORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\bhelp\s*=\s*(?:"([^"\\]*)"|'([^'\\]*)')"#).unwrap());

static METAVAR_KEYWORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\bmetavar\s*=\s*(?:"([^"\\]*)"|'([^'\\]*)')"#).unwrap());

static FLAG_ACTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\baction\s*=\s*["'](?:store_true|store_false|store_const|count|help|version)["']|\bis_flag\s*=\s*True"#)
        .unwrap()
});

static GETOPTS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\bgetopts\s+["']?:?([A-Za-z0-9:]+)["']?"#).unwrap());

/// What a `case` switches on, as far as the script's arguments go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Subject {
    /// The first argument: its plain-word arms are subcommands, and its
    /// option arms are options.
    First,
    /// Another argument, or each in turn: its option arms are options.
    Argument,
    /// A value the script works out itself, such as `$format`: its arms say
    /// nothing about the arguments.
    Other,
}

/// What the shell code read so far says about the line being read: the
/// `case` statements open around it, and the variables holding an argument.
#[derive(Default)]
pub(super) struct ShellState {
    cases: Vec<Subject>,
    arguments: HashMap<String, Subject>,
}

impl ShellState {
    /// What a `case` word or an assigned value reads: `$1`, `"${1:-}"`, `$@`,
    /// another positional parameter, or a variable holding one of them.
    fn subject(&self, word: &str) -> Subject {
        let word = word.trim().trim_matches(|c: char| c == '"' || c == '\'');
        let Some(captures) = EXPANSION.captures(word) else {
            return Subject::Other;
        };
        let name = captures
            .get(1)
            .or_else(|| captures.get(2))
            .map_or("", |name| name.as_str());
        match name.as_bytes().first() {
            Some(b'1') => Subject::First,
            Some(b'2'..=b'9' | b'@' | b'*') => Subject::Argument,
            _ => self.arguments.get(name).copied().unwrap_or(Subject::Other),
        }
    }

    /// Notes a variable a line sets: one given an argument is remembered, and
    /// one given anything else is forgotten.
    fn track(&mut self, line: &str) {
        let (name, subject) = if let Some(captures) = FOR_LOOP.captures(line) {
            let subject = match captures.get(2) {
                None => Subject::Argument,
                Some(list) if self.subject(list.as_str()) == Subject::Other => Subject::Other,
                Some(_) => Subject::Argument,
            };
            (captures[1].to_owned(), subject)
        } else if let Some(captures) = ASSIGNMENT.captures(line) {
            let value = captures[2].trim_end_matches(';');
            (captures[1].to_owned(), self.subject(value))
        } else {
            return;
        };
        if subject == Subject::Other {
            self.arguments.remove(&name);
        } else {
            self.arguments.insert(name, subject);
        }
    }

    /// Reads the `case` arms and `esac`s in text inside a `case`, split on
    /// `;;` so a compact `--force) F=1 ;; esac` is read too. Returns whether
    /// the text held any.
    fn arms(&mut self, text: &str, found: &mut Found) -> bool {
        let pieces: Vec<&str> = text
            .split(";;")
            .map(|piece| py_strip(piece.trim_start_matches('&')))
            .collect();
        let mut read = false;
        for (index, piece) in pieces.iter().enumerate() {
            if is_esac(piece) {
                self.cases.pop();
                read = true;
                continue;
            }
            let Some(&subject) = self.cases.last() else {
                continue;
            };
            if piece.is_empty() || subject == Subject::Other {
                continue;
            }
            // `build) ... ;; # Build the site` keeps its comment past the `;;`.
            let comment = pieces
                .get(index + 1)
                .filter(|next| next.starts_with('#'))
                .map_or(String::new(), |next| format!(" {next}"));
            if let Some(captures) = CASE_OPTION_ARM.captures(piece) {
                case_option_arm(&captures[1], &format!("{}{comment}", &captures[2]), found);
                read = true;
            } else if subject == Subject::First {
                if let Some(captures) = CASE_WORD_ARM.captures(piece) {
                    case_word_arm(&captures[1], &format!("{}{comment}", &captures[2]), found);
                    read = true;
                }
            }
        }
        read
    }
}

fn is_esac(text: &str) -> bool {
    text == "esac" || text.starts_with("esac ") || text.starts_with("esac;")
}

/// What one line of a script's code adds: `case` arms, parser calls and
/// `getopts` letters. `rest` starts at this line, for calls that wrap.
pub(super) fn source_line(line: &str, rest: &[&str], shell: &mut ShellState, found: &mut Found) {
    shell.track(line);
    if let Some(start) = CASE_START.captures(line) {
        let subject = shell.subject(&start[1]);
        shell.cases.push(subject);
        let after = start.get(0).map_or(line.len(), |matched| matched.end());
        shell.arms(&line[after..], found);
        return;
    }
    if shell.cases.is_empty() {
        if is_esac(line) {
            return;
        }
    } else if shell.arms(line, found) {
        return;
    }
    // A parser call inside a quoted string, as in
    // `printf '%s\n' "parser.add_argument('--x')"`, is text another command
    // prints, not a call.
    let call = PARSER_CALL
        .find_iter(line)
        .find(|matched| !inside_quotes(&line[..matched.start()]));
    if let Some(matched) = call {
        let commander_or_click = matched.as_str().starts_with('.');
        parser_call(
            &call_text(&line[matched.end()..], &rest[1..]),
            commander_or_click,
            found,
        );
    }
    for captures in COMPARED_OPTION.captures_iter(line) {
        if let Some(name) = (1..=4).find_map(|group| captures.get(group)) {
            found.option(name.as_str(), None, "");
        }
    }
    if let Some(captures) = GETOPTS.captures(line) {
        getopts_letters(&captures[1], found);
    }
}

/// Whether text ending here leaves a quoted string open, so what follows it
/// on the line is part of that string.
pub(super) fn inside_quotes(before: &str) -> bool {
    let mut open: Option<char> = None;
    let mut escaped = false;
    for c in before.chars() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if open == Some(c) {
            open = None;
        } else if open.is_none() && matches!(c, '"' | '\'' | '`') {
            open = Some(c);
        }
    }
    open.is_some()
}

/// `--repo|-r)` with what the arm does: an arm that reads `$2` or shifts
/// twice takes a value.
fn case_option_arm(arms: &str, body: &str, found: &mut Found) {
    let takes_value = arms.contains('=')
        || ["$2", "${2", "shift 2"]
            .iter()
            .any(|mark| body.contains(mark));
    let names: Vec<String> = arms
        .split('|')
        .map(|arm| arm.trim().trim_matches(|c: char| c == '"' || c == '\''))
        .map(|arm| arm.trim_end_matches('*').trim_end_matches('=').to_owned())
        .collect();
    let value = takes_value.then_some(VALUE_PLACEHOLDER);
    found.aliases(&names, value, trailing_comment(body));
}

/// `build|b)` under a `case` on the first argument: a subcommand.
fn case_word_arm(arms: &str, body: &str, found: &mut Found) {
    let description = trailing_comment(body);
    for arm in arms.split('|') {
        found.command(
            arm.trim().trim_matches(|c: char| c == '"' || c == '\''),
            description,
        );
    }
}

/// The text after a ` # ` comment on an arm, which scripts often use to say
/// what the arm does.
fn trailing_comment(body: &str) -> &str {
    body.split_once(" # ")
        .map_or("", |(_, comment)| py_strip(comment))
}

/// A parser call's arguments, joined across the next few lines when it wraps.
pub(super) fn call_text(first: &str, following: &[&str]) -> String {
    let mut text = first.to_owned();
    let mut depth: i32 = 1 + paren_balance(first);
    for line in following.iter().take(6) {
        if depth <= 0 {
            break;
        }
        text.push(' ');
        text.push_str(py_strip(line));
        depth += paren_balance(line);
    }
    text
}

fn paren_balance(text: &str) -> i32 {
    text.chars().fold(0, |depth, c| match c {
        '(' => depth + 1,
        ')' => depth - 1,
        _ => depth,
    })
}

/// `add_argument("-r", "--repo", help=...)`, `.option("-r, --repo <name>",
/// "Repository")` and `click.option("--repo", "-r")`. `commander_or_click` is
/// a `.option(` call: Commander names a value as `<name>` and otherwise takes
/// none, while Click passes keywords and takes a value unless `is_flag`.
fn parser_call(arguments: &str, commander_or_click: bool, found: &mut Found) {
    let mut names: Vec<String> = Vec::new();
    let mut value: Option<String> = None;
    let mut first_text: Option<String> = None;
    for captures in STRING_LITERAL.captures_iter(arguments) {
        let whole = captures.get(0).map_or(0, |m| m.start());
        let literal = captures
            .get(1)
            .or(captures.get(2))
            .map_or("", |m| m.as_str());
        let words: Vec<&str> = literal
            .split(|c: char| c.is_whitespace() || c == ',' || c == '|')
            .filter(|word| !word.is_empty())
            .collect();
        let names_option = words
            .first()
            .is_some_and(|word| is_option_name(word.split('=').next().unwrap_or("")));
        if names_option {
            for word in words {
                let name = word.split('=').next().unwrap_or("");
                if is_option_name(name) {
                    names.push(name.to_owned());
                } else if value.is_none() && word.starts_with(['<', '[']) {
                    value = Some(word.to_owned());
                }
            }
        } else if first_text.is_none()
            && !names.is_empty()
            && !arguments[..whole].trim_end().ends_with('=')
        {
            // A keyword's literal (`default="x"`) is not a description.
            first_text = Some(literal.to_owned());
        }
    }
    if names.is_empty() {
        return;
    }
    let keyword = |regex: &Regex| {
        regex
            .captures(arguments)
            .and_then(|captures| captures.get(1).or(captures.get(2)))
            .map(|m| m.as_str().to_owned())
    };
    let description = keyword(&HELP_KEYWORD).or(first_text).unwrap_or_default();
    let commander = commander_or_click && !arguments.contains('=');
    if value.is_none() && !commander && !FLAG_ACTION.is_match(arguments) {
        value = keyword(&METAVAR_KEYWORD).or_else(|| Some(VALUE_PLACEHOLDER.to_owned()));
    }
    found.aliases(&names, value.as_deref(), &description);
}

/// `getopts "rn:v"`: a letter followed by `:` takes a value.
fn getopts_letters(spec: &str, found: &mut Found) {
    let letters: Vec<char> = spec.chars().collect();
    for (at, letter) in letters.iter().enumerate() {
        if *letter == ':' {
            continue;
        }
        let takes_value = letters.get(at + 1) == Some(&':');
        found.option(
            &format!("-{letter}"),
            takes_value.then_some(VALUE_PLACEHOLDER),
            "",
        );
    }
}
