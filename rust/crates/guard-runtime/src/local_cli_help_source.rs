//! The code lines of a script source that name its variations: shell `case`
//! arms, option parser calls (`add_argument`, `.option`), arguments compared
//! against an option, and `getopts` letters. Like the rest of the source read,
//! nothing here runs the script.

use std::sync::LazyLock;

use regex::Regex;

use super::super::{is_skipped, COMMAND_NAME};
use super::{
    is_option_name, Found, LocalCliCommand, DESCRIPTION_CHARS, MAX_SOURCE_COMMANDS,
    VALUE_PLACEHOLDER,
};
use crate::daemon_lifecycle_text::py_strip;

static CASE_OPTION_ARM: LazyLock<Regex> = LazyLock::new(|| {
    let arm = r#"["']?-{1,2}[A-Za-z0-9][A-Za-z0-9_-]*(?:=\*?)?["']?"#;
    Regex::new(&format!(r"^\(?\s*({arm}(?:\s*\|\s*{arm})*)\s*\)(.*)$")).unwrap()
});

static CASE_WORD_ARM: LazyLock<Regex> = LazyLock::new(|| {
    let arm = r#"["']?[A-Za-z][A-Za-z0-9_-]{0,40}["']?"#;
    Regex::new(&format!(r"^\(?\s*({arm}(?:\s*\|\s*{arm})*)\s*\)(.*)$")).unwrap()
});

/// `case "$1" in`, `case $1 in` or `case "${1:-}" in`: the first argument
/// picks a branch, so its plain-word arms are subcommands.
static CASE_FIRST_ARGUMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^case\s+"?\$\{?1(?::-[^}]*)?\}?"?\s+in\b"#).unwrap());

static CASE_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^case\s+\S+\s+in(?:\s|$)").unwrap());

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

static STRING_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""([^"\\]*)"|'([^'\\]*)'"#).unwrap());

static HELP_KEYWORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\bhelp\s*=\s*(?:"([^"\\]*)"|'([^'\\]*)')"#).unwrap());

static METAVAR_KEYWORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\bmetavar\s*=\s*(?:"([^"\\]*)"|'([^'\\]*)')"#).unwrap());

static FLAG_ACTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\baction\s*=\s*["'](?:store_true|store_false|store_const|count|help|version)["']|\bis_flag\s*=\s*True"#)
        .unwrap()
});

static GETOPTS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\bgetopts\s+["']?:?([A-Za-z0-9:]+)["']?"#).unwrap());

/// What one line of a script's code adds: `case` arms, parser calls and
/// `getopts` letters. `rest` starts at this line, for calls that wrap.
pub(super) fn source_line(
    line: &str,
    rest: &[&str],
    case_depth: &mut Vec<bool>,
    found: &mut Found,
) {
    if CASE_START.is_match(line) {
        case_depth.push(CASE_FIRST_ARGUMENT.is_match(line));
        return;
    }
    if line == "esac" || line.starts_with("esac ") || line.starts_with("esac;") {
        case_depth.pop();
        return;
    }
    if !case_depth.is_empty() {
        if let Some(captures) = CASE_OPTION_ARM.captures(line) {
            case_option_arm(&captures[1], &captures[2], found);
            return;
        }
        if case_depth.last() == Some(&true) {
            if let Some(captures) = CASE_WORD_ARM.captures(line) {
                case_word_arm(&captures[1], &captures[2], found);
                return;
            }
        }
    }
    if let Some(matched) = PARSER_CALL.find(line) {
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
    let description: String = trailing_comment(body)
        .chars()
        .take(DESCRIPTION_CHARS)
        .collect();
    for arm in arms.split('|') {
        let name = arm.trim().trim_matches(|c: char| c == '"' || c == '\'');
        let known = found.commands.iter().any(|command| command.name == name);
        if !COMMAND_NAME.is_match(name)
            || is_skipped(name)
            || known
            || found.commands.len() >= MAX_SOURCE_COMMANDS
        {
            continue;
        }
        found.commands.push(LocalCliCommand {
            command_id: name.to_owned(),
            name: name.to_owned(),
            usage: name.to_owned(),
            description: description.clone(),
            parent_id: None,
        });
    }
}

/// The text after a ` # ` comment on an arm, which scripts often use to say
/// what the arm does.
fn trailing_comment(body: &str) -> &str {
    body.split_once(" # ")
        .map_or("", |(_, comment)| py_strip(comment))
}

/// A parser call's arguments, joined across the next few lines when it wraps.
fn call_text(first: &str, following: &[&str]) -> String {
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
