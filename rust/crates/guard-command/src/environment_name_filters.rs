//! Pipeline stages that render variable names without their values.
//!
//! `printenv` alone prints every value a process was given, so Guard reviews
//! it. An agent working out which variable a service reads asks for the list
//! of names often enough that reviewing the question stalls ordinary work,
//! so one shape of it is proven here instead.
//!
//! The shape is narrow on purpose. `printenv` ends every variable with a
//! newline, but a value may carry a newline of its own: a PEM key, a
//! certificate and a JSON credential all do. Each line after the first then
//! holds value bytes and no name, so a stage that keeps "the text before the
//! `=`" keeps secret text on those lines. `cut -d= -f1` prints such a line
//! whole, because it has no delimiter to cut at, and `awk -F= '{print $1}'`
//! prints the whole record for the same reason. Neither can prove the value
//! is gone, so neither is proven here.
//!
//! `grep -o` is different. It prints a match or nothing at all, so what it
//! renders is bounded by the pattern rather than by the line. The pattern is
//! accepted only when it is anchored at the start of the line, when every
//! alternative has to begin with a character the user spelled out, and when
//! every character it can match is an upper-case letter, a digit or `_`, the
//! characters a variable name is written in. Case folding (`-i`) is refused
//! for the same reason. A match is then the start of a line's leading run of
//! those characters: on a name line that is the name, and it stops at the
//! `=`. A line of value bytes matches only where the value itself holds a
//! newline followed by the spelled prefix, and even then the match stops at
//! the first lower-case letter, `+`, `/` or `=`, so the base64 body of a key
//! or certificate, which mixes cases on every line, cannot be read through
//! it.

use crate::codex_output_py::py_strip;
use crate::sfrs_patterns::SHELL_COMMAND_SEPARATORS;
use crate::sfrs_shell_tokens::{
    iter_shell_command_segments, shell_segment_primary_command, split_shell_parts,
};

/// A token with one surrounding pair of quotes removed, or `None` when a
/// quote is left inside it. Guard would otherwise read `-F'"='` as the `=`
/// this proof rests on, when the shell passes a two-character separator the
/// proof says nothing about.
pub(crate) fn unquoted(token: &str) -> Option<String> {
    let trimmed = py_strip(token);
    let mut chars = trimmed.chars();
    let inner = match (chars.next(), chars.next_back()) {
        (Some(open @ ('\'' | '"')), Some(close)) if open == close => chars.as_str(),
        _ => trimmed,
    };
    (!inner.contains(['\'', '"'])).then(|| inner.to_owned())
}

/// Every argument with its quotes removed, or `None` when one of them keeps
/// a quote and so cannot be read with certainty.
fn unquoted_arguments(arguments: &[String]) -> Option<Vec<String>> {
    arguments
        .iter()
        .map(|argument| unquoted(argument))
        .collect()
}

/// Whether `c` is one of the characters a variable name is written in. Lower
/// case is left out on purpose: a value line of base64 or hex mixes cases,
/// and a match that may read lower case could follow one to its end.
fn is_name_char(c: char) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'
}

/// Whether a bracket expression matches only characters a variable name is
/// written in. A negated class matches far more, and so does a range that
/// leaves the upper-case letters or the digits, such as `[0-A]` or `[A-z]`.
fn class_stays_in_a_name(body: &str) -> bool {
    let chars: Vec<char> = body.chars().collect();
    if chars.first() == Some(&'^') || chars.is_empty() {
        return false;
    }
    let mut index = 0;
    while index < chars.len() {
        let low = chars[index];
        if !is_name_char(low) {
            return false;
        }
        if index + 2 < chars.len() && chars[index + 1] == '-' {
            let high = chars[index + 2];
            let same_kind = (low.is_ascii_uppercase() && high.is_ascii_uppercase())
                || (low.is_ascii_digit() && high.is_ascii_digit());
            if !same_kind || low > high {
                return false;
            }
            index += 3;
            continue;
        }
        index += 1;
    }
    true
}

/// A walk over an extended regular expression, far enough into it to answer
/// two questions: can any match reach past the name, and must every match
/// begin with a character the pattern spells out.
struct PatternWalk<'a> {
    chars: &'a [char],
    index: usize,
}

/// Whether every match of the piece just read has to begin with a literal
/// character. A piece that may begin with a bracket expression does not, so
/// it could start a match on a line that carries no name at all.
type LiteralLed = bool;

impl PatternWalk<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.index).copied()
    }

    /// `sequence ( '|' sequence )*`, read only inside a group. ERE binds `|`
    /// loosest, so `^A|B` anchors only its first alternative; the top level is
    /// therefore a single sequence, and a `|` there stops the walk short of the
    /// end and refuses the pattern. Inside a group every alternative sits at
    /// the position the anchored sequence puts it, and the group is
    /// literal-led only when all of them are.
    fn alternation(&mut self) -> Option<LiteralLed> {
        let mut literal_led = self.sequence()?;
        while self.peek() == Some('|') {
            self.index += 1;
            literal_led &= self.sequence()?;
        }
        Some(literal_led)
    }

    /// `item*`, up to the end of the pattern or of this alternative.
    fn sequence(&mut self) -> Option<LiteralLed> {
        let mut first = None;
        while !matches!(self.peek(), None | Some('|') | Some(')')) {
            let item = self.item()?;
            first.get_or_insert(item);
        }
        Some(first.unwrap_or(false))
    }

    /// `atom quantifier?`. A quantifier that allows the atom to be absent
    /// leaves the match free to begin at whatever follows it, so the item no
    /// longer pins the start of the match to a literal.
    fn item(&mut self) -> Option<LiteralLed> {
        let atom = self.atom()?;
        match self.peek() {
            Some('*' | '?') => {
                self.index += 1;
                Some(false)
            }
            Some('+') => {
                self.index += 1;
                Some(atom)
            }
            _ => Some(atom),
        }
    }

    fn atom(&mut self) -> Option<LiteralLed> {
        match self.peek()? {
            '(' => {
                self.index += 1;
                let inner = self.alternation()?;
                if self.peek() != Some(')') {
                    return None;
                }
                self.index += 1;
                Some(inner)
            }
            '[' => {
                let close = self.chars[self.index..].iter().position(|c| *c == ']')?;
                let body: String = self.chars[self.index + 1..self.index + close]
                    .iter()
                    .collect();
                if !class_stays_in_a_name(&body) {
                    return None;
                }
                self.index += close + 1;
                Some(false)
            }
            c if is_name_char(c) => {
                self.index += 1;
                Some(true)
            }
            _ => None,
        }
    }
}

/// Whether every match of `pattern` stays inside a variable name and has to
/// start with a character the pattern spells out. A wildcard, an escape, a
/// negated class, a lower-case character, an unbalanced group or a top-level
/// `|` refuses the pattern, and so does one whose match could begin anywhere
/// on a line.
pub(crate) fn pattern_matches_inside_a_name(pattern: &str) -> bool {
    let Some(rest) = pattern.strip_prefix('^') else {
        return false;
    };
    let chars: Vec<char> = rest.chars().collect();
    let mut walk = PatternWalk {
        chars: &chars,
        index: 0,
    };
    let Some(literal_led) = walk.sequence() else {
        return false;
    };
    walk.index == chars.len() && literal_led
}

/// `grep -oE '^PREFIX[A-Z_]*'`: `-o` prints the match alone, and the pattern
/// can only match inside a variable name, so no value is rendered.
fn grep_prints_name_matches_only(args: &[&str]) -> bool {
    let mut only_matching = false;
    let mut pattern: Option<&str> = None;
    let mut index = 0;
    while index < args.len() {
        let arg = args[index];
        index += 1;
        match arg {
            "--only-matching" => {
                only_matching = true;
                continue;
            }
            "--extended-regexp" => continue,
            "-e" | "--regexp" => {
                let Some(value) = args.get(index).copied() else {
                    return false;
                };
                index += 1;
                if pattern.replace(value).is_some() {
                    return false;
                }
                continue;
            }
            _ => {}
        }
        if let Some(cluster) = arg
            .strip_prefix('-')
            .filter(|rest| !rest.is_empty() && !rest.starts_with('-'))
        {
            for letter in cluster.chars() {
                match letter {
                    'o' => only_matching = true,
                    'E' | 'a' | 'h' | 's' => {}
                    _ => return false,
                }
            }
            continue;
        }
        if arg.starts_with('-') || pattern.replace(arg).is_some() {
            return false;
        }
    }
    only_matching && pattern.is_some_and(pattern_matches_inside_a_name)
}

/// Whether a pipeline stage renders only the names of the variables that
/// reach it. Such a stage drops everything after the `=` before any later
/// stage sees it, so no command further down the pipeline can print a value.
fn renders_only_variable_names(segment: &[String]) -> bool {
    let Some(command) = segment_bare_command(segment) else {
        return false;
    };
    stage_renders_only_variable_names(&command, &segment[1..])
}

/// Whether a stage named `command`, given `arguments`, renders only the
/// names of the variables that reach it.
pub(crate) fn stage_renders_only_variable_names(command: &str, arguments: &[String]) -> bool {
    let Some(args) = unquoted_arguments(arguments) else {
        return false;
    };
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match command {
        "grep" | "egrep" => grep_prints_name_matches_only(&args),
        _ => false,
    }
}

/// Whether `text` counts a number of options and nothing more: `20`, `+5`.
fn is_count(text: &str) -> bool {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
}

/// Whether every argument is one of the named flags, taking no value of its
/// own. A flag that carries a value can name a file to write, a file to read
/// or a program to run -- `sort -o NAME`, `sort --files0-from=LIST` and
/// `sort --compress-program=sh` all do -- so only valueless flags pass.
fn flags_only(args: &[&str], short: &str, long: &[&str]) -> bool {
    args.iter().all(|arg| {
        if arg.starts_with("--") {
            return long.contains(arg);
        }
        match arg.strip_prefix('-') {
            Some(cluster) if !cluster.is_empty() => {
                cluster.chars().all(|letter| short.contains(letter))
            }
            _ => false,
        }
    })
}

/// `head` and `tail` take a count, so they are read apart from the stages
/// whose flags carry no value at all. The count is the only value accepted.
fn count_flags_only(args: &[&str]) -> bool {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index];
        index += 1;
        if let Some(value) = arg
            .strip_prefix("--lines=")
            .or_else(|| arg.strip_prefix("--bytes="))
        {
            if !is_count(value) {
                return false;
            }
            continue;
        }
        if matches!(arg, "-n" | "-c" | "--lines" | "--bytes") {
            let Some(value) = args.get(index) else {
                return false;
            };
            if !is_count(value) {
                return false;
            }
            index += 1;
            continue;
        }
        let Some(rest) = arg
            .strip_prefix('-')
            .filter(|rest| !rest.is_empty() && !rest.starts_with('-'))
        else {
            return false;
        };
        if !is_count(rest.strip_prefix(['n', 'c']).unwrap_or(rest)) {
            return false;
        }
    }
    true
}

const SORT_FLAGS: &str = "ubdfinrsVhz";
const SORT_LONG_FLAGS: &[&str] = &[
    "--unique",
    "--reverse",
    "--ignore-case",
    "--numeric-sort",
    "--general-numeric-sort",
    "--human-numeric-sort",
    "--version-sort",
    "--dictionary-order",
    "--ignore-leading-blanks",
    "--stable",
    "--zero-terminated",
];
const UNIQ_FLAGS: &str = "cdui";
const UNIQ_LONG_FLAGS: &[&str] = &["--count", "--repeated", "--unique", "--ignore-case"];
const WC_FLAGS: &str = "lwmc";
const WC_LONG_FLAGS: &[&str] = &["--lines", "--words", "--chars", "--bytes"];
const CAT_FLAGS: &str = "nbsETAve";
const CAT_LONG_FLAGS: &[&str] = &[
    "--number",
    "--number-nonblank",
    "--squeeze-blank",
    "--show-ends",
    "--show-tabs",
    "--show-all",
    "--show-nonprinting",
];

/// Whether a stage placed after the name filter can only reorder, count or
/// trim the lines it is handed. The values are gone by then, so such a stage
/// renders no secret; one that runs a program or names a file is refused.
pub(crate) fn stage_only_reorders_lines(command: &str, arguments: &[String]) -> bool {
    let Some(args) = unquoted_arguments(arguments) else {
        return false;
    };
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match command {
        "sort" => flags_only(&args, SORT_FLAGS, SORT_LONG_FLAGS),
        "uniq" => flags_only(&args, UNIQ_FLAGS, UNIQ_LONG_FLAGS),
        "wc" => flags_only(&args, WC_FLAGS, WC_LONG_FLAGS),
        "cat" => flags_only(&args, CAT_FLAGS, CAT_LONG_FLAGS),
        "head" | "tail" => count_flags_only(&args),
        "nl" => args.is_empty(),
        _ => false,
    }
}

/// Whether a bare environment dump names `command` and carries no operand.
pub(crate) fn stage_is_plain_env_dump(command: &str, arguments: &[String]) -> bool {
    matches!(command, "printenv" | "env") && arguments.is_empty()
}

/// The command a segment runs, when the segment names it plainly: the very
/// first token, spelled as the command's own name. A leading assignment, a
/// wrapper or a path such as `/tmp/sort` leaves the proof reading one
/// program while the shell runs another, so each one refuses the segment.
fn segment_bare_command(segment: &[String]) -> Option<String> {
    let (command, index) = shell_segment_primary_command(segment);
    let command = command?;
    (index == Some(0) && segment.first() == Some(&command)).then_some(command)
}

/// Whether the segment is a bare environment dump, with no variable named
/// and nothing else on it: `printenv` or `env` alone.
fn segment_is_plain_env_dump(segment: &[String]) -> bool {
    segment.len() == 1
        && segment_bare_command(segment)
            .is_some_and(|command| matches!(command.as_str(), "printenv" | "env"))
}

/// For each segment [`iter_shell_command_segments`] returns, whether the
/// separator that ended it was a pipe. The walk matches that function's, so
/// the two line up position by position.
pub(crate) fn segments_piped_into_next(parts: &[String]) -> Vec<bool> {
    let mut links = Vec::new();
    let mut open = false;
    for part in parts {
        let token = py_strip(part);
        if token.is_empty() {
            continue;
        }
        if SHELL_COMMAND_SEPARATORS.contains(&token) {
            if open {
                links.push(matches!(token, "|" | "|&"));
                open = false;
            }
            continue;
        }
        open = true;
    }
    if open {
        links.push(false);
    }
    links
}

/// Whether a stage can only reorder, count or trim the lines it is handed.
fn segment_only_reorders_lines(segment: &[String]) -> bool {
    segment_bare_command(segment)
        .is_some_and(|command| stage_only_reorders_lines(&command, &segment[1..]))
}

/// Whether the dump at `index` is piped straight into a stage that renders
/// variable names alone, and every stage piped on from there can only
/// reorder, count or trim the names it is handed.
pub(crate) fn dump_feeds_a_name_filter(
    segments: &[Vec<String>],
    piped: &[bool],
    index: usize,
) -> bool {
    if !piped.get(index).copied().unwrap_or(false) || !segment_is_plain_env_dump(&segments[index]) {
        return false;
    }
    let Some(filter) = segments.get(index + 1) else {
        return false;
    };
    if !renders_only_variable_names(filter) {
        return false;
    }
    let mut stage = index + 1;
    while piped.get(stage).copied().unwrap_or(false) {
        let Some(next) = segments.get(stage + 1) else {
            return false;
        };
        if !segment_only_reorders_lines(next) {
            return false;
        }
        stage += 1;
    }
    true
}

/// Whether the single `printenv` in `text` is piped into a stage that
/// renders only variable names. Listing the names a process was given shows
/// no secret, and an agent asks for that list often.
pub(crate) fn printenv_renders_only_names(text: &str) -> bool {
    if text.matches("printenv").count() != 1 {
        return false;
    }
    let parts = split_shell_parts(text);
    let segments = iter_shell_command_segments(&parts);
    let piped = segments_piped_into_next(&parts);
    (0..segments.len()).any(|index| dump_feeds_a_name_filter(&segments, &piped, index))
}

#[cfg(test)]
#[path = "environment_name_filters_tests.rs"]
mod tests;
