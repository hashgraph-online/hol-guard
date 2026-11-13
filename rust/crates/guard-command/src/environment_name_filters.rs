//! Listings of environment variable names that never render a value.
//!
//! `printenv` and `env` print every variable as `NAME=value` followed by a
//! newline, but a value may carry newlines of its own: a PEM key, a
//! certificate and a JSON credential all do. Every line after the first one
//! of such a value then reaches the next stage looking like any other line,
//! so no filter over that output can tell a name from value bytes. `cut -d=
//! -f1` and `awk -F= '{print $1}'` print such a line whole, and `grep -o`
//! with an anchored, upper-case pattern prints the part of it that matches:
//! a value holding a newline and then an access key id comes out of
//! `printenv | grep -oE '^AKIA[A-Z0-9_]*'` as the whole key id. A spelled
//! prefix is no boundary when secrets carry a well-known one, so a dump
//! piped into a filter keeps its review.
//!
//! A listing is proven only when the names are produced without the values
//! ever being rendered. `awk 'BEGIN { for (name in ENVIRON) print name }'`
//! walks the keys of awk's environment array and prints each key: the
//! program runs before any input is read, names no file, and never indexes
//! the array, so no value reaches its output. The program is read token by
//! token against that one shape and refused on any other character.

use crate::codex_output_py::py_strip;

/// A token with one surrounding pair of quotes removed, or `None` when a
/// quote is left inside it. A quote left inside changes what the shell hands
/// the program, so the token is not read at all.
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

/// Whether a stage placed after the listing can only reorder, count or trim
/// the names it is handed. Such a stage renders nothing it was not given; one
/// that runs a program or names a file is refused.
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

/// One lexical piece of an awk program: a name or a single punctuation mark.
fn awk_tokens(program: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut chars = program.chars().peekable();
    while let Some(&next) = chars.peek() {
        if matches!(next, ' ' | '\t' | '\n') {
            chars.next();
        } else if matches!(next, '{' | '}' | '(' | ')' | ';') {
            tokens.push(next.to_string());
            chars.next();
        } else if next.is_ascii_alphabetic() || next == '_' {
            let mut word = String::new();
            while let Some(&letter) = chars.peek() {
                if !(letter.is_ascii_alphanumeric() || letter == '_') {
                    break;
                }
                word.push(letter);
                chars.next();
            }
            tokens.push(word);
        } else {
            return None;
        }
    }
    Some(tokens)
}

/// Whether `name` can be an awk loop variable written in lower case. Upper
/// case is left to awk's own variables, such as `ENVIRON` and `ORS`.
fn is_loop_variable(name: &str) -> bool {
    let mut letters = name.chars();
    letters
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first == '_')
        && letters
            .all(|letter| letter.is_ascii_lowercase() || letter.is_ascii_digit() || letter == '_')
}

/// Whether `program` is `BEGIN { for (name in ENVIRON) print name }`, with
/// any spacing and an optional `;` after the `print`. The loop variable must
/// be the one printed, so `print name, ENVIRON[name]` and `print ENVIRON[name]`
/// are refused along with every other program.
pub(crate) fn awk_program_lists_environment_names(program: &str) -> bool {
    let Some(tokens) = awk_tokens(program) else {
        return false;
    };
    let tokens: Vec<&str> = tokens.iter().map(String::as_str).collect();
    let body = match tokens.as_slice() {
        [body @ .., ";", "}"] | [body @ .., "}"] => body,
        _ => return false,
    };
    let ["BEGIN", "{", "for", "(", loop_variable, "in", "ENVIRON", ")", "print", printed] = body
    else {
        return false;
    };
    is_loop_variable(loop_variable) && loop_variable == printed
}

/// Whether the arguments of an `awk` stage are exactly one program that lists
/// environment variable names. Any option, such as `-f FILE` or `-v`, and any
/// operand naming a file refuse the stage.
pub(crate) fn stage_lists_environment_names(command: &str, arguments: &[String]) -> bool {
    let [program] = arguments else {
        return false;
    };
    command == "awk"
        && unquoted(program).is_some_and(|program| awk_program_lists_environment_names(&program))
}

#[cfg(test)]
#[path = "environment_name_filters_tests.rs"]
mod tests;
