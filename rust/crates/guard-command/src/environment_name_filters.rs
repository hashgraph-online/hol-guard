//! Pipeline stages that render variable names without their values.
//!
//! `printenv` alone prints every value a process was given, so Guard reviews
//! it. Piped into a stage that keeps only the text before the `=`, it prints
//! a list of names and no secret at all, and an agent asks for that list
//! often enough that reviewing it stalls ordinary work. Each screen below
//! refuses anything it cannot prove drops the value.

use crate::hook_adapter_pytext::py_strip;
use crate::sfrs_patterns::SHELL_COMMAND_SEPARATORS;
use crate::sfrs_shell_tokens::{
    iter_shell_command_segments, shell_segment_primary_command, split_shell_parts,
};

/// A token with its surrounding quotes removed, so `-d'='` and `-d=` read
/// alike whichever way the shell splitter handed them over.
pub(crate) fn bare(token: &str) -> String {
    py_strip(token).replace(['\'', '"'], "")
}

/// An option token split into its name and the value attached to it:
/// `--fields=1` and `-f1` both carry their value, `-f` does not.
fn split_option(arg: &str) -> (&str, Option<&str>) {
    if let Some(rest) = arg.strip_prefix("--") {
        return match rest.split_once('=') {
            Some((name, value)) => (&arg[..name.len() + 2], Some(value)),
            None => (arg, None),
        };
    }
    if arg.len() > 2 && arg.starts_with('-') {
        return (&arg[..2], Some(&arg[2..]));
    }
    (arg, None)
}

fn option_value<'a>(
    inline: Option<&'a str>,
    args: &[&'a str],
    index: &mut usize,
) -> Option<&'a str> {
    if inline.is_some() {
        return inline;
    }
    let value = args.get(*index).copied();
    if value.is_some() {
        *index += 1;
    }
    value
}

/// `cut -d= -f1`: the delimiter is the `=` that ends a variable name, and
/// only the field before it is printed. Any other field, delimiter or
/// operand leaves a value reachable.
fn cut_prints_first_field(args: &[&str]) -> bool {
    let mut delimiter = None;
    let mut fields = None;
    let mut index = 0;
    while index < args.len() {
        let arg = args[index];
        index += 1;
        let (name, inline) = split_option(arg);
        let holder = match name {
            "-d" | "--delimiter" => &mut delimiter,
            "-f" | "--fields" => &mut fields,
            _ => return false,
        };
        let Some(value) = option_value(inline, args, &mut index) else {
            return false;
        };
        if holder.replace(value).is_some() {
            return false;
        }
    }
    delimiter == Some("=") && fields == Some("1")
}

/// `awk -F= '{print $1}'`: the record splits on the `=`, and the program
/// prints the first field and nothing else.
fn awk_prints_first_field(args: &[&str]) -> bool {
    let mut separator = None;
    let mut program: Option<&str> = None;
    let mut index = 0;
    while index < args.len() {
        let arg = args[index];
        index += 1;
        if arg.starts_with('-') && arg != "-" {
            let (name, inline) = split_option(arg);
            if !matches!(name, "-F" | "--field-separator") {
                return false;
            }
            let Some(value) = option_value(inline, args, &mut index) else {
                return false;
            };
            if separator.replace(value).is_some() {
                return false;
            }
            continue;
        }
        if program.replace(arg).is_some() {
            return false;
        }
    }
    separator == Some("=")
        && program.is_some_and(|text| {
            text.chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                == "{print$1}"
        })
}

/// Whether a bracket expression can match the `=` that ends a variable name.
/// A negated class matches it, and so would a range that spans it, such as
/// `[0-A]`.
fn class_excludes_equals(body: &str) -> bool {
    let chars: Vec<char> = body.chars().collect();
    if chars.first() == Some(&'^') || chars.is_empty() {
        return false;
    }
    let mut index = 0;
    while index < chars.len() {
        let low = chars[index];
        if !low.is_ascii_alphanumeric() && low != '_' {
            return false;
        }
        if index + 2 < chars.len() && chars[index + 1] == '-' {
            let high = chars[index + 2];
            if !high.is_ascii_alphanumeric() || low > high || (low..=high).contains(&'=') {
                return false;
            }
            index += 3;
            continue;
        }
        index += 1;
    }
    true
}

/// Whether every match of `pattern` stays inside a variable name: it is
/// anchored at the start of the line, and nothing in it can match the `=`
/// that ends the name. A wildcard, an escape or a negated class could reach
/// past it, so each one refuses the pattern.
fn pattern_matches_inside_a_name(pattern: &str) -> bool {
    let Some(rest) = pattern.strip_prefix('^') else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    let chars: Vec<char> = rest.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        match chars[index] {
            '[' => {
                let Some(close) = chars[index..].iter().position(|c| *c == ']') else {
                    return false;
                };
                let body: String = chars[index + 1..index + close].iter().collect();
                if !class_excludes_equals(&body) {
                    return false;
                }
                index += close + 1;
            }
            c if c.is_ascii_alphanumeric() || c == '_' => index += 1,
            '(' | ')' | '|' | '*' | '+' | '?' => index += 1,
            _ => return false,
        }
    }
    true
}

/// `grep -oE '^PREFIX[A-Z_]*'`: `-o` prints the match alone, and the
/// pattern can only match inside a variable name, so no value is rendered.
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
                    'E' | 'i' | 'a' | 'h' | 's' => {}
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
    let (Some(command), Some(index)) = shell_segment_primary_command(segment) else {
        return false;
    };
    stage_renders_only_variable_names(&command, &segment[index + 1..])
}

/// Whether a stage named `command`, given `arguments`, renders only the
/// names of the variables that reach it.
pub(crate) fn stage_renders_only_variable_names(command: &str, arguments: &[String]) -> bool {
    let args: Vec<String> = arguments.iter().map(|arg| bare(arg)).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match command {
        "cut" => cut_prints_first_field(&args),
        "awk" | "gawk" | "mawk" => awk_prints_first_field(&args),
        "grep" | "egrep" => grep_prints_name_matches_only(&args),
        _ => false,
    }
}

/// Whether a stage placed after the name filter can only reorder, count or
/// trim the lines it is handed. The values are gone by then, so such a stage
/// renders no secret; one that runs a program or names a file is refused.
pub(crate) fn stage_only_reorders_lines(command: &str, arguments: &[String]) -> bool {
    matches!(
        command,
        "sort" | "uniq" | "head" | "tail" | "wc" | "nl" | "cat"
    ) && arguments
        .iter()
        .all(|argument| bare(argument).starts_with('-'))
}

/// Whether a bare environment dump names `command` and carries no operand.
pub(crate) fn stage_is_plain_env_dump(command: &str, arguments: &[String]) -> bool {
    matches!(command, "printenv" | "env") && arguments.is_empty()
}

/// Whether the segment is a bare environment dump, with no variable named
/// and nothing else on it: `printenv` or `env` alone.
fn segment_is_plain_env_dump(segment: &[String]) -> bool {
    let (Some(command), Some(index)) = shell_segment_primary_command(segment) else {
        return false;
    };
    matches!(command.as_str(), "printenv" | "env") && segment.len() == index + 1
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

/// Whether the dump at `index` is piped straight into a stage that renders
/// variable names alone.
pub(crate) fn dump_feeds_a_name_filter(
    segments: &[Vec<String>],
    piped: &[bool],
    index: usize,
) -> bool {
    piped.get(index).copied().unwrap_or(false)
        && segment_is_plain_env_dump(&segments[index])
        && segments
            .get(index + 1)
            .is_some_and(|next| renders_only_variable_names(next))
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
