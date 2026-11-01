//! Argument parsers for the read-only pipe filters (`cat`, `head`, `tail`,
//! `nl`, `wc`, `sed`).

use std::sync::OnceLock;

use regex::Regex;

use crate::codex_output_py::py_strip;

pub(crate) const READ_ONLY_PIPE_FILTERS: &[&str] = &["cat", "head", "nl", "tail", "sed", "wc"];

const NL_VALUE_OPTIONS: &[&str] = &[
    "-b",
    "--body-numbering",
    "-d",
    "--section-delimiter",
    "-f",
    "--footer-numbering",
    "-h",
    "--header-numbering",
    "-i",
    "--line-increment",
    "-l",
    "--join-blank-lines",
    "-n",
    "--number-format",
    "-s",
    "--number-separator",
    "-v",
    "--starting-line-number",
    "-w",
    "--number-width",
];

const WC_BOOLEAN_OPTIONS: &[&str] = &[
    "-c",
    "--bytes",
    "-m",
    "--chars",
    "-l",
    "--lines",
    "-L",
    "--max-line-length",
    "-w",
    "--words",
];

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static pattern"))
}

fn full(cell: &'static OnceLock<Regex>, pattern: &str, text: &str) -> bool {
    regex(cell, &format!("^(?:{pattern})$")).is_match(text)
}

/// `re.fullmatch(r"\d{1,6}", value.strip())`.
pub(crate) fn count_arg_is_bounded(value: &str) -> bool {
    static CELL: OnceLock<Regex> = OnceLock::new();
    full(&CELL, r"\d{1,6}", py_strip(value))
}

/// `_codex_cat_targets`.
pub(crate) fn cat_targets(args: &[String]) -> Vec<String> {
    let mut targets = Vec::new();
    let mut after_terminator = false;
    for arg in args {
        if after_terminator {
            targets.push(arg.clone());
            continue;
        }
        if arg == "--" {
            after_terminator = true;
            continue;
        }
        if arg == "-" || arg.starts_with('-') {
            continue;
        }
        targets.push(arg.clone());
    }
    targets
}

/// `_codex_nl_targets`; `None` rejects the arguments.
pub(crate) fn nl_targets(args: &[String]) -> Option<Vec<String>> {
    static CELL: OnceLock<Regex> = OnceLock::new();
    let mut targets = Vec::new();
    let mut skip_value = false;
    let mut after_options = false;
    for arg in args {
        if skip_value {
            skip_value = false;
            continue;
        }
        if after_options {
            targets.push(arg.clone());
            continue;
        }
        if arg == "--" {
            after_options = true;
            continue;
        }
        if NL_VALUE_OPTIONS.contains(&arg.as_str()) {
            skip_value = true;
            continue;
        }
        if NL_VALUE_OPTIONS
            .iter()
            .any(|option| option.starts_with("--") && arg.starts_with(&format!("{option}=")))
        {
            continue;
        }
        if full(&CELL, r"-[bdfhilnsvw].+", arg) {
            continue;
        }
        if arg == "-" || arg.starts_with('-') {
            return None;
        }
        targets.push(arg.clone());
    }
    if skip_value || targets.len() > 1 {
        return None;
    }
    Some(targets)
}

/// `_codex_wc_targets`.
pub(crate) fn wc_targets(args: &[String]) -> Option<Vec<String>> {
    static CELL: OnceLock<Regex> = OnceLock::new();
    let mut targets = Vec::new();
    let mut after_options = false;
    for arg in args {
        if after_options {
            targets.push(arg.clone());
            continue;
        }
        if arg == "--" {
            after_options = true;
            continue;
        }
        if WC_BOOLEAN_OPTIONS.contains(&arg.as_str()) || full(&CELL, r"-[cmlLw]+", arg) {
            continue;
        }
        if arg == "-" || arg.starts_with('-') {
            return None;
        }
        targets.push(arg.clone());
    }
    Some(targets)
}

/// `_parse_codex_head_tail_args`: `(targets, valid, skip_next)`.
pub(crate) fn parse_head_tail_args(args: &[String]) -> (Vec<String>, bool, bool) {
    static CELL: OnceLock<Regex> = OnceLock::new();
    let mut targets = Vec::new();
    let mut skip_next = false;
    let mut after_terminator = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            if !count_arg_is_bounded(arg) {
                return (Vec::new(), false, false);
            }
            continue;
        }
        if after_terminator {
            targets.push(arg.clone());
            continue;
        }
        if arg == "--" {
            after_terminator = true;
            continue;
        }
        if matches!(arg.as_str(), "-n" | "--lines" | "-c" | "--bytes") {
            skip_next = true;
            continue;
        }
        if arg.starts_with("--lines=") || arg.starts_with("--bytes=") {
            let value = arg.split_once('=').map_or("", |(_, value)| value);
            if !count_arg_is_bounded(value) {
                return (Vec::new(), false, false);
            }
            continue;
        }
        if full(&CELL, r"-\d{1,6}", arg) {
            continue;
        }
        if arg.starts_with('-') {
            return (Vec::new(), false, false);
        }
        targets.push(arg.clone());
    }
    (targets, true, skip_next)
}

/// `_CodexSedReadOnlyArgs`.
pub(crate) struct SedArgs {
    pub(crate) scripts: Vec<String>,
    pub(crate) targets: Vec<String>,
    pub(crate) saw_print_suppression: bool,
}

/// `_parse_codex_sed_read_only_args`.
pub(crate) fn parse_sed_args(args: &[String]) -> Option<SedArgs> {
    let mut scripts: Vec<String> = Vec::new();
    let mut targets = Vec::new();
    let mut skip_next_script = false;
    let mut after_terminator = false;
    let mut saw_print_suppression = false;
    for arg in args {
        if skip_next_script {
            skip_next_script = false;
            scripts.push(arg.clone());
            continue;
        }
        if after_terminator {
            targets.push(arg.clone());
            continue;
        }
        if arg == "--" {
            after_terminator = true;
            continue;
        }
        if arg == "-i"
            || arg == "--in-place"
            || arg.starts_with("-i")
            || arg.starts_with("--in-place=")
        {
            return None;
        }
        if matches!(arg.as_str(), "-n" | "--quiet" | "--silent") {
            saw_print_suppression = true;
            continue;
        }
        if arg == "-e" || arg == "--expression" {
            skip_next_script = true;
            continue;
        }
        if arg.starts_with("-e") && arg.chars().count() > 2 {
            scripts.push(arg.chars().skip(2).collect());
            continue;
        }
        if let Some(script) = arg.strip_prefix("--expression=") {
            scripts.push(script.to_owned());
            continue;
        }
        if arg.starts_with('-') {
            return None;
        }
        if scripts.is_empty() {
            scripts.push(arg.clone());
            continue;
        }
        targets.push(arg.clone());
    }
    if skip_next_script || scripts.is_empty() {
        return None;
    }
    Some(SedArgs {
        scripts,
        targets,
        saw_print_suppression,
    })
}

/// `sed_script_is_bounded_print`.
pub(crate) fn sed_script_is_bounded_print(script: &str) -> bool {
    let stripped = py_strip(script);
    if stripped.is_empty() {
        return false;
    }
    stripped
        .split(';')
        .all(|part| sed_print_command_is_bounded(py_strip(part)))
}

fn sed_print_command_is_bounded(command: &str) -> bool {
    let Some(body) = command.strip_suffix('p') else {
        return false;
    };
    let body = py_strip(body);
    if body.is_empty() {
        return true;
    }
    let parts: Vec<&str> = body.split(',').collect();
    parts.len() <= 2 && parts.iter().all(|part| sed_address_is_bounded(part))
}

fn sed_address_is_bounded(value: &str) -> bool {
    static CELL: OnceLock<Regex> = OnceLock::new();
    let address = py_strip(value);
    address == "$" || full(&CELL, r"\d{1,6}", address) || sed_context_address_is_bounded(address)
}

/// A `/regex/` address: the spelling a reader uses to print the region around
/// a line it can name but has not counted, as in `sed -n '/fn main/,/^}/p'`.
///
/// Only the slash pair is read. An alternative `\%...%` delimiter, a negated
/// address, a second unescaped slash (which would end the address and leave
/// the rest a command of its own) and an empty pattern (sed's "reuse the last
/// regex", which this reading never saw) all stay unread, so a script that
/// spells one keeps its review.
fn sed_context_address_is_bounded(address: &str) -> bool {
    let Some(body) = address.strip_prefix('/') else {
        return false;
    };
    let body = body.strip_suffix(['I', 'M']).unwrap_or(body);
    let Some(pattern) = body.strip_suffix('/') else {
        return false;
    };
    if pattern.is_empty() {
        return false;
    }
    let mut escaped = false;
    for character in pattern.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '/' => return false,
            _ => {}
        }
    }
    // A trailing backslash escaped the closing delimiter, so the address the
    // line spells is not the one read here.
    !escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn parsers_follow_the_retired_python() {
        assert_eq!(cat_targets(&v(&["-n", "a", "--", "-b"])), v(&["a", "-b"]));
        assert_eq!(nl_targets(&v(&["-ba", "a.py"])), Some(v(&["a.py"])));
        assert_eq!(nl_targets(&v(&["-x", "a.py"])), None);
        assert_eq!(wc_targets(&v(&["-lw", "a.py"])), Some(v(&["a.py"])));
        assert_eq!(
            parse_head_tail_args(&v(&["-n", "5", "a"])),
            (v(&["a"]), true, false)
        );
        assert_eq!(
            parse_head_tail_args(&v(&["-n", "x", "a"])),
            (Vec::new(), false, false)
        );
        assert!(sed_script_is_bounded_print("1,20p"));
        assert!(!sed_script_is_bounded_print("1,2,3p"));
        assert!(!sed_script_is_bounded_print("w x"));
        let sed = parse_sed_args(&v(&["-n", "1,5p", "a.py"])).expect("sed");
        assert_eq!(sed.scripts, v(&["1,5p"]));
        assert!(sed.saw_print_suppression);
        assert!(parse_sed_args(&v(&["-i", "s/a/b/", "a"])).is_none());
    }

    #[test]
    fn a_slash_delimited_address_prints_a_named_region() {
        // The region a reader names rather than counts: both ends of the range
        // may be regexes, and either end may be a line number instead.
        assert!(sed_script_is_bounded_print("/fn main/,/^}/p"));
        assert!(sed_script_is_bounded_print("/needle/p"));
        assert!(sed_script_is_bounded_print("0,/needle/p"));
        assert!(sed_script_is_bounded_print("/needle/,$p"));
        assert!(sed_script_is_bounded_print("/needle/,20p"));
        // A pattern may hold an escaped delimiter, and may carry sed's own
        // case-insensitive and multiline flags.
        assert!(sed_script_is_bounded_print(r"/guard\/plugins/p"));
        assert!(sed_script_is_bounded_print("/needle/Ip"));
        assert!(sed_script_is_bounded_print("/needle/Mp"));
    }

    #[test]
    fn an_address_that_leaves_a_command_unread_keeps_its_review() {
        // A second unescaped slash ends the address, so `d` here is a delete
        // this reading never saw.
        assert!(!sed_script_is_bounded_print("/a/d/p"));
        // A trailing backslash escapes the closing delimiter, so the address
        // runs on past the text read above.
        assert!(!sed_script_is_bounded_print(r"/a\/p"));
        // An empty pattern reuses sed's last regex, which this reading never
        // saw either.
        assert!(!sed_script_is_bounded_print("//p"));
        // A negated address and an alternative delimiter are both unread.
        assert!(!sed_script_is_bounded_print("/a/!p"));
        assert!(!sed_script_is_bounded_print(r"\%a%p"));
        // A substitution still ends in `p` but is not an address at all.
        assert!(!sed_script_is_bounded_print("s/a/b/p"));
        // Three addresses are not a range.
        assert!(!sed_script_is_bounded_print("/a/,/b/,/c/p"));
    }
}
