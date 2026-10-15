//! Argument parsers for the read-only viewers (`cat`, `head`, `tail`, `nl`,
//! `wc`, `yq`, `sed`) and `git grep`, as used by the Codex tool-output review.

use std::sync::OnceLock;

use regex::Regex;

use crate::codex_output_py::py_strip;

pub(crate) const READ_ONLY_SEARCH_COMMANDS: &[&str] = &["fd", "rg", "grep", "egrep", "fgrep"];
pub(crate) const READ_ONLY_VIEW_COMMANDS: &[&str] =
    &["cat", "head", "nl", "tail", "sed", "wc", "yq"];
pub(crate) const READ_ONLY_PIPE_FILTERS: &[&str] = &["cat", "head", "nl", "tail", "sed", "wc"];
pub(crate) const READ_ONLY_SEARCH_WRAPPERS: &[&str] = &["bash", "sh", "zsh"];

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

const YQ_BOOLEAN_OPTIONS: &[&str] = &[
    "-C",
    "--colors",
    "-e",
    "--exit-status",
    "-M",
    "--no-colors",
    "-N",
    "--no-doc",
    "-n",
    "--null-input",
    "-P",
    "--prettyPrint",
    "-r",
    "--unwrapScalar",
];

const YQ_VALUE_OPTIONS: &[&str] = &["-I", "--indent", "-o", "--output-format"];

pub(crate) const GIT_GLOBAL_VALUE_FLAGS: &[&str] = &[
    "-c",
    "--config-env",
    "--exec-path",
    "--git-dir",
    "--work-tree",
    "--namespace",
];

pub(crate) const SAFE_GIT_GLOBAL_BOOLEAN_FLAGS: &[&str] = &[
    "--bare",
    "--glob-pathspecs",
    "--literal-pathspecs",
    "--no-literal-pathspecs",
    "--no-pager",
    "--noglob-pathspecs",
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

/// `_codex_yq_expression_and_targets`.
pub(crate) fn yq_expression_and_targets(args: &[String]) -> Option<(String, Vec<String>)> {
    static OPTION: OnceLock<Regex> = OnceLock::new();
    static EXTERNAL: OnceLock<Regex> = OnceLock::new();
    let mut positional = Vec::new();
    let mut skip_value = false;
    let mut after_options = false;
    for arg in args {
        if skip_value {
            skip_value = false;
            continue;
        }
        if after_options {
            positional.push(arg.clone());
            continue;
        }
        if arg == "--" {
            after_options = true;
            continue;
        }
        if YQ_BOOLEAN_OPTIONS.contains(&arg.as_str()) {
            continue;
        }
        if YQ_VALUE_OPTIONS.contains(&arg.as_str()) {
            skip_value = true;
            continue;
        }
        if YQ_VALUE_OPTIONS
            .iter()
            .any(|option| option.starts_with("--") && arg.starts_with(&format!("{option}=")))
        {
            continue;
        }
        if full(&OPTION, r"-(?:I\d+|o(?:json|props|xml|yaml))", arg) {
            continue;
        }
        if arg.starts_with('-') {
            return None;
        }
        positional.push(arg.clone());
    }
    if skip_value || positional.len() < 2 {
        return None;
    }
    let expression = positional[0].clone();
    let targets: Vec<String> = positional[1..].to_vec();
    let external = regex(
        &EXTERNAL,
        r"(?i)(?:\$ENV(?:\.|\b)|(?:^|[^A-Za-z0-9_])(?:env|strenv|envsubst|eval|load(?:_[A-Za-z0-9_]+)?)[\s\x1c-\x1f]*\()",
    );
    if !expression.starts_with('.')
        || ["#", "\n", "\r"]
            .iter()
            .any(|marker| expression.contains(marker))
        || external.is_match(&expression)
    {
        return None;
    }
    if targets.iter().any(|target| target == "-") {
        return None;
    }
    Some((expression, targets))
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
    address == "$" || full(&CELL, r"\d{1,6}", address)
}

/// `_git_grep_search_args`.
pub(crate) fn git_grep_search_args(args: &[String]) -> Option<Vec<String>> {
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "grep" {
            return Some(args[index + 1..].to_vec());
        }
        if GIT_GLOBAL_VALUE_FLAGS.contains(&arg.as_str()) {
            index += 2;
            continue;
        }
        if GIT_GLOBAL_VALUE_FLAGS
            .iter()
            .any(|flag| arg.starts_with(&format!("{flag}=")))
        {
            index += 1;
            continue;
        }
        if SAFE_GIT_GLOBAL_BOOLEAN_FLAGS.contains(&arg.as_str()) {
            index += 1;
            continue;
        }
        return None;
    }
    None
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
            yq_expression_and_targets(&v(&[".a", "x.yaml"])),
            Some((".a".to_owned(), v(&["x.yaml"])))
        );
        assert_eq!(
            yq_expression_and_targets(&v(&[".a | env(X)", "x.yaml"])),
            None
        );
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
        assert_eq!(
            git_grep_search_args(&v(&["--no-pager", "grep", "x"])),
            Some(v(&["x"]))
        );
        assert_eq!(git_grep_search_args(&v(&["log"])), None);
    }
}
