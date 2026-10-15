//! Read-only command filter validation (`read_only_filters.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::Path;
use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;

use crate::codex_output_args::sed_script_is_bounded_print;
use crate::codex_output_env::Ctx;
use crate::codex_output_py::{py_strip, PyPath};
use crate::false_positive_rules::{
    target_is_known_skill_doc_path, SOURCE_INSPECTION_BENIGN_DOTFILES,
    SOURCE_INSPECTION_EXTENSIONS, SOURCE_INSPECTION_PARTS, SOURCE_INSPECTION_SENSITIVE_PARTS,
};
use crate::hook_adapter_pytext::compile_fancy;
use crate::sfrs_search_filters::{
    read_only_lookup_filter_grep_args_are_safe, read_only_lookup_filter_rg_args_are_safe,
};

static DIGITS_1_6: LazyLock<FancyRegex> = LazyLock::new(|| compile_fancy(r"\A\d{1,6}\z"));
static DASH_DIGITS_1_6: LazyLock<FancyRegex> = LazyLock::new(|| compile_fancy(r"\A-\d{1,6}\z"));
static RG_CONFIG_ASSIGNMENT: LazyLock<FancyRegex> =
    LazyLock::new(|| compile_fancy(r"(?:^|[\s;&|])(?:export\s+)?RIPGREP_CONFIG_PATH\s*="));

pub(crate) fn matches_re(re: &FancyRegex, text: &str) -> bool {
    re.is_match(text).unwrap_or(false)
}

/// `_read_only_lookup_filter_segment_is_safe`.
pub(crate) fn read_only_lookup_filter_segment_is_safe(
    command: &str,
    args: &[String],
    home_dir: Option<&Path>,
    require_explicit_rg_no_config: bool,
    ctx: &Ctx,
) -> bool {
    match command {
        "cat" => {
            args.is_empty()
                || args
                    .iter()
                    .all(|arg| arg == "-" || (arg.starts_with('-') && !arg.contains('>')))
        }
        "sed" => read_only_lookup_sed_args_are_safe(args, false, home_dir),
        "head" | "tail" => read_only_lookup_head_tail_args_are_safe(args, false, home_dir),
        "grep" | "egrep" | "fgrep" => read_only_lookup_filter_grep_args_are_safe(args, home_dir),
        "rg" => {
            (!require_explicit_rg_no_config || args.iter().any(|arg| arg == "--no-config"))
                && read_only_lookup_filter_rg_args_are_safe(args, ctx)
        }
        _ => false,
    }
}

/// `_github_output_filter_segment_is_safe`.
pub(crate) fn github_output_filter_segment_is_safe(
    command: &str,
    args: &[String],
    home_dir: Option<&Path>,
    command_text: Option<&str>,
    ctx: &Ctx,
) -> bool {
    let require_no_config = command == "rg" && !ripgrep_configuration_is_absent(command_text, ctx);
    read_only_lookup_filter_segment_is_safe(command, args, home_dir, require_no_config, ctx)
}

/// `_ripgrep_configuration_is_absent`.
pub(crate) fn ripgrep_configuration_is_absent(command_text: Option<&str>, ctx: &Ctx) -> bool {
    let configured = ctx
        .host
        .env("RIPGREP_CONFIG_PATH")
        .is_some_and(|value| !value.is_empty());
    let Some(command_text) = command_text else {
        return false;
    };
    if configured {
        return false;
    }
    !matches_re(&RG_CONFIG_ASSIGNMENT, command_text)
}

/// `_read_only_lookup_may_be_primary`.
pub(crate) fn read_only_lookup_may_be_primary(
    known_command: bool,
    control_before: &[String],
    safe_pipe_filter: bool,
) -> bool {
    known_command && (control_before != ["|"] || safe_pipe_filter)
}

fn all_targets_safe(targets: &[String], home_dir: Option<&Path>) -> bool {
    targets
        .iter()
        .all(|target| read_only_lookup_target_is_safe(target, false, home_dir))
}

/// `_read_only_lookup_sed_args_are_safe`.
pub(crate) fn read_only_lookup_sed_args_are_safe(
    args: &[String],
    require_target: bool,
    home_dir: Option<&Path>,
) -> bool {
    let mut scripts: Vec<String> = Vec::new();
    let mut targets: Vec<String> = Vec::new();
    let mut saw_print_suppression = false;
    let mut skip_script = false;
    let mut after_options = false;
    for arg in args {
        let arg = arg.as_str();
        if skip_script {
            skip_script = false;
            scripts.push(arg.to_owned());
            continue;
        }
        if after_options {
            targets.push(arg.to_owned());
            continue;
        }
        if arg == "--" {
            after_options = true;
            continue;
        }
        if arg == "-i"
            || arg == "--in-place"
            || arg.starts_with("-i")
            || arg.starts_with("--in-place=")
        {
            return false;
        }
        if matches!(arg, "-n" | "--quiet" | "--silent") {
            saw_print_suppression = true;
            continue;
        }
        if arg == "-e" || arg == "--expression" {
            skip_script = true;
            continue;
        }
        if arg.starts_with("-e") && arg.chars().count() > 2 {
            scripts.push(arg[2..].to_owned());
            continue;
        }
        if let Some(script) = arg.strip_prefix("--expression=") {
            scripts.push(script.to_owned());
            continue;
        }
        if arg.starts_with('-') {
            return false;
        }
        if scripts.is_empty() {
            scripts.push(arg.to_owned());
        } else {
            targets.push(arg.to_owned());
        }
    }
    if skip_script || scripts.is_empty() || !saw_print_suppression {
        return false;
    }
    if !scripts
        .iter()
        .all(|script| sed_script_is_bounded_print(script))
    {
        return false;
    }
    if require_target {
        return !targets.is_empty() && all_targets_safe(&targets, home_dir);
    }
    targets.is_empty()
}

/// `_read_only_lookup_head_tail_args_are_safe`.
pub(crate) fn read_only_lookup_head_tail_args_are_safe(
    args: &[String],
    require_target: bool,
    home_dir: Option<&Path>,
) -> bool {
    let mut targets: Vec<String> = Vec::new();
    let mut skip_count = false;
    let mut after_options = false;
    for arg in args {
        let arg = arg.as_str();
        if skip_count {
            skip_count = false;
            if !matches_re(&DIGITS_1_6, py_strip(arg)) {
                return false;
            }
            continue;
        }
        if after_options {
            targets.push(arg.to_owned());
            continue;
        }
        if arg == "--" {
            after_options = true;
            continue;
        }
        if matches!(arg, "-n" | "--lines" | "-c" | "--bytes") {
            skip_count = true;
            continue;
        }
        if let Some(count) = arg
            .strip_prefix("--lines=")
            .or_else(|| arg.strip_prefix("--bytes="))
        {
            if !matches_re(&DIGITS_1_6, py_strip(count)) {
                return false;
            }
            continue;
        }
        if matches_re(&DASH_DIGITS_1_6, arg) {
            continue;
        }
        if arg.starts_with('-') {
            return false;
        }
        targets.push(arg.to_owned());
    }
    if skip_count {
        return false;
    }
    if require_target {
        return !targets.is_empty() && all_targets_safe(&targets, home_dir);
    }
    targets.is_empty()
}

/// `_read_only_lookup_arg_is_redirection`.
pub(crate) fn read_only_lookup_arg_is_redirection(arg: &str) -> bool {
    if matches!(
        arg,
        ">" | ">>" | ">|" | "1>" | "1>>" | "1>|" | "2>" | "2>>" | "2>|" | "<" | "0<"
    ) {
        return true;
    }
    split_attached_redirection_token(arg).is_some()
}

/// `_read_only_lookup_target_is_safe`.
pub(crate) fn read_only_lookup_target_is_safe(
    target: &str,
    allow_dirs: bool,
    home_dir: Option<&Path>,
) -> bool {
    let stripped = py_strip(target).trim_matches(|c| c == '\'' || c == '"');
    if stripped.is_empty() || stripped == "." {
        return allow_dirs;
    }
    if stripped == "-" {
        return false;
    }
    if ["$", "`", "<", ">", "|", ";", "&"]
        .iter()
        .any(|marker| stripped.contains(marker))
    {
        return false;
    }
    let normalized = stripped.replace('\\', "/");
    let path = PyPath::new(&normalized);
    let parts: Vec<String> = path
        .parts()
        .into_iter()
        .filter(|part| !matches!(part.as_str(), "" | "/" | "."))
        .collect();
    let lowered: Vec<String> = parts.iter().map(|part| part.to_lowercase()).collect();
    if parts.is_empty() {
        return allow_dirs;
    }
    if parts.iter().any(|part| part == "..")
        || ["*", "?", "[", "]", "{", "}"]
            .iter()
            .any(|marker| stripped.contains(marker))
    {
        return false;
    }
    if lowered
        .iter()
        .any(|part| SOURCE_INSPECTION_SENSITIVE_PARTS.contains(&part.as_str()))
    {
        return false;
    }
    if target_is_known_skill_doc_path(stripped, home_dir) {
        return true;
    }
    let hidden: Vec<&String> = lowered
        .iter()
        .filter(|part| part.starts_with('.'))
        .collect();
    if !hidden.is_empty()
        && !hidden
            .iter()
            .all(|part| SOURCE_INSPECTION_BENIGN_DOTFILES.contains(&part.as_str()))
    {
        return false;
    }
    if lowered
        .iter()
        .any(|part| SOURCE_INSPECTION_PARTS.contains(&part.as_str()))
    {
        return true;
    }
    if SOURCE_INSPECTION_EXTENSIONS.contains(&path.suffix().to_lowercase().as_str()) {
        return true;
    }
    allow_dirs
}

/// `_split_attached_redirection_token`: `(prefix, fd, operator, target)`.
pub(crate) fn split_attached_redirection_token(
    token: &str,
) -> Option<(String, String, String, String)> {
    let chars: Vec<char> = token.chars().collect();
    for (index, character) in chars.iter().enumerate() {
        if *character != '>' {
            continue;
        }
        let op = attached_redirection_operator(&chars, index);
        let prefix: &[char] = &chars[..index];
        if prefix
            .iter()
            .any(|c| crate::codex_output_py::is_py_space(*c) || matches!(c, '<' | '>'))
        {
            continue;
        }
        let target: String = chars[(index + op.chars().count()).min(chars.len())..]
            .iter()
            .collect();
        let (mut prefix, mut fd) = (prefix.iter().collect::<String>(), String::new());
        if let Some(last) = prefix.chars().last() {
            if matches!(last, '0' | '1' | '2') {
                fd = last.to_string();
                prefix.pop();
            }
        }
        return Some((prefix, fd, op.to_owned(), target));
    }
    None
}

/// `_attached_redirection_operator`.
pub(crate) fn attached_redirection_operator(chars: &[char], index: usize) -> &'static str {
    match chars.get(index + 1) {
        Some('|') => ">|",
        Some('>') => ">>",
        _ => ">",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn target_safety_matches_the_python_rules() {
        assert!(read_only_lookup_target_is_safe("src/lib.rs", false, None));
        assert!(!read_only_lookup_target_is_safe("a/../b.rs", false, None));
        assert!(!read_only_lookup_target_is_safe(".env", true, None));
        assert!(read_only_lookup_target_is_safe(".", true, None));
        assert!(!read_only_lookup_target_is_safe("$HOME/x.rs", true, None));
    }

    #[test]
    fn head_tail_and_sed_filters() {
        assert!(read_only_lookup_head_tail_args_are_safe(
            &args(&["-n", "5"]),
            false,
            None
        ));
        assert!(!read_only_lookup_head_tail_args_are_safe(
            &args(&["-n", "x"]),
            false,
            None
        ));
        assert!(read_only_lookup_sed_args_are_safe(
            &args(&["-n", "1,5p"]),
            false,
            None
        ));
        assert!(!read_only_lookup_sed_args_are_safe(
            &args(&["-i", "s/a/b/"]),
            false,
            None
        ));
    }

    #[test]
    fn attached_redirection_split() {
        assert_eq!(
            split_attached_redirection_token("cmd2>>file"),
            Some(("cmd".into(), "2".into(), ">>".into(), "file".into()))
        );
        assert_eq!(
            split_attached_redirection_token("a>b").map(|t| t.2),
            Some(">".to_owned())
        );
        assert_eq!(split_attached_redirection_token("plain"), None);
    }
}
