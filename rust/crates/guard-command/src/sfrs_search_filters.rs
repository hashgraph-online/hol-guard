//! grep and ripgrep stdin-filter validation (`read_only_filters.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::Path;
use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;

use crate::codex_output_env::Ctx;
use crate::codex_output_py::py_strip;
use crate::hook_adapter_pytext::compile_fancy;
use crate::sfrs_read_only_filters::{
    matches_re, read_only_lookup_arg_is_redirection, read_only_lookup_target_is_safe,
};

static RG_DYNAMIC_ARG: LazyLock<FancyRegex> =
    LazyLock::new(|| compile_fancy(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?!_-]|\{|\()"));

const GREP_PATTERN_OPTIONS: &[&str] = &["-e", "--regexp"];
const GREP_PATTERN_FILE_OPTIONS: &[&str] = &["-f", "--file"];
const GREP_FILTER_FILE_OPTIONS: &[&str] = &["--exclude-from"];
const GREP_SKIP_NEXT_OPTIONS: &[&str] = &[
    "-A",
    "-B",
    "-C",
    "-m",
    "--after-context",
    "--before-context",
    "--context",
    "--max-count",
];
const RG_FILTER_BOOLEAN_OPTIONS: &[&str] = &[
    "--case-sensitive",
    "--fixed-strings",
    "--ignore-case",
    "--invert-match",
    "--line-number",
    "--no-config",
    "--only-matching",
    "--quiet",
    "--smart-case",
    "--word-regexp",
    "--line-regexp",
];
const RG_FILTER_BOOLEAN_SHORT_OPTIONS: &str = "FiInNoqSsvwx";

/// `_read_only_lookup_filter_grep_args_are_safe`.
pub(crate) fn read_only_lookup_filter_grep_args_are_safe(
    args: &[String],
    home_dir: Option<&Path>,
) -> bool {
    if args.is_empty() {
        return false;
    }
    let safe = |target: &str| read_only_lookup_target_is_safe(target, false, home_dir);
    let mut saw_pattern = false;
    let mut after_options = false;
    let mut skip_next_is_pattern = false;
    let mut skip_next_is_file = false;
    let mut skip_next_file_sets_pattern = false;
    let mut skip_next_is_value = false;
    for arg in args {
        let arg = arg.as_str();
        if skip_next_is_pattern {
            skip_next_is_pattern = false;
            saw_pattern = true;
            continue;
        }
        if skip_next_is_file {
            skip_next_is_file = false;
            if !safe(arg) {
                return false;
            }
            if skip_next_file_sets_pattern {
                saw_pattern = true;
            }
            continue;
        }
        if skip_next_is_value {
            skip_next_is_value = false;
            continue;
        }
        if read_only_lookup_arg_is_redirection(arg) {
            return false;
        }
        if after_options {
            if !saw_pattern {
                saw_pattern = true;
                continue;
            }
            if !safe(arg) {
                return false;
            }
            continue;
        }
        if arg == "--" {
            after_options = true;
            continue;
        }
        if GREP_PATTERN_OPTIONS.contains(&arg) {
            skip_next_is_pattern = true;
            saw_pattern = true;
            continue;
        }
        if GREP_PATTERN_FILE_OPTIONS.contains(&arg) {
            skip_next_is_file = true;
            skip_next_file_sets_pattern = true;
            continue;
        }
        if GREP_FILTER_FILE_OPTIONS.contains(&arg) {
            skip_next_is_file = true;
            skip_next_file_sets_pattern = false;
            continue;
        }
        if GREP_SKIP_NEXT_OPTIONS.contains(&arg) {
            skip_next_is_value = true;
            continue;
        }
        if arg.starts_with("--") {
            if let Some((key, value)) = arg.split_once('=') {
                if GREP_PATTERN_FILE_OPTIONS.contains(&key) {
                    if !safe(value) {
                        return false;
                    }
                    saw_pattern = true;
                } else if GREP_FILTER_FILE_OPTIONS.contains(&key) {
                    if !safe(value) {
                        return false;
                    }
                } else if GREP_PATTERN_OPTIONS.contains(&key) {
                    saw_pattern = true;
                }
            }
            continue;
        }
        if arg.starts_with('-') && arg != "-" {
            let body = &arg[1..];
            for (offset, ch) in body.char_indices() {
                if ch == 'f' {
                    let file_arg = &body[offset + 1..];
                    if file_arg.is_empty() {
                        skip_next_is_file = true;
                        skip_next_file_sets_pattern = true;
                    } else {
                        if !safe(file_arg) {
                            return false;
                        }
                        saw_pattern = true;
                    }
                    break;
                } else if ch == 'e' {
                    saw_pattern = true;
                    break;
                }
            }
            continue;
        }
        if !saw_pattern {
            saw_pattern = true;
        } else if !safe(arg) {
            return false;
        }
    }
    !(skip_next_is_pattern || skip_next_is_file || skip_next_is_value)
}

/// `_read_only_lookup_filter_rg_args_are_safe`.
pub(crate) fn read_only_lookup_filter_rg_args_are_safe(args: &[String], ctx: &Ctx) -> bool {
    if args.is_empty() {
        return false;
    }
    let mut saw_pattern = false;
    let mut expect_pattern = false;
    let mut after_options = false;
    let mut saw_no_config = false;
    for arg in args {
        let arg = arg.as_str();
        if read_only_lookup_arg_is_redirection(arg) {
            return false;
        }
        if arg.contains('`') || matches_re(&RG_DYNAMIC_ARG, arg) {
            return false;
        }
        if expect_pattern {
            expect_pattern = false;
            if arg.is_empty() {
                return false;
            }
            saw_pattern = true;
            continue;
        }
        if after_options {
            if saw_pattern {
                return false;
            }
            saw_pattern = !arg.is_empty();
            continue;
        }
        if arg == "--" {
            after_options = true;
            continue;
        }
        if arg == "--no-config" {
            if saw_no_config {
                return false;
            }
            saw_no_config = true;
            continue;
        }
        if arg == "-e" || arg == "--regexp" {
            if saw_pattern {
                return false;
            }
            expect_pattern = true;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--regexp=") {
            if saw_pattern || value.is_empty() {
                return false;
            }
            saw_pattern = true;
            continue;
        }
        if RG_FILTER_BOOLEAN_OPTIONS.contains(&arg) {
            continue;
        }
        if arg.starts_with('-') && arg != "-" {
            if !arg.starts_with("--")
                && arg[1..]
                    .chars()
                    .all(|c| RG_FILTER_BOOLEAN_SHORT_OPTIONS.contains(c))
            {
                continue;
            }
            return false;
        }
        if saw_pattern {
            return false;
        }
        saw_pattern = !arg.is_empty();
    }
    let configured = ctx
        .host
        .env("RIPGREP_CONFIG_PATH")
        .is_some_and(|value| !py_strip(&value).is_empty());
    let config_is_disabled = saw_no_config || !configured;
    saw_pattern && config_is_disabled && !expect_pattern
}
