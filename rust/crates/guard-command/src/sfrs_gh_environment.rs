//! GitHub environment and argument review checks
//! (`secret_file_request_services/github_shell_capabilities.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::Path;

use crate::codex_output_env::Ctx;
use crate::hook_adapter_pytext::compile_fancy;
use crate::sfrs_constants::READ_ONLY_LOOKUP_FILTERS;
use crate::sfrs_interpreter_scripts::{
    is_python_interpreter_command, script_interpreter_texts, script_is_read_only_observer,
};
use crate::sfrs_jq::github_jq_filter_args_are_safe;
use crate::sfrs_quote_tokens::{shell_token_segments, shell_tokens_preserving_quote_context};
use crate::sfrs_read_only_filters::github_output_filter_segment_is_safe;
use crate::sfrs_selectors::github_repository_selector_is_safe;
use crate::sfrs_shell_tokens::{
    iter_shell_command_segments, normalized_shell_command_name,
    shell_command_token_without_attached_redirection, shell_segment_primary_command,
    split_shell_parts,
};
use crate::sfrs_substitution::{
    github_argument_token_has_untrusted_expansion, shell_command_scripts,
};
use fancy_regex::Regex as FancyRegex;
use std::sync::LazyLock;

static SORT_FLAGS: LazyLock<FancyRegex> = LazyLock::new(|| compile_fancy(r"\A-[nru]+\z"));

const PROTECTED_NAMES: [&str; 5] = [
    "GH_CONFIG_DIR",
    "GH_ENTERPRISE_TOKEN",
    "GH_TOKEN",
    "GITHUB_ENTERPRISE_TOKEN",
    "GITHUB_TOKEN",
];

fn partition(token: &str) -> (&str, bool, &str) {
    match token.split_once('=') {
        Some((name, value)) => (name, true, value),
        None => (token, false, ""),
    }
}

/// `_github_environment_name`.
pub(crate) fn github_environment_name(name: &str) -> bool {
    PROTECTED_NAMES.contains(&name) || name == "GH_HOST" || name == "GH_REPO"
}

/// `_github_environment_requires_review`. Later assignments of a name win, as
/// with `dict(assignments)`.
pub(crate) fn github_environment_requires_review(assignments: &[(String, String)]) -> bool {
    let mut normalized: HashMap<&str, &str> = HashMap::new();
    for (name, value) in assignments {
        normalized.insert(name.as_str(), value.as_str());
    }
    if PROTECTED_NAMES
        .iter()
        .any(|name| normalized.contains_key(name))
    {
        return true;
    }
    if let Some(host) = normalized.get("GH_HOST") {
        if caseless::default_case_fold_str(host) != "github.com" {
            return true;
        }
    }
    normalized
        .get("GH_REPO")
        .is_some_and(|repo| !github_repository_selector_is_safe(repo))
}

fn has_expansion_marker(name: &str) -> bool {
    name.contains('$') || name.contains('`')
}

fn leading_assignments(segment: &[String], count: usize) -> Vec<(String, String)> {
    segment[..count]
        .iter()
        .filter(|token| token.contains('='))
        .map(|token| {
            let (name, _, value) = partition(token);
            (name.to_owned(), value.to_owned())
        })
        .collect()
}

fn merged(
    exported: &HashMap<String, String>,
    local: Vec<(String, String)>,
) -> Vec<(String, String)> {
    let mut combined: HashMap<String, String> = exported.clone();
    for (name, value) in local {
        combined.insert(name, value);
    }
    combined.into_iter().collect()
}

/// `_persistent_github_environment_requires_review`.
pub(crate) fn persistent_github_environment_requires_review(parts: &[String]) -> bool {
    let mut shell_values: HashMap<String, String> = HashMap::new();
    let mut exported: HashMap<String, String> = HashMap::new();
    for segment in iter_shell_command_segments(parts) {
        let (command_name, command_index) = shell_segment_primary_command(&segment);
        let (Some(command_name), Some(command_index)) = (command_name, command_index) else {
            for token in &segment {
                let (name, separator, value) = partition(token);
                if separator {
                    shell_values.insert(name.to_owned(), value.to_owned());
                    if exported.contains_key(name) {
                        exported.insert(name.to_owned(), value.to_owned());
                    }
                }
            }
            continue;
        };
        let args = &segment[command_index + 1..];
        if command_name == "unset" {
            for name in args {
                shell_values.remove(name);
                exported.remove(name);
            }
            continue;
        }
        if matches!(
            command_name.as_str(),
            "export" | "readonly" | "declare" | "typeset"
        ) {
            let export_enabled = command_name == "export" || args.iter().any(|arg| arg == "-x");
            let names = || {
                args.iter()
                    .filter(|token| !token.starts_with('-'))
                    .map(|token| partition(token).0)
            };
            if !names().any(|name| github_environment_name(name) || has_expansion_marker(name)) {
                continue;
            }
            if !export_enabled {
                if names().any(github_environment_name) {
                    return true;
                }
                continue;
            }
            for token in args {
                if token.starts_with('-') {
                    if token != "-x" {
                        return true;
                    }
                    continue;
                }
                let (name, separator, value) = partition(token);
                if has_expansion_marker(name) {
                    return true;
                }
                if separator {
                    shell_values.insert(name.to_owned(), value.to_owned());
                }
                if let Some(current) = shell_values.get(name) {
                    exported.insert(name.to_owned(), current.clone());
                } else if github_environment_name(name) {
                    return true;
                }
            }
            continue;
        }
        if matches!(command_name.as_str(), "bash" | "sh" | "zsh") {
            let inherited = merged(&exported, leading_assignments(&segment, command_index));
            let scripts = shell_command_scripts(&segment);
            if !scripts.is_empty() && github_environment_requires_review(&inherited) {
                return true;
            }
            if scripts
                .iter()
                .any(|script| github_script_requires_review(script))
            {
                return true;
            }
        }
        if command_name != "gh" {
            continue;
        }
        let effective = merged(&exported, leading_assignments(&segment, command_index));
        if github_environment_requires_review(&effective) {
            return true;
        }
    }
    false
}

/// `_github_shell_has_dynamic_arguments`.
pub(crate) fn github_shell_has_dynamic_arguments(command_text: &str) -> bool {
    for contextual in shell_token_segments(&shell_tokens_preserving_quote_context(command_text)) {
        let plain: Vec<String> = contextual.iter().map(|token| token.plain.clone()).collect();
        if shell_segment_is_command_builtin_lookup(&plain) {
            continue;
        }
        let (name, index) = shell_segment_primary_command(&plain);
        let (Some(name), Some(index)) = (name, index) else {
            continue;
        };
        if name != "gh" {
            continue;
        }
        if contextual[index + 1..]
            .iter()
            .any(|token| github_argument_token_has_untrusted_expansion(&token.raw))
        {
            return true;
        }
    }
    false
}

/// `_github_script_requires_review`.
pub(crate) fn github_script_requires_review(script: &str) -> bool {
    let parts = split_shell_parts(script);
    persistent_github_environment_requires_review(&parts)
        || github_shell_has_dynamic_arguments(script)
}

/// `_command_builtin_options_are_lookup_only`.
pub(crate) fn command_builtin_options_are_lookup_only(
    segment: &[String],
    mut index: usize,
) -> bool {
    while index < segment.len() {
        let plain = &segment[index];
        if plain == "--" || !plain.starts_with('-') {
            return false;
        }
        if plain[1..].contains('v') || plain[1..].contains('V') {
            return true;
        }
        index += 1;
    }
    false
}

/// `_shell_segment_is_command_builtin_lookup`.
pub(crate) fn shell_segment_is_command_builtin_lookup(segment: &[String]) -> bool {
    for (index, token) in segment.iter().enumerate() {
        let name =
            normalized_shell_command_name(&shell_command_token_without_attached_redirection(token));
        if name == "command" {
            return command_builtin_options_are_lookup_only(segment, index + 1);
        }
    }
    false
}

/// `_github_pipeline_companion_is_read_only`.
pub(crate) fn github_pipeline_companion_is_read_only(
    segment: &[String],
    home_dir: Option<&Path>,
    command_text: &str,
    ctx: &Ctx,
) -> bool {
    let (name, index) = shell_segment_primary_command(segment);
    let (Some(name), Some(index)) = (name, index) else {
        return false;
    };
    if is_python_interpreter_command(&name) {
        let scripts = script_interpreter_texts(segment);
        return !scripts.is_empty()
            && scripts
                .iter()
                .all(|text| script_is_read_only_observer(text));
    }
    let redirected = segment[index + 1..].iter().any(|token| {
        (token.contains('>') || token.contains('<')) && token != "2>&1" && token != "1>&2"
    });
    if redirected {
        return false;
    }
    let args: Vec<String> = segment[index + 1..]
        .iter()
        .filter(|token| *token != "2>&1" && *token != "1>&2")
        .cloned()
        .collect();
    match name.as_str() {
        "jq" => github_jq_filter_args_are_safe(&args),
        "sort" => args
            .iter()
            .all(|arg| SORT_FLAGS.is_match(arg).unwrap_or(false)),
        "uniq" => args.is_empty() || args == ["-c"],
        other if READ_ONLY_LOOKUP_FILTERS.contains(&other) => {
            github_output_filter_segment_is_safe(other, &args, home_dir, Some(command_text), ctx)
        }
        _ => false,
    }
}
