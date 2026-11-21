//! GitHub shell capability entry point
//! (`secret_file_request_services/github_shell_capabilities.py`,
//! `classify_github_shell_capabilities`).

// Consumed by the request classifier slices.
#![allow(dead_code)]

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::codex_output_env::Ctx;
use crate::env_wrapper::parse_env_wrapper;
use crate::github_capability_contract::{
    github_assessment, GitHubCommandAssessment, GitHubCommandCapability,
};
use crate::github_command_capabilities::classify_github_cli;
use crate::sfrs_gh_bindings::py_pattern;
use crate::sfrs_gh_environment::{
    github_environment_requires_review, github_script_requires_review,
    github_shell_has_dynamic_arguments, persistent_github_environment_requires_review,
    shell_segment_is_command_builtin_lookup,
};
use crate::sfrs_gh_shell::{classify_github_shell_capabilities as classify_shell, Scope, Tracked};
use crate::sfrs_shell_tokens::{
    iter_shell_command_segments, shell_segment_primary_command, split_shell_parts,
};
use crate::sfrs_substitution::shell_command_scripts;

static FUNCTION_DEFINITION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&py_pattern(
        r"(?:\A|[;&\n])\s*(?:function\s+[A-Za-z_][A-Za-z0-9_]*(?:\s*\(\s*\))?|[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\))\s*\{",
    ))
    .expect("constant pattern")
});
static ALIAS_DEFINITION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&py_pattern(
        r"(?:\A|[;&\n])\s*alias\s+[A-Za-z_][A-Za-z0-9_]*\s*=",
    ))
    .expect("constant pattern")
});
static DEFERRED_EFFECT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&py_pattern(
        r"(?:\A|[;{&|\n])\s*gh(?:\s|\z)|\b(?:GH|GITHUB)_(?:CONFIG_DIR|ENTERPRISE_TOKEN|HOST|REPO|TOKEN)\b",
    ))
    .expect("constant pattern")
});

fn unknown(reason: &str, detail: &str) -> GitHubCommandAssessment {
    github_assessment(&[GitHubCommandCapability::Unknown], reason, detail)
}

fn untrusted_environment(detail: &str) -> GitHubCommandAssessment {
    unknown("github.command.untrusted-environment", detail)
}

/// `classify_github_shell_capabilities`: adapts the shared shell parser to
/// focused GitHub capability composition.
pub(crate) fn classify_github_shell_capabilities(
    command_text: &str,
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> Option<GitHubCommandAssessment> {
    classify_with(command_text, home_dir, ctx, classify_github_cli)
}

/// Same classification with an explicit GitHub CLI argument classifier.
pub(crate) fn classify_with(
    command_text: &str,
    home_dir: Option<&Path>,
    ctx: &Ctx,
    classify: fn(&[String]) -> GitHubCommandAssessment,
) -> Option<GitHubCommandAssessment> {
    if (FUNCTION_DEFINITION.is_match(command_text) || ALIAS_DEFINITION.is_match(command_text))
        && DEFERRED_EFFECT.is_match(command_text)
    {
        return Some(unknown(
            "github.command.shell-function",
            "Shell functions in a GitHub command compound require explicit review.",
        ));
    }
    let parts = split_shell_parts(command_text);
    if persistent_github_environment_requires_review(&parts) {
        return Some(untrusted_environment(
            "Exported GitHub host or credential configuration requires explicit review.",
        ));
    }
    if github_shell_has_dynamic_arguments(command_text) {
        return Some(unknown(
            "github.command.dynamic-argument",
            "Dynamic GitHub arguments require explicit review.",
        ));
    }
    for segment in iter_shell_command_segments(&parts) {
        if shell_segment_is_command_builtin_lookup(&segment) {
            continue;
        }
        if segment.first().map(String::as_str) == Some("env") {
            if let Some(found) = raw_env_review(&segment) {
                return Some(found);
            }
        }
        let (command_name, command_index) = shell_segment_primary_command(&segment);
        let mut assignments: Vec<(String, String)> = segment[..command_index.unwrap_or(0)]
            .iter()
            .filter(|token| token.contains('='))
            .filter_map(|token| token.split_once('='))
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect();
        let mut targets_github = command_name.as_deref() == Some("gh");
        if let (Some("env"), Some(index)) = (command_name.as_deref(), command_index) {
            let parsed = parse_env_wrapper(&segment[index + 1..], None, None);
            if parsed.complete && parsed.executable_argv.first().map(String::as_str) == Some("gh") {
                assignments.extend(parsed.environment_delta.assignments);
                targets_github = true;
            }
        }
        if targets_github && github_environment_requires_review(&assignments) {
            return Some(untrusted_environment(
                "Inline GitHub host or credential configuration requires explicit review.",
            ));
        }
    }
    let scope = Scope {
        home_dir,
        root_text: command_text,
        ctx,
        classify,
    };
    classify_shell(command_text, &scope, 0, &Tracked::default())
}

/// Review of an `env ...` segment that wraps `gh` or a nested shell.
fn raw_env_review(segment: &[String]) -> Option<GitHubCommandAssessment> {
    let parsed = parse_env_wrapper(&segment[1..], None, None);
    if !parsed.complete {
        return None;
    }
    let raw_assignments = parsed.environment_delta.assignments;
    let executable = parsed.executable_argv;
    let first = executable.first().map(String::as_str);
    if first == Some("gh") && github_environment_requires_review(&raw_assignments) {
        return Some(untrusted_environment(
            "Expanded GitHub environment or arguments require explicit review.",
        ));
    }
    if matches!(first, Some("bash" | "sh" | "zsh")) {
        let scripts = shell_command_scripts(&executable);
        if !scripts.is_empty() && github_environment_requires_review(&raw_assignments) {
            return Some(untrusted_environment(
                "Nested GitHub environment configuration requires explicit review.",
            ));
        }
        if scripts
            .iter()
            .any(|script| github_script_requires_review(script))
        {
            return Some(unknown(
                "github.command.dynamic-nested-shell",
                "Nested dynamic GitHub arguments require explicit review.",
            ));
        }
    }
    None
}
