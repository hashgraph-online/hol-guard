//! Critical effect rules and lexical command/option helpers.
use super::shell::{destructive_timeout_shell, partition};
use crate::canonical_command::CanonicalCommand;
use crate::effect_decision::GuardAction;
use crate::github_capability_contract::GitHubCommandCapability;
use crate::github_command_capabilities::classify_github_cli;
use crate::CommandSegmentV1;

const AWS_GLOBAL_VALUE_OPTIONS: &[&str] = &[
    "--ca-bundle",
    "--cli-binary-format",
    "--cli-connect-timeout",
    "--cli-read-timeout",
    "--color",
    "--endpoint-url",
    "--output",
    "--profile",
    "--query",
    "--region",
];
const AWS_GLOBAL_BOOLEAN_OPTIONS: &[&str] = &[
    "--cli-auto-prompt",
    "--debug",
    "--no-cli-auto-prompt",
    "--no-cli-pager",
    "--no-paginate",
    "--no-sign-request",
    "--no-verify-ssl",
];
const STRIPE_GLOBAL_VALUE_OPTIONS: &[&str] = &[
    "--api-base",
    "--api-key",
    "--color",
    "--config",
    "--device-name",
    "--log-level",
    "--project-name",
    "--stripe-account",
];
const STRIPE_GLOBAL_BOOLEAN_OPTIONS: &[&str] = &["--help", "--live", "--show-headers", "--version"];
const WINDOWS_EXECUTABLES: &[&str] = &[
    "aws",
    "bunx",
    "cat",
    "docker",
    "gcloud",
    "getfacl",
    "gh",
    "hol-guard",
    "keyring",
    "npm",
    "npx",
    "plugin-guard",
    "rm",
    "stripe",
    "systemctl",
    "timeout",
    "xargs",
];

/// `_critical_floor` (:217).
pub(super) fn critical_floor(
    command: &CanonicalCommand,
    segment: &CommandSegmentV1,
    executable: &str,
    arguments: &[String],
) -> Option<(GuardAction, &'static str)> {
    let normalized: Vec<String> = arguments.iter().map(|item| item.to_lowercase()).collect();
    if executable == "aws"
        && command_path(
            &normalized,
            &["route53", "delete-hosted-zone"],
            AWS_GLOBAL_VALUE_OPTIONS,
            AWS_GLOBAL_BOOLEAN_OPTIONS,
            true,
        )
    {
        return Some((GuardAction::Block, "critical.remote-destructive"));
    }
    if executable == "stripe"
        && command_path(
            &normalized,
            &["products", "delete"],
            STRIPE_GLOBAL_VALUE_OPTIONS,
            STRIPE_GLOBAL_BOOLEAN_OPTIONS,
            false,
        )
    {
        return Some((GuardAction::Block, "critical.remote-destructive"));
    }
    if executable == "rm" && destructive_remove(arguments) {
        return Some((GuardAction::Block, "critical.destructive-filesystem"));
    }
    if executable == "timeout" && destructive_timeout_shell(arguments) {
        return Some((GuardAction::Block, "critical.destructive-filesystem"));
    }
    if executable == "gh" && destructive_graphql(arguments) {
        return Some((GuardAction::Block, "critical.destructive-graphql"));
    }
    if executable == "hol-guard" || executable == "plugin-guard" {
        if let Some(guard_control) = guard_control_floor(&normalized) {
            return Some(guard_control);
        }
    }
    if segment.path_overridden {
        return Some((
            GuardAction::RequireReapproval,
            "critical.path-provenance-drift",
        ));
    }
    if ["npx", "npm", "pnpm", "yarn", "bunx"].contains(&executable)
        && local_package_source(&normalized)
    {
        return Some((
            GuardAction::RequireReapproval,
            "critical.package-source-drift",
        ));
    }
    if executable == "cat" && segment.execution_context.starts_with("substitution:") {
        return Some((
            GuardAction::RequireReapproval,
            "critical.dynamic-sensitive-read",
        ));
    }
    if executable == "cat" && is_pipeline_segment(command, segment) {
        return Some((
            GuardAction::RequireReapproval,
            "critical.pipeline-sensitive-read",
        ));
    }
    if executable == "keyring" && normalized.first().map(String::as_str) == Some("get") {
        return Some((
            GuardAction::RequireReapproval,
            "critical.credential-metadata",
        ));
    }
    if executable == "npm" && normalized.first().map(String::as_str) == Some("view") {
        return Some((GuardAction::Review, "critical.package-registry-read"));
    }
    if executable == "docker" && docker_read(&normalized) {
        return Some((GuardAction::Review, "critical.container-state-read"));
    }
    if executable == "aws"
        && normalized
            .get(..2)
            .map(|s| s.iter().map(String::as_str).collect::<Vec<_>>())
            == Some(vec!["sts", "get-caller-identity"])
    {
        return Some((GuardAction::Review, "critical.cloud-identity-read"));
    }
    if executable == "gcloud"
        && normalized
            .get(..2)
            .map(|s| s.iter().map(String::as_str).collect::<Vec<_>>())
            == Some(vec!["projects", "describe"])
    {
        return Some((GuardAction::Review, "critical.cloud-identity-read"));
    }
    if ["getfacl", "systemctl"].contains(&executable) {
        return Some((GuardAction::Review, "critical.system-metadata-read"));
    }
    None
}

/// `_executable_name` (:278).
pub(super) fn executable_name(segment: &CommandSegmentV1) -> String {
    let executable = segment
        .executable
        .as_deref()
        .unwrap_or("")
        .replace('\\', "/");
    let name = executable.rsplit('/').next().unwrap_or("").to_lowercase();
    if name.ends_with(".exe") {
        let stem = &name[..name.len() - 4];
        if WINDOWS_EXECUTABLES.contains(&stem) {
            return stem.to_owned();
        }
    }
    name
}

/// `_recursive_force` (:286).
fn recursive_force(arguments: &[String]) -> bool {
    let option_end = arguments
        .iter()
        .position(|a| a == "--")
        .unwrap_or(arguments.len());
    let flags: Vec<&String> = arguments[..option_end]
        .iter()
        .filter(|item| item.starts_with('-') && item.as_str() != "-")
        .collect();
    let has_recursive = flags.iter().any(|item| {
        long_option_prefix(item, "--recursive")
            || (!item.starts_with("--") && (item[1..].contains('r') || item[1..].contains('R')))
    });
    let has_force = flags.iter().any(|item| {
        long_option_prefix(item, "--force") || (!item.starts_with("--") && item[1..].contains('f'))
    });
    has_recursive && has_force
}

/// `_long_option_prefix` (:297).
fn long_option_prefix(argument: &str, expected: &str) -> bool {
    argument.len() > 2 && argument.starts_with("--") && expected.starts_with(argument)
}

/// `_destructive_remove` (:301).
pub(super) fn destructive_remove(arguments: &[String]) -> bool {
    if !recursive_force(arguments) {
        return false;
    }
    let option_end = arguments
        .iter()
        .position(|a| a == "--")
        .unwrap_or(arguments.len());
    let mut targets: Vec<&String> = arguments[..option_end]
        .iter()
        .filter(|item| !item.starts_with('-'))
        .collect();
    if option_end < arguments.len() {
        targets.extend(arguments[option_end + 1..].iter());
    }
    const ROUTINE_OUTPUTS: &[&str] = &[
        ".cache",
        ".pytest_cache",
        ".ruff_cache",
        "build",
        "coverage",
        "dist",
    ];
    targets.is_empty()
        || targets.iter().any(|target| {
            let trimmed = target.trim_end_matches('/');
            let trimmed = trimmed.strip_prefix("./").unwrap_or(trimmed);
            !ROUTINE_OUTPUTS.contains(&trimmed)
        })
}

/// `_destructive_graphql` (:321).
fn destructive_graphql(arguments: &[String]) -> bool {
    let assessment = classify_github_cli(arguments);
    assessment.reason_code.starts_with("github.graphql.")
        && assessment
            .capabilities
            .contains(&GitHubCommandCapability::DeleteRemote)
}

/// `_local_package_source` (:423).
fn local_package_source(arguments: &[String]) -> bool {
    arguments.iter().any(|item| {
        item.contains("file:")
            || item.starts_with("./")
            || item.starts_with("../")
            || item.starts_with('/')
    })
}

/// `_command_path` (:429).
fn command_path(
    arguments: &[String],
    expected: &[&str],
    value_options: &[&str],
    boolean_options: &[&str],
    allow_unique_prefix: bool,
) -> bool {
    let mut positional: Vec<String> = Vec::new();
    let mut index = 0usize;
    while index < arguments.len() && positional.len() < expected.len() {
        let argument = &arguments[index];
        let (option, separator, _value) = partition(argument, '=');
        let normalized_option = if allow_unique_prefix {
            resolved_option(
                option,
                &value_options
                    .iter()
                    .chain(boolean_options.iter())
                    .copied()
                    .collect::<Vec<_>>(),
            )
        } else {
            option.to_owned()
        };
        if value_options.contains(&normalized_option.as_str()) {
            index += if !separator.is_empty() { 1 } else { 2 };
            continue;
        }
        if boolean_options.contains(&normalized_option.as_str()) && separator.is_empty() {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            return false;
        }
        positional.push(argument.clone());
        index += 1;
    }
    positional
        .iter()
        .map(String::as_str)
        .eq(expected.iter().copied())
}

/// `_resolved_option` (:453).
pub(super) fn resolved_option(option: &str, known: &[&str]) -> String {
    if known.contains(&option) || !option.starts_with("--") {
        return option.to_owned();
    }
    let matches: Vec<&&str> = known
        .iter()
        .filter(|candidate| candidate.starts_with(option))
        .collect();
    if matches.len() == 1 {
        matches[0].to_string()
    } else {
        option.to_owned()
    }
}

/// `_contains_ordered` (:460).
fn contains_ordered(arguments: &[String], first: &str, second: &str) -> bool {
    let Some(first_index) = arguments.iter().position(|a| a == first) else {
        return false;
    };
    arguments[first_index + 1..].iter().any(|a| a == second)
}

/// `_guard_control_floor` (:473).
pub(super) fn guard_control_floor(arguments: &[String]) -> Option<(GuardAction, &'static str)> {
    let control_tokens = ["capability", "clear", "policy", "uninstall"];
    let is_control = arguments
        .iter()
        .any(|a| control_tokens.contains(&a.as_str()))
        || contains_ordered(arguments, "hooks", "remove");
    if is_control
        && arguments
            .iter()
            .any(|item| ["help", "--help", "-h"].contains(&item.as_str()))
    {
        return Some((GuardAction::Review, "critical.guard-control-help"));
    }
    if contains_ordered(arguments, "capability", "consume") {
        return Some((GuardAction::Block, "critical.capability-replay"));
    }
    if arguments.iter().any(|a| a == "uninstall") || contains_ordered(arguments, "hooks", "remove")
    {
        return Some((GuardAction::Block, "critical.guard-self-protection"));
    }
    if contains_ordered(arguments, "policy", "disable") {
        return Some((GuardAction::Block, "critical.guard-policy-tamper"));
    }
    if arguments.iter().any(|a| a == "clear") && arguments.iter().any(|a| a == "--all") {
        return Some((GuardAction::Block, "critical.guard-data-tamper"));
    }
    None
}

/// `_path_export_index` (:492).
pub(super) fn path_export_index(command: &CanonicalCommand) -> Option<usize> {
    command.segments.iter().position(|segment| {
        executable_name(segment) == "export"
            && segment
                .arguments
                .iter()
                .any(|argument| argument.to_lowercase().starts_with("path="))
    })
}

/// `_is_pipeline_segment` (:501). `item is not segment` → pointer inequality.
fn is_pipeline_segment(command: &CanonicalCommand, segment: &CommandSegmentV1) -> bool {
    command.segments.iter().any(|item| {
        item.execution_context == segment.execution_context && !std::ptr::eq(item, segment)
    })
}

/// `_docker_read` (:505).
fn docker_read(arguments: &[String]) -> bool {
    arguments.first().map(String::as_str) == Some("inspect")
        || arguments
            .get(..2)
            .map(|s| s.iter().map(String::as_str).collect::<Vec<_>>())
            == Some(vec!["compose", "ps"])
}
