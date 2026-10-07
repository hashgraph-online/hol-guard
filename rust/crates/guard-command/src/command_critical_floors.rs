//! Rust port of `runtime/command_critical_floors.py`.
//!
//! Fail-closed decision factors for security-critical command effects.
//! `workflow_authorization` arrives as the wire projection
//! `GitHubWorkflowAuthorizationV1` (the Python `_seal` object-identity check
//! becomes the `sealed` flag).

use std::collections::BTreeMap;

use crate::canonical_command::CanonicalCommand;
use crate::command_launcher_floors::{launcher_child_commands, shlex_split};
use crate::effect_decision::{
    DecisionBasis, DecisionFactor, DecisionFactorSource, GuardAction, ProofRoute,
};
use crate::github_capability_contract::GitHubCommandCapability;
use crate::github_capability_interaction::github_capability_action_class;
use crate::github_command_capabilities::classify_github_cli;
use crate::github_workflow_authorization::{
    github_workflow_authorization_evidence, GitHubWorkflowAuthorizationV1,
};
use crate::{parse_command, CommandModelRequestV1, CommandSegmentV1};

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
const ENV_LONG_BOOLEAN_OPTIONS: &[&str] = &[
    "--debug",
    "--ignore-environment",
    "--list-signal-handling",
    "--null",
];
const ENV_LONG_VALUE_OPTIONS: &[&str] = &["--argv0", "--chdir", "--unset"];
const ENV_SHORT_BOOLEAN_OPTIONS: &[char] = &['0', 'i', 'v'];
const ENV_SHORT_VALUE_OPTIONS: &[char] = &['C', 'P', 'a', 'u'];
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
const MAX_LAUNCHER_CHILDREN: usize = 256;

/// `command_critical_floor_factors` (:79). The public entry dedupes factors
/// by `semantic_key` after the recursive walk.
pub fn command_critical_floor_factors(
    command: &CanonicalCommand,
    authorization: Option<&GitHubWorkflowAuthorizationV1>,
    explicitly_allowed_github_capabilities: &[GitHubCommandCapability],
) -> Vec<DecisionFactor> {
    let mut remaining = [MAX_LAUNCHER_CHILDREN];
    let factors = inner(
        command,
        authorization,
        explicitly_allowed_github_capabilities,
        0,
        &mut remaining,
    );
    // `tuple({factor.semantic_key: factor for factor in factors}.values())`
    // — insertion-ordered dedupe by semantic key; later duplicates replace.
    let mut map: BTreeMap<Vec<String>, DecisionFactor> = BTreeMap::new();
    let mut order: Vec<Vec<String>> = Vec::new();
    for factor in factors {
        let key = factor.semantic_key();
        if !map.contains_key(&key) {
            order.push(key.clone());
        }
        map.insert(key, factor);
    }
    order
        .into_iter()
        .map(|key| map.remove(&key).unwrap())
        .collect()
}

/// `_command_critical_floor_factors` (:105).
fn inner(
    command: &CanonicalCommand,
    authorization: Option<&GitHubWorkflowAuthorizationV1>,
    explicitly_allowed_github_capabilities: &[GitHubCommandCapability],
    depth: usize,
    remaining_launcher_children: &mut [usize; 1],
) -> Vec<DecisionFactor> {
    let mut factors: Vec<DecisionFactor> = Vec::new();
    let authorization_evidence =
        github_workflow_authorization_evidence(authorization, &command.security_identity);
    let mut authorized_action_class: Option<&'static str> = None;
    if let Some((proof, action_class)) = authorization_evidence {
        authorized_action_class = Some(action_class);
        let operation_id = command.security_identity.rsplit(':').next().unwrap_or("");
        factors.push(DecisionFactor {
            source: DecisionFactorSource::Authorization,
            reason_code: "github-workflow-capability".to_owned(),
            basis: DecisionBasis {
                action_floor: GuardAction::Allow,
                proof_route: Some(ProofRoute::WorkflowAuthorized),
            },
            segment_ref: None,
            operation_ref: Some(format!("operation:{operation_id}")),
            producer_ref: Some("runtime:github-workflow-authorization-v1".to_owned()),
            evidence_digest: None,
            assessment: None,
            proof: Some(proof),
        });
    }
    let path_export_index = path_export_index(command);
    if let Some(export_index) = path_export_index {
        factors.push(factor(
            command,
            export_index,
            GuardAction::RequireReapproval,
            "critical.path-provenance-drift",
        ));
    }
    for (index, segment) in command.segments.iter().enumerate() {
        let executable = executable_name(segment);
        let arguments = &segment.arguments;
        let windows_executable = segment
            .executable
            .as_deref()
            .unwrap_or("")
            .to_lowercase()
            .ends_with(".exe");
        if let Some(github_factor) = github_factor(
            command,
            index,
            &executable,
            arguments,
            authorized_action_class,
            explicitly_allowed_github_capabilities,
            depth > 0 || !command.wrapper_chain.is_empty(),
            windows_executable,
        ) {
            factors.push(github_factor);
        }
        if let Some((action, reason_code)) =
            critical_floor(command, segment, &executable, arguments)
        {
            factors.push(factor(command, index, action, reason_code));
        }
        let launcher_children = launcher_child_commands(&executable, arguments);
        if depth < 3 {
            for child in launcher_children {
                if remaining_launcher_children[0] == 0 {
                    factors.push(factor(
                        command,
                        index,
                        GuardAction::Block,
                        "critical.launcher-expansion-limit",
                    ));
                    break;
                }
                remaining_launcher_children[0] -= 1;
                factors.extend(inner(
                    &child,
                    None,
                    &[],
                    depth + 1,
                    remaining_launcher_children,
                ));
            }
        } else if !launcher_children.is_empty() {
            factors.push(factor(
                command,
                index,
                GuardAction::Block,
                "critical.launcher-depth-limit",
            ));
        }
    }
    factors
}

/// `_github_factor` (:175).
#[allow(clippy::too_many_arguments)]
fn github_factor(
    command: &CanonicalCommand,
    index: usize,
    executable: &str,
    arguments: &[String],
    authorized_action_class: Option<&'static str>,
    explicitly_allowed_capabilities: &[GitHubCommandCapability],
    indirect: bool,
    windows_executable: bool,
) -> Option<DecisionFactor> {
    if executable != "gh" {
        return None;
    }
    let assessment = classify_github_cli(arguments);
    let action_floor = assessment.action_floor();
    if !indirect
        && action_floor != GuardAction::Block
        && !assessment
            .capabilities
            .contains(&GitHubCommandCapability::Unknown)
        && assessment
            .capabilities
            .iter()
            .all(|capability| explicitly_allowed_capabilities.contains(capability))
    {
        return None;
    }
    if authorized_action_class.is_some()
        && action_floor != GuardAction::Allow
        && github_capability_action_class(&assessment).ok() == authorized_action_class
    {
        return None;
    }
    let indirect_routine_mutation = (indirect || windows_executable)
        && assessment.capabilities.iter().any(|capability| {
            matches!(
                capability,
                GitHubCommandCapability::RoutineMergeRemote
                    | GitHubCommandCapability::RoutineWorkflowRemote
            )
        });
    if action_floor == GuardAction::Allow && !indirect_routine_mutation {
        return None;
    }
    let mut effective_floor = action_floor;
    if (indirect || windows_executable) && effective_floor != GuardAction::Block {
        effective_floor = GuardAction::RequireReapproval;
    }
    Some(factor(
        command,
        index,
        effective_floor,
        "critical.github-cli",
    ))
}

/// `_critical_floor` (:217).
fn critical_floor(
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

/// `_factor` (:265).
fn factor(
    command: &CanonicalCommand,
    index: usize,
    action: GuardAction,
    reason_code: &str,
) -> DecisionFactor {
    let operation_id = command.security_identity.rsplit(':').next().unwrap_or("");
    DecisionFactor {
        source: DecisionFactorSource::Policy,
        reason_code: reason_code.to_owned(),
        basis: DecisionBasis {
            action_floor: action,
            proof_route: None,
        },
        segment_ref: Some(format!("segment:{index}")),
        operation_ref: Some(format!("operation:{operation_id}")),
        producer_ref: Some("runtime:command-critical-floors-v1".to_owned()),
        evidence_digest: None,
        assessment: None,
        proof: None,
    }
}

/// `_executable_name` (:278).
fn executable_name(segment: &CommandSegmentV1) -> String {
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
fn destructive_remove(arguments: &[String]) -> bool {
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

/// `_destructive_timeout_shell` (:325). `parse_shell_command` on the native
/// path cannot raise — `parse_command` returns `Ok(uncertain)` — matching the
/// Python call site which has no exception handling.
fn destructive_timeout_shell(arguments: &[String]) -> bool {
    let expanded = expand_env_split_string(arguments);
    // `enumerate(expanded[:-1])` — last token cannot pair with a `-c` arg.
    for index in 0..expanded.len().saturating_sub(1) {
        let shell = expanded[index]
            .replace('\\', "/")
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_lowercase();
        if !["ash", "bash", "dash", "sh", "zsh"].contains(&shell.as_str()) {
            continue;
        }
        let Some(command_text) = shell_command_text(&expanded[index + 1..]) else {
            continue;
        };
        let nested = parse_command(&CommandModelRequestV1 {
            command: command_text,
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        })
        .expect("resident parse_command always returns a CanonicalCommandV1");
        let nested = CanonicalCommand::from_v1(&nested);
        return nested.segments.iter().any(|segment| {
            executable_name(segment) == "rm" && destructive_remove(&segment.arguments)
        });
    }
    false
}

/// `_expand_env_split_string` (:341).
fn expand_env_split_string(arguments: &[String]) -> Vec<String> {
    for index in 0..arguments.len().saturating_sub(1) {
        let name = arguments[index]
            .replace('\\', "/")
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_lowercase();
        if name != "env" {
            continue;
        }
        let Some((split_string, consumed)) = env_split_string(arguments, index + 1) else {
            return arguments.to_vec();
        };
        let split = match shlex_split(&split_string) {
            Ok(split) => split,
            Err(_) => return arguments.to_vec(),
        };
        if split.is_empty() {
            return arguments.to_vec();
        }
        let mut out: Vec<String> = Vec::with_capacity(arguments.len() + split.len());
        out.extend_from_slice(&arguments[..index + 1]);
        out.extend(split);
        out.extend_from_slice(&arguments[consumed..]);
        return out;
    }
    arguments.to_vec()
}

/// `_env_split_string` (:356): returns `(split_string, consumed)` or `None`.
fn env_split_string(arguments: &[String], start: usize) -> Option<(String, usize)> {
    let mut index = start;
    while index < arguments.len() {
        let argument = &arguments[index];
        if ENV_LONG_BOOLEAN_OPTIONS.contains(&argument.as_str()) {
            index += 1;
            continue;
        }
        let (option, separator, value) = partition(argument, '=');
        if ENV_LONG_VALUE_OPTIONS.contains(&option) {
            if !separator.is_empty() {
                if value.is_empty() {
                    return None;
                }
                index += 1;
                continue;
            }
            if index + 1 >= arguments.len() || arguments[index + 1].is_empty() {
                return None;
            }
            index += 2;
            continue;
        }
        if option == "--split-string" {
            if !separator.is_empty() {
                return if value.is_empty() {
                    None
                } else {
                    Some((value.to_owned(), index + 1))
                };
            }
            if index + 1 >= arguments.len() || arguments[index + 1].is_empty() {
                return None;
            }
            return Some((arguments[index + 1].clone(), index + 2));
        }
        if argument.starts_with("--") || !argument.starts_with('-') || argument == "-" {
            return None;
        }
        let chars: Vec<char> = argument.chars().collect();
        let mut cursor = 1usize;
        let mut loop_broke = false;
        while cursor < chars.len() {
            let short_option = chars[cursor];
            if ENV_SHORT_BOOLEAN_OPTIONS.contains(&short_option) {
                cursor += 1;
                continue;
            }
            if short_option == 'S' {
                let attached: String = chars[cursor + 1..].iter().collect();
                if !attached.is_empty() {
                    return Some((attached, index + 1));
                }
                if index + 1 >= arguments.len() || arguments[index + 1].is_empty() {
                    return None;
                }
                return Some((arguments[index + 1].clone(), index + 2));
            }
            if !ENV_SHORT_VALUE_OPTIONS.contains(&short_option) {
                return None;
            }
            if cursor + 1 < chars.len() {
                index += 1;
            } else if index + 1 < arguments.len() && !arguments[index + 1].is_empty() {
                index += 2;
            } else {
                return None;
            }
            loop_broke = true;
            break;
        }
        if !loop_broke {
            index += 1;
        }
    }
    None
}

/// `_shell_command_text` (:398).
fn shell_command_text(arguments: &[String]) -> Option<String> {
    const OPTIONS_WITH_VALUES: &[&str] = &["-O", "-o", "--init-file", "--rcfile"];
    let mut index = 0usize;
    while index < arguments.len() {
        let argument = &arguments[index];
        if OPTIONS_WITH_VALUES.contains(&argument.as_str()) {
            index += 2;
            continue;
        }
        if argument == "--" {
            return None;
        }
        if let Some(stripped) = argument.strip_prefix('-') {
            if !argument.starts_with("--") && stripped.contains('c') {
                return arguments.get(index + 1).cloned();
            }
            index += 1;
            continue;
        }
        return None;
    }
    None
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
fn resolved_option(option: &str, known: &[&str]) -> String {
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
fn guard_control_floor(arguments: &[String]) -> Option<(GuardAction, &'static str)> {
    let control_tokens = ["capability", "clear", "policy", "uninstall"];
    if arguments
        .iter()
        .any(|a| control_tokens.contains(&a.as_str()))
        && arguments
            .iter()
            .any(|item| ["help", "--help", "-h"].contains(&item.as_str()))
    {
        return Some((GuardAction::Review, "critical.guard-control-help"));
    }
    if contains_ordered(arguments, "capability", "consume") {
        return Some((GuardAction::Block, "critical.capability-replay"));
    }
    if arguments.iter().any(|a| a == "uninstall") {
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
fn path_export_index(command: &CanonicalCommand) -> Option<usize> {
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

/// `str.partition` equivalent over a single char.
fn partition(argument: &str, separator: char) -> (&str, &str, &str) {
    match argument.find(separator) {
        Some(at) => (&argument[..at], &argument[at..at + 1], &argument[at + 1..]),
        None => (argument, "", ""),
    }
}
