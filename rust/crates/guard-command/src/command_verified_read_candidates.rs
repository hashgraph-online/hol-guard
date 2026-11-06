//! Rust port of `runtime/command_verified_read_candidates.py`.
//!
//! `redirects`/`embedded_commands` are always empty on the native path
//! (`canonical_command.rs::from_v1`), so `command_has_exact_plain_shell_shape`
//! covers the full plain-command guard.

use std::sync::OnceLock;

use regex::Regex;

use crate::canonical_command::CanonicalCommand;
use crate::command_candidate_common::command_has_exact_plain_shell_shape;
use crate::effect_decision::{DecisionBasis, DecisionFactor, DecisionFactorSource, GuardAction};
use crate::github_command_capabilities::classify_github_cli;
use crate::CommandSegmentV1;

#[allow(dead_code)]
pub const VERIFIED_READ_CANDIDATE_VERSION: &str = "guard.verified-read-candidate.v1";

fn count_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\A(?:-[0-9]{1,6}|--(?:lines|bytes)=[0-9]{1,6})\z").unwrap())
}

fn sed_range_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\A[0-9]{1,6}(?:,[0-9]{1,6})?p\z").unwrap())
}

#[allow(dead_code)]
fn repository_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\z").unwrap())
}

const LOCAL_EXECUTABLES: &[&str] = &["fd", "git", "head", "ls", "pwd", "rg", "sed", "tail"];

/// `verified_read_candidate_factor` (:22).
pub fn verified_read_candidate_factor(command: &CanonicalCommand) -> Option<DecisionFactor> {
    let operation = verified_read_candidate_operation(command)?;
    Some(DecisionFactor {
        source: DecisionFactorSource::Policy,
        reason_code: "verified-read-proof-required".to_owned(),
        basis: DecisionBasis {
            action_floor: GuardAction::Review,
            proof_route: None,
        },
        segment_ref: None,
        operation_ref: Some(format!("operation:{operation}")),
        producer_ref: Some("policy:verified-read-candidate-v1".to_owned()),
        evidence_digest: None,
        assessment: None,
        proof: None,
    })
}

/// `verified_read_candidate_operation` (:39).
pub fn verified_read_candidate_operation(command: &CanonicalCommand) -> Option<&'static str> {
    if !command_has_exact_plain_shell_shape(command) {
        return None;
    }
    let segments = &command.segments;
    let mut offset = 0;
    if segments[0].executable.as_deref() == Some("cd") {
        // Python checks `len(arguments) == 1` then `_plain_target(arguments[0])`.
        if segments[0].arguments.len() != 1 || !plain_target(&segments[0].arguments[0]) {
            return None;
        }
        offset = 1;
    }
    if offset == segments.len() {
        return None;
    }
    let rest = &segments[offset..];
    let executable_names: Vec<String> = rest.iter().map(name).collect();
    if executable_names == ["gh"] {
        return github_operation(&rest[0]);
    }
    if executable_names
        .iter()
        .any(|n| !LOCAL_EXECUTABLES.contains(&n.as_str()))
    {
        return None;
    }
    if !rest.iter().all(local_segment_is_candidate) {
        return None;
    }
    if rest.len() > 1 && !bounded_pipeline(rest) {
        return None;
    }
    Some("workspace-read")
}

/// `_local_segment_is_candidate` (:69).
fn local_segment_is_candidate(segment: &CommandSegmentV1) -> bool {
    let name = name(segment);
    let args = &segment.arguments;
    match name.as_str() {
        "pwd" => args.is_empty(),
        "ls" => args
            .iter()
            .all(|arg| arg.starts_with('-') || plain_target(arg)),
        "head" | "tail" => {
            !args.is_empty()
                && args
                    .iter()
                    .all(|arg| count_re().is_match(arg) || plain_target(arg))
        }
        "sed" => {
            args.len() >= 3
                && args[0] == "-n"
                && sed_range_re().is_match(&args[1])
                && args[2..].iter().all(|arg| plain_target(arg))
        }
        "fd" => fd_candidate(args),
        "rg" => rg_candidate(args),
        "git" => git_candidate(args),
        _ => false,
    }
}

/// `_fd_candidate` (:95).
fn fd_candidate(args: &[String]) -> bool {
    if args.len() < 2
        || args.iter().any(|arg| {
            ["-x", "-X", "--exec", "--exec-batch", "-L", "--follow"].contains(&arg.as_str())
        })
    {
        return false;
    }
    args.iter().all(|arg| !dynamic(arg)) && args.iter().any(|arg| plain_target(arg))
}

/// `_rg_candidate` (:100).
fn rg_candidate(args: &[String]) -> bool {
    if args.is_empty()
        || args.iter().any(|arg| {
            [
                "--hidden",
                "--follow",
                "-L",
                "--pre",
                "--pre-glob",
                "--files-with-matches",
            ]
            .contains(&arg.as_str())
                || arg.starts_with("--pre=")
        })
    {
        return false;
    }
    let positional: Vec<&String> = args.iter().filter(|arg| !arg.starts_with('-')).collect();
    // A flag-only search (`rg --files`) has no positional operand at all.
    let targets = positional.get(1..).unwrap_or_default();
    !positional.is_empty()
        && !targets.is_empty()
        && args.iter().all(|arg| !dynamic(arg))
        && targets.iter().all(|arg| source_target(arg))
}

/// `_git_candidate` (:114).
fn git_candidate(args: &[String]) -> bool {
    const SETS: &[&[&str]] = &[
        &["rev-parse", "--show-toplevel"],
        &["status", "--short"],
        &["diff", "--check"],
        &["log", "-5", "--oneline"],
        &["show", "--stat", "--oneline", "HEAD"],
        &["branch", "--show-current"],
    ];
    SETS.iter().any(|expected| {
        expected.len() == args.len() && expected.iter().zip(args.iter()).all(|(e, a)| e == a)
    })
}

/// `_bounded_pipeline` (:122).
fn bounded_pipeline(segments: &[CommandSegmentV1]) -> bool {
    if segments.len() != 2 || segments[0].pipeline_index != 0 || segments[1].pipeline_index != 1 {
        return false;
    }
    ["fd", "rg"].contains(&name(&segments[0]).as_str())
        && ["head", "tail"].contains(&name(&segments[1]).as_str())
}

/// `_github_operation` (:128).
fn github_operation(segment: &CommandSegmentV1) -> Option<&'static str> {
    let assessment = classify_github_cli(&segment.arguments);
    if assessment.capability.as_str() != "read_remote"
        || assessment.capabilities.len() != 1
        || assessment.capabilities[0].as_str() != "read_remote"
    {
        return None;
    }
    let args = &segment.arguments;
    if args.len() < 5
        || !matches!(
            (args[0].as_str(), args[1].as_str()),
            ("pr", "view") | ("pr", "checks")
        )
    {
        return None;
    }
    // `args[2].isdigit()` — Python digit property (Nd + numeric digits).
    // `char::is_numeric` covers Nd/No/Nl; argv selectors are ASCII in
    // practice and both predicates agree on the full ASCII range.
    if !args[2].chars().all(|c| c.is_numeric()) || args.iter().any(|arg| dynamic(arg)) {
        return None;
    }
    Some("github-pull-request-read")
}

/// `_name` (:144): `Path(segment.executable or "").name.lower()`.
fn name(segment: &CommandSegmentV1) -> String {
    let executable = segment.executable.as_deref().unwrap_or("");
    let base = executable.rsplit(['/', '\\']).next().unwrap_or("");
    base.to_lowercase()
}

/// `_plain_target` (:148).
fn plain_target(value: &str) -> bool {
    !value.is_empty() && !value.starts_with('-') && !dynamic(value)
}

/// `_source_target` (:152).
fn source_target(value: &str) -> bool {
    let normalized = value.replace('\\', "/");
    let normalized = normalized.strip_prefix("./").unwrap_or(&normalized);
    plain_target(value) && ["src", "tests"].contains(&normalized.split('/').next().unwrap_or(""))
}

/// `_dynamic` (:158).
fn dynamic(value: &str) -> bool {
    value
        .chars()
        .any(|c| matches!(c, '$' | '`' | '<' | '>' | '|' | ';' | '&' | '\x00'))
}

#[cfg(test)]
mod flag_only_search_tests {
    use super::rg_candidate;

    #[test]
    fn flag_only_search_is_not_a_candidate_and_does_not_panic() {
        for args in [&["--files"][..], &["--version"], &["-n", "--no-heading"]] {
            let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
            assert!(!rg_candidate(&args), "{args:?}");
        }
    }
}
