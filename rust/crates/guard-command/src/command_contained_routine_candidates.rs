//! Rust port of `runtime/command_contained_routine_candidates.py`.

use crate::canonical_command::CanonicalCommand;
use crate::command_candidate_common::command_has_exact_plain_shell_shape;
use crate::effect_decision::{DecisionBasis, DecisionFactor, DecisionFactorSource, GuardAction};
use crate::CommandSegmentV1;

#[allow(dead_code)]
pub const CONTAINED_ROUTINE_CANDIDATE_VERSION: &str = "guard.contained-routine-candidate.v1";

/// `contained_routine_candidate_factor` (:16).
pub fn contained_routine_candidate_factor(command: &CanonicalCommand) -> Option<DecisionFactor> {
    let operation = contained_routine_candidate_operation(command)?;
    Some(DecisionFactor {
        source: DecisionFactorSource::Policy,
        reason_code: "contained-routine-proof-required".to_owned(),
        basis: DecisionBasis {
            action_floor: GuardAction::Review,
            proof_route: None,
        },
        segment_ref: None,
        operation_ref: Some(format!("operation:{operation}")),
        producer_ref: Some("policy:contained-routine-candidate-v1".to_owned()),
        evidence_digest: None,
        assessment: None,
        proof: None,
    })
}

/// `contained_routine_candidate_operation` (:31).
pub fn contained_routine_candidate_operation(command: &CanonicalCommand) -> Option<&'static str> {
    if !command_has_exact_plain_shell_shape(command) || command.segments.len() < 2 {
        return None;
    }
    let (directory, segments) = command.segments.split_first()?;
    if name(directory) != "cd"
        || directory.arguments.len() != 1
        || !plain_value(&directory.arguments[0])
    {
        return None;
    }
    let signature: Vec<(String, Vec<String>)> = segments
        .iter()
        .map(|s| (name(s), s.arguments.clone()))
        .collect();
    // Compare directly against the frozen signature table.
    type Sig = Vec<(&'static str, Vec<&'static str>)>;
    let actual: Vec<(&str, Vec<&str>)> = signature
        .iter()
        .map(|(n, args)| (n.as_str(), args.iter().map(String::as_str).collect()))
        .collect();
    let test: Sig = vec![("pytest", vec!["-q", "tests/test_guard_runtime.py"])];
    if eq(&actual, &test) {
        return Some("test");
    }
    if eq(&actual, &[("ruff", vec!["check", "src", "tests"])]) {
        return Some("lint");
    }
    if eq(&actual, &[("bun", vec!["run", "build"])]) {
        return Some("build");
    }
    for s in [
        vec![
            ("bun", vec!["run", "typecheck", "2>&1"]),
            ("head", vec!["-40"]),
        ],
        vec![
            ("npx", vec!["tsc", "--noEmit", "--pretty", "2>&1"]),
            ("head", vec!["-40"]),
        ],
    ] {
        if eq(&actual, &s) {
            return Some("typecheck");
        }
    }
    if eq(
        &actual,
        &[(
            "find",
            vec![
                "src",
                "-name",
                "*.py",
                "-exec",
                "python",
                "-m",
                "py_compile",
                "{}",
                "+",
            ],
        )],
    ) {
        return Some("compile-check");
    }
    for s in [
        vec![("cargo", vec!["tree", "--depth", "2"])],
        vec![("bun", vec!["pm", "ls", "--all"])],
        vec![("uv", vec!["tree", "--depth", "2"])],
    ] {
        if eq(&actual, &s) {
            return Some("dependency-tree");
        }
    }
    for s in [
        vec![("rg", vec!["-n", "error", "logs"]), ("head", vec!["-40"])],
        vec![
            ("git", vec!["status", "--porcelain=v1"]),
            ("wc", vec!["-l"]),
        ],
    ] {
        if eq(&actual, &s) {
            return Some("workspace-check");
        }
    }
    None
}

fn eq(a: &[(&str, Vec<&str>)], b: &[(&str, Vec<&str>)]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|((an, aa), (bn, ba))| an == bn && aa == ba)
}

/// `_name` (:67): `Path(segment.executable or "").name.lower()`.
fn name(segment: &CommandSegmentV1) -> String {
    let exe = segment.executable.as_deref().unwrap_or("");
    exe.rsplit('/').next().unwrap_or(exe).to_lowercase()
}

/// `_plain_value` (:71).
fn plain_value(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value
            .chars()
            .any(|c| matches!(c, '$' | '`' | '<' | '>' | '|' | ';' | '&' | '\0'))
}
