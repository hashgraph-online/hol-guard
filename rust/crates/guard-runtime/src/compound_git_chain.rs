//! Whole-command shapes: leading-`cd` chains, standalone routines, and the
//! exact `git cat-file -e` object existence query.

use std::path::Path;

use guard_contracts::CompoundGitSegmentV1;

use crate::compound_git_args as args;
use crate::compound_git_facts::GitFacts;
use crate::compound_git_paths::resolve;
use crate::compound_git_segments::{
    is_low_risk_git_inspection_segment, is_low_risk_git_push_segment,
};
use crate::local_mcp_grant_identity::shlex_split;

const MAX_OUTPUT_LINES: u64 = 1000;

fn leading_literal_cd(segment: &CompoundGitSegmentV1) -> bool {
    segment.control_before.is_empty()
        && segment.directory_operation.as_deref() == Some("cd")
        && segment.tokens.len() == 2
        && segment.tokens[0] == "cd"
}

fn safe_echo_segment(segment: &CompoundGitSegmentV1) -> bool {
    segment.tokens.len() >= 2
        && segment.control_before == ["&&"]
        && segment.control_after == ["&&"]
        && segment.tokens[1..]
            .iter()
            .all(|token| !matches!(token.as_str(), "-e" | "-E" | "-n") && !args::is_dynamic(token))
}

pub(crate) fn safe_bound_segment(
    segment: &CompoundGitSegmentV1,
    previous: &CompoundGitSegmentV1,
) -> bool {
    if segment.control_before != ["|"] || segment.tokens.len() != 2 {
        return false;
    }
    if previous.tokens.first().map(String::as_str) != Some("git") || previous.control_after != ["|"]
    {
        return false;
    }
    let Some(digits) = segment.tokens[1].strip_prefix('-') else {
        return false;
    };
    args::all_ascii_digits(digits)
        && (1..=MAX_OUTPUT_LINES).contains(&args::saturating_number(digits))
}

/// A deterministic leading-`cd` Git routine.
pub(crate) fn is_low_risk_compound_git_inspection(
    facts: &dyn GitFacts,
    segments: &[CompoundGitSegmentV1],
    complete: bool,
) -> bool {
    if !complete || segments.len() < 2 || !leading_literal_cd(&segments[0]) {
        return false;
    }
    let mut saw_git = false;
    for (index, segment) in segments.iter().enumerate().skip(1) {
        if segment
            .control_before
            .iter()
            .chain(&segment.control_after)
            .any(|control| !matches!(control.as_str(), "&&" | "|"))
        {
            return false;
        }
        match segment.tokens.first().map(String::as_str).unwrap_or("") {
            "git" => {
                if !(is_low_risk_git_inspection_segment(facts, segment, None)
                    || is_low_risk_git_push_segment(facts, segment))
                {
                    return false;
                }
                saw_git = true;
            }
            "echo" => {
                if !safe_echo_segment(segment) {
                    return false;
                }
            }
            "head" | "tail" => {
                if !safe_bound_segment(segment, &segments[index - 1]) {
                    return false;
                }
            }
            _ => return false,
        }
    }
    saw_git
}

/// One bounded Git read or configured-origin ref refresh.
pub(crate) fn is_low_risk_standalone_git_routine(
    facts: &dyn GitFacts,
    segments: &[CompoundGitSegmentV1],
    complete: bool,
    home_dir: Option<&Path>,
) -> bool {
    let [segment] = segments else {
        return false;
    };
    complete
        && segment.tokens.first().map(String::as_str) == Some("git")
        && segment.control_before.is_empty()
        && segment.control_after.is_empty()
        && is_low_risk_git_inspection_segment(facts, segment, home_dir)
}

/// An exact, output-free Git object existence query.
pub(crate) fn is_safe_standalone_git_object_existence_query(
    facts: &dyn GitFacts,
    command_text: &str,
    cwd: &Path,
) -> bool {
    let Some(parts) = shlex_split(command_text) else {
        return false;
    };
    let Some(execution_cwd) = resolve(cwd) else {
        return false;
    };
    let Some(git) = facts.trusted_git(&execution_cwd) else {
        return false;
    };
    parts.len() == 4
        && parts[0] == "git"
        && parts[1] == "cat-file"
        && parts[2] == "-e"
        && args::safe_object_existence_operand(&parts[3])
        && facts.object_query_is_safe(&execution_cwd, &git)
}
