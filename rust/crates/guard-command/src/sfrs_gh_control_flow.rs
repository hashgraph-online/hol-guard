//! Statically skip GitHub pipelines that cannot run under `&&`, `||` or `if`
//! (`runtime/github_shell_control_flow.py`).

// Consumed by the GitHub shell classifier slice.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use crate::sfrs_gh_bindings::{conditional_pipeline_connectors, token_is_shell_assignment};
use crate::sfrs_shell_tokens::shell_segment_primary_command;

fn strip_lower(token: &str) -> String {
    token.trim_matches(['"', '\'']).to_lowercase()
}

/// Possible exit statuses of a pipeline: `(may_be_false, may_be_true)`.
#[derive(Clone, Copy)]
struct Statuses {
    false_possible: bool,
    true_possible: bool,
}

impl Statuses {
    const NONE: Self = Self {
        false_possible: false,
        true_possible: false,
    };
    const BOTH: Self = Self {
        false_possible: true,
        true_possible: true,
    };

    fn union(self, other: Self) -> Self {
        Self {
            false_possible: self.false_possible || other.false_possible,
            true_possible: self.true_possible || other.true_possible,
        }
    }
}

/// `_literal_pipeline_truth`.
fn literal_pipeline_truth(pipeline: &[Vec<String>]) -> Option<bool> {
    if pipeline.len() != 1 {
        return None;
    }
    let segment = &pipeline[0];
    let (name, index) = shell_segment_primary_command(segment);
    let (Some(name), Some(index)) = (name, index) else {
        return None;
    };
    if name != "true" && name != "false" {
        return None;
    }
    if segment[index].contains(['>', '<']) {
        return None;
    }
    for (position, token) in segment.iter().enumerate() {
        if position == index || token_is_shell_assignment(token) {
            continue;
        }
        return None;
    }
    Some(name == "true")
}

/// `_and_or_skipped_indexes`.
fn and_or_skipped_indexes(
    pipelines: &[Vec<Vec<String>>],
    connectors: &HashMap<usize, String>,
) -> HashSet<usize> {
    let mut skipped = HashSet::new();
    let mut accumulated = Statuses::NONE;
    for (index, pipeline) in pipelines.iter().enumerate() {
        if pipeline.is_empty() {
            accumulated = Statuses::NONE;
            continue;
        }
        let current = match literal_pipeline_truth(pipeline) {
            None => Statuses::BOTH,
            Some(true) => Statuses {
                false_possible: false,
                true_possible: true,
            },
            Some(false) => Statuses {
                false_possible: true,
                true_possible: false,
            },
        };
        if index == 0 {
            accumulated = current;
            continue;
        }
        match connectors.get(&index).map(String::as_str) {
            Some("&&") => {
                if !accumulated.true_possible {
                    skipped.insert(index);
                    continue;
                }
                let preserved = if accumulated.false_possible {
                    Statuses {
                        false_possible: true,
                        true_possible: false,
                    }
                } else {
                    Statuses::NONE
                };
                accumulated = current.union(preserved);
            }
            Some("||") => {
                if !accumulated.false_possible {
                    skipped.insert(index);
                    continue;
                }
                let preserved = if accumulated.true_possible {
                    Statuses {
                        false_possible: false,
                        true_possible: true,
                    }
                } else {
                    Statuses::NONE
                };
                accumulated = current.union(preserved);
            }
            _ => accumulated = current,
        }
    }
    skipped
}

/// `_if_branch_effects`.
fn if_branch_effects(pipelines: &[Vec<Vec<String>>]) -> (HashSet<usize>, HashSet<usize>) {
    let mut extra_conditional = HashSet::new();
    let mut skipped = HashSet::new();
    let mut stack: Vec<(Option<bool>, Option<&'static str>)> = Vec::new();
    for (index, pipeline) in pipelines.iter().enumerate() {
        let segment: &[String] = pipeline.first().map_or(&[], Vec::as_slice);
        let first = segment
            .first()
            .map(|token| strip_lower(token))
            .unwrap_or_default();
        if first == "if" {
            let condition = segment
                .get(1)
                .map(|token| strip_lower(token))
                .unwrap_or_default();
            let truth = match condition.as_str() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            };
            stack.push((truth, None));
            continue;
        }
        if first == "fi" {
            stack.pop();
            continue;
        }
        if matches!(first.as_str(), "then" | "else" | "elif") {
            if let Some(top) = stack.last_mut() {
                let truth = if first == "elif" { None } else { top.0 };
                let branch = if first == "else" { "else" } else { "then" };
                *top = (truth, Some(branch));
            }
        }
        let Some(&(truth, Some(branch))) = stack.last() else {
            continue;
        };
        match truth {
            None => {
                extra_conditional.insert(index);
            }
            Some(truth) if (branch == "then" && !truth) || (branch == "else" && truth) => {
                skipped.insert(index);
            }
            Some(_) => {}
        }
    }
    (extra_conditional, skipped)
}

/// `pipeline_control_flow`: conditional and statically skipped pipelines.
pub(crate) fn pipeline_control_flow(
    parts: &[String],
    pipelines: &[Vec<Vec<String>>],
) -> (HashSet<usize>, HashSet<usize>) {
    let connectors = conditional_pipeline_connectors(parts);
    let mut skipped = and_or_skipped_indexes(pipelines, &connectors);
    let (extra_conditional, if_skipped) = if_branch_effects(pipelines);
    skipped.extend(if_skipped);
    let mut conditional: HashSet<usize> = connectors.into_keys().collect();
    conditional.extend(extra_conditional);
    (conditional, skipped)
}
