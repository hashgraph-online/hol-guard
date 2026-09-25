//! Bounded attribution for catalog rules without a declarative matcher.
//!
//! This is an admission boundary, not a claim that Python's context-sensitive
//! classifiers have all been translated. A relevant unsupported form produces
//! owned uncertainty; an invalid canonical model fails the whole evaluation.
//! Neither outcome may be interpreted as an empty successful observation set.

use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::collections::BTreeMap;
use std::time::Instant;

#[path = "command_compatibility/catalog.rs"]
mod catalog;
#[path = "command_compatibility/domains.rs"]
mod domains;
#[path = "command_compatibility/git.rs"]
mod git;
#[path = "command_compatibility/github.rs"]
mod github;

pub use catalog::compatibility_rule_ids;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityMatch {
    pub rule_id: &'static str,
    pub segment_indexes: Vec<usize>,
    pub uncertainty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityPermissionMatch {
    pub permission_id: &'static str,
    pub segment_indexes: Vec<usize>,
    pub uncertainty: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompatibilityObservations {
    pub rule_matches: Vec<CompatibilityMatch>,
    pub permission_matches: Vec<CompatibilityPermissionMatch>,
}

impl CompatibilityObservations {
    fn rule(&mut self, rule_id: &'static str, index: usize, uncertainty: bool) {
        self.rule_matches.push(CompatibilityMatch {
            rule_id,
            segment_indexes: vec![index],
            uncertainty,
        });
    }

    fn permission(&mut self, permission_id: &'static str, index: usize, uncertainty: bool) {
        self.permission_matches.push(CompatibilityPermissionMatch {
            permission_id,
            segment_indexes: vec![index],
            uncertainty,
        });
    }

    fn normalize(&mut self) {
        let mut rules: BTreeMap<&'static str, (Vec<usize>, bool)> = BTreeMap::new();
        for item in self.rule_matches.drain(..) {
            let value = rules.entry(item.rule_id).or_default();
            value.0.extend(item.segment_indexes);
            value.1 |= item.uncertainty;
        }
        self.rule_matches = rules
            .into_iter()
            .map(|(rule_id, (mut indexes, uncertainty))| {
                indexes.sort_unstable();
                indexes.dedup();
                CompatibilityMatch {
                    rule_id,
                    segment_indexes: indexes,
                    uncertainty,
                }
            })
            .collect();
        let mut permissions: BTreeMap<&'static str, (Vec<usize>, bool)> = BTreeMap::new();
        for item in self.permission_matches.drain(..) {
            let value = permissions.entry(item.permission_id).or_default();
            value.0.extend(item.segment_indexes);
            value.1 |= item.uncertainty;
        }
        self.permission_matches = permissions
            .into_iter()
            .map(|(permission_id, (mut indexes, uncertainty))| {
                indexes.sort_unstable();
                indexes.dedup();
                CompatibilityPermissionMatch {
                    permission_id,
                    segment_indexes: indexes,
                    uncertainty,
                }
            })
            .collect();
    }
}

fn deadline_check(deadline: Option<Instant>) -> Result<(), &'static str> {
    if deadline.is_some_and(|limit| Instant::now() >= limit) {
        Err("native_command_compatibility_deadline")
    } else {
        Ok(())
    }
}

fn basename(segment: &CommandSegmentV1) -> String {
    let value = segment.executable.as_deref().unwrap_or("");
    let basename = value.rsplit(['/', '\\']).next().unwrap_or(value);
    let name = crate::command_ascii_comparison::lowercase_for_ascii_comparison(basename);
    name.strip_suffix(".exe")
        .or_else(|| name.strip_suffix(".cmd"))
        .unwrap_or(&name)
        .to_owned()
}

pub fn compatibility_observations(
    command: &CanonicalCommandV1,
    deadline: Option<Instant>,
) -> Result<CompatibilityObservations, &'static str> {
    deadline_check(deadline)?;
    if command.normalized_text.len() > 32_768
        || command.segments.len() > 128
        || command.segments.iter().any(|segment| {
            segment.tokens.len() > 2_048
                || segment.arguments.len() > 2_048
                || segment.text.len() > 32_768
                || segment
                    .executable
                    .as_ref()
                    .is_some_and(|value| value.len() > 32_768)
        })
        || command
            .segments
            .iter()
            .map(|segment| segment.tokens.len())
            .sum::<usize>()
            > 2_048
        || command
            .segments
            .iter()
            .map(|segment| segment.arguments.len())
            .sum::<usize>()
            > 2_048
        || command
            .segments
            .iter()
            .flat_map(|segment| &segment.tokens)
            .map(String::len)
            .sum::<usize>()
            > 32_768
        || command
            .segments
            .iter()
            .flat_map(|segment| &segment.arguments)
            .map(String::len)
            .sum::<usize>()
            > 32_768
    {
        return Err("native_command_compatibility_limit");
    }
    if command.confidence != "exact"
        || command.uncertainty_reason.is_some()
        || command.segments.is_empty()
        || command.path_overridden
        || command
            .wrapper_chain
            .iter()
            .any(|wrapper| wrapper != "sudo")
    {
        return Err("native_command_compatibility_model_unsupported");
    }
    let mut result = CompatibilityObservations::default();
    for (index, segment) in command.segments.iter().enumerate() {
        deadline_check(deadline)?;
        if segment.executable.is_none()
            || segment.path_overridden
            || segment
                .wrapper_chain
                .iter()
                .any(|wrapper| wrapper != "sudo")
            || !segment.environment_names.is_empty()
            || segment.text.contains('\0')
            || segment.arguments.iter().any(|value| value.contains('\0'))
        {
            return Err("native_command_compatibility_context_unsupported");
        }
        match basename(segment).as_str() {
            "git" => git::observe(segment, index, &mut result),
            "gh" => github::observe(segment, index, &mut result),
            _ => {}
        }
        domains::observe(command, segment, index, &mut result);
    }
    deadline_check(deadline)?;
    result.normalize();
    Ok(result)
}
