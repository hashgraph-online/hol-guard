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
#[path = "command_compatibility/environment.rs"]
mod environment;
#[path = "command_compatibility/git.rs"]
mod git;
#[path = "command_compatibility/github.rs"]
mod github;

pub use catalog::compatibility_rule_ids;
pub(crate) use environment::inert_environment_name;

pub(crate) fn github_arguments_are_read_only(arguments: &[String], text: &str) -> bool {
    github::arguments_are_read_only(arguments, text)
}

pub(crate) fn git_inspection_arguments<'a>(
    arguments: &'a [String],
    context: crate::pretool::PathContext<'_>,
) -> Option<&'a [String]> {
    git::inspection_arguments(arguments, context)
}

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

    fn mark_uncertain(&mut self, segments: &[usize]) {
        let steered = |indexes: &[usize]| indexes.iter().any(|index| segments.contains(index));
        for item in &mut self.rule_matches {
            item.uncertainty |= steered(&item.segment_indexes);
        }
        for item in &mut self.permission_matches {
            item.uncertainty |= steered(&item.segment_indexes);
        }
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

/// Whether the canonical model is exact enough for structured observation.
/// Commands the parser cannot represent have no attributable segment evidence;
/// their intrinsic floor stays authoritative instead of an observation error.
pub(crate) fn compatibility_model_supported(command: &CanonicalCommandV1) -> bool {
    command.confidence == "exact"
        && command.uncertainty_reason.is_none()
        && !command.segments.is_empty()
        && !command.path_overridden
        && command
            .wrapper_chain
            .iter()
            .all(|wrapper| matches!(wrapper.as_str(), "sudo" | "timeout"))
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

/// Toolchain runners take the rest of the command as code they compile or
/// execute. A non-inert assignment can point that runner at other code, and
/// the loader and compiler names do that for any program. Credential names
/// swap whose authority any program runs with, as `env NAME=` already does.
fn assignment_prefix_is_unsupported(segment: &CommandSegmentV1) -> bool {
    let non_inert = segment
        .environment_names
        .iter()
        .any(|name| !environment::inert_environment_name(name));
    non_inert
        && (segment.environment_names.iter().any(|name| {
            matches!(
                name.as_str(),
                "CC" | "GIT_SSH_COMMAND"
                    | "GOFLAGS"
                    | "LD_PRELOAD"
                    | "NODE_OPTIONS"
                    | "NODE_PATH"
                    | "RUSTFLAGS"
            ) || environment::credential_routing_environment_name(name)
        }) || matches!(
            basename(segment).as_str(),
            "bun" | "cargo" | "go" | "node" | "npm" | "vite"
        ))
}

pub fn compatibility_observations(
    command: &CanonicalCommandV1,
    deadline: Option<Instant>,
) -> Result<CompatibilityObservations, &'static str> {
    compatibility_observations_with_context(
        command,
        deadline,
        crate::pretool::PathContext::default(),
    )
}

pub fn compatibility_observations_with_context(
    command: &CanonicalCommandV1,
    deadline: Option<Instant>,
    context: crate::pretool::PathContext<'_>,
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
    if !compatibility_model_supported(command) {
        return Err("native_command_compatibility_model_unsupported");
    }
    let mut result = CompatibilityObservations::default();
    let mut steered = Vec::new();
    for (index, segment) in command.segments.iter().enumerate() {
        deadline_check(deadline)?;
        if segment.executable.is_none()
            || segment.path_overridden
            || segment
                .wrapper_chain
                .iter()
                .any(|wrapper| !matches!(wrapper.as_str(), "sudo" | "timeout"))
            || segment.text.contains('\0')
            || segment.arguments.iter().any(|value| value.contains('\0'))
        {
            return Err("native_command_compatibility_context_unsupported");
        }
        // Inert names (`CI`, `LANG`, `LC_*`) do not steer, so the segment
        // keeps the same permission decision as the unprefixed command.
        // A loader, compiler or credential name, or any non-inert name on a
        // toolchain runner, is not a reviewable prefix: it can run other code
        // or another identity, so the context is unsupported. Every other non-inert name (`GIT_DIR=`,
        // `GH_HOST=`, `X=`) stays uncertainty. It takes the owners' floor and
        // no permission can allow it, without turning the evaluation into a
        // failure that would hide a disabled permission.
        if assignment_prefix_is_unsupported(segment) {
            return Err("native_command_compatibility_context_unsupported");
        }
        if segment
            .environment_names
            .iter()
            .any(|name| !environment::inert_environment_name(name))
        {
            steered.push(index);
        }
        match basename(segment).as_str() {
            "git" => git::observe_with_context(segment, index, &mut result, context),
            "gh" => github::observe(segment, index, &mut result),
            _ => {}
        }
        domains::observe(command, segment, index, &mut result);
    }
    deadline_check(deadline)?;
    result.mark_uncertain(&steered);
    result.normalize();
    Ok(result)
}
