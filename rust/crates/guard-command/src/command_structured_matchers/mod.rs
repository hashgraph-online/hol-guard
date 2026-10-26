//! Versioned, compiled counterparts of the Python structured command matchers.
//!
//! These grammars intentionally retain their distinct option-scanning rules.
//! In particular, `present_flags` preserves raw spelling and stops at `--`,
//! whereas option-setting extraction continues after that token. Combining the
//! scanners would change the existing extension contract.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use serde::Deserialize;
use serde_json::Value;

use crate::command_database_matchers::check_command_bounds;
use crate::command_option_parsing::python_is_whitespace;
use crate::{CanonicalCommandV1, CommandSegmentV1};

mod grammar;

pub(crate) use grammar::{leading_flags_and_operands, operands_without_options, present_flags};
use grammar::{option_values, split_option_setting};

type MatchResult = Result<Vec<usize>, &'static str>;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeadingOperandCountConfig {
    executables: BTreeSet<String>,
    minimum_operands: usize,
    #[serde(default)]
    options_with_values: BTreeSet<String>,
    #[serde(default)]
    forbidden_flags: BTreeSet<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubcommandOperandPrefixConfig {
    executables: BTreeSet<String>,
    subcommands: Vec<String>,
    operand_prefixes: BTreeSet<String>,
    #[serde(default)]
    leading_options_with_values: BTreeSet<String>,
    #[serde(default)]
    options_with_values: BTreeSet<String>,
    #[serde(default)]
    leading_operands_to_skip: usize,
    #[serde(default)]
    options_supplying_leading_operands: BTreeSet<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionValueKeyConfig {
    executables: BTreeSet<String>,
    option_names: BTreeSet<String>,
    value_keys: BTreeSet<String>,
    #[serde(default)]
    forbidden_flags: BTreeSet<String>,
    #[serde(default)]
    ignored_values: BTreeSet<String>,
    #[serde(default)]
    required_key_values: Vec<(String, String)>,
    #[serde(default)]
    cluster_options_with_values: BTreeSet<String>,
    // Derived once during compilation; never accepted from the wire.
    #[serde(skip)]
    all_value_options: BTreeSet<String>,
    #[serde(skip)]
    ordered_options: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentNameConfig {
    executables: BTreeSet<String>,
    environment_names: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub enum StructuredMatcher {
    LeadingOperandCount(LeadingOperandCountConfig),
    SubcommandOperandPrefix(SubcommandOperandPrefixConfig),
    OptionValueKey(OptionValueKeyConfig),
    EnvironmentName(EnvironmentNameConfig),
}

impl StructuredMatcher {
    pub fn from_config(op: &str, config: Value) -> Result<Self, &'static str> {
        let invalid = |_| "invalid_structured_matcher_config";
        match op {
            "leading-operand-count.v1" => {
                let mut config: LeadingOperandCountConfig =
                    serde_json::from_value(config).map_err(invalid)?;
                config.executables = normalize_lower_set(config.executables)?;
                config.options_with_values = normalize_option_set(config.options_with_values)?;
                config.forbidden_flags = normalize_option_set(config.forbidden_flags)?;
                if config.executables.is_empty() || config.minimum_operands == 0 {
                    return Err("invalid_structured_matcher_config");
                }
                Ok(Self::LeadingOperandCount(config))
            }
            "subcommand-operand-prefix.v1" => {
                let mut config: SubcommandOperandPrefixConfig =
                    serde_json::from_value(config).map_err(invalid)?;
                config.executables = normalize_lower_set(config.executables)?;
                config.subcommands = config
                    .subcommands
                    .into_iter()
                    .filter(|value| !python_trim(value).is_empty())
                    .map(|value| lowercase(python_trim(&value)))
                    .collect::<Result<_, _>>()?;
                config.operand_prefixes.retain(|value| !value.is_empty());
                // The Python contract deliberately leaves these option sets
                // and operand prefixes unnormalized.
                if config.executables.is_empty()
                    || config.subcommands.is_empty()
                    || config.operand_prefixes.is_empty()
                {
                    return Err("invalid_structured_matcher_config");
                }
                Ok(Self::SubcommandOperandPrefix(config))
            }
            "option-value-key.v1" => {
                let mut config: OptionValueKeyConfig =
                    serde_json::from_value(config).map_err(invalid)?;
                config.executables = normalize_lower_set(config.executables)?;
                config.option_names = normalize_trim_set(config.option_names);
                config.value_keys = normalize_lower_set(config.value_keys)?;
                config.forbidden_flags = normalize_option_set(config.forbidden_flags)?;
                config.ignored_values = normalize_lower_set(config.ignored_values)?;
                config.required_key_values = config
                    .required_key_values
                    .into_iter()
                    .filter(|(key, value)| {
                        !python_trim(key).is_empty() && !python_trim(value).is_empty()
                    })
                    .map(|(key, value)| {
                        Ok((
                            lowercase(python_trim(&key))?,
                            lowercase(python_trim(&value))?,
                        ))
                    })
                    .collect::<Result<_, &'static str>>()?;
                config.cluster_options_with_values =
                    normalize_trim_set(config.cluster_options_with_values);
                if config.executables.is_empty()
                    || config.option_names.is_empty()
                    || config.value_keys.is_empty()
                {
                    return Err("invalid_structured_matcher_config");
                }
                config.all_value_options = config
                    .option_names
                    .union(&config.cluster_options_with_values)
                    .cloned()
                    .collect();
                config.ordered_options = config.option_names.iter().cloned().collect();
                config
                    .ordered_options
                    .sort_by_key(|value| std::cmp::Reverse(value.chars().count()));
                Ok(Self::OptionValueKey(config))
            }
            "environment-name.v1" => {
                let mut config: EnvironmentNameConfig =
                    serde_json::from_value(config).map_err(invalid)?;
                config.executables = normalize_lower_set(config.executables)?;
                config.environment_names = config
                    .environment_names
                    .into_iter()
                    .filter(|value| !python_trim(value).is_empty())
                    .map(|value| uppercase(python_trim(&value)))
                    .collect::<Result<_, _>>()?;
                if config.executables.is_empty() || config.environment_names.is_empty() {
                    return Err("invalid_structured_matcher_config");
                }
                Ok(Self::EnvironmentName(config))
            }
            _ => Err("unsupported_structured_matcher"),
        }
    }

    #[cfg(test)]
    pub fn match_segments(&self, command: &CanonicalCommandV1) -> MatchResult {
        self.match_segments_with_deadline(command, None)
    }

    pub fn match_segments_with_deadline(
        &self,
        command: &CanonicalCommandV1,
        deadline: Option<Instant>,
    ) -> MatchResult {
        check_deadline(deadline)?;
        check_command_bounds(command)?;
        if command.confidence != "exact" {
            return Err("structured_command_uncertain");
        }
        let mut matches = Vec::new();
        for (index, segment) in command.segments.iter().enumerate() {
            check_deadline(deadline)?;
            let matched = match self {
                Self::LeadingOperandCount(config) => {
                    if !segment_matches_executable(segment, &config.executables)? {
                        continue;
                    }
                    let (flags, operands) = leading_flags_and_operands(
                        &segment.arguments,
                        &config.options_with_values,
                    )?;
                    config.forbidden_flags.is_disjoint(&flags)
                        && operands.len() >= config.minimum_operands
                }
                Self::SubcommandOperandPrefix(config) => {
                    if !segment_matches_executable(segment, &config.executables)? {
                        continue;
                    }
                    let (_, leading_operands) = leading_flags_and_operands(
                        &segment.arguments,
                        &config.leading_options_with_values,
                    )?;
                    if leading_operands.len() < config.subcommands.len() {
                        continue;
                    }
                    let lowered: Vec<_> = leading_operands[..config.subcommands.len()]
                        .iter()
                        .map(|value| lowercase(value))
                        .collect::<Result<_, _>>()?;
                    if lowered != config.subcommands {
                        continue;
                    }
                    let arguments = &leading_operands[config.subcommands.len()..];
                    let operands =
                        operands_without_options(arguments, &config.options_with_values)?;
                    let flags = present_flags(arguments, &config.options_with_values);
                    let skip = if flags.is_disjoint(&config.options_supplying_leading_operands) {
                        config.leading_operands_to_skip.min(operands.len())
                    } else {
                        0
                    };
                    operands[skip..].iter().any(|operand| {
                        config.operand_prefixes.iter().any(|prefix| {
                            operand.len() > prefix.len() && operand.starts_with(prefix)
                        })
                    })
                }
                Self::OptionValueKey(config) => {
                    if !segment_matches_executable(segment, &config.executables)? {
                        continue;
                    }
                    let flags = present_flags(&segment.arguments, &config.all_value_options);
                    if !config.forbidden_flags.is_disjoint(&flags) {
                        continue;
                    }
                    let mut settings = BTreeMap::new();
                    for value in option_values(
                        &segment.arguments,
                        &config.option_names,
                        &config.ordered_options,
                        &config.all_value_options,
                    ) {
                        let (key, value) = split_option_setting(value)?;
                        if !key.is_empty() {
                            // SSH-style settings use the first occurrence.
                            settings.entry(key).or_insert(value);
                        }
                    }
                    if config
                        .required_key_values
                        .iter()
                        .any(|(key, value)| settings.get(key) != Some(value))
                    {
                        continue;
                    }
                    config.value_keys.iter().any(|key| {
                        settings
                            .get(key)
                            .is_some_and(|value| !config.ignored_values.contains(value))
                    })
                }
                Self::EnvironmentName(config) => {
                    if !segment_matches_executable(segment, &config.executables)? {
                        continue;
                    }
                    let present_names = segment
                        .environment_names
                        .iter()
                        .map(|name| uppercase(name))
                        .collect::<Result<BTreeSet<_>, _>>()?;
                    !config.environment_names.is_disjoint(&present_names)
                }
            };
            check_deadline(deadline)?;
            if matched {
                matches.push(index);
            }
        }
        // Also covers an empty command or a final segment that continued
        // after an unsuccessful bounded scan. Never return partial evidence.
        check_deadline(deadline)?;
        Ok(matches)
    }
}

pub(crate) fn check_deadline(deadline: Option<Instant>) -> Result<(), &'static str> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err("matcher_deadline_exceeded");
    }
    Ok(())
}

pub(crate) fn python_trim(value: &str) -> &str {
    value.trim_matches(python_is_whitespace)
}

// The Rust compiler and the supported Python runtime can ship different
// Unicode case tables. Do not silently equate these tables on a security
// decision: non-ASCII case conversion remains an explicit capability miss.
// Non-ASCII opaque operands and prefixes do not require case conversion.
fn lowercase(value: &str) -> Result<String, &'static str> {
    if !value.is_ascii() {
        return Err("unsupported_unicode_case_mapping");
    }
    Ok(value.to_ascii_lowercase())
}

fn uppercase(value: &str) -> Result<String, &'static str> {
    if !value.is_ascii() {
        return Err("unsupported_unicode_case_mapping");
    }
    Ok(value.to_ascii_uppercase())
}

pub(crate) fn normalize_lower_set(
    values: BTreeSet<String>,
) -> Result<BTreeSet<String>, &'static str> {
    values
        .into_iter()
        .filter(|value| !python_trim(value).is_empty())
        .map(|value| lowercase(python_trim(&value)))
        .collect()
}

fn normalize_trim_set(values: BTreeSet<String>) -> BTreeSet<String> {
    values
        .into_iter()
        .filter(|value| !python_trim(value).is_empty())
        .map(|value| python_trim(&value).to_owned())
        .collect()
}

pub(crate) fn normalize_option_set(
    values: BTreeSet<String>,
) -> Result<BTreeSet<String>, &'static str> {
    values
        .into_iter()
        .filter(|value| !python_trim(value).is_empty())
        .map(|value| normalize_option_token(&value))
        .collect()
}

fn normalize_option_token(value: &str) -> Result<String, &'static str> {
    let stripped = python_trim(value);
    if stripped.starts_with("--") {
        lowercase(stripped)
    } else {
        Ok(stripped.to_owned())
    }
}

pub(crate) fn segment_matches_executable(
    segment: &CommandSegmentV1,
    executables: &BTreeSet<String>,
) -> Result<bool, &'static str> {
    let Some(executable) = &segment.executable else {
        return Ok(false);
    };
    let basename = executable.rsplit(['/', '\\']).next().unwrap_or("");
    Ok(executables.contains(&lowercase(basename)?))
}

#[cfg(test)]
mod tests;
