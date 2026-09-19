//! Compiled counterparts of the three reviewed database command grammars.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use serde::Deserialize;
use serde_json::Value;

use crate::command_option_parsing::{python_is_alphanumeric, python_is_whitespace};
use crate::command_structured_matchers::{
    check_deadline, leading_flags_and_operands, normalize_lower_set, normalize_option_set,
    present_flags, python_trim, segment_matches_executable,
};
use crate::{
    CanonicalCommandV1, CommandSegmentV1, MAX_COMMAND_BYTES, MAX_COMMAND_SEGMENTS,
    MAX_COMMAND_TOKENS,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArgumentCommandConfig {
    executables: BTreeSet<String>,
    command: String,
    minimum_abbreviation_length: usize,
    #[serde(default)]
    minimum_position: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommandSequenceConfig {
    executables: BTreeSet<String>,
    command_arities: Vec<(String, usize)>,
    target_commands: BTreeSet<String>,
    #[serde(default)]
    options_with_values: BTreeSet<String>,
    #[serde(default)]
    forbidden_flags: BTreeSet<String>,
    #[serde(skip)]
    arities: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LeadingSubcommandConfig {
    executables: BTreeSet<String>,
    subcommands: Vec<String>,
    #[serde(default)]
    options_with_values: BTreeSet<String>,
    #[serde(default)]
    forbidden_flags: BTreeSet<String>,
    #[serde(default)]
    required_flags_anywhere: BTreeSet<String>,
    #[serde(default)]
    interleaved_options_with_values: BTreeSet<String>,
    #[serde(default)]
    forbidden_flags_before_delimiter: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub(crate) enum DatabaseMatcher {
    ArgumentCommand(ArgumentCommandConfig),
    CommandSequence(CommandSequenceConfig),
    LeadingSubcommand(LeadingSubcommandConfig),
}

impl DatabaseMatcher {
    pub(crate) fn from_config(op: &str, config: Value) -> Result<Self, &'static str> {
        let invalid = |_| "invalid_database_matcher_config";
        match op {
            "argument-command.v1" => {
                let mut config: ArgumentCommandConfig =
                    serde_json::from_value(config).map_err(invalid)?;
                config.executables = normalize_lower_set(config.executables)?;
                config.command = ascii_lower(python_trim(&config.command))?;
                if config.executables.is_empty()
                    || config.command.is_empty()
                    || config.minimum_abbreviation_length == 0
                    || config.minimum_abbreviation_length > config.command.len()
                {
                    return Err("invalid_database_matcher_config");
                }
                Ok(Self::ArgumentCommand(config))
            }
            "command-sequence.v1" => {
                let mut config: CommandSequenceConfig =
                    serde_json::from_value(config).map_err(invalid)?;
                config.executables = normalize_lower_set(config.executables)?;
                config.command_arities = config
                    .command_arities
                    .into_iter()
                    .map(|(name, arity)| Ok((ascii_lower(python_trim(&name))?, arity)))
                    .collect::<Result<_, &'static str>>()?;
                config.target_commands = normalize_lower_set(config.target_commands)?;
                config.options_with_values = normalize_option_set(config.options_with_values)?;
                config.forbidden_flags = normalize_option_set(config.forbidden_flags)?;
                config.arities = config.command_arities.iter().cloned().collect();
                if config.executables.is_empty()
                    || config.arities.is_empty()
                    || config.target_commands.is_empty()
                    || config.arities.len() != config.command_arities.len()
                    || !config
                        .target_commands
                        .iter()
                        .all(|target| config.arities.contains_key(target))
                {
                    return Err("invalid_database_matcher_config");
                }
                Ok(Self::CommandSequence(config))
            }
            "leading-subcommand.v1" => {
                let mut config: LeadingSubcommandConfig =
                    serde_json::from_value(config).map_err(invalid)?;
                config.executables = normalize_lower_set(config.executables)?;
                config.subcommands = config
                    .subcommands
                    .into_iter()
                    .filter(|value| !python_trim(value).is_empty())
                    .map(|value| ascii_lower(python_trim(&value)))
                    .collect::<Result<_, _>>()?;
                config.options_with_values = normalize_option_set(config.options_with_values)?;
                config.forbidden_flags = normalize_option_set(config.forbidden_flags)?;
                config.required_flags_anywhere =
                    normalize_lower_set(config.required_flags_anywhere)?;
                config.interleaved_options_with_values =
                    normalize_option_set(config.interleaved_options_with_values)?;
                config.forbidden_flags_before_delimiter =
                    normalize_option_set(config.forbidden_flags_before_delimiter)?;
                if config.executables.is_empty() || config.subcommands.is_empty() {
                    return Err("invalid_database_matcher_config");
                }
                Ok(Self::LeadingSubcommand(config))
            }
            _ => Err("unsupported_database_matcher"),
        }
    }

    #[cfg(test)]
    pub(crate) fn match_segments(
        &self,
        command: &CanonicalCommandV1,
    ) -> Result<Vec<usize>, &'static str> {
        self.match_segments_with_deadline(command, None)
    }

    pub(crate) fn match_segments_with_deadline(
        &self,
        command: &CanonicalCommandV1,
        deadline: Option<Instant>,
    ) -> Result<Vec<usize>, &'static str> {
        check_deadline(deadline)?;
        check_command_bounds(command)?;
        if command.confidence != "exact" {
            return Err("database_command_uncertain");
        }
        let mut matches = Vec::new();
        for (index, segment) in command.segments.iter().enumerate() {
            check_deadline(deadline)?;
            let matched = match self {
                Self::ArgumentCommand(config) => config.matches(segment, deadline)?,
                Self::CommandSequence(config) => config.matches(segment, deadline)?,
                Self::LeadingSubcommand(config) => config.matches(segment, deadline)?,
            };
            check_deadline(deadline)?;
            if matched {
                matches.push(index);
            }
        }
        check_deadline(deadline)?;
        Ok(matches)
    }
}

impl ArgumentCommandConfig {
    fn matches(
        &self,
        segment: &CommandSegmentV1,
        deadline: Option<Instant>,
    ) -> Result<bool, &'static str> {
        if !segment_matches_executable(segment, &self.executables)? {
            return Ok(false);
        }
        for argument in segment.arguments.iter().skip(self.minimum_position) {
            check_deadline(deadline)?;
            let argument = python_trim(argument);
            let Some(position) = argument.find(python_is_whitespace) else {
                continue;
            };
            if argument[position..]
                .trim_start_matches(python_is_whitespace)
                .is_empty()
            {
                continue;
            }
            let token = ascii_lower(&argument[..position])?;
            if token.len() >= self.minimum_abbreviation_length && self.command.starts_with(&token) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl CommandSequenceConfig {
    fn matches(
        &self,
        segment: &CommandSegmentV1,
        deadline: Option<Instant>,
    ) -> Result<bool, &'static str> {
        if !segment_matches_executable(segment, &self.executables)? {
            return Ok(false);
        }
        for argument in &segment.arguments {
            if self.forbidden_flags.contains(&normalize_option_token(
                argument.split('=').next().unwrap_or(""),
            )?) {
                return Ok(false);
            }
        }
        let (_, operands) =
            leading_flags_and_operands(&segment.arguments, &self.options_with_values)?;
        let mut position = 0usize;
        while let Some(argument) = operands.get(position) {
            check_deadline(deadline)?;
            let token = ascii_lower(python_trim(argument))?;
            let mut candidates = self
                .arities
                .iter()
                .filter(|(name, _)| name.starts_with(&token));
            let Some((resolved, arity)) = candidates.next() else {
                break;
            };
            if candidates.next().is_some() {
                break;
            }
            if self.target_commands.contains(resolved) {
                return Ok(true);
            }
            position = position.saturating_add(1).saturating_add(*arity);
        }
        Ok(false)
    }
}

impl LeadingSubcommandConfig {
    fn matches(
        &self,
        segment: &CommandSegmentV1,
        deadline: Option<Instant>,
    ) -> Result<bool, &'static str> {
        if !segment_matches_executable(segment, &self.executables)? {
            return Ok(false);
        }
        let (flags, operands) =
            leading_flags_and_operands(&segment.arguments, &self.options_with_values)?;
        if !self.forbidden_flags.is_disjoint(&flags)
            || self.exits_before_execution(&segment.arguments)?
        {
            return Ok(false);
        }
        let mut position = 0usize;
        for expected in &self.subcommands {
            check_deadline(deadline)?;
            while let Some(token) = operands.get(position) {
                if !token.starts_with('-')
                    || token == "-"
                    || !self
                        .interleaved_options_with_values
                        .contains(&normalize_option_token(
                            token.split('=').next().unwrap_or(""),
                        )?)
                {
                    break;
                }
                position += if token.contains('=') { 1 } else { 2 };
            }
            let Some(token) = operands.get(position) else {
                return Ok(false);
            };
            if &ascii_lower(token)? != expected {
                return Ok(false);
            }
            position += 1;
        }
        if self.required_flags_anywhere.is_empty() {
            return Ok(true);
        }
        let lowered = segment
            .arguments
            .iter()
            .map(|value| ascii_lower(value))
            .collect::<Result<Vec<_>, _>>()?;
        let flags = present_flags(&lowered, &self.options_with_values);
        Ok(self.required_flags_anywhere.is_subset(&flags))
    }

    fn exits_before_execution(&self, arguments: &[String]) -> Result<bool, &'static str> {
        if self.forbidden_flags_before_delimiter.is_empty() {
            return Ok(false);
        }
        for argument in arguments {
            if argument == "--" {
                return Ok(false);
            }
            if !argument.starts_with('-') || argument == "-" {
                continue;
            }
            if self
                .forbidden_flags_before_delimiter
                .contains(&normalize_option_token(
                    argument.split('=').next().unwrap_or(""),
                )?)
            {
                return Ok(true);
            }
            if !argument.starts_with("--") && argument.chars().nth(2).is_some() {
                for character in argument[1..].chars() {
                    if !python_is_alphanumeric(character) {
                        break;
                    }
                    if self
                        .forbidden_flags_before_delimiter
                        .contains(&format!("-{character}"))
                    {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
}

pub(crate) fn ascii_lower(value: &str) -> Result<String, &'static str> {
    if !value.is_ascii() {
        return Err("unsupported_unicode_case_mapping");
    }
    Ok(value.to_ascii_lowercase())
}

fn normalize_option_token(value: &str) -> Result<String, &'static str> {
    let value = python_trim(value);
    if value.starts_with("--") {
        ascii_lower(value)
    } else {
        Ok(value.to_owned())
    }
}

pub(crate) fn check_command_bounds(command: &CanonicalCommandV1) -> Result<(), &'static str> {
    if command.segments.len() > MAX_COMMAND_SEGMENTS
        || command.normalized_text.len() > MAX_COMMAND_BYTES
    {
        return Err("native_matcher_command_limit_exceeded");
    }
    let mut tokens = 0usize;
    let mut bytes = 0usize;
    for segment in &command.segments {
        tokens = tokens
            .saturating_add(segment.arguments.len())
            .saturating_add(usize::from(segment.executable.is_some()));
        bytes = bytes.saturating_add(segment.executable.as_ref().map_or(0, String::len));
        for argument in &segment.arguments {
            bytes = bytes.saturating_add(argument.len());
        }
        if tokens > MAX_COMMAND_TOKENS || bytes > MAX_COMMAND_BYTES {
            return Err("native_matcher_command_limit_exceeded");
        }
    }
    Ok(())
}
