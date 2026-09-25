//! Direction-sensitive matcher programs for copy-style command lines.

use std::collections::BTreeSet;
use std::time::Instant;

use serde::Deserialize;
use serde_json::Value;

use crate::command_database_matchers::check_command_bounds;
use crate::command_option_parsing::{python_is_alphabetic, python_is_whitespace};
use crate::command_structured_matchers::{
    check_deadline, normalize_lower_set, normalize_option_set, operands_without_options,
    present_flags, segment_matches_executable,
};
use crate::CanonicalCommandV1;

fn default_minimum_operands() -> usize {
    2
}

// Separate wire structures keep deny_unknown_fields effective for every
// grammar. Serde flatten plus deny_unknown_fields does not provide that
// guarantee, and must not admit fields belonging to a different operation.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrailingOperandConfig {
    executables: BTreeSet<String>,
    #[serde(default)]
    options_with_values: BTreeSet<String>,
    #[serde(default)]
    required_flags: BTreeSet<String>,
    #[serde(default)]
    forbidden_flags: BTreeSet<String>,
    #[serde(default = "default_minimum_operands")]
    minimum_operands: usize,
    #[serde(default)]
    excluded_first_arguments: BTreeSet<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrailingOperandPrefixConfig {
    executables: BTreeSet<String>,
    #[serde(default)]
    options_with_values: BTreeSet<String>,
    #[serde(default)]
    required_flags: BTreeSet<String>,
    #[serde(default)]
    forbidden_flags: BTreeSet<String>,
    #[serde(default = "default_minimum_operands")]
    minimum_operands: usize,
    #[serde(default)]
    excluded_first_arguments: BTreeSet<String>,
    #[serde(default)]
    operand_prefixes: BTreeSet<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrailingOperandRemoteAliasConfig {
    executables: BTreeSet<String>,
    #[serde(default)]
    options_with_values: BTreeSet<String>,
    #[serde(default)]
    required_flags: BTreeSet<String>,
    #[serde(default)]
    forbidden_flags: BTreeSet<String>,
    #[serde(default = "default_minimum_operands")]
    minimum_operands: usize,
    #[serde(default)]
    excluded_first_arguments: BTreeSet<String>,
    #[serde(default)]
    allow_bare_names: bool,
    #[serde(default)]
    bare_names_only: bool,
}

#[derive(Debug, Clone)]
pub enum OperandMatcher {
    OperandGatedFlags(TrailingOperandConfig),
    TrailingOperandPrefix {
        common: TrailingOperandConfig,
        prefixes: BTreeSet<String>,
    },
    TrailingOperandHostTarget(TrailingOperandConfig),
    TrailingOperandRemoteAlias {
        common: TrailingOperandConfig,
        allow_bare_names: bool,
        bare_names_only: bool,
    },
}

impl TrailingOperandConfig {
    fn normalized(mut self) -> Result<Self, &'static str> {
        self.executables = normalize_lower_set(self.executables)?;
        self.options_with_values = normalize_option_set(self.options_with_values)?;
        self.required_flags = normalize_option_set(self.required_flags)?;
        self.forbidden_flags = normalize_option_set(self.forbidden_flags)?;
        if self.executables.is_empty() || self.minimum_operands == 0 {
            return Err("invalid_operand_matcher_config");
        }
        Ok(self)
    }
}

impl OperandMatcher {
    pub fn from_config(op: &str, config: Value) -> Result<Self, &'static str> {
        let invalid = |_| "invalid_operand_matcher_config";
        match op {
            "operand-gated-flags.v1" => {
                let config: TrailingOperandConfig =
                    serde_json::from_value(config).map_err(invalid)?;
                let config = config.normalized()?;
                if config.required_flags.is_empty() {
                    return Err("invalid_operand_matcher_config");
                }
                Ok(Self::OperandGatedFlags(config))
            }
            "trailing-operand-host-target.v1" => {
                let config: TrailingOperandConfig =
                    serde_json::from_value(config).map_err(invalid)?;
                Ok(Self::TrailingOperandHostTarget(config.normalized()?))
            }
            "trailing-operand-prefix.v1" => {
                let config: TrailingOperandPrefixConfig =
                    serde_json::from_value(config).map_err(invalid)?;
                let mut prefixes = config.operand_prefixes;
                prefixes.retain(|value| !value.is_empty());
                if prefixes.is_empty() {
                    return Err("invalid_operand_matcher_config");
                }
                let common = TrailingOperandConfig {
                    executables: config.executables,
                    options_with_values: config.options_with_values,
                    required_flags: config.required_flags,
                    forbidden_flags: config.forbidden_flags,
                    minimum_operands: config.minimum_operands,
                    excluded_first_arguments: config.excluded_first_arguments,
                }
                .normalized()?;
                Ok(Self::TrailingOperandPrefix { common, prefixes })
            }
            "trailing-operand-remote-alias.v1" => {
                let config: TrailingOperandRemoteAliasConfig =
                    serde_json::from_value(config).map_err(invalid)?;
                let common = TrailingOperandConfig {
                    executables: config.executables,
                    options_with_values: config.options_with_values,
                    required_flags: config.required_flags,
                    forbidden_flags: config.forbidden_flags,
                    minimum_operands: config.minimum_operands,
                    excluded_first_arguments: config.excluded_first_arguments,
                }
                .normalized()?;
                Ok(Self::TrailingOperandRemoteAlias {
                    common,
                    allow_bare_names: config.allow_bare_names,
                    bare_names_only: config.bare_names_only,
                })
            }
            _ => Err("unsupported_operand_matcher"),
        }
    }

    #[cfg(test)]
    pub fn match_segments(&self, command: &CanonicalCommandV1) -> Result<Vec<usize>, &'static str> {
        self.match_segments_with_deadline(command, None)
    }

    pub fn match_segments_with_deadline(
        &self,
        command: &CanonicalCommandV1,
        deadline: Option<Instant>,
    ) -> Result<Vec<usize>, &'static str> {
        check_deadline(deadline)?;
        check_command_bounds(command)?;
        if command.confidence != "exact" {
            return Err("operand_command_uncertain");
        }
        let common = match self {
            Self::OperandGatedFlags(common) | Self::TrailingOperandHostTarget(common) => common,
            Self::TrailingOperandPrefix { common, .. }
            | Self::TrailingOperandRemoteAlias { common, .. } => common,
        };
        let mut matches = Vec::new();
        for (index, segment) in command.segments.iter().enumerate() {
            check_deadline(deadline)?;
            if !segment_matches_executable(segment, &common.executables)? {
                continue;
            }
            // Dispatch exclusions examine the literal raw first argument.
            if segment
                .arguments
                .first()
                .is_some_and(|value| common.excluded_first_arguments.contains(value))
            {
                continue;
            }
            let flags = present_flags(&segment.arguments, &common.options_with_values);
            if !common.required_flags.is_subset(&flags)
                || !common.forbidden_flags.is_disjoint(&flags)
            {
                continue;
            }
            let operands =
                operands_without_options(&segment.arguments, &common.options_with_values)?;
            if operands.len() < common.minimum_operands {
                continue;
            }
            // Compilation validates minimum_operands >= 1.
            let destination = operands[operands.len() - 1];
            let matched = match self {
                Self::OperandGatedFlags(_) => true,
                Self::TrailingOperandPrefix { prefixes, .. } => prefixes.iter().any(|prefix| {
                    destination.len() > prefix.len() && destination.starts_with(prefix)
                }),
                Self::TrailingOperandHostTarget(_) => is_remote_host_target(destination),
                Self::TrailingOperandRemoteAlias {
                    allow_bare_names,
                    bare_names_only,
                    ..
                } => is_remote_alias_target(destination, *allow_bare_names, *bare_names_only),
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

fn is_remote_host_target(operand: &str) -> bool {
    if operand.contains("://") {
        return false;
    }
    let rest = operand.split_once('@').map_or(operand, |(_, rest)| rest);
    if rest.starts_with('[') {
        return rest
            .find("]:")
            .is_some_and(|closing| closing > 1 && rest.len() > closing + 2);
    }
    let Some((host, path)) = rest.split_once(':') else {
        return false;
    };
    if host.is_empty() || path.is_empty() || host.chars().any(python_is_whitespace) {
        return false;
    }
    let mut characters = host.chars();
    let first = characters.next().expect("nonempty host checked above");
    !(characters.next().is_none() && python_is_alphabetic(first))
}

fn is_remote_alias_target(operand: &str, allow_bare_names: bool, bare_names_only: bool) -> bool {
    if operand.contains("://") {
        return false;
    }
    if let Some((head, _)) = operand.split_once(':') {
        if bare_names_only || head.contains(['@', '/', '\\']) || head.chars().take(2).count() <= 1 {
            return false;
        }
        return !head.chars().any(python_is_whitespace);
    }
    if !allow_bare_names {
        return false;
    }
    // This ordering is observable: `name\\/` is accepted, `name/\\` is not.
    let name = operand.trim_end_matches('/').trim_end_matches('\\');
    if name.chars().take(2).count() <= 1
        || name.starts_with('-')
        || matches!(name, "." | "..")
        || name.contains(['@', '/', '\\'])
    {
        return false;
    }
    !name.chars().any(python_is_whitespace)
}
