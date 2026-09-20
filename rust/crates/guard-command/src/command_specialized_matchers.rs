//! Reviewed framework, deployment, curl, expansion and literal matcher nodes.

use std::collections::BTreeSet;
use std::time::Instant;

use serde::Deserialize;
use serde_json::Value;

use crate::command_database_matchers::check_command_bounds;
use crate::command_option_parsing::{argument_semantics, known_option_advance};
use crate::command_structured_matchers::{
    check_deadline, leading_flags_and_operands, segment_matches_executable,
};
use crate::{CanonicalCommandV1, CommandSegmentV1};

use crate::command_ascii_comparison::{self as ascii_comparison, lowercase_for_ascii_comparison};

#[path = "command_curl_operations.rs"]
mod curl;
#[path = "command_reviewed_literal.rs"]
mod literal;

use literal::ReviewedLiteralConfig;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PhpArtisanConfig {
    subcommands: Vec<String>,
    #[serde(default)]
    required_flags: BTreeSet<String>,
    #[serde(skip)]
    executables: BTreeSet<String>,
    #[serde(skip)]
    php_value_options: BTreeSet<String>,
    #[serde(skip)]
    artisan_value_options: BTreeSet<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ZeroOperandConfig {
    executables: BTreeSet<String>,
    required_flags: BTreeSet<String>,
    options_with_values: BTreeSet<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CurlElasticsearchConfig {
    #[serde(default = "curl_executables")]
    executables: BTreeSet<String>,
    #[serde(default = "elasticsearch_ports")]
    service_ports: BTreeSet<u16>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Repo2nbExpansionConfig {
    #[serde(default = "reverse_subcommand")]
    subcommand: String,
    #[serde(default = "repo2nb_launchers")]
    launchers: Vec<Vec<String>>,
    #[serde(default = "wrapper_value_options")]
    leading_options_with_values: BTreeSet<String>,
    #[serde(default = "expansion_markers")]
    expansion_markers: BTreeSet<String>,
    #[serde(skip)]
    compiled_launchers: Vec<CompiledLauncher>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PromptBranchVersionedPackageConfig {
    subcommand: String,
    package_launchers: BTreeSet<String>,
    wrapper_executables: BTreeSet<String>,
    wrapper_options_with_values: BTreeSet<String>,
    wrapper_flags: BTreeSet<String>,
    package_launcher_options_with_values: BTreeSet<String>,
    package_launcher_flags: BTreeSet<String>,
    #[serde(default = "promptbranch_package_prefix")]
    package_prefix: String,
    #[serde(default)]
    excluded_qualifiers: BTreeSet<String>,
    #[serde(default)]
    required_flags: BTreeSet<String>,
    #[serde(default)]
    options_with_values: BTreeSet<String>,
    #[serde(default)]
    flags: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct CompiledLauncher {
    executables: BTreeSet<String>,
    prefix: Vec<String>,
    wrapper: bool,
}

#[derive(Debug, Clone)]
pub(crate) enum SpecializedMatcher {
    PhpArtisan(PhpArtisanConfig),
    ZeroOperand(ZeroOperandConfig),
    CurlElasticsearch(CurlElasticsearchConfig),
    PromptBranchVersionedPackage(PromptBranchVersionedPackageConfig),
    Repo2nbExpansion(Repo2nbExpansionConfig),
    ReviewedLiteral(ReviewedLiteralConfig),
}

impl SpecializedMatcher {
    pub(crate) fn from_config(op: &str, config: Value) -> Result<Self, &'static str> {
        let invalid = |_| "invalid_specialized_matcher_config";
        match op {
            "php-artisan-script.v1" => {
                let mut config: PhpArtisanConfig =
                    serde_json::from_value(config).map_err(invalid)?;
                if config
                    .subcommands
                    .iter()
                    .chain(&config.required_flags)
                    .any(|value| !value.is_ascii())
                {
                    return Err("unsupported_specialized_unicode_config");
                }
                config.executables = string_set(&["php", "php.cmd", "php.exe"]);
                config.php_value_options = string_set(&["-c", "-d", "-z", "--define", "--php-ini"]);
                config.artisan_value_options = string_set(&["--env"]);
                Ok(Self::PhpArtisan(config))
            }
            "zero-operand-flags.v1" => Ok(Self::ZeroOperand(
                serde_json::from_value(config).map_err(invalid)?,
            )),
            "curl-elasticsearch-delete.v1" => Ok(Self::CurlElasticsearch(
                serde_json::from_value(config).map_err(invalid)?,
            )),
            "promptbranch-versioned-package.v1" => {
                let config: PromptBranchVersionedPackageConfig =
                    serde_json::from_value(config).map_err(invalid)?;
                if !config.valid() {
                    return Err("invalid_promptbranch_versioned_package_config");
                }
                Ok(Self::PromptBranchVersionedPackage(config))
            }
            "repo2nb-expansion.v1" => {
                let mut config: Repo2nbExpansionConfig =
                    serde_json::from_value(config).map_err(invalid)?;
                if !config.subcommand.is_ascii()
                    || config
                        .launchers
                        .iter()
                        .flatten()
                        .chain(&config.leading_options_with_values)
                        .chain(&config.expansion_markers)
                        .any(|value| !value.is_ascii())
                {
                    return Err("unsupported_specialized_unicode_config");
                }
                if config.launchers.iter().any(Vec::is_empty) {
                    return Err("invalid_repo2nb_launcher");
                }
                config.compiled_launchers = config
                    .launchers
                    .iter()
                    .map(|launcher| CompiledLauncher {
                        executables: BTreeSet::from([launcher[0].clone()]),
                        prefix: launcher[1..]
                            .iter()
                            .chain(std::iter::once(&config.subcommand))
                            .cloned()
                            .collect(),
                        wrapper: matches!(launcher[0].as_str(), "exec" | "xargs"),
                    })
                    .collect();
                Ok(Self::Repo2nbExpansion(config))
            }
            "reviewed-literal.v1" => {
                let config: ReviewedLiteralConfig =
                    serde_json::from_value(config).map_err(invalid)?;
                Ok(Self::ReviewedLiteral(config.validate()?))
            }
            _ => Err("unsupported_specialized_matcher"),
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
            return Err("specialized_command_uncertain");
        }
        if let Self::ReviewedLiteral(config) = self {
            let matched = config.matches(command);
            check_deadline(deadline)?;
            return Ok(if matched { vec![0] } else { Vec::new() });
        }
        let mut matches = Vec::new();
        for (index, segment) in command.segments.iter().enumerate() {
            check_deadline(deadline)?;
            let matched = match self {
                Self::PhpArtisan(config) => config.matches(segment)?,
                Self::ZeroOperand(config) => {
                    if !segment_matches_executable(segment, &config.executables)? {
                        continue;
                    }
                    let (flags, operands) = leading_flags_and_operands(
                        &segment.arguments,
                        &config.options_with_values,
                    )?;
                    operands.is_empty() && config.required_flags.is_subset(&flags)
                }
                Self::CurlElasticsearch(config) => {
                    if !segment_matches_executable(segment, &config.executables)? {
                        continue;
                    }
                    curl::destructive_elasticsearch_operation(
                        &segment.arguments,
                        &config.service_ports,
                        deadline,
                    )?
                }
                Self::PromptBranchVersionedPackage(config) => config.matches(segment, deadline)?,
                Self::Repo2nbExpansion(config) => config.matches(segment, deadline)?,
                Self::ReviewedLiteral(_) => unreachable!("handled before segment iteration"),
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

impl PromptBranchVersionedPackageConfig {
    fn valid(&self) -> bool {
        !self.subcommand.is_empty()
            && self.package_prefix.ends_with('@')
            && !self.package_launchers.is_empty()
            && !self.wrapper_executables.is_empty()
            && std::iter::once(&self.subcommand)
                .chain(std::iter::once(&self.package_prefix))
                .chain(&self.package_launchers)
                .chain(&self.wrapper_executables)
                .chain(&self.wrapper_options_with_values)
                .chain(&self.wrapper_flags)
                .chain(&self.package_launcher_options_with_values)
                .chain(&self.package_launcher_flags)
                .chain(&self.excluded_qualifiers)
                .chain(&self.required_flags)
                .chain(&self.options_with_values)
                .chain(&self.flags)
                .all(|value| value.is_ascii() && !value.is_empty() && value.len() <= 4_096)
    }

    fn matches(
        &self,
        segment: &CommandSegmentV1,
        deadline: Option<Instant>,
    ) -> Result<bool, &'static str> {
        let Some(executable) = segment.executable.as_deref() else {
            return Ok(false);
        };
        let executable = lowercase_for_ascii_comparison(
            executable.rsplit(['/', '\\']).next().unwrap_or(executable),
        );
        if !self.package_launchers.contains(&executable)
            && !self.wrapper_executables.contains(&executable)
        {
            return Ok(false);
        }
        let arguments = segment
            .arguments
            .iter()
            .map(|argument| lowercase_for_ascii_comparison(argument))
            .collect::<Vec<_>>();
        let exec_options = BTreeSet::from(["-a".to_owned()]);
        let launcher_arguments = if self.wrapper_executables.contains(&executable) {
            let wrapper_options =
                if matches!(executable.as_str(), "xargs" | "xargs.cmd" | "xargs.exe") {
                    &self.wrapper_options_with_values
                } else {
                    &exec_options
                };
            leading_operand_suffixes(&arguments, wrapper_options, &self.wrapper_flags, deadline)?
                .into_iter()
                .filter_map(|suffix| {
                    suffix
                        .first()
                        .is_some_and(|launcher| self.package_launchers.contains(launcher))
                        .then_some(&suffix[1..])
                })
                .collect::<Vec<_>>()
        } else {
            vec![arguments.as_slice()]
        };

        let mut matched_launch = false;
        for launcher_arguments in launcher_arguments {
            for candidate in leading_operand_suffixes(
                launcher_arguments,
                &self.package_launcher_options_with_values,
                &self.package_launcher_flags,
                deadline,
            )? {
                if candidate.len() >= 2
                    && candidate[0].starts_with(&self.package_prefix)
                    && candidate[0].len() > self.package_prefix.len()
                    && !self
                        .excluded_qualifiers
                        .contains(&candidate[0][self.package_prefix.len()..])
                    && candidate[1] == self.subcommand
                {
                    matched_launch = true;
                    break;
                }
            }
            if matched_launch {
                break;
            }
        }
        if !matched_launch {
            return Ok(false);
        }
        if self.required_flags.is_empty() {
            return Ok(true);
        }
        let options_with_values = self
            .options_with_values
            .union(&self.wrapper_options_with_values)
            .chain(&self.package_launcher_options_with_values)
            .cloned()
            .collect::<BTreeSet<_>>();
        let known_flags = self
            .flags
            .union(&self.required_flags)
            .chain(&self.wrapper_flags)
            .chain(&self.package_launcher_flags)
            .cloned()
            .collect::<BTreeSet<_>>();
        let semantics = argument_semantics(&arguments, &options_with_values, &BTreeSet::new());
        Ok(self.required_flags.is_subset(&semantics.present_flags)
            && crate::command_option_parsing::flags_present_in_all_option_parses_with_deadline(
                &arguments,
                &self.required_flags,
                &options_with_values,
                &known_flags,
                deadline,
            ))
    }
}

fn leading_operand_suffixes<'a>(
    arguments: &'a [String],
    options_with_values: &BTreeSet<String>,
    flags: &BTreeSet<String>,
    deadline: Option<Instant>,
) -> Result<Vec<&'a [String]>, &'static str> {
    let mut pending = vec![0];
    let mut visited = BTreeSet::new();
    let mut suffixes = Vec::new();
    while let Some(index) = pending.pop() {
        check_deadline(deadline)?;
        if !visited.insert(index) || index >= arguments.len() {
            continue;
        }
        let argument = &arguments[index];
        if argument == "--" {
            if index + 1 < arguments.len() {
                suffixes.push(&arguments[index + 1..]);
            }
            continue;
        }
        if argument.len() <= 1 || !argument.starts_with('-') {
            suffixes.push(&arguments[index..]);
            continue;
        }
        if let Some(advance) = known_option_advance(argument, options_with_values, flags) {
            pending.push(index + advance);
            continue;
        }
        pending.push(index + 1);
        if !argument.contains('=') && index + 1 < arguments.len() {
            pending.push(index + 2);
        }
    }
    Ok(suffixes)
}

impl PhpArtisanConfig {
    fn matches(&self, segment: &CommandSegmentV1) -> Result<bool, &'static str> {
        if !ascii_comparison::executable_matches(segment, &self.executables) {
            return Ok(false);
        }
        let arguments = segment
            .arguments
            .iter()
            .map(|argument| lowercase_for_ascii_comparison(argument))
            .collect::<Vec<_>>();
        let (_, operands) = leading_flags_and_operands(&arguments, &self.php_value_options)?;
        let Some(script) = operands.first() else {
            return Ok(false);
        };
        if script.rsplit(['/', '\\']).next() != Some("artisan") {
            return Ok(false);
        }
        let arguments = &operands[1..];
        let semantics =
            argument_semantics(arguments, &self.artisan_value_options, &BTreeSet::new());
        if !self.required_flags.is_subset(&semantics.present_flags) {
            return Ok(false);
        }
        let (_, operands) = leading_flags_and_operands(arguments, &self.artisan_value_options)?;
        Ok(operands.starts_with(&self.subcommands))
    }
}

impl Repo2nbExpansionConfig {
    fn matches(
        &self,
        segment: &CommandSegmentV1,
        deadline: Option<Instant>,
    ) -> Result<bool, &'static str> {
        if segment.executable.is_none() {
            return Ok(false);
        }
        let mut cached_arguments = None;
        for launcher in &self.compiled_launchers {
            check_deadline(deadline)?;
            if !ascii_comparison::executable_matches(segment, &launcher.executables) {
                continue;
            }
            // An unrelated executable cannot require normalization of its
            // opaque operands. Reuse the result for this launcher's variants.
            let arguments = cached_arguments.get_or_insert_with(|| {
                segment
                    .arguments
                    .iter()
                    .map(|argument| lowercase_for_ascii_comparison(argument))
                    .collect::<Vec<_>>()
            });
            let mut candidate = arguments.as_slice();
            if launcher.wrapper {
                candidate = after_leading_options(candidate, &self.leading_options_with_values);
            }
            if !candidate.starts_with(&launcher.prefix) {
                continue;
            }
            return Ok(candidate[launcher.prefix.len()..].iter().any(|argument| {
                self.expansion_markers
                    .iter()
                    .any(|marker| argument.contains(marker))
            }));
        }
        Ok(false)
    }
}

fn after_leading_options<'a>(arguments: &'a [String], options: &BTreeSet<String>) -> &'a [String] {
    let mut index = 0;
    let flags = BTreeSet::new();
    while let Some(argument) = arguments.get(index) {
        if argument == "--" {
            return &arguments[index + 1..];
        }
        if !argument.starts_with('-') {
            return &arguments[index..];
        }
        index += known_option_advance(argument, options, &flags).unwrap_or(1);
    }
    &[]
}

fn string_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}
fn curl_executables() -> BTreeSet<String> {
    string_set(&["curl", "curl.cmd", "curl.exe"])
}
fn elasticsearch_ports() -> BTreeSet<u16> {
    BTreeSet::from([9200])
}
fn reverse_subcommand() -> String {
    "reverse".to_owned()
}
fn promptbranch_package_prefix() -> String {
    "@promptbranch/cli@".to_owned()
}
fn wrapper_value_options() -> BTreeSet<String> {
    string_set(&["-n", "-P", "-I", "-L", "-s"])
}
fn expansion_markers() -> BTreeSet<String> {
    string_set(&["$", "`"])
}
fn repo2nb_launchers() -> Vec<Vec<String>> {
    [
        vec!["repo2nb"],
        vec!["python", "-m", "repo2nb"],
        vec!["python3", "-m", "repo2nb"],
        vec!["py", "-m", "repo2nb"],
        vec!["exec", "repo2nb"],
        vec!["exec", "python", "-m", "repo2nb"],
        vec!["exec", "python3", "-m", "repo2nb"],
        vec!["exec", "py", "-m", "repo2nb"],
        vec!["xargs", "repo2nb"],
        vec!["xargs", "python", "-m", "repo2nb"],
        vec!["xargs", "python3", "-m", "repo2nb"],
        vec!["xargs", "py", "-m", "repo2nb"],
    ]
    .into_iter()
    .map(|values| values.into_iter().map(str::to_owned).collect())
    .collect()
}

#[cfg(test)]
#[path = "command_specialized_matchers_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "command_specialized_unicode_tests.rs"]
mod unicode_tests;
