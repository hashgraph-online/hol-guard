//! Reviewed omairc wrapper and send-help matcher nodes.

use std::collections::BTreeSet;
use std::time::Instant;

use serde::Deserialize;
use serde_json::Value;

use crate::command_ascii_comparison::{self as ascii_comparison, lowercase_for_ascii_comparison};
use crate::command_option_parsing::{known_option_advance, matches_subcommands_conservatively_with_deadline};
use crate::command_structured_matchers::check_deadline;
use crate::CommandSegmentV1;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OmaircWrapperSubcommandConfig {
    wrapper: String,
    subcommands: Vec<String>,
    #[serde(default)]
    options_with_values: BTreeSet<String>,
    #[serde(default = "default_true")]
    fail_secure_unknown_options: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OmaircSendHelpConfig {
    #[serde(default = "send_subcommand")]
    subcommand: String,
    #[serde(default = "omairc_launchers")]
    launchers: Vec<Vec<String>>,
    #[serde(default = "network_options")]
    network_options: BTreeSet<String>,
    #[serde(default = "wrapper_value_options")]
    leading_options_with_values: BTreeSet<String>,
    #[serde(skip)]
    compiled_launchers: Vec<CompiledLauncher>,
}

#[derive(Debug, Clone)]
struct CompiledLauncher {
    executables: BTreeSet<String>,
    wrapper: Option<String>,
}

impl OmaircSendHelpConfig {
    pub(crate) fn from_config(config: Value) -> Result<Self, &'static str> {
        let mut config: Self = serde_json::from_value(config).map_err(|_| "invalid_specialized_matcher_config")?;
        if !config.subcommand.is_ascii()
            || config
                .launchers
                .iter()
                .flatten()
                .chain(&config.network_options)
                .any(|value| !value.is_ascii())
        {
            return Err("unsupported_specialized_unicode_config");
        }
        if config.launchers.iter().any(Vec::is_empty) {
            return Err("invalid_omairc_launcher");
        }
        config.compiled_launchers = config
            .launchers
            .iter()
            .map(|launcher| CompiledLauncher {
                executables: executable_names(&launcher[0]),
                wrapper: match launcher[0].as_str() {
                    "exec" | "xargs" => Some(launcher[0].clone()),
                    _ => None,
                },
            })
            .collect();
        Ok(config)
    }

    pub(crate) fn matches(
        &self,
        segment: &CommandSegmentV1,
        deadline: Option<Instant>,
    ) -> Result<bool, &'static str> {
        if segment.executable.is_none() {
            return Ok(false);
        }
        let arguments = segment
            .arguments
            .iter()
            .map(|argument| lowercase_for_ascii_comparison(argument))
            .collect::<Vec<_>>();
        for launcher in &self.compiled_launchers {
            check_deadline(deadline)?;
            if !ascii_comparison::executable_matches(segment, &launcher.executables) {
                continue;
            }
            let subcommand_arguments = match launcher.wrapper.as_deref() {
                Some(wrapper) => {
                    let after_wrapper = after_leading_options(&arguments, &wrapper_leading_options(wrapper));
                    let Some(child) = after_wrapper.first() else {
                        continue;
                    };
                    if !argument_matches_executable(child, &omairc_executables()) {
                        continue;
                    }
                    after_wrapper[1..].to_vec()
                }
                None => arguments.clone(),
            };
            if subcommand_arguments.first().map(String::as_str) != Some(self.subcommand.as_str()) {
                continue;
            }
            if send_help_requested(&subcommand_arguments[1..], &self.network_options) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl OmaircWrapperSubcommandConfig {
    pub(crate) fn from_config(config: Value) -> Result<Self, &'static str> {
        let config: Self = serde_json::from_value(config).map_err(|_| "invalid_specialized_matcher_config")?;
        if !config.wrapper.is_ascii()
            || config
                .subcommands
                .iter()
                .chain(&config.options_with_values)
                .any(|value| !value.is_ascii())
        {
            return Err("unsupported_specialized_unicode_config");
        }
        if config.subcommands.is_empty() {
            return Err("invalid_omairc_subcommand");
        }
        Ok(config)
    }

    pub(crate) fn matches(
        &self,
        segment: &CommandSegmentV1,
        deadline: Option<Instant>,
    ) -> Result<bool, &'static str> {
        if segment.executable.is_none() {
            return Ok(false);
        }
        let wrapper_executables = executable_names(&self.wrapper);
        if !ascii_comparison::executable_matches(segment, &wrapper_executables) {
            return Ok(false);
        }
        let arguments = segment
            .arguments
            .iter()
            .map(|argument| lowercase_for_ascii_comparison(argument))
            .collect::<Vec<_>>();
        let leading_options = wrapper_leading_options(&self.wrapper);
        let after_wrapper = after_leading_options(&arguments, &leading_options);
        let Some(child) = after_wrapper.first() else {
            return Ok(false);
        };
        if !argument_matches_executable(child, &omairc_executables()) {
            return Ok(false);
        }
        let subcommand_arguments = &after_wrapper[1..];
        if subcommand_arguments.starts_with(&self.subcommands) {
            return Ok(true);
        }
        if !self.fail_secure_unknown_options {
            return Ok(false);
        }
        Ok(matches_subcommands_conservatively_with_deadline(
            subcommand_arguments,
            &self.subcommands,
            &self.options_with_values,
            &BTreeSet::new(),
            deadline,
        ))
    }
}

fn send_help_requested(arguments: &[String], network_options: &BTreeSet<String>) -> bool {
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--" {
            return false;
        }
        if network_options.contains(argument) {
            index += 2;
            continue;
        }
        if let Some((option_name, value)) = argument.split_once('=') {
            if network_options.contains(option_name) && !value.is_empty() {
                index += 1;
                continue;
            }
        }
        if argument == "--help" {
            return true;
        }
        if argument.starts_with('-') {
            index += 1;
            continue;
        }
        return false;
    }
    false
}

fn after_leading_options(arguments: &[String], options: &BTreeSet<String>) -> &[String] {
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

fn argument_matches_executable(argument: &str, executables: &BTreeSet<String>) -> bool {
    let basename = argument.rsplit(['/', '\\']).next().unwrap_or(argument);
    executables.contains(&lowercase_for_ascii_comparison(basename))
}

fn executable_names(name: &str) -> BTreeSet<String> {
    BTreeSet::from([
        name.to_owned(),
        format!("{name}.cmd"),
        format!("{name}.exe"),
    ])
}

fn omairc_executables() -> BTreeSet<String> {
    executable_names("omairc")
}

fn wrapper_leading_options(wrapper: &str) -> BTreeSet<String> {
    if wrapper == "xargs" {
        xargs_value_options()
    } else if wrapper == "exec" {
        BTreeSet::from(["-a".to_owned()])
    } else {
        BTreeSet::new()
    }
}

fn xargs_value_options() -> BTreeSet<String> {
    [
        "--arg-file",
        "--delimiter",
        "--eof",
        "--max-args",
        "--max-chars",
        "--max-lines",
        "--max-procs",
        "--replace",
        "-E",
        "-I",
        "-J",
        "-L",
        "-P",
        "-R",
        "-S",
        "-a",
        "-d",
        "-e",
        "-n",
        "-s",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn default_true() -> bool {
    true
}

fn send_subcommand() -> String {
    "send".to_owned()
}

fn network_options() -> BTreeSet<String> {
    BTreeSet::from(["--network".to_owned()])
}

fn wrapper_value_options() -> BTreeSet<String> {
    xargs_value_options()
}

fn omairc_launchers() -> Vec<Vec<String>> {
    [
        vec!["omairc"],
        vec!["exec", "omairc"],
        vec!["xargs", "omairc"],
    ]
    .into_iter()
    .map(|values| values.into_iter().map(str::to_owned).collect())
    .collect()
}
