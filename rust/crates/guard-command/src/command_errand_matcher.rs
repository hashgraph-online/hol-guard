//! Errand v0.4.2 Go-flag and append-only wrapper semantics.

use std::collections::BTreeSet;
use std::time::Instant;

use serde::Deserialize;

use crate::command_ascii_comparison::lowercase_for_ascii_comparison;
use crate::command_option_parsing::known_option_advance;
use crate::command_structured_matchers::check_deadline;
use crate::CommandSegmentV1;

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Operation {
    Run,
    FetchApply,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ErrandConfig {
    operation: Operation,
    subcommands: BTreeSet<String>,
    run_options_with_values: BTreeSet<String>,
    run_flags: BTreeSet<String>,
    fetch_options_with_values: BTreeSet<String>,
    fetch_flags: BTreeSet<String>,
    wrapper_options_with_values: BTreeSet<String>,
    wrapper_flags: BTreeSet<String>,
    expansion_markers: BTreeSet<String>,
}

fn executable_name(value: &str) -> String {
    lowercase_for_ascii_comparison(value.rsplit(['/', '\\']).next().unwrap_or(value))
}

fn is_errand(value: &str) -> bool {
    matches!(
        executable_name(value).as_str(),
        "errand" | "errand.exe" | "errand.cmd"
    )
}

fn go_option(token: &str) -> Option<(&str, Option<&str>)> {
    if token == "-" || token == "--" {
        return None;
    }
    let stripped = token
        .strip_prefix("--")
        .or_else(|| token.strip_prefix('-'))?;
    Some(match stripped.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (stripped, None),
    })
}

impl ErrandConfig {
    pub(super) fn validate(self) -> Result<Self, &'static str> {
        // Python's v1 matcher uses fixed expansion markers, even though the
        // dataclass includes them in its configuration. Admit that profile only.
        let markers: BTreeSet<_> = ["$", "`", "*", "?", "[", "{"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        if self.expansion_markers != markers {
            return Err("invalid_errand_expansion_markers");
        }
        Ok(self)
    }

    fn may_expand(&self, token: &str) -> bool {
        self.expansion_markers
            .iter()
            .any(|marker| token.contains(marker))
    }

    pub(super) fn matches(
        &self,
        segment: &CommandSegmentV1,
        deadline: Option<Instant>,
    ) -> Result<bool, &'static str> {
        let Some(executable) = segment.executable.as_deref() else {
            return Ok(false);
        };
        let executable = executable_name(executable);
        let appendable = matches!(executable.as_str(), "xargs" | "xargs.exe" | "xargs.cmd");
        let mut arguments = segment.arguments.as_slice();
        if !is_errand(&executable) {
            if !appendable && !matches!(executable.as_str(), "exec" | "exec.exe" | "exec.cmd") {
                return Ok(false);
            }
            let names_errand = arguments.iter().any(|token| is_errand(token));
            let mut index = 0;
            while index < arguments.len() {
                check_deadline(deadline)?;
                let token = &arguments[index];
                if token == "--" {
                    index += 1;
                    break;
                }
                if !token.starts_with('-') || token == "-" {
                    break;
                }
                if self.may_expand(token) {
                    return Ok(names_errand);
                }
                let Some(advance) = known_option_advance(
                    token,
                    &self.wrapper_options_with_values,
                    &self.wrapper_flags,
                ) else {
                    return Ok(names_errand);
                };
                if index + advance > arguments.len() {
                    return Ok(names_errand);
                }
                index += advance;
            }
            if arguments.get(index).is_none_or(|token| !is_errand(token)) {
                return Ok(false);
            }
            arguments = &arguments[index + 1..];
        }
        let Some(dispatch) = arguments.first() else {
            return Ok(appendable);
        };
        if self.may_expand(dispatch) {
            return Ok(true);
        }
        match self.operation {
            Operation::FetchApply if dispatch == "fetch" => {
                self.applies_fetch(&arguments[1..], appendable, deadline)
            }
            Operation::Run if !self.subcommands.contains(dispatch) => {
                self.executes_job(arguments, appendable, deadline)
            }
            _ => Ok(false),
        }
    }

    fn executes_job(
        &self,
        arguments: &[String],
        appendable: bool,
        deadline: Option<Instant>,
    ) -> Result<bool, &'static str> {
        let mut index = 0;
        while index < arguments.len() {
            check_deadline(deadline)?;
            let token = &arguments[index];
            if token == "--" {
                return Ok(index + 1 < arguments.len());
            }
            if self.may_expand(token) {
                return Ok(true);
            }
            let Some((name, value)) = go_option(token) else {
                return Ok(true);
            };
            if matches!(name, "h" | "help") {
                return Ok(false);
            }
            if self.run_options_with_values.contains(name) {
                if value.is_none() {
                    index += 1;
                    let Some(value) = arguments.get(index) else {
                        return Ok(appendable);
                    };
                    if self.may_expand(value) {
                        return Ok(true);
                    }
                }
            } else if !self.run_flags.contains(name) {
                return Ok(true);
            }
            index += 1;
        }
        Ok(appendable)
    }

    fn applies_fetch(
        &self,
        arguments: &[String],
        appendable: bool,
        deadline: Option<Instant>,
    ) -> Result<bool, &'static str> {
        let mut apply = false;
        let mut index = 0;
        while index < arguments.len() {
            check_deadline(deadline)?;
            let token = &arguments[index];
            if self.may_expand(token) {
                return Ok(true);
            }
            let Some((name, value)) = go_option(token) else {
                return Ok(apply);
            };
            if matches!(name, "h" | "help") {
                return Ok(false);
            }
            if self.fetch_options_with_values.contains(name) {
                if value.is_none() {
                    index += 1;
                    let Some(value) = arguments.get(index) else {
                        return Ok(apply || appendable);
                    };
                    if self.may_expand(value) {
                        return Ok(true);
                    }
                }
            } else if name == "apply" {
                apply = match value {
                    None | Some("1" | "t" | "T" | "true" | "True" | "TRUE") => true,
                    Some("0" | "f" | "F" | "false" | "False" | "FALSE") => false,
                    _ => return Ok(true),
                };
            } else if !self.fetch_flags.contains(name) {
                return Ok(true);
            }
            index += 1;
        }
        Ok(apply || appendable)
    }
}
