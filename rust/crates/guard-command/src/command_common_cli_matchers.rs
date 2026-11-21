//! Native interpreters for the seven focused common-CLI matcher contracts.
//!
//! These scanners deliberately preserve `command_common_cli_matchers_extra.py`:
//! help checks inspect raw argument tokens, one-shot SQL options retain their
//! existing value extraction, and OpenShift uses its positional/dry-run rules. They do
//! not substitute the separate conservative executable-option grammar.

use serde::Deserialize;

use crate::{CanonicalCommandV1, MAX_COMMAND_BYTES, MAX_COMMAND_SEGMENTS, MAX_COMMAND_TOKENS};

#[path = "command_common_cli_matcher_values.rs"]
mod values;

use values::{basename, has_any, is_executable, normalized_words, option_values, sql_mutation};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyConfig {}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SqlOptionConfig {
    executable: String,
    long_option: String,
    short_option: String,
}

#[derive(Debug, Clone)]
pub(crate) enum CommonCliMatcher {
    AnsibleExecution,
    SqlOptionMutation(SqlOptionConfig),
    DotnetProjectPackage,
    MongoEvalMutation,
    SqliteMutation,
    OpenShiftDeleteDrain,
    OpenShiftMutation,
}

impl CommonCliMatcher {
    pub(crate) fn from_config(op: &str, config: serde_json::Value) -> Result<Self, &'static str> {
        if op == "sql-option-mutation.v1" {
            let config: SqlOptionConfig =
                serde_json::from_value(config).map_err(|_| "native_common_cli_config_invalid")?;
            // Reviewed compiler contracts use literal ASCII option names. A
            // future grammar must be admitted explicitly, not guessed here.
            if [
                &config.executable,
                &config.long_option,
                &config.short_option,
            ]
            .iter()
            .any(|value| value.is_empty() || !value.is_ascii() || value.len() > MAX_COMMAND_BYTES)
                || !config.long_option.starts_with('-')
                || !config.short_option.starts_with('-')
            {
                return Err("native_common_cli_config_unsupported");
            }
            return Ok(Self::SqlOptionMutation(config));
        }
        let matcher = match op {
            "ansible-execution.v1" => Self::AnsibleExecution,
            "dotnet-project-package.v1" => Self::DotnetProjectPackage,
            "mongo-eval-mutation.v1" => Self::MongoEvalMutation,
            "sqlite-mutation.v1" => Self::SqliteMutation,
            "openshift-delete-drain.v1" => Self::OpenShiftDeleteDrain,
            "openshift-mutation.v1" => Self::OpenShiftMutation,
            _ => return Err("native_common_cli_operation_unsupported"),
        };
        serde_json::from_value::<EmptyConfig>(config)
            .map_err(|_| "native_common_cli_config_invalid")?;
        Ok(matcher)
    }

    pub(crate) fn match_segments(
        &self,
        command: &CanonicalCommandV1,
    ) -> Result<Vec<usize>, &'static str> {
        if command.confidence != "exact" {
            return Err("native_common_cli_command_uncertain");
        }
        if command.segments.len() > MAX_COMMAND_SEGMENTS
            || command.normalized_text.len() > MAX_COMMAND_BYTES
        {
            return Err("native_common_cli_command_limit_exceeded");
        }
        let mut count = 0usize;
        let mut bytes = 0usize;
        let mut matched = Vec::new();
        for (index, segment) in command.segments.iter().enumerate() {
            count = count
                .saturating_add(segment.arguments.len())
                .saturating_add(usize::from(segment.executable.is_some()));
            bytes = bytes.saturating_add(segment.executable.as_ref().map_or(0, String::len));
            for argument in &segment.arguments {
                bytes = bytes.saturating_add(argument.len());
            }
            if count > MAX_COMMAND_TOKENS || bytes > MAX_COMMAND_BYTES {
                return Err("native_common_cli_command_limit_exceeded");
            }
            let executable = basename(segment.executable.as_deref());
            if self.matches_arguments(&executable, &segment.arguments) {
                matched.push(index);
            }
        }
        Ok(matched)
    }

    fn matches_arguments(&self, executable: &str, arguments: &[String]) -> bool {
        match self {
            Self::AnsibleExecution => ansible_execution(executable, arguments),
            Self::SqlOptionMutation(config) => {
                is_executable(executable, &config.executable)
                    && !has_any(arguments, &["--help", "-h"])
                    && option_values(arguments, &config.long_option, &config.short_option)
                        .into_iter()
                        .any(sql_mutation)
            }
            Self::DotnetProjectPackage => {
                if !is_executable(executable, "dotnet") || has_any(arguments, &["--help", "-h"]) {
                    return false;
                }
                arguments.windows(4).any(|window| {
                    window[0].to_lowercase() == "add"
                        && window[2].to_lowercase() == "package"
                        && !window[1].starts_with('-')
                        && !window[3].starts_with('-')
                })
            }
            Self::MongoEvalMutation => {
                if !is_executable(executable, "mongosh") || has_any(arguments, &["--help", "-h"]) {
                    return false;
                }
                option_values(arguments, "--eval", "-e")
                    .into_iter()
                    .any(|value| {
                        let compact: String = value
                            .to_lowercase()
                            .chars()
                            .filter(|character| {
                                !crate::command_option_parsing::python_is_whitespace(*character)
                            })
                            .collect();
                        [
                            "dropdatabase(",
                            "dropuser(",
                            ".drop(",
                            ".deleteone(",
                            ".deletemany(",
                            ".remove(",
                        ]
                        .iter()
                        .any(|marker| compact.contains(marker))
                    })
            }
            Self::SqliteMutation => {
                is_executable(executable, "sqlite3")
                    && !has_any(arguments, &["--help", "-h"])
                    && arguments.iter().any(|argument| {
                        let lowered = normalized_words(argument);
                        sql_mutation(argument)
                            || lowered.starts_with(".restore ")
                            || lowered.starts_with(".import ")
                    })
            }
            Self::OpenShiftDeleteDrain => openshift_mutation(executable, arguments, true),
            Self::OpenShiftMutation => openshift_mutation(executable, arguments, false),
        }
    }
}

fn ansible_execution(executable: &str, arguments: &[String]) -> bool {
    let kind = ["ansible", "ansible-playbook", "ansible-pull"]
        .into_iter()
        .find(|kind| is_executable(executable, kind));
    let Some(kind) = kind else {
        return false;
    };
    if arguments.is_empty() || has_any(arguments, &["--help", "-h", "--version"]) {
        return false;
    }
    if kind == "ansible" && has_any(arguments, &["--list-hosts"]) {
        return false;
    }
    if kind == "ansible-playbook"
        && has_any(
            arguments,
            &[
                "--syntax-check",
                "--list-hosts",
                "--list-tasks",
                "--list-tags",
            ],
        )
    {
        return false;
    }
    true
}

fn openshift_mutation(executable: &str, arguments: &[String], destructive: bool) -> bool {
    if !is_executable(executable, "oc") || has_any(arguments, &["--help", "-h"]) {
        return false;
    }
    let lowered: Vec<_> = arguments
        .iter()
        .map(|argument| argument.to_lowercase())
        .collect();
    let operands: Vec<_> = lowered
        .iter()
        .filter(|argument| !argument.starts_with('-'))
        .map(String::as_str)
        .collect();
    let first = operands.first().copied();
    let delete = first == Some("delete");
    let drain = operands.starts_with(&["adm", "drain"]);
    let recognized = if destructive {
        delete || drain
    } else {
        matches!(first, Some("apply" | "patch" | "scale"))
            || operands.starts_with(&["rollout", "restart"])
    };
    if !recognized {
        return false;
    }
    if !destructive || delete {
        let dry_values = option_values(arguments, "--dry-run", "--dry-run");
        if dry_values
            .last()
            .is_some_and(|value| matches!(value.to_lowercase().as_str(), "client" | "server"))
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
#[path = "command_common_cli_matchers_tests.rs"]
mod tests;
