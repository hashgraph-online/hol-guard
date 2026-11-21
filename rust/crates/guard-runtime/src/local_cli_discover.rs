//! The `local-cli-discover` command: the commands a verified local CLI takes
//! (`runtime/local_cli_help.discover_local_cli_commands`).
//!
//! The caller has already matched the CLI to the identity the operator
//! approved and built its `--help` argv. Here the script source is read before
//! anything runs, `--help` runs only as far as that source allows, and nested
//! commands are probed only for a parser that answers `<command> --help`
//! without running the command. The caller merges what comes back onto the
//! default catalog.

use std::collections::HashSet;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::local_cli_help::{help_commands, source_read, HelpHandler, LocalCliCommand};
use crate::local_cli_help_probe::{run_cli_help, COMMAND_NAME};
use crate::local_cli_script_source::{local_import_paths, read_local_module, read_script_source};

pub(crate) const COMMAND: &str = "local-cli-discover";
pub(crate) const FEATURE: &str = "local-cli-discover-v1";
const MAX_NESTED_PROBES: usize = 8;
const MAX_ARGV: usize = 3;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    /// The CLI's name, the first word of every invocation its help shows.
    name: String,
    /// `script` (run through an interpreter) or `executable`.
    kind: String,
    argv: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    Ok,
    Empty,
    Failed,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Empty => "empty",
            Self::Failed => "failed",
        }
    }
}

pub(crate) fn run_command(bytes: &[u8]) -> Value {
    let request = match serde_json::from_slice::<Request>(bytes) {
        Ok(request)
            if !request.name.is_empty()
                && matches!(request.kind.as_str(), "script" | "executable")
                && (2..=MAX_ARGV).contains(&request.argv.len()) =>
        {
            request
        }
        _ => return json!({"ok": false, "error": "The CLI discovery request was not understood."}),
    };
    let (commands, status) = discover(&request.name, &request.kind, &request.argv, &mut |argv| {
        run_cli_help(argv)
    });
    json!({
        "ok": true,
        "result": {"commands": commands, "status": status.as_str()},
    })
}

/// `script_source_path`: the script a `--help` argv would run, and whether it
/// counts only with a `#!` line, so a compiled program is never read as text.
fn script_source(kind: &str, argv: &[String]) -> Option<(String, bool)> {
    match (kind, argv.len()) {
        ("script", 3) => Some((argv[1].clone(), false)),
        ("executable", 2) => Some((argv[0].clone(), true)),
        _ => None,
    }
}

fn read_help(output: &str, invocation: &[String]) -> Option<Vec<LocalCliCommand>> {
    (!output.trim().is_empty()).then(|| help_commands(output, None, invocation))
}

pub(crate) fn discover(
    name: &str,
    kind: &str,
    argv: &[String],
    probe: &mut dyn FnMut(&[String]) -> String,
) -> (Vec<LocalCliCommand>, Status) {
    let invocation = vec![name.to_owned()];
    if let Some((script, shebang_only)) = script_source(kind, argv) {
        if let Some(text) = read_script_source(&script, shebang_only) {
            return discover_from_source(argv, &invocation, &script, &text, probe);
        }
    }
    let output = probe(argv);
    let Some(discovered) = read_help(&output, &invocation) else {
        return (Vec::new(), Status::Failed);
    };
    if discovered.is_empty() {
        return (Vec::new(), Status::Empty);
    }
    let discovered = if discovered.len() <= MAX_NESTED_PROBES {
        with_nested_commands(argv, discovered, probe, name, &output)
    } else {
        discovered
    };
    (discovered, Status::Ok)
}

/// Read a script before running it, and run it only as far as its source
/// allows. A script that never looks for `--help` would do its normal work
/// when given it, so it is not run at all. One whose own code answers
/// `--help` is run once with it. Only a parser library such as argparse or
/// Commander answers `<command> --help` for each command without running
/// that command, so only then are the commands probed one by one.
fn discover_from_source(
    argv: &[String],
    invocation: &[String],
    script: &str,
    text: &str,
    probe: &mut dyn FnMut(&[String]) -> String,
) -> (Vec<LocalCliCommand>, Status) {
    let read = source_read(text, invocation);
    let mut from_source = read.commands;
    let mut handler = read.help;
    let imports: Vec<&str> = read.imports.iter().map(String::as_str).collect();
    for module in local_import_paths(script, &imports) {
        let Some(module_text) = read_local_module(&module, script) else {
            continue;
        };
        let imported = source_read(&module_text, invocation);
        from_source.extend(imported.commands);
        // The entry script decides whether a parser answers each command's
        // --help; a module can only show that something checks for it.
        if imported.help != HelpHandler::None && handler == HelpHandler::None {
            handler = HelpHandler::Script;
        }
    }
    if handler == HelpHandler::None {
        let found = distinct(from_source);
        let status = if found.is_empty() {
            Status::Empty
        } else {
            Status::Ok
        };
        return (found, status);
    }
    let output = probe(argv);
    let mut discovered = read_help(&output, invocation);
    if let Some(found) = discovered.take() {
        discovered = Some(
            if !found.is_empty()
                && handler == HelpHandler::Framework
                && found.len() <= MAX_NESTED_PROBES
            {
                with_nested_commands(argv, found, probe, &invocation[0], &output)
            } else {
                found
            },
        );
    }
    let answered = discovered.is_some();
    let found = distinct(
        discovered
            .unwrap_or_default()
            .into_iter()
            .chain(from_source),
    );
    if !found.is_empty() {
        (found, Status::Ok)
    } else if answered {
        (found, Status::Empty)
    } else {
        (found, Status::Failed)
    }
}

/// The first of each command id: help output over the source, the script over
/// its modules.
fn distinct(commands: impl IntoIterator<Item = LocalCliCommand>) -> Vec<LocalCliCommand> {
    let mut seen = HashSet::new();
    commands
        .into_iter()
        .filter(|command| seen.insert(command.command_id.clone()))
        .collect()
}

fn help_words(text: &str) -> Vec<&str> {
    text.split_whitespace().collect()
}

fn listed_entries<'a>(
    commands: impl IntoIterator<Item = &'a LocalCliCommand>,
) -> HashSet<(String, String)> {
    commands
        .into_iter()
        .map(|command| {
            (
                command.command_id.clone(),
                help_words(&command.description).join(" "),
            )
        })
        .collect()
}

fn with_nested_commands(
    argv: &[String],
    discovered: Vec<LocalCliCommand>,
    probe: &mut dyn FnMut(&[String]) -> String,
    program: &str,
    parent_help: &str,
) -> Vec<LocalCliCommand> {
    let mut seen: HashSet<String> = discovered
        .iter()
        .map(|command| command.command_id.clone())
        .collect();
    let prefix = &argv[..argv.len() - 1];
    let top_level_help = help_words(parent_help);
    let top_level_entries = listed_entries(
        discovered
            .iter()
            .filter(|command| command.parent_id.is_none()),
    );
    let mut nested = discovered.clone();
    for command in &discovered {
        // An option has no help of its own to probe.
        if command.parent_id.is_some() || !COMMAND_NAME.is_match(&command.name) {
            continue;
        }
        let mut child_argv = prefix.to_vec();
        child_argv.push(command.name.clone());
        child_argv.push("--help".to_owned());
        let child_output = probe(&child_argv);
        // A script that reads only --help prints its own help again for every
        // command, which would add each one again under every other.
        if child_output.trim().is_empty() || help_words(&child_output) == top_level_help {
            continue;
        }
        let children = help_commands(
            &child_output,
            None,
            &[program.to_owned(), command.name.clone()],
        );
        // The same help under another heading lists the same commands with the
        // same descriptions; a command whose subcommands share those names
        // describes them differently, so they are kept.
        if listed_entries(&children) == top_level_entries {
            continue;
        }
        for child in children {
            let child_id = format!("{}.{}", command.command_id, child.command_id);
            if seen.contains(&child_id) || !COMMAND_NAME.is_match(&child.command_id) {
                continue;
            }
            seen.insert(child_id.clone());
            let usage = if child.usage.is_empty() {
                &child.name
            } else {
                &child.usage
            };
            nested.push(LocalCliCommand {
                command_id: child_id,
                name: format!("{} {}", command.name, child.name),
                usage: format!("{} {usage}", command.name),
                description: child.description,
                parent_id: Some(command.command_id.clone()),
            });
        }
    }
    nested
}

#[cfg(test)]
#[path = "local_cli_discover_tests.rs"]
mod tests;
