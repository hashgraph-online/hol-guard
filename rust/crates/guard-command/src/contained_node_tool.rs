//! Which local tool a contained node-tool command runs, and in which mode.
//!
//! `npx eslint src`, `pnpm lint`, `npm exec -- prettier --check .` and `node
//! node_modules/typescript/bin/tsc --noEmit` are four spellings of the same
//! three runs. The pre-tool pass reads one of them and admits the work; the
//! sink then has to reach the same tool, the same arguments and the same
//! mode, or it plans a run the admitted receipt does not describe.
//!
//! One reading settles all of it: the manager spelling is peeled, the entry a
//! `node` command names is resolved to the tool that publishes it, and the
//! mode gate (`tsc --noEmit`, `vite build`, Prettier in a checking mode, and
//! no token that writes or chains) answers once. The entrypoint names come
//! back with the answer, so the sink resolves the files for the tool native
//! authority chose rather than looking the tool up a second time.

#[cfg(test)]
#[path = "contained_node_tool_tests.rs"]
mod tests;

#[path = "node_tool_modes.rs"]
pub(crate) mod node_tool_modes;

pub(crate) use node_tool_modes::{
    config_declares_no_emit, entry_tool, local_package_entry, supported_tool, supported_tool_in,
    tool_entries,
};

use crate::pretool::{manager_local_bin_arguments, manager_script_task};
use crate::restricted_command::RestrictedPytestError;
use serde_json::{json, Value};
use std::path::Path;

/// A refused command, and the sandbox reason a refusal that is not about the
/// command itself carries instead.
const INVALID: &str = "node_tool_invalid_command";
const SANDBOX_UNAVAILABLE: &str = "pytest_restricted_sandbox_unavailable";

/// The bounds a `--max-old-space-size` option may name, in MiB. Below the
/// floor Node cannot start its own heap, and the ceiling is the largest heap
/// the contained profiles will reserve.
const HEAP_FLOOR_MIB: u64 = 16;
const HEAP_CEILING_MIB: u64 = 131_072;

/// What a supported tool's run produces: a report, or a build's output tree.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ToolMode {
    Report,
    Build,
}

/// What the command turned out to be.
#[derive(PartialEq, Eq, Debug)]
pub(crate) enum NodeToolRoute {
    /// A package manager running one named script. The script's body lives in
    /// the project's manifest, which the caller reads and hands back.
    Script { task: String },
    /// The tool the run starts, the arguments it is given, and the
    /// entrypoints the tool publishes.
    Tool {
        name: &'static str,
        arguments: Vec<String>,
        runtime_arguments: Vec<String>,
        expected_entry: Option<String>,
        entries: &'static [&'static str],
        mode: ToolMode,
    },
    /// The command is not one of the supported runs.
    Invalid {
        code: &'static str,
        message: &'static str,
    },
}

/// The words a manager run passes on to the script it names.
///
/// The first reading answered `Script`, so the command is a manager run; a
/// command that is not leaves no tail to carry.
fn script_tail(command: &[String], windows: bool) -> &[String] {
    let Some((program, rest)) = command.split_first() else {
        return &[];
    };
    let name = program_name(program, windows);
    manager_script_task(&name, rest).map_or(&[][..], |(_, tail)| tail)
}

fn invalid(message: &'static str) -> NodeToolRoute {
    NodeToolRoute::Invalid {
        code: INVALID,
        message,
    }
}

/// The program a command names, without the image extension Windows appends.
///
/// A harness on Windows hands over the resolved `node.exe`, which is the
/// program `node`, and `CreateProcess` resolves images without regard to
/// case, so the name is compared in its lowercase spelling. Elsewhere a
/// trailing `.exe` is an ordinary part of a file name and stays, and a
/// backslash is an ordinary character rather than a separator.
fn program_name(argument: &str, windows: bool) -> String {
    let separators: &[char] = if windows { &['/', '\\'] } else { &['/'] };
    let trimmed = argument.trim_end_matches(separators);
    let name = trimmed.rsplit(separators).next().unwrap_or(trimmed);
    if !windows {
        return name.to_owned();
    }
    match name.rfind('.') {
        Some(dot) if dot > 0 && name[dot + 1..].eq_ignore_ascii_case("exe") => {
            name[..dot].to_lowercase()
        }
        _ => name.to_owned(),
    }
}

/// Whether any supported tool could take every word the manager passed on.
///
/// The admission reads the command before the manifest is resolved, so the
/// task name is all it has and the tool behind it is not yet known. Asking
/// whether some supported tool admits the whole tail keeps the routing receipt
/// from being handed to a run no tool could take, while leaving the exact
/// reading to the sink, which knows which tool the body spells.
pub(crate) fn passed_tail_reports_only_for_some_tool(tail: &[String]) -> bool {
    ["eslint", "tsc", "prettier"]
        .iter()
        .any(|tool| passed_tail_reports_only(tool, tail))
}

/// Whether every word a manager passed on after `--` only changes how the
/// tool reports what it found.
///
/// The tail is the agent's own text rather than the manifest's, so it is read
/// against the options each tool may be handed instead of screened for the
/// writes it must not contain. A refused-word list would have to keep up with
/// every spelling that turns writing back on, and tsc alone defeats one:
/// its parser reads an optional `true`/`false` after a boolean option, so
/// `tsc --noEmit false` emits while still carrying `--noEmit`. A word this
/// list has not met is refused, and the run is left to ordinary review.
pub(crate) fn passed_tail_reports_only(tool: &str, tail: &[String]) -> bool {
    // An entry ending in `=` admits that option with a value attached. The
    // separated spelling is not accepted: its value is a bare word, and a bare
    // word is what turns a boolean option around or names a file to write.
    let allowed: &[&str] = match tool {
        "eslint" => &[
            "--quiet",
            "--color",
            "--no-color",
            "--no-warn-ignored",
            "--max-warnings=",
        ],
        "tsc" => &[
            "--noEmit",
            "--pretty",
            "--noErrorTruncation",
            "--listFilesOnly",
            "--explainFiles",
            "--diagnostics",
            "--extendedDiagnostics",
            "--skipLibCheck",
            "--strict",
        ],
        "prettier" => &["--check", "--list-different", "-l", "--no-color"],
        // `vite build` writes its output, and every option it takes moves or
        // widens that write, so it is run as the manifest spells it.
        _ => &[],
    };
    // The one option whose value a run may spell as a separate word, and the
    // only shape that value may take. A count is not a file name and not the
    // `true`/`false` a boolean option reads back, so admitting it carries
    // nothing the attached spelling does not already carry.
    let counted: &[&str] = if tool == "eslint" {
        &["--max-warnings"]
    } else {
        &[]
    };
    let mut words = tail.iter();
    while let Some(word) = words.next() {
        if counted.contains(&word.as_str()) {
            if !words
                .next()
                .is_some_and(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
            {
                return false;
            }
            continue;
        }
        let known = allowed.iter().any(|option| match option.strip_suffix('=') {
            Some(name) => word
                .strip_prefix(name)
                .and_then(|rest| rest.strip_prefix('='))
                .is_some_and(|value| !value.is_empty()),
            None => word == option,
        });
        if !known {
            return false;
        }
    }
    true
}

/// Whether an argument list rewrites the files it visits or runs more than
/// the one tool. A value spelling enables the same write: `--write=true`
/// turns Prettier's rewrite on just as `--write` does.
pub(crate) fn writes_or_chains(arguments: &[String]) -> bool {
    arguments.iter().any(|word| {
        matches!(
            word.as_str(),
            ";" | "&&"
                | "||"
                | "|"
                | "|&"
                | "&"
                | "--fix"
                | "--fix-dry-run"
                | "--output-file"
                | "-o"
                | "--emitDeclarationOnly"
                | "--write"
                | "-w"
        ) || word.starts_with("--fix=")
            || word.starts_with("--output-file=")
            || word.starts_with("--write=")
    })
}

/// Whether a word is a package manager's own spelling of a local-bin run.
/// The arguments behind it are peeled by [`manager_local_bin_arguments`];
/// this only says that the spelling was used, so `npm exec --filter a vite`
/// is reported as a local-bin run with no runner rather than as a script.
fn local_bin_verb(manager: &str, word: &str) -> bool {
    matches!(
        (manager, word),
        ("npm", "exec" | "x") | ("pnpm" | "yarn", "exec")
    )
}

/// The bounded Node heap option this run may keep, if it names one.
fn bounded_heap(argument: &str) -> Option<bool> {
    let value = argument.strip_prefix("--max-old-space-size=")?;
    let bounded = !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value
            .parse::<u64>()
            .is_ok_and(|mib| (HEAP_FLOOR_MIB..=HEAP_CEILING_MIB).contains(&mib));
    Some(bounded)
}

/// Where the gate lands once a tool name and its arguments are known.
fn gate(
    name: &str,
    mut arguments: Vec<String>,
    runtime_arguments: Vec<String>,
    expected_entry: Option<String>,
    directory: Option<&Path>,
) -> NodeToolRoute {
    // One reading of the project answers both questions: whether the run is
    // one this route admits, and whether the `--noEmit` it is admitted for
    // has to be written back onto its command line. Asking the filesystem
    // twice would let a config written between the two answers admit a run
    // whose arguments never carried the option.
    let from_config = config_declares_no_emit(name, &arguments, directory);
    let Some((name, entries, mode)) =
        node_tool_modes::supported_tool_declared(name, &arguments, from_config)
    else {
        return invalid(
            "Only local ESLint, no-emit TypeScript and Prettier in a checking mode are supported.",
        );
    };
    if writes_or_chains(&arguments) {
        return invalid("The lint/typecheck input has write or shell effects.");
    }
    // The project declared the no-emit mode this route admitted, so the run
    // carries it on its own command line. Whatever the file says by the time
    // the run starts, the process that starts cannot emit.
    if from_config {
        arguments.push("--noEmit".to_owned());
    }
    NodeToolRoute::Tool {
        name,
        arguments,
        runtime_arguments,
        expected_entry,
        entries,
        mode,
    }
}

/// The run a contained node-tool command stands for.
///
/// `script_body` carries the tokens of the manifest script a previous answer
/// named, so the body is gated as the tool run it spells rather than read a
/// second way. The body is the whole command: a script that itself starts a
/// manager or a `node` entrypoint is not one of the supported runs.
pub(crate) fn node_tool_route(
    command: &[String],
    script_body: Option<&[String]>,
    windows: bool,
    directory: Option<&Path>,
) -> NodeToolRoute {
    if let Some(tokens) = script_body {
        let Some((name, arguments)) = tokens.split_first() else {
            return invalid("The requested local script is empty.");
        };
        // The manager hands the words after `--` to the body it starts, so
        // `npm run lint -- --fix` is the body holding `--fix`. Reading them
        // back off the command gates them with the run they belong to instead
        // of losing them between the two readings.
        let mut arguments = arguments.to_vec();
        let tail = script_tail(command, windows);
        // A tail carrying a write or a shell effect is refused with the body
        // it belongs to, which names the effect found. This screen answers
        // the narrower question left over: a word that writes nothing by
        // itself but is not one the tool may be handed.
        if !writes_or_chains(tail) && !passed_tail_reports_only(name, tail) {
            return invalid(
                "The requested local script was passed an option the tool may not take.",
            );
        }
        arguments.extend_from_slice(tail);
        return gate(name, arguments, Vec::new(), None, directory);
    }
    let Some((program, rest)) = command.split_first() else {
        return gate("", Vec::new(), Vec::new(), None, directory);
    };
    let mut name = program_name(program, windows);
    let mut arguments = rest.to_vec();
    if name == "bun" && arguments.first().is_some_and(|word| word == "x") {
        // `bun x` is Bun's spelling of `bunx`.
        name = "bunx".to_owned();
        arguments.remove(0);
    }
    let mut runtime_arguments = Vec::new();
    let mut expected_entry = None;
    if crate::contained_argv::manager_reporting_options_peeled(&name, &arguments)
        .first()
        .is_some_and(|word| local_bin_verb(&name, word))
    {
        // `npm exec`, `npm x`, `pnpm exec` and `yarn exec` are each manager's
        // spelling of a local-bin run. A manager option before the tool (`-c`
        // runs a shell, `-r`/`--filter` fan out) is not accepted. An option
        // that only chooses how much the manager prints names no verb, so the
        // subcommand is read behind it, the same way the admission reads it:
        // otherwise a quiet `exec` the admission routed here would arrive as
        // a package script and never start its tool.
        let Some(peeled) = manager_local_bin_arguments(&name, &arguments).map(|local_run| {
            let (runner, rest) = local_run.split_first().expect("a peeled run names a tool");
            (runner.clone(), rest.to_vec())
        }) else {
            return invalid("Missing local runner.");
        };
        (name, arguments) = peeled;
    } else if matches!(name.as_str(), "bun" | "npm" | "pnpm" | "yarn") {
        let Some((task, _)) = manager_script_task(&name, &arguments) else {
            return invalid("Only a single named package script is supported.");
        };
        if windows {
            return NodeToolRoute::Invalid {
                code: SANDBOX_UNAVAILABLE,
                message: "Package scripts do not run contained on Windows yet.",
            };
        }
        return NodeToolRoute::Script {
            task: task.to_owned(),
        };
    } else if matches!(name.as_str(), "bunx" | "npx") {
        if arguments.first().is_some_and(|word| word == "--no-install") {
            arguments.remove(0);
        }
        if arguments.is_empty() {
            return invalid("Missing local runner.");
        }
        name = arguments.remove(0);
    } else if matches!(name.as_str(), "node" | "nodejs") {
        if let Some(bounded) = arguments.first().and_then(|word| bounded_heap(word)) {
            if !bounded {
                return invalid("Invalid bounded Node memory option.");
            }
            runtime_arguments.push(arguments.remove(0));
        }
        if arguments.is_empty() {
            return invalid("Missing local entrypoint.");
        }
        let entry = arguments.remove(0);
        name = entry_tool(&entry).to_owned();
        expected_entry = Some(entry);
    }
    gate(
        &name,
        arguments,
        runtime_arguments,
        expected_entry,
        directory,
    )
}

/// The routing request as the caller spells it: the platform the command was
/// read on and the manifest script body the caller already resolved, both
/// optional. A body that is present but not a list of words is a malformed
/// request, not an empty one, so it is refused rather than routed.
pub(crate) fn route_request(
    input: &Value,
    command: &[String],
) -> Result<Value, RestrictedPytestError> {
    let windows = input
        .get("windows")
        .and_then(Value::as_bool)
        .unwrap_or(cfg!(windows));
    // The directory the run starts in, when the caller knows it. Without one
    // a `tsc` run is read from its command line alone.
    let directory = input
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|cwd| !cwd.is_empty())
        .map(Path::new);
    let body = input.get("script_body").cloned().unwrap_or(Value::Null);
    let script_body = if body.is_null() {
        None
    } else {
        Some(serde_json::from_value::<Vec<String>>(body).map_err(|_| {
            RestrictedPytestError::new(
                "pytest_restricted_invalid_command",
                "Invalid restricted execution request.",
            )
        })?)
    };
    route_reply(command, script_body.as_deref(), windows, directory)
}

/// The route as the sink reads it: one reading of the spelling, the tool it
/// names and the mode gate, so the sink never recomputes the verdict.
pub(crate) fn route_reply(
    command: &[String],
    script_body: Option<&[String]>,
    windows: bool,
    directory: Option<&Path>,
) -> Result<Value, RestrictedPytestError> {
    match node_tool_route(command, script_body, windows, directory) {
        NodeToolRoute::Script { task } => Ok(json!({ "kind": "script", "task": task })),
        NodeToolRoute::Tool {
            name,
            arguments,
            runtime_arguments,
            expected_entry,
            entries,
            mode,
        } => Ok(json!({
            "kind": "tool",
            "name": name,
            "arguments": arguments,
            "runtime_arguments": runtime_arguments,
            "expected_entry": expected_entry,
            "entries": entries,
            "mode": match mode {
                ToolMode::Report => "report",
                ToolMode::Build => "build",
            },
        })),
        NodeToolRoute::Invalid { code, message } => Err(RestrictedPytestError::new(code, message)),
    }
}
