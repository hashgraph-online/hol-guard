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

use crate::pretool::{manager_local_bin_arguments, manager_script_task};
use crate::restricted_command::RestrictedPytestError;
use serde_json::{json, Value};

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

/// Prettier publishes one entrypoint per major, and version 2 remains common
/// enough to name: Prettier 3 moved its executable into `bin/`.
pub(crate) const PRETTIER_ENTRIES: [&str; 2] =
    ["prettier/bin/prettier.cjs", "prettier/bin-prettier.js"];

/// Every supported tool and the entrypoints its published versions install.
/// A tool that publishes one entrypoint per major is installed under
/// whichever spelling its version uses, so every spelling is named and the
/// caller keeps the one the nearest project installs.
const TOOL_ENTRIES: &[(&str, &[&str])] = &[
    ("eslint", &["eslint/bin/eslint.js"]),
    ("tsc", &["typescript/bin/tsc"]),
    ("vite", &["vite/bin/vite.js"]),
    ("prettier", &PRETTIER_ENTRIES),
];

/// A local file path with a `node_modules` component naming one tool's
/// published entrypoint: `node_modules/<entry>`, `./node_modules/<entry>` or
/// `<dir>/node_modules/<entry>`.
pub(crate) fn local_package_entry(entry: &str, package_entry: &str) -> bool {
    entry
        .strip_suffix(package_entry)
        .and_then(|prefix| prefix.strip_suffix("node_modules/"))
        .is_some_and(|prefix| prefix.is_empty() || prefix.ends_with('/'))
}

/// Whether a Prettier command asks only whether the files are formatted.
/// `--check` and `--list-different` print and exit; every other spelling may
/// reach `--write`, which rewrites each file it visits.
pub(crate) fn prettier_checks(arguments: &[String]) -> bool {
    arguments.iter().any(|argument| {
        matches!(
            argument.as_str(),
            "--check" | "-c" | "--list-different" | "-l"
        )
    })
}

/// The admitted tool of this name and the entrypoints it publishes.
pub(crate) fn tool_entries(name: &str) -> Option<(&'static str, &'static [&'static str])> {
    TOOL_ENTRIES.iter().copied().find(|(tool, _)| *tool == name)
}

/// The supported tool a name stands for, the entrypoints it publishes and
/// the mode it runs in, or `None` when the tool or its mode is not one of the
/// supported runs.
pub(crate) fn supported_tool(
    name: &str,
    arguments: &[String],
) -> Option<(&'static str, &'static [&'static str], ToolMode)> {
    let mode = match name {
        "eslint" => ToolMode::Report,
        "tsc" if arguments.iter().any(|word| word == "--noEmit") => ToolMode::Report,
        // Only a checking mode reports instead of rewriting the files it visits.
        "prettier" if prettier_checks(arguments) => ToolMode::Report,
        "vite" if arguments.first().is_some_and(|word| word == "build") => ToolMode::Build,
        _ => return None,
    };
    let (tool, entries) = tool_entries(name)?;
    Some((tool, entries, mode))
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

/// The tool a `node` command starts, from the entrypoint it names, or `""`
/// when the entrypoint belongs to no supported tool.
pub(crate) fn entry_tool(entry: &str) -> &'static str {
    TOOL_ENTRIES
        .iter()
        .find(|(_, entries)| {
            entries
                .iter()
                .any(|published| local_package_entry(entry, published))
        })
        .map_or("", |(tool, _)| *tool)
}

/// Where the gate lands once a tool name and its arguments are known.
fn gate(
    name: &str,
    arguments: Vec<String>,
    runtime_arguments: Vec<String>,
    expected_entry: Option<String>,
) -> NodeToolRoute {
    let Some((name, entries, mode)) = supported_tool(name, &arguments) else {
        return invalid(
            "Only local ESLint, no-emit TypeScript and Prettier in a checking mode are supported.",
        );
    };
    if writes_or_chains(&arguments) {
        return invalid("The lint/typecheck input has write or shell effects.");
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
) -> NodeToolRoute {
    if let Some(tokens) = script_body {
        let Some((name, arguments)) = tokens.split_first() else {
            return invalid("The requested local script is empty.");
        };
        return gate(name, arguments.to_vec(), Vec::new(), None);
    }
    let Some((program, rest)) = command.split_first() else {
        return gate("", Vec::new(), Vec::new(), None);
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
    if arguments
        .first()
        .is_some_and(|word| local_bin_verb(&name, word))
    {
        // `npm exec`, `npm x`, `pnpm exec` and `yarn exec` are each manager's
        // spelling of a local-bin run. A manager option before the tool (`-c`
        // runs a shell, `-r`/`--filter` fan out) is not accepted.
        let Some(peeled) = manager_local_bin_arguments(&name, &arguments).map(|local_run| {
            let (runner, rest) = local_run.split_first().expect("a peeled run names a tool");
            (runner.clone(), rest.to_vec())
        }) else {
            return invalid("Missing local runner.");
        };
        (name, arguments) = peeled;
    } else if matches!(name.as_str(), "bun" | "npm" | "pnpm" | "yarn") {
        let Some(task) = manager_script_task(&name, &arguments) else {
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
    gate(&name, arguments, runtime_arguments, expected_entry)
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
    route_reply(command, script_body.as_deref(), windows)
}

/// The route as the sink reads it: one reading of the spelling, the tool it
/// names and the mode gate, so the sink never recomputes the verdict.
pub(crate) fn route_reply(
    command: &[String],
    script_body: Option<&[String]>,
    windows: bool,
) -> Result<Value, RestrictedPytestError> {
    match node_tool_route(command, script_body, windows) {
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
