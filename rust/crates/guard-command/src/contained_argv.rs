//! Portable bounded argv admission for contained Node, Vitest and inline runs.
#[cfg(test)]
#[path = "contained_argv_tests.rs"]
mod tests;
use crate::contained_node_tool::local_package_entry;
use crate::restricted_command::{normalized_command, RestrictedPytestError};
use crate::sfrs_shlex::{split_with, PLAIN_LEXER, STRICT_LEXER};
use regex::Regex;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::LazyLock;

const NODE_INVALID: &str = "node_test_restricted_invalid_command";
const VITEST_INVALID: &str = "vitest_restricted_invalid_command";

/// Vitest's installed entry points. `vitest.mjs` is the package's declared
/// `bin` shim and `dist/cli.js` is the module that shim imports, so both
/// spellings start the project's own installed runner.
pub(crate) fn local_vitest_entry(argument: &str) -> bool {
    local_package_entry(argument, "vitest/vitest.mjs")
        || local_package_entry(argument, "vitest/dist/cli.js")
}

/// The program a word names; on Windows without `.exe`, as the pre-tool parser
/// reads it, so `node.exe` and a resolved `C:\...\python.exe` name `node` and
/// `python`. Every reading of a program name goes through here, so a
/// Windows-spelled tool names the same program wherever it is read.
pub(crate) fn program_name(value: &str) -> &str {
    let name = Path::new(value)
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or(value);
    match name.len().checked_sub(4) {
        Some(stem)
            if cfg!(windows)
                && stem > 0
                && name.is_char_boundary(stem)
                && name[stem..].eq_ignore_ascii_case(".exe") =>
        {
            &name[..stem]
        }
        _ => name,
    }
}

/// The program the command runs, as [`program_name`] reads its first word.
fn basename(command: &[String]) -> &str {
    command.first().map(|v| program_name(v)).unwrap_or("")
}

pub fn node_runtime_args(command: &[String]) -> Result<Vec<String>, RestrictedPytestError> {
    let argv = normalized_command(command)?;
    if argv.len() >= 2 && matches!(basename(&argv), "node" | "nodejs") {
        if let Some(value) = argv[1].strip_prefix("--max-old-space-size=") {
            // Python accepts arbitrarily many leading zeroes; bound the wire,
            // not numeric parsing, without rejecting that lexical form.
            let digits = value.trim_start_matches('0');
            let number = digits.parse::<u32>().ok();
            if value.is_empty()
                || !value.bytes().all(|v| v.is_ascii_digit())
                || !number.is_some_and(|v| (16..=131072).contains(&v))
            {
                return Err(RestrictedPytestError::new(
                    NODE_INVALID,
                    "Invalid bounded Node memory option.",
                ));
            }
            return Ok(vec![argv[1].clone()]);
        }
    }
    Ok(vec![])
}

pub fn test_script(script: &str) -> bool {
    named_test_script(script, false)
}

/// A workspace script under any plain name. Windows has no workspace sandbox,
/// so there the read-only boundary also runs an ordinary script that the
/// pre-tool check found reads no network, credential store or write; it
/// authorizes the resolved launch again before running it.
fn windows_plain_script(script: &str, node: bool) -> bool {
    static NAME: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-][A-Za-z0-9_.-]*\.py$").unwrap());
    static NODE_NAME: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-][A-Za-z0-9_.-]*\.(?:js|mjs|cjs)$").unwrap());
    let name = if node { &NODE_NAME } else { &NAME };
    cfg!(windows)
        && workspace_script_path(script)
        && name.is_match(script.rsplit('/').next().unwrap_or(""))
}

fn workspace_script_path(script: &str) -> bool {
    !script.is_empty()
        && !script.starts_with(['-', '/', '~', '$'])
        && !script.contains(['\\', '$', '`'])
        && script
            .trim_end_matches('/')
            .split('/')
            .all(|v| !v.is_empty() && v != "..")
}

fn named_test_script(script: &str, node: bool) -> bool {
    static NAME: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"^(?:test_[A-Za-z0-9_-]*|[A-Za-z0-9_-]*_test|test|tests|runtests|run_tests)\.py$",
        )
        .unwrap()
    });
    workspace_script_path(script)
        && if node {
            static NODE_NAME: LazyLock<Regex> = LazyLock::new(|| {
                Regex::new(r"^(?:[A-Za-z0-9_.-]*(?:\.test|\.spec|_test)|test_[A-Za-z0-9_.-]*|tests?)\.(?:js|mjs|cjs|jsx|ts|mts|cts|tsx)$").unwrap()
            });
            NODE_NAME.is_match(script.rsplit('/').next().unwrap_or(""))
        } else {
            NAME.is_match(script.rsplit('/').next().unwrap_or(""))
        }
}

pub fn node_script_index(command: &[String], start: usize) -> Option<usize> {
    static FLAGS: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^(?:--experimental-strip-types|--experimental-transform-types|--no-warnings|--disable-warning=[A-Za-z0-9_]{1,64})$").unwrap()
    });
    let mut index = start;
    while command
        .get(index)
        .is_some_and(|value| FLAGS.is_match(value))
    {
        index += 1;
    }
    command
        .get(index)
        .filter(|value| named_test_script(value, true) || windows_plain_script(value, true))
        .map(|_| index)
}

pub fn tsx_test_invocation(
    command: &[String],
) -> Result<Option<(String, Vec<String>)>, RestrictedPytestError> {
    let name = basename(command);
    let Some(mut args) = command.get(1..) else {
        return Ok(None);
    };
    if name == "npx" && args.first().is_some_and(|value| value == "--no-install") {
        args = &args[1..];
    }
    if name == "npx" && args.first().is_some_and(|value| value == "tsx") {
        args = &args[1..];
    } else if matches!(name, "node" | "nodejs") {
        args = &args[node_runtime_args(command)?.len()..];
        if !args.first().is_some_and(|value| {
            value
                .replace('\\', "/")
                .ends_with("/node_modules/tsx/dist/cli.mjs")
        }) {
            return Ok(None);
        }
        args = &args[1..];
    } else if name != "tsx" {
        return Ok(None);
    }
    Ok(args
        .first()
        .filter(|value| named_test_script(value, true))
        .map(|script| (script.clone(), args[1..].to_vec())))
}

pub fn python_runtime_args(command: &[String]) -> Option<Vec<String>> {
    let mut flags = 0;
    let mut index = 1;
    while let Some(arg) = command.get(index) {
        let bits = match arg.as_str() {
            "-I" => 1,
            "-S" => 2,
            "-IS" | "-SI" => 3,
            _ => break,
        };
        if flags & bits != 0 {
            return None;
        }
        flags |= bits;
        index += 1;
    }
    let inline = command.len() == index + 2 && command[index] == "-c";
    let unittest = command.get(index).is_some_and(|value| value == "-m")
        && command
            .get(index + 1)
            .is_some_and(|value| value == "unittest")
        && command[index + 2..]
            .iter()
            .all(|value| !value.contains(['<', '>', '|', '&', ';', '`', '$']));
    if !inline
        && !unittest
        && !command
            .get(index)
            .is_some_and(|v| test_script(v) || windows_plain_script(v, false))
    {
        return None;
    }
    Some(command[1..index].to_vec())
}

pub fn inline_eval(command: &[String]) -> Result<bool, RestrictedPytestError> {
    static PYTHON: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^python(?:\d+(?:\.\d+)*)?$").unwrap());
    if command.is_empty() {
        return Ok(false);
    }
    if PYTHON.is_match(basename(command)) {
        return Ok(python_runtime_args(command).is_some());
    }
    if basename(command) == "bun" {
        return Ok(
            command.len() == 3 && matches!(command[1].as_str(), "-e" | "--eval" | "-p" | "--print")
        );
    }
    if !matches!(basename(command), "node" | "nodejs") {
        return Ok(false);
    }
    let index = 1 + node_runtime_args(command)?.len();
    Ok(
        (command.len() == index + 2 && matches!(command[index].as_str(), "-e" | "--eval"))
            || node_script_index(command, index).is_some(),
    )
}

pub fn bun_vitest_invocation(command: &[String]) -> Option<(Option<String>, Vec<String>)> {
    bun_runner_invocation(command).map(|(directory, _, tail)| (directory, tail))
}

fn bun_runner_invocation(
    command: &[String],
) -> Option<(Option<String>, &'static str, Vec<String>)> {
    let name = basename(command);
    if !matches!(name, "bun" | "bunx") {
        return None;
    }
    let mut args = &command[1..];
    let mut directory = None;
    if args.first().is_some_and(|v| v == "--cwd") {
        let value = args.get(1)?;
        if value.is_empty() || value.starts_with('-') {
            return None;
        }
        directory = Some(value.clone());
        args = &args[2..];
    } else if let Some(value) = args.first().and_then(|v| v.strip_prefix("--cwd=")) {
        if value.is_empty() {
            return None;
        }
        directory = Some(value.to_owned());
        args = &args[1..];
    }
    if name == "bunx" {
        directory.as_ref()?;
    } else {
        if args.first()?.as_str() != "x" {
            return None;
        }
        args = &args[1..];
    }
    if args.first().is_some_and(|v| v == "--no-install") {
        args = &args[1..];
    }
    let (tool, tail) = runner_tail(args)?;
    Some((directory, tool, tail))
}

/// True when `arguments` name a contained Node test runner and a call that
/// runs once. Vitest needs the `run` verb that takes it out of watch mode;
/// Jest has no verb and runs once unless the call asks it to watch.
pub(crate) fn contained_runner_call(arguments: &[String]) -> bool {
    matches!(arguments, [tool, rest @ ..]
        if (tool == "vitest" && rest.first().is_some_and(|value| value == "run"))
            || (tool == "jest" && jest_contained_call(rest)))
}

/// True when a Jest call both finishes on its own and takes everything it
/// loads from the workspace.
pub(crate) fn jest_contained_call(arguments: &[String]) -> bool {
    jest_runs_once(arguments) && jest_reads_its_own_workspace(arguments)
}

/// A watching Jest run never finishes inside the sink, so only a call that
/// asks for no watch is contained. Jest reads its options through yargs, which
/// takes a kebab spelling of every camelCase name, so the name is read with
/// its separators removed. Watch mode has no short spelling: `-w` is Jest's
/// `--maxWorkers`, and `--watchman` names the file crawler, not the mode.
pub(crate) fn jest_runs_once(arguments: &[String]) -> bool {
    !arguments
        .iter()
        .any(|argument| matches!(option_name(argument).as_str(), "watch" | "watchall"))
}

/// The option an argument names, lowercased and without its separators or its
/// value, so `--watch-all=false` and `--watchAll` both read as `watchall`. An
/// argument that is not a long option names nothing.
fn option_name(argument: &str) -> String {
    let Some(flag) = argument.strip_prefix("--") else {
        return String::new();
    };
    let name = flag.split_once('=').map_or(flag, |(name, _)| name);
    name.chars()
        .filter(|character| *character != '-' && *character != '_')
        .flat_map(char::to_lowercase)
        .collect()
}

/// Jest loads its config, transforms, reporters, environment and test runner
/// from option values, so any of them can name a module. The workspace's own
/// files are what the read-only sandbox was admitted for; a value that leaves
/// it would run code the admission never covered. This screen reads every
/// argument rather than a list of the options that take a module, because a
/// Jest release adds options faster than the list would follow.
pub(crate) fn jest_reads_its_own_workspace(arguments: &[String]) -> bool {
    !arguments
        .iter()
        .any(|argument| leaves_the_workspace(argument))
}

/// Whether any part of an argument names a path outside the workspace. Jest
/// reads its options through yargs-parser, which takes a value joined with
/// `=`, attached straight to a short alias (`-c/etc/jest.config.js`), or
/// spelled as inline JSON (`--config '{"setupFiles":["/tmp/x.js"]}'`), so the
/// argument is screened whole and in pieces rather than as one path. Short
/// aliases also group: yargs-parser walks the group a letter at a time and
/// hands the rest of it to whichever letter a non-word character follows, so
/// `-ic/etc/jest.config.js` is `--runInBand --config /etc/jest.config.js`.
/// Which letter takes the value is yargs-parser's to decide, so every tail of
/// the group is screened rather than only the one after the first letter.
fn leaves_the_workspace(argument: &str) -> bool {
    // Jest reads an inline `--config` value with `JSON.parse`, which turns a
    // `\uXXXX` escape into its character after this screen has looked at the
    // raw text: `a/\u002e\u002e/etc/x.js` is `a/../etc/x.js` by the time Jest
    // resolves it. Screening the decoded form would mean parsing the argument
    // as Jest will, so a quoted argument carrying such an escape goes to
    // review instead. Review is where an ordinary call ends up anyway.
    if argument.contains('"') && argument.contains("\\u") {
        return true;
    }
    let group = argument
        .strip_prefix('-')
        .filter(|rest| !rest.starts_with('-'))
        .unwrap_or_default();
    let tails = group
        .char_indices()
        .skip(1)
        .map(|(index, _)| &group[index..]);
    std::iter::once(argument)
        .chain(tails)
        .chain(argument.split(|character: char| {
            character.is_whitespace() || "\"',:;=[]{}".contains(character)
        }))
        .any(path_leaves_the_workspace)
}

/// True when a value names a path this workspace does not hold: an absolute
/// path, a home-relative one, or a relative path that climbs out.
fn path_leaves_the_workspace(value: &str) -> bool {
    let value = value.replace('\\', "/");
    let bytes = value.as_bytes();
    let windows_root =
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/';
    value.starts_with('/')
        || value.starts_with("~/")
        || value == "~"
        || windows_root
        || value.split('/').any(|segment| segment == "..")
}

/// The runner a contained call names, with the arguments the sink hands it.
fn runner_tail(arguments: &[String]) -> Option<(&'static str, Vec<String>)> {
    let [tool, rest @ ..] = arguments else {
        return None;
    };
    contained_runner_call(arguments).then(|| {
        (
            if tool == "jest" { "jest" } else { "vitest" },
            rest.to_vec(),
        )
    })
}

/// The same, as the error the sink reports. A call that names a contained
/// runner but asks it to keep running is a verb problem, not an unknown
/// command, so it keeps the narrower message.
fn runner_tail_or_error(
    arguments: &[String],
) -> Result<(&'static str, Vec<String>), RestrictedPytestError> {
    match runner_tail(arguments) {
        Some(found) => Ok(found),
        None => match arguments.first().map(String::as_str) {
            Some("vitest") => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected Vitest requires direct run argv.",
            )),
            Some("jest") if !jest_runs_once(&arguments[1..]) => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected Jest requires a run that does not watch.",
            )),
            Some("jest") => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected Jest reads its configuration and modules from this workspace.",
            )),
            _ => invalid_vitest(),
        },
    }
}

/// pnpm options that change only what the run prints. `--stream`,
/// `--aggregate-output` and `--use-stderr` say where the lines go rather than
/// which packages produce them, so they are here with `--silent` and the
/// colour pair. Every option that chooses packages — `-r`, `--recursive`,
/// `--filter`, `-F`, `--filter-prod`, `--parallel`,
/// `--workspace-concurrency` — is absent, along with the options that move
/// the directory or the registry.
const PNPM_REPORTING_FLAGS: &[&str] = &[
    "--silent",
    "-s",
    "--color",
    "--no-color",
    "--stream",
    "--aggregate-output",
    "--use-stderr",
];

/// pnpm reporting options that take a value, in either spelling.
const PNPM_REPORTING_VALUES: &[&str] = &["--reporter", "--loglevel"];

/// npm's output options. The workspace options (`--workspace`, `-w`,
/// `--workspaces`, `--ws`) are absent because they choose which packages the
/// run reaches, and `--prefix` and `-C` are absent because they move the
/// directory it runs in; both are read where a directory or a package set is
/// decided rather than peeled here.
const NPM_REPORTING_FLAGS: &[&str] = &[
    "--silent",
    "-s",
    "--quiet",
    "--color",
    "--no-color",
    "--verbose",
    "--no-progress",
    "--no-update-notifier",
    "--timing",
    "--no-timing",
    "-d",
    "-dd",
    "-ddd",
];

/// npm's one reporting option that takes a value.
const NPM_REPORTING_VALUES: &[&str] = &["--loglevel"];

/// yarn's output options. yarn classic chooses packages with a `workspace`
/// verb rather than an option, so there is no fan-out spelling to exclude.
const YARN_REPORTING_FLAGS: &[&str] = &[
    "--silent",
    "-s",
    "--no-progress",
    "--non-interactive",
    "--no-color",
    "--verbose",
];

/// `arguments` with the leading npm, pnpm or yarn options that only change
/// what the run prints removed, so the `exec` behind them is read as the verb it
/// is. A reporting option names no package and moves no directory, so
/// `pnpm --silent exec tsc` runs the same local bin `pnpm exec tsc` does.
///
/// A value option whose value is written separately eats the next word, so
/// `pnpm --reporter exec tsc` consumes `exec` and leaves `tsc`, which is not
/// a verb and keeps the review. That is the right answer: pnpm reads that
/// line the same way.
pub(crate) fn manager_reporting_options_peeled<'a>(
    manager: &str,
    mut arguments: &'a [String],
) -> &'a [String] {
    let (flags, values): (&[&str], &[&str]) = match manager {
        "npm" => (NPM_REPORTING_FLAGS, NPM_REPORTING_VALUES),
        "pnpm" => (PNPM_REPORTING_FLAGS, PNPM_REPORTING_VALUES),
        "yarn" => (YARN_REPORTING_FLAGS, &[]),
        _ => return arguments,
    };
    while let [option, tail @ ..] = arguments {
        if flags.contains(&option.as_str()) {
            arguments = tail;
            continue;
        }
        let (name, written_inline) = match option.split_once('=') {
            Some((name, _)) => (name, true),
            None => (option.as_str(), false),
        };
        if !values.contains(&name) {
            break;
        }
        arguments = match (written_inline, tail) {
            (true, tail) => tail,
            (false, [value, rest @ ..]) if !value.starts_with('-') => rest,
            (false, _) => break,
        };
    }
    arguments
}

/// The arguments from the tool on, when `command` is a manager's bare `exec`
/// spelling of a local-bin run: `npm exec`, `npm x`, `pnpm exec` or
/// `yarn exec`, each with an optional `--`. The sink runs the project's own
/// tool, never the manager, so a manager option before the tool (`-c` runs a
/// shell, `-r`/`--filter` fan out) is not a local-bin run. The options that
/// only choose how much the manager prints are the exception, peeled by
/// [`manager_reporting_options_peeled`] before the verb is read.
fn manager_exec_tool(command: &[String]) -> Option<&[String]> {
    let manager = basename(command);
    let arguments = manager_reporting_options_peeled(manager, command.get(1..)?);
    let (npm, mut rest) = match (manager, arguments) {
        ("npm", [verb, rest @ ..]) if verb == "exec" || verb == "x" => (true, rest),
        ("pnpm" | "yarn", [verb, rest @ ..]) if verb == "exec" => (false, rest),
        _ => return None,
    };
    // `npm exec` answers the install prompt and chooses between the cache and
    // the registry before the tool, the way `npx` does. None of those options
    // names a package, so the tool behind them is still the workspace's own
    // one, and the route that admits the run has to read the same argv the
    // sink will. The pnpm and yarn options left after the reporting peel
    // choose which packages the run reaches, so they are not peeled here.
    if npm {
        while let [option, tail @ ..] = rest {
            if !npm_exec_inert_option(option) {
                break;
            }
            rest = tail;
        }
    }
    let rest = match rest {
        [separator, rest @ ..] if separator == "--" => rest,
        rest => rest,
    };
    rest.first().filter(|tool| !tool.starts_with('-'))?;
    Some(rest)
}

/// Whether an `npm exec` option names no package. The answer is read from the
/// table `npx` itself is parsed with, so the two spellings of one run cannot
/// drift apart. The separator is left out of the answer: it ends the options
/// rather than being one, and the peel above reads it on its own.
pub(crate) fn npm_exec_inert_option(option: &str) -> bool {
    crate::package_intent_parser::runner_options::local_execution_flags("npx")
        .iter()
        .any(|flag| *flag != "--" && *flag == option)
}

/// `npm exec vitest run ...`, `npm exec jest ...` and the other manager
/// `exec` spellings, as the runner and the arguments the sink hands it.
fn manager_exec_runner(command: &[String]) -> Option<(&'static str, Vec<String>)> {
    manager_exec_tool(command).and_then(runner_tail)
}

pub fn vitest_arguments(command: &[String]) -> Result<Vec<String>, RestrictedPytestError> {
    contained_runner_invocation(command).map(|(_, arguments)| arguments)
}

/// The contained Node test runner a call names, with the arguments the sink
/// hands it. Vitest keeps its `run` verb; Jest's tail starts at its first
/// argument.
pub fn contained_runner_invocation(
    command: &[String],
) -> Result<(&'static str, Vec<String>), RestrictedPytestError> {
    let argv = normalized_command(command)?;
    let name = basename(&argv);
    let runtime = node_runtime_args(&argv)?;
    let invocation = bun_runner_invocation(&argv);
    let call: Vec<String> =
        if let Some((_, tool, tail)) = invocation.filter(|_| matches!(name, "bun" | "bunx")) {
            std::iter::once(tool.to_owned()).chain(tail).collect()
        } else if matches!(name, "bunx" | "npx") {
            let mut args = &argv[1..];
            if args.first().is_some_and(|v| v == "--no-install") {
                args = &args[1..];
            }
            args.to_vec()
        } else if let Some(args) = manager_exec_tool(&argv) {
            args.to_vec()
        } else if matches!(name, "vitest" | "jest") {
            let mut call = vec![name.to_owned()];
            call.extend_from_slice(&argv[1..]);
            call
        } else if matches!(name, "node" | "nodejs") {
            let args = &argv[1 + runtime.len()..];
            let entry = args
                .first()
                .map(|value| value.replace('\\', "/"))
                .unwrap_or_default();
            let tool = if local_vitest_entry(&entry) {
                "vitest"
            } else if local_package_entry(&entry, "jest/bin/jest.js") {
                "jest"
            } else {
                return invalid_vitest();
            };
            let mut call = vec![tool.to_owned()];
            call.extend_from_slice(&args[1..]);
            call
        } else {
            return invalid_vitest();
        };
    let (tool, args) = runner_tail_or_error(&call)?;
    if args
        .iter()
        .any(|v| matches!(v.as_str(), ";" | "&&" | "||" | "|" | "|&" | "&"))
    {
        return Err(RestrictedPytestError::new(
            VITEST_INVALID,
            "Protected Vitest requires direct run argv.",
        ));
    }
    Ok((tool, args))
}

fn invalid_vitest<T>() -> Result<T, RestrictedPytestError> {
    Err(RestrictedPytestError::new(
        VITEST_INVALID,
        "Only local Vitest run is supported.",
    ))
}

/// The command the pre-tool pass answered for, or null when the call is its
/// own answer: a trailing group's command list, an activation's target, or
/// both. A sink that plans the call again has to plan the text the pre-tool
/// pass answered for, or it refuses the work that answer already admitted.
fn contained_target(input: &Value) -> Value {
    let text = input
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let context = crate::pretool::PathContext {
        home_dir: input.get("home").and_then(Value::as_str),
        cwd: input.get("cwd").and_then(Value::as_str),
        ..Default::default()
    };
    crate::pretool::generic::contained_target(text, context).map_or(Value::Null, Value::String)
}

/// The words a manifest script spells, read with the lexer that reads it in
/// `package_script_route`.
///
/// Splitting a script into the words a run will execute is a reading of a
/// command, so it belongs here rather than in the sink. The route already
/// reads the manifest's `lint` script with `PLAIN_LEXER` to admit `npm run
/// lint`; the sink read the same text a second time with Python's `shlex`.
/// Two readings of one script can part — this lexer leaves a backslash alone
/// where the platform spells paths with it, `shlex` always escapes — and the
/// words a run executes have to be the words that were read.
fn script_words(input: &Value) -> Result<Vec<String>, RestrictedPytestError> {
    let script = input.get("script").and_then(Value::as_str).ok_or_else(|| {
        RestrictedPytestError::new(
            "node_tool_invalid_command",
            "The requested local script is unavailable.",
        )
    })?;
    split_with(PLAIN_LEXER, script).map_err(|_| {
        RestrictedPytestError::new(
            "node_tool_invalid_command",
            "The local script could not be parsed.",
        )
    })
}

/// The words a contained command spells, read with the lexer that read it
/// when the command was admitted.
///
/// `pretool` lexes the hook's command text with `PLAIN_LEXER` to decide the
/// run is contained; the sink then read that same text a second time with
/// Python's `shlex` to find the prefix it peels and the program it plans.
/// Two readings of one command can part — this lexer leaves a backslash alone
/// where the platform spells paths with it, `shlex` always escapes — so the
/// receipt the sink draws has to be drawn over the words authority read.
fn command_words(input: &Value) -> Result<Vec<String>, RestrictedPytestError> {
    let text = input
        .get("command_text")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            RestrictedPytestError::new(
                "pytest_restricted_invalid_command",
                "Invalid restricted execution request.",
            )
        })?;
    split_with(PLAIN_LEXER, text).map_err(|_| {
        RestrictedPytestError::new(
            "pytest_restricted_invalid_command",
            "Invalid restricted execution request.",
        )
    })
}

/// The absolute words a command spells, read with the lexer that knows where
/// one command in the text ends and the next begins.
///
/// A workspace plan may carry a read root for a script that lives outside the
/// workspace, and that grant is admitted only when the command names the file.
/// Deciding whether it does is a reading of the same text this runtime
/// admitted: `python3 /tmp/a.py;echo ok` names `/tmp/a.py`, while `python3
/// /tmp/a.py#x` names a file of its own and no grant. Reading it a second time
/// in Python is a second grammar over a command authority has already read.
fn command_absolute_words(input: &Value) -> Result<Vec<String>, RestrictedPytestError> {
    let text = input
        .get("command_text")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            RestrictedPytestError::new(
                "pytest_restricted_invalid_command",
                "Invalid restricted execution request.",
            )
        })?;
    let words = split_with(STRICT_LEXER, text).map_err(|_| {
        RestrictedPytestError::new(
            "pytest_restricted_invalid_command",
            "Invalid restricted execution request.",
        )
    })?;
    Ok(words
        .into_iter()
        .filter(|word| word.starts_with('/'))
        .collect())
}

pub fn evaluate(operation: &str, input: &Value) -> Option<Value> {
    if operation == "contained_target" {
        return Some(json!({ "value": contained_target(input) }));
    }
    if operation == "command_absolute_words" {
        return Some(match command_absolute_words(input) {
            Ok(words) => json!({ "value": words }),
            Err(error) => crate::restricted_command::error_reply(error),
        });
    }
    if operation == "command_words" {
        return Some(match command_words(input) {
            Ok(words) => json!({ "value": words }),
            Err(error) => crate::restricted_command::error_reply(error),
        });
    }
    if operation == "script_words" {
        return Some(match script_words(input) {
            Ok(words) => json!({ "value": words }),
            Err(error) => crate::restricted_command::error_reply(error),
        });
    }
    if !matches!(
        operation,
        "node_runtime_args"
            | "python_runtime_args"
            | "inline_eval"
            | "bun_vitest_invocation"
            | "tsx_test_invocation"
            | "vitest_arguments"
            | "contained_kind"
            | "command_prefix_split"
            | "run_prefix_peel"
            | "node_tool_route"
            | "pytest_command"
            | "package_test_resolve"
    ) {
        return None;
    }
    let command = input.get("command").cloned().unwrap_or_else(|| json!([]));
    let Ok(command) = serde_json::from_value::<Vec<String>>(command) else {
        return Some(crate::restricted_command::error_reply(
            RestrictedPytestError::new(
                "pytest_restricted_invalid_command",
                "Invalid restricted execution request.",
            ),
        ));
    };
    let result = match operation {
        "node_runtime_args" => node_runtime_args(&command).map(|v| json!(v)),
        "python_runtime_args" => Ok(json!(python_runtime_args(&command))),
        "inline_eval" => inline_eval(&command).map(|v| json!(v)),
        "bun_vitest_invocation" => Ok(json!(bun_vitest_invocation(&command))),
        "tsx_test_invocation" => tsx_test_invocation(&command).map(|value| json!(value)),
        "vitest_arguments" => vitest_arguments(&command).map(|v| json!(v)),
        "contained_kind" => contained_kind(&command),
        "node_tool_route" => crate::contained_node_tool::route_request(input, &command),
        "pytest_command" => Ok(json!(crate::pytest_argv::command_targets_pytest(&command))),
        "package_test_resolve" => crate::contained_package_test::resolve(
            &command,
            input.get("scripts").and_then(Value::as_object),
        )
        .map(|value| json!(value)),
        "run_prefix_peel" => {
            let (core, seconds) = crate::contained_run_prefix::run_prefix_peel(&command);
            Ok(json!({ "core": core, "seconds": seconds }))
        }
        "command_prefix_split" => {
            let drop_data = input
                .get("drop_data")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let (core_index, assignments, dropped_data) =
                crate::contained_prefix::command_prefix_split(&command, drop_data);
            let assignments: Vec<Value> = assignments
                .into_iter()
                .map(|(name, value)| json!([name, value]))
                .collect();
            Ok(json!({
                "core_index": core_index,
                "assignments": assignments,
                "dropped_data": dropped_data,
            }))
        }
        _ => unreachable!(),
    };
    Some(match result {
        Ok(value) => json!({"value":value}),
        Err(error) => crate::restricted_command::error_reply(error),
    })
}

fn contained_kind(command: &[String]) -> Result<Value, RestrictedPytestError> {
    let inline = inline_eval(command)?;
    let name = basename(command);
    let runtime = if matches!(name, "node" | "nodejs") {
        node_runtime_args(command)?
    } else {
        vec![]
    };
    let index = 1 + runtime.len();
    let node_test =
        command.get(index).is_some_and(|v| v == "--test") && matches!(name, "node" | "nodejs");
    let bun = bun_vitest_invocation(command);
    let entries = command.iter().skip(1).take(2);
    let vitest = !command.is_empty()
        && (matches!(name, "bunx" | "npx" | "vitest" | "jest")
            || manager_exec_runner(command).is_some()
            || bun.is_some()
            || tsx_test_invocation(command)?.is_some()
            || (matches!(name, "node" | "nodejs")
                && entries.clone().any(|v| {
                    let entry = v.replace('\\', "/");
                    local_vitest_entry(&entry) || local_package_entry(&entry, "jest/bin/jest.js")
                })));
    let node_tool = bun.is_none()
        && manager_exec_runner(command).is_none()
        && !command.is_empty()
        && (matches!(
            name,
            "eslint" | "tsc" | "vite" | "prettier" | "bun" | "npm" | "pnpm" | "yarn"
        ) || (matches!(name, "bunx" | "npx")
            && entries
                .clone()
                .any(|v| matches!(v.as_str(), "eslint" | "tsc" | "vite" | "prettier")))
            || (matches!(name, "node" | "nodejs")
                && entries.clone().any(|v| {
                    [
                        "eslint/bin/eslint.js",
                        "typescript/bin/tsc",
                        "vite/bin/vite.js",
                        "prettier/bin/prettier.cjs",
                        "prettier/bin-prettier.js",
                    ]
                    .iter()
                    .any(|entry| local_package_entry(v, entry))
                })));
    // The package-test alias travels with the other kinds so the sink reads
    // every route a command can take in one answer, and an ordinary contained
    // run never pays for a second reading to learn it is not an alias.
    Ok(json!({
        "inline_eval": inline,
        "node_test": node_test,
        "vitest": vitest,
        "git": name == "git",
        "node_tool": node_tool,
        "package_test": crate::contained_package_test::is_package_test(command),
    }))
}
