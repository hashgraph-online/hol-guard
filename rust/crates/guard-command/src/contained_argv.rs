//! Portable bounded argv admission for contained Node, Vitest and inline runs.
#[cfg(test)]
#[path = "contained_argv_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "contained_argv_tsx_tests.rs"]
mod tsx_tests;
use crate::contained_node_tool::{entry_tool, local_bin_entry, local_package_entry};
use crate::restricted_command::{normalized_command, RestrictedPytestError};
use crate::sfrs_shlex::{split_with, PLAIN_LEXER, STRICT_LEXER};
use regex::Regex;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::LazyLock;

const NODE_INVALID: &str = "node_test_restricted_invalid_command";
const VITEST_INVALID: &str = "vitest_restricted_invalid_command";

/// Vitest's installed entry points. `vitest.mjs` is the package's declared
/// `bin` shim, `dist/cli.js` is the module that shim imports, and
/// `node_modules/.bin/vitest` is the link the installer writes to the first
/// of them, so every spelling starts the project's own installed runner.
pub(crate) fn local_vitest_entry(argument: &str) -> bool {
    local_package_entry(argument, "vitest/vitest.mjs")
        || local_package_entry(argument, "vitest/dist/cli.js")
        || local_bin_entry(argument, "vitest")
}

/// Mocha's installed entry points. `bin/mocha.js` is the package's declared
/// `bin` shim from Mocha 10 on; Mocha 8 and 9 publish the same shim without
/// the extension. Both name the installed package's own entry, and the sink
/// runs whichever of them this workspace holds, so reading only the newer
/// spelling would send a working `node node_modules/mocha/bin/mocha` to
/// review while the `npx mocha` beside it runs. The installer's link to that
/// shim names the same run.
pub(crate) fn local_mocha_entry(argument: &str) -> bool {
    local_package_entry(argument, "mocha/bin/mocha.js")
        || local_package_entry(argument, "mocha/bin/mocha")
        || local_bin_entry(argument, "mocha")
}

/// AVA's installed entry points. AVA 6 declares `entrypoints/cli.js`, AVA 4
/// and 5 published the same entry as `entrypoints/cli.mjs`, and AVA 3 kept it
/// at `cli.js`. The sink runs whichever of them this workspace holds, so
/// reading only the current spelling would send a working
/// `node node_modules/ava/entrypoints/cli.mjs` to review while the `npx ava`
/// beside it runs. The installer's link to that entry names the same run.
pub(crate) fn local_ava_entry(argument: &str) -> bool {
    local_package_entry(argument, "ava/entrypoints/cli.js")
        || local_package_entry(argument, "ava/entrypoints/cli.mjs")
        || local_package_entry(argument, "ava/cli.js")
        || local_bin_entry(argument, "ava")
}

/// Jest's installed entry point, and the link its installer writes beside it.
/// `jest-cli` publishes the executable Jest's own `bin` field points at, and
/// `node_modules/.bin/jest` is the link to it, so a call that hands either to
/// a runtime starts this workspace's installed Jest.
pub(crate) fn local_jest_entry(argument: &str) -> bool {
    local_package_entry(argument, "jest/bin/jest.js") || local_bin_entry(argument, "jest")
}

/// Jasmine's installed entry point, and the link its installer writes beside
/// it. `bin/jasmine.js` is the module `jasmine-npm` has declared as its `bin`
/// since Jasmine 3, so one spelling answers for every release a workspace is
/// likely to hold.
pub(crate) fn local_jasmine_entry(argument: &str) -> bool {
    local_package_entry(argument, "jasmine/bin/jasmine.js") || local_bin_entry(argument, "jasmine")
}

/// QUnit's installed entry point, and the link its installer writes beside
/// it. `bin/qunit.js` is the module QUnit declares as its `bin` from QUnit 2
/// on, so it names the installed runner at every release that ships a CLI.
pub(crate) fn local_qunit_entry(argument: &str) -> bool {
    local_package_entry(argument, "qunit/bin/qunit.js") || local_bin_entry(argument, "qunit")
}

/// uvu's installed entry point, and the link its installer writes beside it.
/// uvu declares `bin.js` at the package root rather than under a `bin`
/// directory, and has published it there since 0.3.
pub(crate) fn local_uvu_entry(argument: &str) -> bool {
    local_package_entry(argument, "uvu/bin.js") || local_bin_entry(argument, "uvu")
}

/// tape's installed entry point, and the link its installer writes beside it.
/// tape declares `bin/tape` as its `bin`, an extensionless file it has
/// shipped at that path since 4.0.
pub(crate) fn local_tape_entry(argument: &str) -> bool {
    local_package_entry(argument, "tape/bin/tape") || local_bin_entry(argument, "tape")
}

/// tsd's installed entry point, and the link its installer writes beside it.
/// tsd compiles its TypeScript CLI to `dist/cli.js` and declares that file as
/// its `bin`.
pub(crate) fn local_tsd_entry(argument: &str) -> bool {
    local_package_entry(argument, "tsd/dist/cli.js") || local_bin_entry(argument, "tsd")
}

/// tap's installed entry points. tap 21 declares `dist/esm/run.mjs`; tap 16
/// through 20 published the same entry as `bin/run.js`. The sink runs
/// whichever of them this workspace holds, so reading only the current
/// spelling would send a working `node node_modules/tap/bin/run.js` to review
/// while the `npx tap` beside it runs. The installer's link to that entry
/// names the same run.
pub(crate) fn local_tap_entry(argument: &str) -> bool {
    local_package_entry(argument, "tap/dist/esm/run.mjs")
        || local_package_entry(argument, "tap/bin/run.js")
        || local_bin_entry(argument, "tap")
}

/// borp's installed entry point, and the link its installer writes beside it.
/// borp declares `borp.js` at the package root rather than under a `bin`
/// directory, and has published it there since 0.1.
pub(crate) fn local_borp_entry(argument: &str) -> bool {
    local_package_entry(argument, "borp/borp.js") || local_bin_entry(argument, "borp")
}

/// poku's installed entry point, and the link its installer writes beside it.
/// poku declares `lib/bin/index.js`, the compiled CLI its package ships.
pub(crate) fn local_poku_entry(argument: &str) -> bool {
    local_package_entry(argument, "poku/lib/bin/index.js") || local_bin_entry(argument, "poku")
}

/// lab's installed entry point, and the link its installer writes beside it.
/// lab is published under a scope, so its entry is spelled with the scope
/// directory the installer writes it into; the extensionless `bin/lab` is the
/// module `@hapi/lab` has declared since lab 20.
pub(crate) fn local_lab_entry(argument: &str) -> bool {
    local_package_entry(argument, "@hapi/lab/bin/lab") || local_bin_entry(argument, "lab")
}

/// cucumber-js's installed entry point, and the link its installer writes
/// beside it. The package is scoped, so the entry it declares lands at
/// `node_modules/@cucumber/cucumber/bin/cucumber.js`, while the link takes
/// the executable's own name, `cucumber-js`. That file is a shim that
/// requires the package's `lib/cli/run.js`, and the package has declared it
/// at that path since cucumber-js 8.
pub(crate) fn local_cucumber_entry(argument: &str) -> bool {
    local_package_entry(argument, "@cucumber/cucumber/bin/cucumber.js")
        || local_bin_entry(argument, "cucumber-js")
}

/// Whether a word names one of those installed entry points. A runtime handed
/// this path starts the workspace's own runner, whichever of them it is.
pub(crate) fn local_runner_entry(argument: &str) -> bool {
    let entry = argument.replace('\\', "/");
    local_vitest_entry(&entry)
        || local_jest_entry(&entry)
        || local_mocha_entry(&entry)
        || local_ava_entry(&entry)
        || local_jasmine_entry(&entry)
        || local_qunit_entry(&entry)
        || local_uvu_entry(&entry)
        || local_tape_entry(&entry)
        || local_tsd_entry(&entry)
        || local_tap_entry(&entry)
        || local_borp_entry(&entry)
        || local_poku_entry(&entry)
        || local_lab_entry(&entry)
        || local_cucumber_entry(&entry)
}

/// Whether a call hands Bun one of those entry points as the file to run.
///
/// Bun executes a JavaScript entry the way Node does, so `bun
/// node_modules/vitest/vitest.mjs run` is the run `node` spells beside it, and
/// the sink relaunches the resolved entry under Node for either spelling. The
/// `bun x` wrapper and a `--cwd` prefix name no entry at this position, so
/// they are read by the routes that already carry them rather than here.
pub(crate) fn bun_runner_entry_launch(command: &[String]) -> bool {
    basename(command) == "bun" && command.get(1).is_some_and(|word| local_runner_entry(word))
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

/// The path hygiene every workspace-relative operand has to pass: a relative
/// path with no option spelling, no shell metacharacter and no walk out of the
/// tree it was admitted for.
pub(crate) fn workspace_script_path(script: &str) -> bool {
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

/// A tsx test run split at its script.
struct TsxTestParts<'a> {
    /// The Node test-runner flags ahead of the script.
    flags: &'a [String],
    /// The first path the run names, when it names one. In test-runner mode
    /// Node discovers its own files from the working directory, so a run that
    /// names nothing is still a test run.
    script: Option<&'a String>,
    /// The arguments the script is passed, or the further paths the test
    /// runner loads.
    arguments: &'a [String],
}

fn tsx_test_parts(command: &[String]) -> Result<Option<TsxTestParts<'_>>, RestrictedPytestError> {
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
    let (flags, rest) = args.split_at(tsx_runner_flag_count(args));
    if tsx_runner_test_mode(flags) {
        // Here Node is its own test runner and every remaining word is a path
        // it loads, a directory it resolves, or nothing at all when it
        // discovers the files itself. The leaf names a project gives its specs are not
        // the boundary on that shape -- the workspace is, and the sink
        // resolves each path inside it before the run starts. `node --test`
        // takes the same paths today through the sibling read-only profile,
        // and takes them without resolving them at all, so reading them here
        // admits nothing that was not already contained.
        if !rest.iter().all(|value| workspace_script_path(value)) {
            return Ok(None);
        }
        return Ok(Some(TsxTestParts {
            flags,
            script: rest.first(),
            arguments: rest.get(1..).unwrap_or_default(),
        }));
    }
    // Without those flags the first word is a script Node runs and the rest is
    // its argv, so the leaf still has to name a test file.
    Ok(rest
        .first()
        .filter(|value| named_test_script(value, true))
        .map(|script| TsxTestParts {
            flags,
            script: Some(script),
            arguments: &rest[1..],
        }))
}

/// The script a tsx run names, if it names one, and that script's own argv.
pub type TsxTestInvocation = (Option<String>, Vec<String>);

/// The test script a tsx run names, and the arguments the script is passed.
pub fn tsx_test_invocation(
    command: &[String],
) -> Result<Option<TsxTestInvocation>, RestrictedPytestError> {
    Ok(tsx_test_parts(command)?.map(|parts| (parts.script.cloned(), parts.arguments.to_vec())))
}

/// The Node test-runner flags a tsx run carries, which the sink re-emits in
/// front of the script. Node reads them nowhere else: behind the script they
/// are the script's own arguments, and the run is no longer a test run.
pub fn tsx_test_runner_flags(command: &[String]) -> Result<Vec<String>, RestrictedPytestError> {
    Ok(tsx_test_parts(command)?.map_or_else(Vec::new, |parts| parts.flags.to_vec()))
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

#[path = "contained_argv_runner_calls.rs"]
mod runner_calls;
#[path = "contained_argv_single_pass_runners.rs"]
mod single_pass_runners;
pub(crate) use runner_calls::{
    ava_contained_call, ava_runs_once, bun_test_runs_once, bun_test_script_once,
    contained_runner_call, jest_contained_call, jest_runs_once, mocha_contained_call,
    mocha_runs_once, tsx_runner_flag_count, tsx_runner_test_mode, vitest_runs_once,
    workspace_test_script,
};
pub(crate) use single_pass_runners::{
    borp_contained_call, borp_runs_once, cucumber_contained_call, cucumber_prints_its_report,
    cucumber_runs_once, jasmine_contained_call, jasmine_runs_once, jasmine_sets_no_environment,
    lab_contained_call, lab_runs_once, poku_contained_call, poku_runs_once,
    poku_touches_nothing_else, qunit_contained_call, qunit_runs_once, tap_contained_call,
    tap_runs_tests_once, tap_sets_no_environment, tape_contained_call, tsd_contained_call,
    uvu_contained_call,
};

/// True when a command is Bun's own test runner taking one contained pass.
///
/// `bun test` runs Bun's runner, never the package `test` script, so the
/// package-test alias leaves it alone and it is read here as the direct run
/// it is. The Node test profile carries it: Bun reads files through the same
/// syscalls, and the runner needs nothing from outside the workspace.
pub fn bun_test_invocation(command: &[String]) -> bool {
    basename(command) == "bun"
        && command.get(1).is_some_and(|word| word == "test")
        && bun_test_runs_once(&command[2..])
}

/// True when a command is Bun running one of the workspace's own test files.
///
/// `bun math.test.ts` runs that file as a script. Bun does not start its test
/// runner for it, so the pass is not the runner's; it is that `bun test`
/// already loads this very file, under this very profile, as one of the test
/// files it discovers. Naming it reaches nothing the discovered run does not.
/// The Node test profile carries it for the same reason it carries `bun
/// test`: the runner reaches nothing outside the workspace.
pub fn bun_test_script_invocation(command: &[String]) -> bool {
    !command.is_empty() && basename(command) == "bun" && bun_test_script_once(&command[1..])
}

/// The runner a contained call names, with the arguments the sink hands it.
fn runner_tail(arguments: &[String]) -> Option<(&'static str, Vec<String>)> {
    let [tool, rest @ ..] = arguments else {
        return None;
    };
    contained_runner_call(arguments).then(|| {
        (
            match tool.as_str() {
                "jest" => "jest",
                "mocha" => "mocha",
                "ava" => "ava",
                "jasmine" => "jasmine",
                "qunit" => "qunit",
                "uvu" => "uvu",
                "tape" => "tape",
                "tsd" => "tsd",
                "tap" => "tap",
                "borp" => "borp",
                "poku" => "poku",
                "lab" => "lab",
                "cucumber-js" => "cucumber-js",
                _ => "vitest",
            },
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
            Some("mocha") if !mocha_runs_once(&arguments[1..]) => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected Mocha requires a run that does not watch.",
            )),
            Some("mocha") => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected Mocha reads its configuration and modules from this workspace.",
            )),
            Some("ava") if !ava_runs_once(&arguments[1..]) => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected AVA requires a run that does not watch.",
            )),
            Some("ava") => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected AVA reads its configuration and modules from this workspace.",
            )),
            Some("jasmine") if !jasmine_runs_once(&arguments[1..]) => {
                Err(RestrictedPytestError::new(
                    VITEST_INVALID,
                    "Protected Jasmine runs specs; it does not scaffold a project.",
                ))
            }
            Some("jasmine") if !jasmine_sets_no_environment(&arguments[1..]) => {
                Err(RestrictedPytestError::new(
                    VITEST_INVALID,
                    "Protected Jasmine takes its environment from the run, not from its arguments.",
                ))
            }
            Some("jasmine") => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected Jasmine reads its configuration and helpers from this workspace.",
            )),
            Some("qunit") if !qunit_runs_once(&arguments[1..]) => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected QUnit requires a run that does not watch.",
            )),
            Some("qunit") => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected QUnit reads its modules from this workspace.",
            )),
            Some("uvu") => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected uvu reads its modules from this workspace.",
            )),
            Some("tape") => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected tape reads its modules from this workspace.",
            )),
            Some("tsd") => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected tsd reads its types from this workspace.",
            )),
            Some("tap") if !tap_runs_tests_once(&arguments[1..]) => {
                Err(RestrictedPytestError::new(
                    VITEST_INVALID,
                    "Protected tap runs tests; it does not report, build or open a browser.",
                ))
            }
            Some("tap") if !tap_sets_no_environment(&arguments[1..]) => {
                Err(RestrictedPytestError::new(
                    VITEST_INVALID,
                    "Protected tap takes its environment from the run, not from its arguments.",
                ))
            }
            Some("tap") => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected tap reads its configuration and modules from this workspace.",
            )),
            Some("borp") if !borp_runs_once(&arguments[1..]) => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected borp requires a run that does not watch.",
            )),
            Some("borp") => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected borp reads its modules from this workspace.",
            )),
            Some("poku") if !poku_runs_once(&arguments[1..]) => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected poku requires a run that does not watch.",
            )),
            Some("poku") if !poku_touches_nothing_else(&arguments[1..]) => {
                Err(RestrictedPytestError::new(
                    VITEST_INVALID,
                    "Protected poku runs tests; it does not end processes or load an environment file.",
                ))
            }
            Some("poku") => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected poku reads its modules from this workspace.",
            )),
            Some("lab") if !lab_runs_once(&arguments[1..]) => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected lab runs tests; it does not start a debugger.",
            )),
            Some("lab") => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected lab reads its modules from this workspace.",
            )),
            Some("cucumber-js") if !cucumber_prints_its_report(&arguments[1..]) => {
                Err(RestrictedPytestError::new(
                    VITEST_INVALID,
                    "Protected cucumber-js prints its report here; it does not write it to a file.",
                ))
            }
            Some("cucumber-js") if !cucumber_runs_once(&arguments[1..]) => {
                Err(RestrictedPytestError::new(
                    VITEST_INVALID,
                    "Protected cucumber-js runs its features here; it does not publish the report.",
                ))
            }
            Some("cucumber-js") => Err(RestrictedPytestError::new(
                VITEST_INVALID,
                "Protected cucumber-js reads its features and support code from this workspace.",
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

/// Bun's one output option. `--bun` chooses the runtime the script runs on,
/// `--watch` and `--hot` keep the run alive, and `--filter` fans it out, so
/// none of them is peeled here.
const BUN_REPORTING_FLAGS: &[&str] = &["--silent"];

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
/// what the run prints removed, so the verb or script behind them is read as
/// the one it is. A reporting option names no package and moves no directory,
/// so `pnpm --silent exec tsc` runs the same local bin `pnpm exec tsc` does,
/// and `npm --silent test` runs the same script `npm test` does.
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
        "bun" => (BUN_REPORTING_FLAGS, &[]),
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

/// Whether `word` is the verb that runs a package script. npm and pnpm both
/// list `run-script` as an alias of `run`, and npm's table carries the two
/// transposed spellings `rum` and `urn` as well, so every one of them starts
/// the same script the same way. yarn and bun spell it `run` alone.
///
/// An alias runs exactly what the canonical spelling runs, so the containment
/// routes read them as one verb. Reading only `run` would send
/// `npm run-script lint` to review while the `npm run lint` beside it stays
/// quiet.
pub(crate) fn names_script_run_verb(manager: &str, word: &str) -> bool {
    let manager = program_name(manager);
    word == "run"
        || (matches!(manager, "npm" | "pnpm") && word == "run-script")
        || (manager == "npm" && matches!(word, "rum" | "urn"))
}

/// The script a bare verb names when the manager reads it as its own `test`
/// command. `t` and `tst` are documented aliases of `test` for npm and pnpm,
/// and both run the manifest's `test` entry, so the name this returns is the
/// key the sink looks up rather than the word the line spells.
///
/// Both managers resolve these in their command table, before any lookup
/// against the manifest's scripts, so a project that declares a script named
/// `t` cannot reach it this way either. yarn and bun have no such alias, and
/// pass a bare word straight to the manifest, so reading `t` as `test` for
/// them would run an entry the line never named.
pub(crate) fn aliased_test_script_name(manager: &str, word: &str) -> Option<&'static str> {
    (matches!(program_name(manager), "npm" | "pnpm") && matches!(word, "t" | "tst"))
        .then_some("test")
}

/// The arguments from the tool on, when `command` is a manager's spelling of
/// a local-bin run.
///
/// This is the reading the admission takes, not a second one beside it. The
/// sink plans the run the classifier read, and the classifier reads the kind
/// out of this answer, so a spelling the admission lets through as a
/// local-bin run has to reach the sink as that same run. Two readings of one
/// spelling diverge the moment either is widened: the admission answers with
/// a runner's reason while the classifier still answers with the manager's
/// kind, and the sink refuses the mismatch rather than running the command.
fn manager_exec_tool(command: &[String]) -> Option<&[String]> {
    crate::pretool::manager_local_bin_arguments(basename(command), command.get(1..)?)
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
        } else if matches!(
            name,
            "vitest"
                | "jest"
                | "mocha"
                | "ava"
                | "jasmine"
                | "qunit"
                | "uvu"
                | "tape"
                | "tsd"
                | "tap"
                | "borp"
                | "poku"
                | "lab"
                | "cucumber-js"
        ) {
            let mut call = vec![name.to_owned()];
            call.extend_from_slice(&argv[1..]);
            call
        } else if matches!(name, "node" | "nodejs") || bun_runner_entry_launch(&argv) {
            let args = &argv[1 + runtime.len()..];
            let entry = args
                .first()
                .map(|value| value.replace('\\', "/"))
                .unwrap_or_default();
            let tool = if local_vitest_entry(&entry) {
                "vitest"
            } else if local_jest_entry(&entry) {
                "jest"
            } else if local_mocha_entry(&entry) {
                "mocha"
            } else if local_ava_entry(&entry) {
                "ava"
            } else if local_jasmine_entry(&entry) {
                "jasmine"
            } else if local_qunit_entry(&entry) {
                "qunit"
            } else if local_uvu_entry(&entry) {
                "uvu"
            } else if local_tape_entry(&entry) {
                "tape"
            } else if local_tsd_entry(&entry) {
                "tsd"
            } else if local_tap_entry(&entry) {
                "tap"
            } else if local_borp_entry(&entry) {
                "borp"
            } else if local_poku_entry(&entry) {
                "poku"
            } else if local_lab_entry(&entry) {
                "lab"
            } else if local_cucumber_entry(&entry) {
                "cucumber-js"
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
///
/// A bounded inline shell such as `bash -ec 'pytest -q'` is read as the
/// script it holds, because that script is what the review read. The caller
/// re-authorizes the projected text on its own, so a script the review would
/// not contain still gets refused there.
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
    crate::pretool::generic::contained_target(text, context)
        .or_else(|| inline_shell_target(text))
        .map_or(Value::Null, Value::String)
}

/// The script a bounded inline shell runs, read the way the review reads it.
fn inline_shell_target(text: &str) -> Option<String> {
    crate::inline_shell_script_text(&crate::CommandModelRequestV1 {
        command: text.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "contained-target".into(),
    })
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
    let node_test_argv =
        command.get(index).is_some_and(|v| v == "--test") && matches!(name, "node" | "nodejs");
    let bun = bun_vitest_invocation(command);
    let bun_test = bun_test_invocation(command) || bun_test_script_invocation(command);
    let entries = command.iter().skip(1).take(2);
    let vitest = !command.is_empty()
        && (matches!(
            name,
            "bunx"
                | "npx"
                | "vitest"
                | "jest"
                | "mocha"
                | "ava"
                | "jasmine"
                | "qunit"
                | "uvu"
                | "tape"
                | "tsd"
                | "tap"
                | "borp"
                | "poku"
                | "lab"
                | "cucumber-js"
        ) || manager_exec_runner(command).is_some()
            || bun.is_some()
            || bun_runner_entry_launch(command)
            || tsx_test_invocation(command)?.is_some()
            || (matches!(name, "node" | "nodejs")
                && entries.clone().any(|v| {
                    let entry = v.replace('\\', "/");
                    local_vitest_entry(&entry)
                        || local_jest_entry(&entry)
                        || local_mocha_entry(&entry)
                        || local_ava_entry(&entry)
                        || local_jasmine_entry(&entry)
                        || local_qunit_entry(&entry)
                        || local_uvu_entry(&entry)
                        || local_tape_entry(&entry)
                        || local_tsd_entry(&entry)
                        || local_tap_entry(&entry)
                        || local_borp_entry(&entry)
                        || local_poku_entry(&entry)
                        || local_lab_entry(&entry)
                        || local_cucumber_entry(&entry)
                })));
    let node_tool = bun.is_none()
        && !bun_test
        && !bun_runner_entry_launch(command)
        && manager_exec_runner(command).is_none()
        && !command.is_empty()
        && (matches!(
            name,
            "eslint" | "tsc" | "vite" | "prettier" | "bun" | "npm" | "pnpm" | "yarn"
        ) || (matches!(name, "bunx" | "npx")
            && entries
                .clone()
                .any(|v| matches!(v.as_str(), "eslint" | "tsc" | "vite" | "prettier")))
            // The entry a `node` command names is read back to its tool
            // through the same table the route and the sink read, so a
            // spelling one of them admits cannot be a kind the others miss.
            || (matches!(name, "node" | "nodejs")
                && entries
                    .clone()
                    .any(|v| !entry_tool(&v.replace('\\', "/")).is_empty())));
    // The package-test alias travels with the other kinds so the sink reads
    // every route a command can take in one answer, and an ordinary contained
    // run never pays for a second reading to learn it is not an alias.
    Ok(json!({
        "inline_eval": inline,
        "node_test": node_test_argv || bun_test,
        "vitest": vitest,
        "git": name == "git",
        "node_tool": node_tool,
        "package_test": crate::contained_package_test::is_package_test(command),
    }))
}
