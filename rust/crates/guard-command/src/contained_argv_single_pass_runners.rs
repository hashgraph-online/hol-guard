//! Reading the Node test runners that take one pass by default.
//!
//! Vitest, Jest, Mocha and AVA each carry enough of their own parser to need
//! their own reading. The runners here do not. Jasmine, uvu, tape, tsd, tap
//! and lab have no watch mode at all, and QUnit's, borp's and poku's are a
//! single flag, so what these readings mostly name is the words that run
//! something other than the suite: scaffolding a project, copying example
//! files in, printing a report, opening a browser, setting the environment
//! the tests inherit, or watching. Everything else on their lines is an
//! option value or a spec file, and the shared workspace screen answers for
//! those the way it does for the other runners.

use super::runner_calls::{option_name, reads_its_own_workspace, short_options_carry_watch};

/// True when a Jasmine call both runs its specs once and takes everything it
/// loads from the workspace.
pub(crate) fn jasmine_contained_call(arguments: &[String]) -> bool {
    jasmine_runs_once(arguments)
        && jasmine_sets_no_environment(arguments)
        && reads_its_own_workspace(arguments)
}

/// True when no word on a Jasmine line sets an environment variable.
///
/// Before Jasmine reads a single option it walks the whole line and writes
/// every word that is not a long option and holds an `=` into `process.env`,
/// splitting it at the first `=`. So `NODE_OPTIONS=--import=data:...` is not
/// a spec file to this runner, it is the environment its workers inherit, and
/// the path screen cannot see it: neither half of such a word names a path at
/// all. A word that chooses what Node loads is the thing the workspace screen
/// exists to refuse, so these go to review whatever they carry.
pub(crate) fn jasmine_sets_no_environment(arguments: &[String]) -> bool {
    !arguments
        .iter()
        .any(|argument| !argument.starts_with("--") && argument.contains('='))
}

/// Jasmine has no watch mode, so the only words that stop a call being a test
/// run are the two commands that write into the project: `init` scaffolds a
/// configuration file, and `examples` copies example specs and sources in,
/// overwriting whatever stands where they land. Its other commands --
/// `help`, `version` and `enumerate` -- print and exit.
///
/// Jasmine takes its command by comparing every word on the line against its
/// command names rather than reading only the first, so a spec file named
/// `init` names the command too. This reading screens the word wherever it
/// stands, because that is where Jasmine reads it, `--` included: the
/// terminator is the option parser's, and the command match runs before it.
pub(crate) fn jasmine_runs_once(arguments: &[String]) -> bool {
    !arguments
        .iter()
        .any(|argument| matches!(argument.as_str(), "init" | "examples"))
}

/// True when a QUnit call both runs its tests once and takes everything it
/// loads from the workspace.
pub(crate) fn qunit_contained_call(arguments: &[String]) -> bool {
    qunit_runs_once(arguments) && reads_its_own_workspace(arguments)
}

/// QUnit runs once unless `--watch` is on the line, and it has no commands:
/// every other word is an option value or a file to run.
///
/// Its watch is read differently from Mocha's and AVA's. QUnit's CLI reads
/// Commander, which declares the option as a flag that takes no value, so a
/// `false` after it is not the option's value but another file to run --
/// `--watch false` watches. The name alone is therefore the answer here,
/// whether it stands bare, carries an `=` value, or rides in a short group,
/// which Commander walks one letter at a time the way the other parsers do.
pub(crate) fn qunit_runs_once(arguments: &[String]) -> bool {
    !names_a_watch(arguments)
}

/// Whether a word on the line names a watch, read the way a parser that
/// declares watch as a value-less flag reads it: the name alone decides,
/// whether it stands bare, carries an `=` value, or rides in a short group.
fn names_a_watch(arguments: &[String]) -> bool {
    arguments
        .iter()
        .any(|argument| short_options_carry_watch(argument) || option_name(argument) == "watch")
}

/// True when a uvu call takes everything it loads from the workspace.
///
/// uvu has no watch mode and no commands. Its line is a directory, a test
/// pattern and a few options, of which only `-C/--cwd` moves the run, and
/// that is a path the shared workspace screen already answers for. So a uvu
/// call that stays inside its workspace is a single pass over it, and there
/// is no second reading to make.
pub(crate) fn uvu_contained_call(arguments: &[String]) -> bool {
    reads_its_own_workspace(arguments)
}

/// True when a tape call takes everything it loads from the workspace.
///
/// tape's executable is a single pass by construction: it reads its line with
/// minimist, aliasing `-r` to `require` and `-i` to `ignore`, and then hands
/// every remaining operand to `require` as a path resolved against the
/// working directory. There is no watch flag, no command verb and nothing
/// that writes, so the only question a tape line raises is where its modules
/// come from, which the shared workspace screen already answers.
pub(crate) fn tape_contained_call(arguments: &[String]) -> bool {
    reads_its_own_workspace(arguments)
}

/// True when a tsd call takes everything it checks from the workspace.
///
/// tsd reads its line with meow -- `--typings`, `--files` and `--show-diff`,
/// nothing else -- and takes its first operand as the project directory to
/// check. It type-checks in process against the TypeScript compiler it ships
/// with, so it starts nothing, watches nothing and writes nothing: the paths
/// on its line are all it reaches, and the workspace screen answers for them.
pub(crate) fn tsd_contained_call(arguments: &[String]) -> bool {
    reads_its_own_workspace(arguments)
}

/// True when a borp call both runs its tests once and takes everything it
/// loads from the workspace.
pub(crate) fn borp_contained_call(arguments: &[String]) -> bool {
    borp_runs_once(arguments)
        && borp_writes_no_report(arguments)
        && reads_its_own_workspace(arguments)
}

/// True when no reporter on a borp line sends its output to a file.
///
/// borp spells a reporter as `--reporter`, or `-r`, and reads a colon in the
/// value as a file destination: `--reporter tap:results.txt` writes the run's
/// output to that path. The read-only route carries no write root, so the
/// report the caller asked for cannot be produced and the run fails on a
/// permission the admission never covered. `stdout` and `stderr` are the two
/// destinations that name a stream rather than a file, so they stay readable.
pub(crate) fn borp_writes_no_report(arguments: &[String]) -> bool {
    let mut expecting_reporter = false;
    for argument in arguments {
        if expecting_reporter {
            expecting_reporter = false;
            if reporter_names_a_file(argument) {
                return false;
            }
            continue;
        }
        if option_name(argument) == "reporter" || argument == "-r" {
            match argument.split_once('=') {
                Some((_, value)) => {
                    if reporter_names_a_file(value) {
                        return false;
                    }
                }
                None => expecting_reporter = true,
            }
            continue;
        }
        if let Some(value) = argument.strip_prefix("-r") {
            if !value.is_empty() && !value.starts_with('-') && reporter_names_a_file(value) {
                return false;
            }
        }
    }
    true
}

/// Whether a reporter value sends its output somewhere other than a stream.
fn reporter_names_a_file(value: &str) -> bool {
    value
        .rsplit_once(':')
        .is_some_and(|(_, destination)| !matches!(destination, "stdout" | "stderr"))
}

/// borp runs once unless a watch is named, and it has no commands: every
/// other word is an option value or a file to run.
///
/// Its line is read by Node's own `parseArgs`, where `watch` is declared a
/// boolean with the short alias `-w`. A boolean there never takes the next
/// word, and `--watch=false` is rejected rather than read as off, so the name
/// alone is the answer, exactly as it is for QUnit. `parseArgs` also walks a
/// short group one letter at a time, so `-wc` carries the watch too.
pub(crate) fn borp_runs_once(arguments: &[String]) -> bool {
    !names_a_watch(arguments)
}

/// True when a poku call runs its tests once, reaches nothing outside the
/// run, and takes everything it loads from the workspace.
pub(crate) fn poku_contained_call(arguments: &[String]) -> bool {
    poku_runs_once(arguments)
        && poku_touches_nothing_else(arguments)
        && reads_its_own_workspace(arguments)
}

/// poku runs once unless a watch is named.
///
/// poku reads its own line rather than a parser: it asks whether any word
/// *starts with* `--watch`, so `--watch=false` turns the watch on and
/// `--watchers` would too. The short `-w` is read the same way the other
/// runners' groups are. Both spellings are screened here because either one
/// leaves a run that never finishes inside the sink.
pub(crate) fn poku_runs_once(arguments: &[String]) -> bool {
    !arguments
        .iter()
        .any(|argument| short_options_carry_watch(argument) || poku_names(argument, "watch"))
}

/// True when no word on a poku line reaches past the test run.
///
/// poku carries options that do something other than run tests:
/// `--killPort`, `--killRange` and `--killPid` end processes the run never
/// started, `--envFile` loads a file of environment variables into the test
/// process, and `--denoAllow`/`--denoDeny` hand permissions straight to a
/// Deno runtime. None of those is a path the workspace screen can answer for
/// -- a port, a pid and a permission name are not paths at all -- so they are
/// named here. poku matches these by prefix and by case, so the screen does
/// the same.
pub(crate) fn poku_touches_nothing_else(arguments: &[String]) -> bool {
    const REACHING_OPTIONS: [&str; 6] = [
        "killPort",
        "killRange",
        "killPid",
        "envFile",
        "denoAllow",
        "denoDeny",
    ];
    !arguments.iter().any(|argument| {
        REACHING_OPTIONS
            .iter()
            .any(|option| poku_names(argument, option))
    })
}

/// Whether a word names a poku option. poku asks `startsWith` against the
/// option's own spelling, so the match is by prefix and case-sensitive: an
/// `=` value, a longer name and a trailing character all name the option.
fn poku_names(argument: &str, option: &str) -> bool {
    argument
        .strip_prefix("--")
        .is_some_and(|name| name.starts_with(option))
}

/// True when a lab call both runs its tests once and takes everything it
/// loads from the workspace.
pub(crate) fn lab_contained_call(arguments: &[String]) -> bool {
    lab_runs_once(arguments) && reads_its_own_workspace(arguments)
}

/// lab has no watch mode and no commands, so the words that stop a call
/// being a single read-only pass are the two debugger spellings and the
/// linter's fix pass. `--inspect` and `--inspect-brk` start the suite under
/// Node's debugger and hold the process open on a listening port, and
/// `--lint-fix` asks the linter to rewrite the sources it reads, which the
/// read-only route has no roots for. Its other options name a reporter, a
/// linter, a transform, an output file or a pattern, and those are paths the
/// shared workspace screen answers for.
pub(crate) fn lab_runs_once(arguments: &[String]) -> bool {
    !arguments.iter().any(|argument| {
        matches!(
            option_name(argument).as_str(),
            "inspect" | "inspectbrk" | "lintfix"
        )
    })
}

/// True when a tap call runs its tests once, sets no environment for them,
/// and takes everything it loads from the workspace.
pub(crate) fn tap_contained_call(arguments: &[String]) -> bool {
    tap_runs_tests_once(arguments)
        && tap_sets_no_environment(arguments)
        && reads_its_own_workspace(arguments)
}

/// What this reading names is the watch, the commands that do something
/// other than run the suite, and the options that leave the run.
///
/// tap declares `watch` as a flag with the short `-w`: it runs the suite once
/// and then keeps re-running it as files change, so the call never finishes
/// inside the sink. The name alone is the answer, as it is for borp and
/// QUnit, and a short group carries it the same way.
///
/// tap takes its command from the first positional word and falls back to
/// `run` when there is none, but telling the first positional from an
/// unmodelled option's value means reading tap's whole option table, which a
/// release changes faster than the reading would follow. So a command word is
/// screened wherever it stands, as Jasmine's is. A spec file is spelled as a
/// path rather than as the bare word `report` or `config`, so screening the
/// bare words costs an ordinary run nothing.
///
/// The options named here reach past the suite: `--node-arg` forwards
/// arguments to the Node that runs the tests, `--browser` names a program to
/// launch, and an HTML or lcov coverage report opens that browser on the
/// generated page. `--no-browser` is a different name under this screen, so
/// it stays readable.
pub(crate) fn tap_runs_tests_once(arguments: &[String]) -> bool {
    if names_a_watch(arguments) {
        return false;
    }
    const OTHER_COMMANDS: [&str; 12] = [
        "help",
        "versions",
        "version",
        "build",
        "report",
        "plugin",
        "list",
        "repl",
        "replay",
        "config",
        "debug",
        "node-options",
    ];
    let mut expecting_report = false;
    for argument in arguments {
        if expecting_report {
            expecting_report = false;
            if opens_a_browser(argument) {
                return false;
            }
            continue;
        }
        if OTHER_COMMANDS.contains(&argument.as_str()) {
            return false;
        }
        match option_name(argument).as_str() {
            "nodearg" | "browser" => return false,
            "coveragereport" => match argument.split_once('=') {
                Some((_, value)) => {
                    if opens_a_browser(value) {
                        return false;
                    }
                }
                None => expecting_report = true,
            },
            _ => {}
        }
    }
    true
}

/// Whether a coverage report names one tap opens a browser on. tap writes the
/// other formats to its output and stops there.
fn opens_a_browser(report: &str) -> bool {
    matches!(report, "html" | "html-spa" | "lcov")
}

/// True when no word on a tap line sets the environment its tests run in.
///
/// `--test-env` is written straight into the environment of the process that
/// runs the test files, so it chooses what Node loads there. Neither half of
/// a `NAME=value` pair names a path, so the workspace screen cannot see it
/// and it is named here instead.
pub(crate) fn tap_sets_no_environment(arguments: &[String]) -> bool {
    !arguments
        .iter()
        .any(|argument| option_name(argument) == "testenv")
}
