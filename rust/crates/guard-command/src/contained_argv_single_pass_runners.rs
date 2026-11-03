//! Reading the Node test runners that take one pass by default.
//!
//! Vitest, Jest, Mocha and AVA each carry enough of their own parser to need
//! their own reading. The five here do not. Jasmine, uvu, tape and tsd have
//! no watch mode at all, and QUnit's is a single flag, so what these readings
//! mostly name is the words that run something other than the suite:
//! scaffolding a project, copying example files in, or watching. Everything
//! else on their lines is an option value or a spec file, and the shared
//! workspace screen answers for those the way it does for the other four.

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
    !arguments
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
