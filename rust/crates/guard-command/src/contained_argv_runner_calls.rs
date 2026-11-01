//! Reading a Node test runner's own call.
//!
//! Vitest and Jest both watch by default and both parse their own options, so
//! a contained run is only the call whose spelling their parser reads as one
//! pass over the workspace's tests. The two parsers disagree about what a
//! boolean option takes, so each runner is read against its own.

/// True when `arguments` name a contained Node test runner and a call that
/// runs once. Both runners watch by default, so each one is read for the
/// spelling that takes this call out of watch mode.
pub(crate) fn contained_runner_call(arguments: &[String]) -> bool {
    matches!(arguments, [tool, rest @ ..]
        if (tool == "vitest" && vitest_runs_once(rest))
            || (tool == "jest" && jest_contained_call(rest)))
}

/// True when a Vitest call finishes on its own.
///
/// The `run` verb says so by itself. Every other call Vitest keeps watching
/// unless it carries the spelling that turns the watch off: `--run`,
/// `--no-watch` or `--watch=false`. `related` and `bench` are read with it
/// because they run the workspace's own tests and benchmarks the way `run`
/// does.
///
/// Three readings keep that narrow. Vitest's parser stops at `--`, so only
/// the words before it name options. The first operand selects the command
/// whatever options precede it, so a word naming a command this reading does
/// not model leaves the call at review even with `--run` on the line. And the
/// last watch spelling wins, so an option that turns the watch back on keeps
/// the review wherever it stands.
pub(crate) fn vitest_runs_once(arguments: &[String]) -> bool {
    let arguments = before_terminator(arguments);
    let rest = match arguments.split_first() {
        Some((verb, _)) if verb == "run" => return true,
        Some((verb, rest)) if matches!(verb.as_str(), "related" | "bench") => rest,
        Some((verb, _)) if !verb.starts_with('-') => return false,
        _ => arguments,
    };
    !names_another_command(rest) && vitest_asked_not_to_watch(rest)
}

/// The Vitest commands this reading does not model: `init` scaffolds a
/// config, `list` and `typecheck` do other work, and `dev` and `watch` are
/// the watching run under other names.
const UNMODELED_VITEST_COMMANDS: &[&str] = &["dev", "init", "list", "typecheck", "watch"];

/// Whether any word names one of those commands.
///
/// Vitest takes the command from the first operand, and the reading cannot
/// tell an operand from the value of an option it does not model, so a value
/// spelled like one of these names keeps its call at review.
fn names_another_command(arguments: &[String]) -> bool {
    arguments
        .iter()
        .any(|argument| UNMODELED_VITEST_COMMANDS.contains(&argument.as_str()))
}

/// Whether a Vitest call turns its watch off and leaves it off.
///
/// Vitest reads its options through CAC, which declares every option it
/// carries no value for as a boolean to mri. mri never spends the next word
/// on a declared boolean, so `--watch false` leaves the watch on and reads
/// the word as a test filter; only the `=` spelling carries a value. A bare
/// `--watch`, a `--watch=true` and the short `-w` all turn the watch back on,
/// and mri keeps the last spelling, so an option that turns it on anywhere on
/// the line keeps the review.
fn vitest_asked_not_to_watch(arguments: &[String]) -> bool {
    let turns_watch_off = |argument: &String| {
        argument == "--run"
            || option_name(argument) == "nowatch"
            || (option_name(argument) == "watch" && joined_boolean(argument) == Some(false))
    };
    let turns_watch_on = |argument: &String| {
        short_options_carry_watch(argument)
            || (option_name(argument) == "watch" && joined_boolean(argument) != Some(false))
    };
    arguments.iter().any(turns_watch_off) && !arguments.iter().any(turns_watch_on)
}

/// Whether a short option turns the watch on. `-w` is Vitest's short
/// `--watch`, and mri reads a cluster one letter at a time, so `-uw` carries
/// it too.
fn short_options_carry_watch(argument: &str) -> bool {
    argument
        .strip_prefix('-')
        .is_some_and(|letters| !letters.starts_with('-') && letters.contains('w'))
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
///
/// The option's value decides, not its name. `--watchAll=false` is how a
/// script or an agent says "run once" to a Jest whose project config turns
/// watching on, so reading the name alone would send the call that asks for
/// the contained behaviour to review while the plain `jest` beside it runs.
pub(crate) fn jest_runs_once(arguments: &[String]) -> bool {
    let arguments = before_terminator(arguments);
    !arguments.iter().enumerate().any(|(index, argument)| {
        matches!(option_name(argument).as_str(), "watch" | "watchall")
            && jest_boolean(argument, arguments.get(index + 1)) != Some(false)
    })
}

/// The arguments a runner reads as options. Both parsers stop at `--` and
/// hand the rest to the test filter.
fn before_terminator(arguments: &[String]) -> &[String] {
    match arguments.iter().position(|argument| argument == "--") {
        Some(terminator) => &arguments[..terminator],
        None => arguments,
    }
}

/// The value an option carries joined to its name with `=`, which is the one
/// spelling mri reads for a declared boolean.
fn joined_boolean(argument: &str) -> Option<bool> {
    literal_boolean(argument.split_once('=')?.1)
}

/// The value a Jest boolean option carries, in the two spellings
/// yargs-parser reads: a value joined with `=`, and the literal `true` or
/// `false` that follows a declared boolean.
fn jest_boolean(argument: &str, next: Option<&String>) -> Option<bool> {
    match argument.split_once('=') {
        Some((_, value)) => literal_boolean(value),
        None => literal_boolean(next?),
    }
}

/// The boolean a word names. Both parsers compare it exactly, so `--watch=0`
/// names no boolean and leaves the option at its default, which is on.
fn literal_boolean(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
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

/// The `bun test` options this reading models, paired with whether the option
/// carries a value joined to its name with `=`. Bun's runner parses its own
/// line, so an option missing from this table keeps the call at review rather
/// than leaving the reading to guess what the words around it mean.
///
/// What the table leaves out is the point of it. `--watch` and `--hot` never
/// finish inside the sink; `-u`/`--update-snapshots` rewrites the workspace;
/// `--preload`, `-r`, `--config`, `-c`, `--env-file`, `--define`, `--loader`
/// and `--inspect` each name something the run loads from outside its tests;
/// `--install` fetches; `--cwd` moves the run; and a reporter written to a
/// file is a write.
const BUN_TEST_OPTIONS: &[(&str, bool)] = &[
    ("--bail", true),
    ("--coverage", false),
    ("--only", false),
    ("--rerun-each", true),
    ("--silent", false),
    ("--test-name-pattern", true),
    ("--timeout", true),
    ("--todo", false),
    ("-t", false),
];

/// True when a `bun test` call runs once over the workspace it was admitted
/// for.
///
/// Bun's runner takes a single pass and exits by default, so this reading is
/// about what the rest of the line adds rather than what it must say. Every
/// word is either an option the table above models or an operand -- a path
/// filter, or the pattern a bare `-t` takes -- and an operand naming a path
/// the workspace does not hold leaves the call at review.
pub(crate) fn bun_test_runs_once(arguments: &[String]) -> bool {
    arguments.iter().all(|argument| {
        if !argument.starts_with('-') {
            return !path_leaves_the_workspace(argument);
        }
        let (name, joined) = match argument.split_once('=') {
            Some((name, _)) => (name, true),
            None => (argument.as_str(), false),
        };
        BUN_TEST_OPTIONS
            .iter()
            .any(|(option, takes_value)| *option == name && (*takes_value || !joined))
    })
}
