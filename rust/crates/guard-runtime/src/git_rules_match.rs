//! Matching for the user's own git rules: never skip the hooks that run
//! before a commit or push, and stage files by name rather than the whole
//! tree.
//!
//! The matcher reads the shell command the way the shell runs it, through
//! `env` and `sh -c` (which the command model already unwraps), the common
//! process wrappers (`caffeinate`, `timeout`, `nice`, ...), subshells,
//! `eval`, and inline Python or JavaScript that hands a git command to a
//! process call. A mention of git in text that is never run, such as an
//! `echo`, a commit message or a `print`, is not a match.

use guard_command::command_model::{parse_shell_command, CommandSegment};

use crate::git_rules_state::{Dir, Hooks, State};

/// How deep nested shells, wrappers and inline scripts are followed.
const MAX_DEPTH: usize = 4;

/// Which of the user's git rules a command breaks.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Breaks {
    pub(crate) hook_bypass: bool,
    pub(crate) stage_all: bool,
}

pub(crate) fn breaks(command: &str) -> Breaks {
    let mut found = Breaks::default();
    scan(command, 0, &mut State::default(), &mut found);
    found
}

fn scan(text: &str, depth: usize, state: &mut State, found: &mut Breaks) {
    if depth > MAX_DEPTH || text.trim().is_empty() {
        return;
    }
    let model = parse_shell_command(
        text,
        None,
        None,
        "posix",
        "shell_string",
        "guard-shell",
        true,
    );
    for segment in &model.segments {
        segment_breaks(segment, depth, state, found);
    }
    for embedded in &model.embedded_commands {
        scan(&embedded.text, depth + 1, &mut { *state }, found);
    }
}

fn segment_breaks(segment: &CommandSegment, depth: usize, state: &mut State, found: &mut Breaks) {
    let Some(executable) = segment.executable.as_deref() else {
        return;
    };
    if executable.starts_with('(') {
        let inner = segment.text.trim();
        let inner = inner.strip_prefix('(').unwrap_or(inner);
        let inner = inner.strip_suffix(')').unwrap_or(inner);
        scan(inner, depth + 1, &mut { *state }, found);
        return;
    }
    // The words before the program: assignments, and an `env` the command
    // model left in place inside a compound command.
    let program = base_name(executable);
    let leading: Vec<&str> = segment
        .tokens
        .iter()
        .map(String::as_str)
        .take_while(|token| *token != executable && base_name(token) != program)
        .collect();
    let (hooks, _) = state.hooks.prefix(&leading);
    let mut argv: Vec<&str> = vec![executable];
    argv.extend(segment.arguments.iter().map(String::as_str));
    run(&argv, hooks, depth, state, found);
}

/// One program run with `argv` and the hook switches `hooks` in its
/// environment, looking through wrappers to the program they start.
fn run(argv: &[&str], hooks: Hooks, depth: usize, state: &mut State, found: &mut Breaks) {
    let Some((program, rest)) = argv.split_first() else {
        return;
    };
    // A child shell or script starts from this command's environment.
    let child = State { hooks, ..*state };
    match base_name(program).as_str() {
        "git" => git(rest, hooks, state, found),
        name @ ("cd" | "pushd" | "popd") => state.change_directory(name, rest),
        name @ ("export" | "declare" | "typeset" | "unset") => state.environment(name, rest),
        "env" => {
            let words: Vec<&str> = std::iter::once("env").chain(rest.iter().copied()).collect();
            let (hooks, read) = hooks.prefix(&words);
            if depth < MAX_DEPTH {
                run(&words[read..], hooks, depth + 1, state, found);
            }
        }
        "eval" => {
            // `eval` runs in this shell: its folder and exports carry on,
            // while switches set only for the `eval` itself do not.
            let mut inner = child;
            scan(&rest.join(" "), depth + 1, &mut inner, found);
            state.dir = inner.dir;
            state.previous = inner.previous;
            if hooks == state.hooks {
                state.hooks = inner.hooks;
            }
        }
        "sh" | "bash" | "zsh" | "dash" | "ksh" => {
            if let Some(script) = flag_value(rest, &["-c", "-lc", "-ec", "-ic"]) {
                scan(script, depth + 1, &mut { child }, found);
            }
        }
        name if INLINE_RUNTIMES
            .iter()
            .any(|runtime| name.starts_with(runtime)) =>
        {
            if let Some(code) = flag_value(rest, &["-c", "-e", "--eval", "-p", "--print"]) {
                let hash_comments = !["node", "bun", "deno"]
                    .iter()
                    .any(|runtime| name.starts_with(runtime));
                for call in crate::git_rules_inline::process_calls(code, hash_comments) {
                    match call {
                        crate::git_rules_inline::Call::Shell(text) => {
                            scan(&text, depth + 1, &mut { child }, found)
                        }
                        crate::git_rules_inline::Call::Argv(words) => {
                            let words: Vec<&str> = words.iter().map(String::as_str).collect();
                            run(&words, hooks, depth + 1, &mut { child }, found);
                        }
                    }
                }
            }
        }
        name => {
            if let Some(inner) = wrapped(name, rest) {
                if depth < MAX_DEPTH {
                    run(inner, hooks, depth + 1, state, found);
                }
            }
        }
    }
}

const INLINE_RUNTIMES: &[&str] = &["python", "node", "bun", "deno", "ruby", "perl"];

/// The argv a process wrapper runs, past the wrapper's own options.
fn wrapped<'a>(name: &str, rest: &'a [&'a str]) -> Option<&'a [&'a str]> {
    // Options of each wrapper that take a separate value.
    let valued: &[&str] = match name {
        "caffeinate" => &["-t", "-w"],
        "timeout" => &["-s", "--signal", "-k", "--kill-after"],
        "nice" => &["-n", "--adjustment"],
        "ionice" => &["-c", "-n", "-p"],
        "stdbuf" => &["-i", "-o", "-e"],
        "nohup" | "time" | "command" | "exec" | "doas" | "sudo" => &[],
        _ => return None,
    };
    let mut index = 0;
    while let Some(word) = rest.get(index) {
        if *word == "--" {
            index += 1;
            break;
        }
        if !word.starts_with('-') || *word == "-" {
            break;
        }
        index += if valued.contains(word) { 2 } else { 1 };
    }
    // `timeout` takes its duration before the program.
    if name == "timeout" {
        index += 1;
    }
    rest.get(index..).filter(|inner| !inner.is_empty())
}

/// Git's own options before the subcommand, and the subcommand's rules.
fn git(args: &[&str], hooks: Hooks, state: &State, found: &mut Breaks) {
    let mut config_disarms = false;
    let mut dir = state.dir;
    let mut index = 0;
    while let Some(word) = args.get(index) {
        let next = args.get(index + 1).copied();
        match *word {
            "-C" => {
                if let Some(target) = next.filter(|target| !names_root(target)) {
                    dir = dir.enter(target);
                }
                index += 2;
            }
            "-c" => {
                config_disarms |= next.is_some_and(|pair| {
                    pair.split_once('=')
                        .is_some_and(|(key, value)| disarming_hooks_path(key, value))
                });
                index += 2;
            }
            "--git-dir" | "--work-tree" | "--namespace" | "--config-env" | "--exec-path" => {
                index += 2
            }
            option if option.starts_with('-') => index += 1,
            _ => break,
        }
    }
    let Some(subcommand) = args.get(index) else {
        return;
    };
    let rest = &args[index + 1..];
    let moved = dir != Dir::Root;
    // A commit preview runs no hook and stages nothing.
    if *subcommand == "commit"
        && rest
            .iter()
            .take_while(|word| **word != "--")
            .any(|word| *word == "--dry-run")
    {
        return;
    }
    if HOOK_RUNNING.contains(subcommand) && (hooks.off() || config_disarms) {
        found.hook_bypass = true;
    }
    match *subcommand {
        "commit" => commit(rest, moved, found),
        "add" => add(rest, moved, found),
        "rm" => {
            let (flags, paths) = split_options(rest, &[]);
            if flags.iter().any(|flag| *flag == "--cached")
                && paths.iter().any(|path| whole_tree(path, moved))
            {
                found.stage_all = true;
            }
        }
        "config" => found.hook_bypass |= config_disarms_hooks(rest),
        "push" | "merge" | "am" | "rebase" | "cherry-pick" | "revert" | "pull" => {
            if rest
                .iter()
                .take_while(|word| **word != "--")
                .any(|word| *word == "--no-verify")
            {
                found.hook_bypass = true;
            }
        }
        _ => {}
    }
}

/// Subcommands that run a hook the user relies on.
const HOOK_RUNNING: &[&str] = &[
    "commit",
    "push",
    "merge",
    "am",
    "rebase",
    "cherry-pick",
    "revert",
    "pull",
];

/// `git commit`: `-n` or `--no-verify` skips the hooks; `-a`, `--all` or a
/// whole-tree pathspec commits every change instead of the staged names.
fn commit(rest: &[&str], moved: bool, found: &mut Breaks) {
    const VALUED_SHORT: &[char] = &['m', 'F', 'c', 'C', 't'];
    const VALUED_LONG: &[&str] = &[
        "--message",
        "--file",
        "--reuse-message",
        "--reedit-message",
        "--fixup",
        "--squash",
        "--author",
        "--date",
        "--template",
        "--cleanup",
        "--trailer",
        "--pathspec-from-file",
    ];
    let (flags, paths) = split_options(rest, VALUED_LONG);
    for flag in &flags {
        match *flag {
            "--no-verify" => found.hook_bypass = true,
            "--all" => found.stage_all = true,
            long if long.starts_with("--") => {}
            short => {
                for letter in short.trim_start_matches('-').chars() {
                    match letter {
                        'n' => found.hook_bypass = true,
                        'a' => found.stage_all = true,
                        _ => {}
                    }
                    if VALUED_SHORT.contains(&letter) || letter == 'u' || letter == 'S' {
                        break;
                    }
                }
            }
        }
    }
    if paths.iter().any(|path| whole_tree(path, moved)) {
        found.stage_all = true;
    }
}

/// `git add`: everything, every tracked change, or every file but a few.
fn add(rest: &[&str], moved: bool, found: &mut Breaks) {
    let (flags, paths) = split_options(rest, &["--chmod", "--pathspec-from-file"]);
    let mut all = false;
    for flag in &flags {
        match *flag {
            "--all" | "--update" | "--no-ignore-removal" => all = true,
            "--patch" | "--interactive" | "--edit" | "--dry-run" => return,
            long if long.starts_with("--") => {}
            short => {
                for letter in short.trim_start_matches('-').chars() {
                    match letter {
                        'A' | 'u' => all = true,
                        'p' | 'i' | 'e' | 'n' => return,
                        _ => {}
                    }
                }
            }
        }
    }
    let named: Vec<&&str> = paths.iter().filter(|path| !excludes(path)).collect();
    let only_exclusions = named.is_empty() && !paths.is_empty();
    if (named.is_empty() && all)
        || only_exclusions
        || named.iter().any(|path| whole_tree(path, moved))
    {
        found.stage_all = true;
    }
}

/// Splits a subcommand's words into options and pathspecs. Short options
/// that take a value (`-m msg`) are read by the caller from their cluster;
/// their separate value is skipped here.
fn split_options<'a>(rest: &[&'a str], valued_long: &[&str]) -> (Vec<&'a str>, Vec<&'a str>) {
    const VALUED_SHORT: &[char] = &['m', 'F', 'c', 'C', 't'];
    let mut flags = Vec::new();
    let mut paths = Vec::new();
    let mut index = 0;
    while let Some(word) = rest.get(index) {
        index += 1;
        if *word == "--" {
            paths.extend(rest[index..].iter().copied());
            break;
        }
        if let Some(long) = word.strip_prefix("--") {
            flags.push(*word);
            if !long.contains('=') && valued_long.contains(word) {
                index += 1;
            }
        } else if word.len() > 1 && word.starts_with('-') {
            flags.push(*word);
            // The value of the cluster's first valued letter is the rest of
            // the word, or the next word when nothing follows the letter.
            let letters: Vec<char> = word[1..].chars().collect();
            if let Some(at) = letters
                .iter()
                .position(|letter| VALUED_SHORT.contains(letter))
            {
                if at + 1 == letters.len() {
                    index += 1;
                }
            }
        } else {
            paths.push(*word);
        }
    }
    (flags, paths)
}

/// A pathspec that names the whole working tree.
fn whole_tree(path: &str, moved: bool) -> bool {
    if path.contains("--show-toplevel") {
        return true;
    }
    if let Some(rest) = path.strip_prefix(":/") {
        return matches!(rest, "" | "." | "*");
    }
    if let Some(magic) = path.strip_prefix(":(") {
        if let Some((words, rest)) = magic.split_once(')') {
            return words.split(',').any(|word| word == "top") && matches!(rest, "" | "." | "*");
        }
    }
    !moved && matches!(path, "." | "./" | "*" | "./*")
}

fn excludes(path: &str) -> bool {
    path.starts_with(":!")
        || path.starts_with(":^")
        || path
            .strip_prefix(":(")
            .and_then(|magic| magic.split_once(')'))
            .is_some_and(|(words, _)| words.split(',').any(|word| word == "exclude"))
}

/// Whether `git -C dir` keeps `.` at the tree's top: the current folder, or
/// a folder Guard cannot read (a variable) that names the top.
fn names_root(dir: &str) -> bool {
    matches!(dir, "." | "./")
        || dir.contains("--show-toplevel")
        || dir.starts_with('$')
        || dir.starts_with('/')
}

/// `git config [options] [set] core.hooksPath <value>`: the options that
/// take a value are skipped with it, and a read or an unset never matches.
fn config_disarms_hooks(rest: &[&str]) -> bool {
    const VALUED: &[&str] = &[
        "-f",
        "--file",
        "--blob",
        "--type",
        "--default",
        "--comment",
        "--value",
    ];
    const NOT_A_WRITE: &[&str] = &[
        "--get",
        "--get-all",
        "--get-regexp",
        "--get-urlmatch",
        "--unset",
        "--unset-all",
        "-l",
        "--list",
        "-e",
        "--edit",
        "--remove-section",
        "--rename-section",
        "get",
        "list",
        "unset",
        "edit",
        "remove-section",
        "rename-section",
    ];
    let mut words = Vec::new();
    let mut index = 0;
    while let Some(word) = rest.get(index) {
        index += 1;
        if NOT_A_WRITE.contains(word) {
            return false;
        }
        if VALUED.contains(word) {
            index += 1;
        } else if !word.starts_with('-') {
            words.push(*word);
        }
    }
    if words.first() == Some(&"set") {
        words.remove(0);
    }
    matches!(words.as_slice(), [key, value, ..] if disarming_hooks_path(key, value))
}

fn disarming_hooks_path(key: &str, value: &str) -> bool {
    key.eq_ignore_ascii_case("core.hooksPath")
        && matches!(
            value.trim().trim_matches(|c| c == '"' || c == '\''),
            "" | "/dev/null" | "NUL" | "nul" | "/nonexistent" | "/var/empty"
        )
}

fn flag_value<'a>(rest: &[&'a str], flags: &[&str]) -> Option<&'a str> {
    let at = rest.iter().position(|word| flags.contains(word))?;
    rest.get(at + 1).copied()
}

fn base_name(program: &str) -> String {
    let name = program.rsplit(['/', '\\']).next().unwrap_or(program);
    name.strip_suffix(".exe")
        .unwrap_or(name)
        .to_ascii_lowercase()
}
