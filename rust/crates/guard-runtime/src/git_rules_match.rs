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

use std::path::Path;

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

/// The rules `command` breaks when the agent runs it from `cwd`.
pub(crate) fn breaks(command: &str, cwd: Option<&Path>) -> Breaks {
    let mut found = Breaks::default();
    let top = cwd.and_then(work_tree_top);
    let dir = match (cwd, top) {
        (Some(cwd), Some(top)) => below(cwd, top),
        _ => Dir::Root,
    };
    let mut state = State {
        dir,
        previous: Dir::Elsewhere,
        top,
        origin: cwd,
        ..State::default()
    };
    scan(command, 0, &mut state, &mut found);
    found
}

/// The top of the working tree `cwd` sits in: the nearest folder with a
/// `.git` entry.
pub(crate) fn work_tree_top(cwd: &Path) -> Option<&Path> {
    cwd.ancestors()
        .take(64)
        .find(|folder| folder.join(".git").symlink_metadata().is_ok())
}

/// Where `cwd` sits relative to the top of its working tree.
pub(crate) fn below(cwd: &Path, top: &Path) -> Dir {
    match cwd.strip_prefix(top).map(|rest| rest.components().count()) {
        Ok(0) => Dir::Root,
        Ok(depth) => Dir::Below(u16::try_from(depth).unwrap_or(u16::MAX)),
        Err(_) => Dir::Elsewhere,
    }
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
    // A substitution runs before the command it sits in, in the folder and
    // environment the shell has at that point.
    let mut embedded = model.embedded_commands.iter().peekable();
    let segments = &model.segments;
    for (position, segment) in segments.iter().enumerate() {
        while let Some(inner) = embedded.next_if(|inner| inner.start < segment.end) {
            scan(&inner.text, depth + 1, &mut { *state }, found);
        }
        let (start, end) = span(text, segment);
        let raw = text.get(start..end).unwrap_or(&segment.text);
        let gap = |from: usize, to: usize| operator(text.get(from..to).unwrap_or(";"));
        let before = position
            .checked_sub(1)
            .map(|at| gap(span(text, &segments[at]).1, start));
        let piped = before == Some(Op::Pipe)
            || segments
                .get(position + 1)
                .is_some_and(|next| gap(end, span(text, next).0) == Op::Pipe);
        let fallback = state.fallback.take();
        state.moved_now = false;
        match (before, fallback) {
            // Each part of a pipeline runs in its own shell.
            _ if piped => segment_breaks(segment, raw, depth, &mut { *state }, found),
            // After `cd dir ||`, the command runs only when the change failed.
            (Some(Op::Or), Some(stayed)) => {
                let mut branch = State {
                    dir: stayed,
                    ..*state
                };
                segment_breaks(segment, raw, depth, &mut branch, found);
            }
            _ => segment_breaks(segment, raw, depth, state, found),
        }
        if !state.moved_now {
            state.fallback = None;
        }
    }
    for inner in embedded {
        scan(&inner.text, depth + 1, &mut { *state }, found);
    }
}

/// How a segment joins the one before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    And,
    Or,
    Pipe,
    Then,
}

fn operator(gap: &str) -> Op {
    if gap.contains("||") {
        Op::Or
    } else if gap.contains("&&") {
        Op::And
    } else if gap.contains('|') {
        Op::Pipe
    } else {
        Op::Then
    }
}

/// Where `segment` sits in `text`, in bytes. The command model counts
/// characters, and when it unwraps a leading `env` its span covers only the
/// unwrapped length, so the end is found again from the segment's own text.
fn span(text: &str, segment: &CommandSegment) -> (usize, usize) {
    let byte = |chars: usize| {
        text.char_indices()
            .nth(chars)
            .map_or(text.len(), |(at, _)| at)
    };
    let start = byte(segment.start);
    let fallback = byte(segment.end);
    let own = segment.text.trim_end();
    let end = text
        .get(start..)
        .filter(|_| !own.is_empty())
        .and_then(|rest| rest.find(own))
        .map_or_else(
            || command_end(text, start).max(fallback),
            |at| start + at + own.len(),
        );
    (start, end.max(start))
}

/// The end of the simple command that starts at `from`: the first unquoted
/// `;`, `|`, `&` or newline that is not part of a redirection such as `2>&1`.
fn command_end(text: &str, from: usize) -> usize {
    let Some(rest) = text.get(from..) else {
        return text.len();
    };
    let mut quote = None;
    let mut previous = ' ';
    let mut chars = rest.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        match (quote, c) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('"') | None, '\\') => {
                chars.next();
            }
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(c),
            (None, '&')
                if matches!(previous, '>' | '<')
                    || chars.peek().is_some_and(|(_, next)| *next == '>') => {}
            (None, ';' | '|' | '&' | '\n') => return from + at,
            _ => {}
        }
        previous = c;
    }
    text.len()
}

/// The words without their redirections (`> out`, `2>&1`, `<in`). A word
/// whose first character was quoted, such as the message `'> wip'`, is an
/// argument, not a redirection.
fn without_redirects(words: Vec<crate::git_rules_state::Word>) -> Vec<String> {
    let mut kept = Vec::new();
    let mut words = words.into_iter();
    while let Some(crate::git_rules_state::Word {
        text: word,
        literal,
    }) = words.next()
    {
        let operator = word.trim_start_matches(|c: char| c.is_ascii_digit());
        let operator = operator.strip_prefix('&').unwrap_or(operator);
        if literal || !operator.starts_with(['<', '>']) {
            kept.push(word);
            continue;
        }
        if operator.trim_start_matches(['<', '>', '&', '|']).is_empty() {
            words.next();
        }
    }
    kept
}

/// A word quoted so the shell reads it back as one word.
fn quoted(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

fn segment_breaks(
    segment: &CommandSegment,
    raw: &str,
    depth: usize,
    state: &mut State,
    found: &mut Breaks,
) {
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
    // The command model unwraps a leading `env` and drops its options, so
    // a segment that starts with one is read from its source words: `env -C`
    // moves the folder and `env -u` clears a switch.
    if let Some(words) = crate::git_rules_state::split_marked(raw).map(without_redirects) {
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        let at = words
            .iter()
            .position(|word| crate::git_rules_state::assignment(word).is_none())
            .unwrap_or(words.len());
        if words.get(at).is_some_and(|word| base_name(word) == "env") {
            let (hooks, _) = state.hooks.prefix(&words[..at]);
            run(&words[at..], hooks, depth, state, found);
            return;
        }
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
        "git" => crate::git_rules_git::git(rest, hooks, state, found),
        name @ ("cd" | "pushd" | "popd") => state.change_directory(name, rest),
        name @ ("export" | "declare" | "typeset" | "unset") => state.environment(name, rest),
        "env" => {
            let words: Vec<&str> = std::iter::once("env").chain(rest.iter().copied()).collect();
            let (hooks, read) = hooks.prefix(&words);
            if depth >= MAX_DEPTH {
                return;
            }
            let (folder, split) = env_options(&words[1..read]);
            let mut inner = State { hooks, ..*state };
            if let Some(target) = folder {
                inner.dir = inner.dir.enter(target);
                inner.origin = None;
            }
            match split {
                // `env -S 'git commit --no-verify'` splits its value into
                // the command it runs, ahead of any words that follow.
                Some(split) => {
                    let text = std::iter::once(split.to_owned())
                        .chain(words[read..].iter().map(|word| quoted(word)))
                        .collect::<Vec<_>>()
                        .join(" ");
                    scan(&text, depth + 1, &mut inner, found);
                }
                None => run(&words[read..], hooks, depth + 1, &mut inner, found),
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
                inline(name, code, hooks, depth, child, found);
            }
        }
        _ => {
            // Wrappers start the program after their own options. They are
            // unwrapped in a loop, so a stack of them does not use up the
            // depth limit.
            let mut inner = argv;
            while let Some((program, rest)) = inner.split_first() {
                match wrapped(&base_name(program), rest) {
                    Some(next) => inner = next,
                    None => break,
                }
            }
            if inner.len() < argv.len() {
                run(inner, hooks, depth, state, found);
            }
        }
    }
}

/// The process calls in inline code run by `runtime`, each in the folder it
/// names.
fn inline(runtime: &str, code: &str, hooks: Hooks, depth: usize, child: State, found: &mut Breaks) {
    use crate::git_rules_inline::{scan as calls, unread_risks, Call};
    let hash_comments = !["node", "bun", "deno"]
        .iter()
        .any(|name| runtime.starts_with(name));
    let Some(calls) = calls(code, hash_comments) else {
        let (hook_bypass, stage_all) = unread_risks(code);
        found.hook_bypass |= hook_bypass;
        found.stage_all |= stage_all;
        return;
    };
    for call in calls {
        let mut inner = child;
        if let Some(cwd) = &call.cwd {
            // The same placing as `git -C`: a folder held in a variable is
            // taken as the top of the tree.
            inner.dir = crate::git_rules_git::enter(inner.dir, cwd, inner.top);
            inner.origin = None;
        }
        match call.call {
            Call::Shell(text) => scan(&text, depth + 1, &mut inner, found),
            Call::Argv(words) => {
                let words: Vec<&str> = words.iter().map(String::as_str).collect();
                run(&words, hooks, depth + 1, &mut inner, found);
            }
        }
    }
}

const INLINE_RUNTIMES: &[&str] = &["python", "node", "bun", "deno", "ruby", "perl"];

/// The folder `env -C` starts its command in and the string `env -S` splits
/// into it, from `env`'s own options.
fn env_options<'a>(options: &[&'a str]) -> (Option<&'a str>, Option<&'a str>) {
    let (mut folder, mut split) = (None, None);
    let mut index = 0;
    while let Some(word) = options.get(index) {
        let next = options.get(index + 1).copied();
        match *word {
            "-C" | "--chdir" => {
                folder = next;
                index += 1;
            }
            "-S" | "--split-string" => {
                split = next;
                index += 1;
            }
            "-u" | "--unset" => index += 1,
            word => {
                if let Some(value) = word.strip_prefix("--chdir=") {
                    folder = Some(value);
                } else if let Some(value) = word.strip_prefix("--split-string=") {
                    split = Some(value);
                } else if let Some(value) = word.strip_prefix("-S").filter(|v| !v.is_empty()) {
                    split = Some(value);
                }
            }
        }
        index += 1;
    }
    (folder, split)
}

/// The argv a process wrapper runs, past the wrapper's own options.
fn wrapped<'a, 'b>(name: &str, rest: &'a [&'b str]) -> Option<&'a [&'b str]> {
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
