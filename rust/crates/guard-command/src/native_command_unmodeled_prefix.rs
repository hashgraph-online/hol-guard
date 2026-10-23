//! Which word a piece of shell text hands to the program it runs.
//!
//! A scheduling or buffering prefix such as `nice` or `timeout` runs the
//! program the text already names, as this user and in this directory, so the
//! owners of `nice -n 10 cargo build` are the owners of `cargo build`. Reading
//! that requires knowing which word is the program, and a prefix carries its
//! own options, so the program is not at a fixed offset: `nice -n 10 cargo`,
//! `nice -10 cargo` and `timeout -k 5 30 cargo` each put it somewhere else.
//! Each prefix below is walked through its own documented option grammar. A
//! word that grammar does not cover, a program spelled as a path, a script
//! file this scan never opened, and an interpreter standing behind the prefix
//! all leave a program the text does not name, so each one keeps the
//! evaluation failure the command arrived with.
use super::{command_basename, is_assignment, without_redirections, INTERPRETERS, SHELL_PREFIXES};

/// One prefix's option grammar: the short letters it takes alone, the short
/// letters that carry a value, the same for its long spellings, whether a
/// bare number is its own option, and whether it spends a positional on a
/// duration before the program.
struct Grammar {
    prefix: &'static str,
    short_flags: &'static str,
    short_values: &'static str,
    long_flags: &'static [&'static str],
    long_values: &'static [&'static str],
    numeric_flag: bool,
    duration_operand: bool,
}

/// Prefixes that run the program the text names after them, changing how it is
/// scheduled or buffered rather than who runs it or what it reads. `sudo`,
/// `doas` and `chroot` change the user or the root they run under, `flock`
/// takes a lock file, and the tracers write a file of their own, so none of
/// them is here.
///
/// The shell's `exec` belongs with them: `exec npm test` runs exactly what
/// `npm test` runs, as this user and in this directory, and only replaces the
/// shell process instead of forking one. It takes no option this grammar
/// covers, so `exec -a name prog`, `exec -c prog` and `exec -l prog` leave the
/// program unknown, as does an `exec` that names no program at all and only
/// moves the shell's own file descriptors.
const GRAMMARS: &[Grammar] = &[
    Grammar {
        prefix: "exec",
        short_flags: "",
        short_values: "",
        long_flags: &[],
        long_values: &[],
        numeric_flag: false,
        duration_operand: false,
    },
    Grammar {
        prefix: "nice",
        short_flags: "",
        short_values: "n",
        long_flags: &["help", "version"],
        long_values: &["adjustment"],
        // `nice -10 cargo build` is the adjustment spelled on its own.
        numeric_flag: true,
        duration_operand: false,
    },
    Grammar {
        prefix: "nohup",
        short_flags: "",
        short_values: "",
        long_flags: &["help", "version"],
        long_values: &[],
        numeric_flag: false,
        duration_operand: false,
    },
    Grammar {
        prefix: "setsid",
        short_flags: "cfw",
        short_values: "",
        long_flags: &["ctty", "fork", "wait", "help", "version"],
        long_values: &[],
        numeric_flag: false,
        duration_operand: false,
    },
    Grammar {
        prefix: "stdbuf",
        short_flags: "",
        short_values: "ioe",
        long_flags: &["help", "version"],
        long_values: &["input", "output", "error"],
        numeric_flag: false,
        duration_operand: false,
    },
    Grammar {
        prefix: "timeout",
        short_flags: "fv",
        short_values: "ks",
        long_flags: &[
            "foreground",
            "preserve-status",
            "verbose",
            "help",
            "version",
        ],
        long_values: &["kill-after", "signal"],
        numeric_flag: false,
        duration_operand: true,
    },
    Grammar {
        prefix: "gtimeout",
        short_flags: "fv",
        short_values: "ks",
        long_flags: &[
            "foreground",
            "preserve-status",
            "verbose",
            "help",
            "version",
        ],
        long_values: &["kill-after", "signal"],
        numeric_flag: false,
        duration_operand: true,
    },
];

/// A launcher spelled as a bare command name.
///
/// `./nice` and `/tmp/tools/timeout` are programs of the user's own that share
/// a launcher's name and do whatever they were written to do, so neither is
/// read as one.
pub(super) fn is_launcher(word: &str) -> bool {
    !word.contains(['/', '\\']) && grammar(&command_basename(word)).is_some()
}

fn grammar(prefix: &str) -> Option<&'static Grammar> {
    GRAMMARS.iter().find(|grammar| grammar.prefix == prefix)
}

/// Whether a backgrounded or prefixed interpreter still names a program file
/// this scan did not read. A `python -m` module launch does not: the module is
/// an argument, same as the foreground command.
///
/// `sourcing_read` says the files this command sources were read, so the
/// question is asked of everything beside the sourcing. Without it the
/// `source` answered for the whole command: `source .venv/bin/activate &&
/// python -m pytest` reads one file, that file is already in hand, and the
/// module launch next to it was still refused for naming a file nobody read.
pub(super) fn interpreter_launch_reads_a_file(shell: &str, sourcing_read: bool) -> bool {
    without_redirections(shell)
        .split(|character: char| {
            matches!(
                character,
                ';' | '&' | '|' | '(' | ')' | '{' | '}' | '\n' | '`'
            )
        })
        .filter(|piece: &&str| !(sourcing_read && sources_a_file(piece)))
        .any(command_reads_a_program_file)
}

/// Whether the piece runs the shell's `source` builtin. A path-qualified
/// `./source` is a program of the user's own, so only the bare spellings
/// count, the same way the segment scan reads them.
fn sources_a_file(piece: &str) -> bool {
    piece
        .split_whitespace()
        .map(|word| word.trim_matches(['\'', '"']))
        .find(|word| !word.is_empty() && !is_assignment(word))
        .is_some_and(|word| matches!(word, "." | "source"))
}

/// Whether the text is a scheduling prefix standing in front of the program it
/// already names. Every other wrapper the parser leaves uncertain hides
/// something the floor cannot read: a shell behind `-c` runs a program spelled
/// in its own argument, `sudo` runs it as somebody else, and an `env` carrying
/// a live assignment changes what it inherits. Those keep their failure.
pub(super) fn launch_only(literal: &str) -> bool {
    let first_piece = literal
        .split(|character: char| {
            matches!(
                character,
                ';' | '&' | '|' | '(' | ')' | '{' | '}' | '\n' | '`'
            )
        })
        .next()
        .unwrap_or_default();
    wrapper_names_its_program(first_piece) && !interpreter_launch_reads_a_file(literal, false)
}

/// Whether the wrapper the text begins with runs the program the text already
/// names.
///
/// A launcher does when its own grammar counts past its options. An `env`
/// does too when it hands its environment to no program at all: it writes the
/// environment and exits, the way `printenv` does, so the rest of the text is
/// the whole of what runs. No grammar covers that `env`, because it launches
/// nothing to count options for, and without this arm `env`, `env -0` and
/// `env | grep '^PATH='` kept the parser's wrapper failure and blocked
/// outright, with no approval to give them. The dump still reaches the
/// owners' floor, which is never less than review, so what changes is that it
/// can be reviewed rather than only refused - a path-spelled `./env` of the
/// user's own included.
///
/// `env` spends a positional only on the program it runs, and the assignments
/// it carries stand before that program. They are read in the order the text
/// wrote them rather than dropped, because an assignment ends option parsing:
/// in `env PATH=. -i` the `-i` is the program name, not a flag, and dropping
/// the assignment first would read that command as a dump. An `env` that does
/// name a program keeps its failure: that program is one this scan has not
/// read.
fn wrapper_names_its_program(piece: &str) -> bool {
    let words: Vec<&str> = piece
        .split_whitespace()
        .map(|word| word.trim_matches(['\'', '"']))
        .filter(|word| !word.is_empty())
        .collect();
    let Some(first) = words.first() else {
        return false;
    };
    if command_basename(first) == "env" || command_basename(first) == "env.exe" {
        return !env_runs_a_program(&words[1..]);
    }
    is_launcher(first)
}

fn command_reads_a_program_file(piece: &str) -> bool {
    let words: Vec<&str> = piece
        .split_whitespace()
        .map(|word| word.trim_matches(['\'', '"']))
        .filter(|word| !word.is_empty())
        // Only the assignments a command carries in front of it belong to the
        // shell; one further along is an argument, and dropping it would move
        // the program this scan reads.
        .skip_while(|word| is_assignment(word))
        // `nohup` is a shell prefix and a launcher at once. Skipping it here
        // would hand the script behind it to the program scan as the program
        // itself, so a launcher stops the skip and keeps its own grammar.
        .skip_while(|word| SHELL_PREFIXES.contains(word) && !is_launcher(word))
        .collect();
    let Some(program) = words.first() else {
        return false;
    };
    if is_launcher(program) {
        return prefix_reads_a_program_file(&words);
    }
    reads_a_program_file(&words, 0)
}

/// The same question asked of the program a launcher hands its options to.
///
/// A launcher runs that program directly, so a path or a script name there is
/// a file whose own text names the programs it runs, and this scan has not
/// read it. `nice ./deploy.sh` is that file, not the one word `deploy.sh`.
pub(crate) fn prefix_reads_a_program_file(words: &[&str]) -> bool {
    // Options this grammar does not cover leave the program unknown, and an
    // unknown program is read as one this scan never saw.
    let Some(index) = program_index(words) else {
        return true;
    };
    let rest = &words[index..];
    let Some(program) = rest.first() else {
        return true;
    };
    // A launcher hands its program to whatever stands next, which may be
    // another launcher or a shell prefix: `nohup timeout 30 bash -lc …` runs
    // the shell behind `timeout`, and reading only the word `timeout` would
    // miss it. Walk a stacked launcher down to the program it runs, and keep
    // the failure for any other prefix standing in that position.
    if is_launcher(program) {
        return prefix_reads_a_program_file(rest);
    }
    if SHELL_PREFIXES.contains(&command_basename(program).as_str()) {
        return true;
    }
    program.contains(['/', '\\']) || names_a_script(program) || reads_a_program_file(rest, 0)
}

/// The command a launcher prefix stands in front of, as a slice of the text.
///
/// `nohup node server.js` runs `node server.js`, as this user and in this
/// directory, and `nice -n 10 ./scripts/run.sh` runs the script. The launcher
/// adds a scheduling number, a buffering mode or a hangup that the program
/// behind it would have run with anyway, so the command the floor reads is the
/// one the text already names - which is what the parser models exactly when
/// the prefix is not written.
///
/// Only a prefix this scan can count past is read, and only in front of plain
/// text: an operator, a redirect, a quote, a backslash or an expansion makes
/// the words behind the launcher something other than the command they look
/// like, so the text keeps the failure it arrives with. A stacked launcher is
/// walked down to the program it finally runs.
pub(crate) fn launcher_body(text: &str) -> Option<&str> {
    if text.contains([
        ';', '&', '|', '(', ')', '{', '}', '<', '>', '\n', '`', '$', '\'', '"', '\\',
    ]) {
        return None;
    }
    let spans = word_spans(text);
    let words: Vec<&str> = spans.iter().map(|(_, word)| *word).collect();
    let mut index = 0;
    while is_launcher(words.get(index)?) {
        // Every grammar here counts at least the launcher itself, so the walk
        // moves forward and ends at the program or at a prefix it cannot read.
        index += program_index(&words[index..])?;
    }
    (index > 0).then(|| &text[spans[index].0..])
}

/// Each word of the text with the byte offset it starts at, so a word can be
/// handed back as a slice of the text it came from.
fn word_spans(text: &str) -> Vec<(usize, &str)> {
    let mut spans = Vec::new();
    let mut start = None;
    for (offset, character) in text.char_indices() {
        match (character.is_whitespace(), start) {
            (false, None) => start = Some(offset),
            (true, Some(begin)) => {
                spans.push((begin, &text[begin..offset]));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(begin) = start {
        spans.push((begin, &text[begin..]));
    }
    spans
}

/// Whether the word at `index` is an interpreter that takes the program it
/// runs from a file this scan never read.
fn reads_a_program_file(words: &[&str], index: usize) -> bool {
    let Some(program) = words.get(index) else {
        return true;
    };
    let program = command_basename(program);
    if program == "env" || program == "env.exe" {
        return env_runs_a_program(&words[index + 1..]);
    }
    if !is_python(program.as_str()) {
        return INTERPRETERS.contains(&program.as_str());
    }
    !python_module_launch(&words[index + 1..])
}

/// Whether this `env` hands its environment to a program, or only prints it.
///
/// `env` is an interpreter when a program follows it: `env sh -c …` runs
/// whatever that shell is given. With no program operand it runs nothing at
/// all - it writes the environment and exits, the way `printenv` does - so
/// reading it as an interpreter that launches an unread file left `env`,
/// `env -0` and `env | grep '^PATH='` blocked outright, with no approval to
/// give them. The dump itself still reaches the owners' floor, so it is
/// reviewed rather than allowed; what changes is that it can be reviewed.
///
/// `env` spends a positional only on the program, so the first word that is
/// not one of its own options is that program. The caller has already dropped
/// the `NAME=value` assignments, which stand before the program in any case.
///
/// Only the options that are known to run nothing count as a dump; every other
/// option says a program runs. `-S`/`--split-string` carries its program in
/// its own value, so `env -Sbash`, `env --split-string=sh` and the cluster
/// `env -iS'sh -c id'` are all shell launches spelled as a single
/// dash-prefixed word, and a scan that skipped unrecognised options would read
/// them as harmless dumps and offer them an approval. `-C`/`--chdir` and `-P`
/// locate a program rather than describe one, so they are read the same way.
fn env_runs_a_program(words: &[&str]) -> bool {
    let mut index = 0;
    while let Some(word) = words.get(index) {
        // `--` ends option parsing, and so does an assignment, which is the
        // first operand that is not an option. What follows either is the same
        // run both times: assignments, then the program if the text names one.
        // `env PATH=. -i` runs a program named `-i`, and `env -- FOO=bar` sets
        // a variable for nothing and prints the environment.
        if *word == "--" {
            return operands_name_a_program(&words[index + 1..]);
        }
        if is_assignment(word) {
            return operands_name_a_program(&words[index..]);
        }
        if !word.starts_with('-') || *word == "-" {
            return true;
        }
        match env_option(word) {
            None => return true,
            // A split value spends the next word; an attached one carries its own.
            Some(spends_a_word) => index += 1 + usize::from(spends_a_word),
        }
    }
    false
}

/// Whether a run of `env` operands that can no longer hold options names a
/// program. Every assignment in it is an environment update; the first word
/// that is not one is the program, whatever shape it has.
fn operands_name_a_program(operands: &[&str]) -> bool {
    operands.iter().any(|operand| !is_assignment(operand))
}

/// Whether this option leaves `env` printing its environment, and if so whether
/// its value is the next word. `None` means the option runs a program.
fn env_option(word: &str) -> Option<bool> {
    if let Some(long) = word.strip_prefix("--") {
        let (name, attached) = match long.split_once('=') {
            Some((name, _)) => (name, true),
            None => (long, false),
        };
        return match name {
            "ignore-environment" | "null" | "debug" | "help" | "version" => Some(false),
            "unset" => Some(!attached),
            _ => None,
        };
    }
    let mut characters = word[1..].chars();
    while let Some(letter) = characters.next() {
        match letter {
            // Value-less flags; the cluster continues after them.
            'i' | '0' | 'v' => {}
            // `-u NAME` takes the rest of the cluster, or the next word when
            // the cluster ends here.
            'u' => return Some(characters.next().is_none()),
            _ => return None,
        }
    }
    Some(false)
}

/// A word naming a file an interpreter reads, rather than a program on the
/// path. The file's own text names the programs it runs, and this scan has not
/// read it.
fn names_a_script(word: &str) -> bool {
    let word = word.to_ascii_lowercase();
    [
        ".sh", ".bash", ".zsh", ".ksh", ".py", ".rb", ".pl", ".js", ".mjs", ".cjs", ".ts", ".ps1",
        ".bat", ".cmd",
    ]
    .iter()
    .any(|suffix| word.ends_with(suffix))
}

/// Where the program sits in a launcher's words, or `None` when the launcher's
/// own options cannot be counted past.
fn program_index(words: &[&str]) -> Option<usize> {
    let grammar = grammar(&command_basename(words.first()?))?;
    let mut index = 1;
    while let Some(word) = words.get(index) {
        if *word == "--" {
            index += 1;
            break;
        }
        if !word.starts_with('-') {
            break;
        }
        // A lone `-` is this launcher's own operand in no grammar here.
        if *word == "-" {
            return None;
        }
        index += 1 + option_consumes(grammar, word)?;
    }
    if grammar.duration_operand {
        if !is_duration(words.get(index)?) {
            return None;
        }
        index += 1;
    }
    (index < words.len()).then_some(index)
}

/// How many further words an option word carries, or `None` when this
/// launcher does not document it.
fn option_consumes(grammar: &Grammar, word: &str) -> Option<usize> {
    if let Some(long) = word.strip_prefix("--") {
        let (name, inline) = match long.split_once('=') {
            Some((name, _)) => (name, true),
            None => (long, false),
        };
        if grammar.long_values.contains(&name) {
            return Some(usize::from(!inline));
        }
        return grammar.long_flags.contains(&name).then_some(0);
    }
    let cluster = word.strip_prefix('-')?;
    if grammar.numeric_flag && cluster.bytes().all(|byte| byte.is_ascii_digit()) {
        return Some(0);
    }
    for (position, letter) in cluster.char_indices() {
        if grammar.short_values.contains(letter) {
            // A value glued to its letter leaves the next word alone.
            return Some(usize::from(
                cluster[position + letter.len_utf8()..].is_empty(),
            ));
        }
        if !grammar.short_flags.contains(letter) {
            return None;
        }
    }
    Some(0)
}

/// `timeout` spends one operand on how long it waits: a number with an
/// optional unit.
fn is_duration(word: &str) -> bool {
    let number = word.strip_suffix(['s', 'm', 'h', 'd']).unwrap_or(word);
    number.bytes().any(|byte| byte.is_ascii_digit())
        && number
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
}

fn is_python(name: &str) -> bool {
    name.strip_prefix("python").is_some_and(|version| {
        version
            .split('.')
            .all(|part| part.is_empty() || part.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

/// `python -m module` before any script path, inline source, or stdin.
fn python_module_launch(arguments: &[&str]) -> bool {
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index];
        if argument == "-m" {
            return arguments.get(index + 1).is_some();
        }
        if argument == "-c" || argument == "-" || argument == "--" {
            return false;
        }
        if matches!(argument, "-W" | "-X" | "--check-hash-based-pycs") {
            index += 2;
            continue;
        }
        if argument.starts_with('-') {
            index += 1;
            continue;
        }
        return false;
    }
    false
}

#[cfg(test)]
#[path = "native_command_unmodeled_prefix_program_tests.rs"]
mod tests;
