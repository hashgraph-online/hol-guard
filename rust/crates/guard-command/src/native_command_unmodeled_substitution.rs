//! A command substitution whose commands are named in the text prints words
//! into the command around it. `printf '%s\n' "$(dirname "$PWD")"` and
//! `kill $(cat server.pid)` run `dirname` and `cat`, and the output becomes
//! arguments of `printf` and `kill`: never a program, an operator or a
//! redirect target. Every program such a command runs is named, so its owners
//! bound it the way they bound the rest of the text.
//!
//! A process substitution reads the same way. `diff <(sort a.txt) b.txt` runs
//! `sort` and hands `diff` the path of a pipe to read, so the word it leaves
//! behind is an operand exactly as a printed word is, and every program it
//! runs is named. Only the input form is read: `>(cmd)` feeds the inner
//! program data this text does not hold, so it stays an evaluation failure.
//!
//! The substitution that stays an evaluation failure is the one that could run
//! a program the text does not name or put its output somewhere the floor
//! cannot read: in command position, in an assignment, as a redirect target,
//! or holding a nested substitution, a backtick, a redirect, a subshell, a
//! background job, an expansion that builds a program name, an interpreter or
//! a lookup the lookup reader did not prove, or fed to a launcher, a
//! `find -exec` or an option that can stand before the program.
//!
//! Two reads come out of the same scan. `bounded_substitutions` answers the
//! strict question: may the text be rewritten with the output stood in for,
//! and whose owners does it add. `reviewable_substitutions` answers the
//! weaker one the uncertain floor asks: can every program this text runs be
//! named well enough to put the command on a review card. Only the second
//! reads a value an assignment keeps, and it never lowers a floor: the
//! uncertain floor starts at `review` and only rises, so the most a command
//! gains by clearing it is an approval card where it had a block with
//! nothing to answer.

use std::collections::BTreeSet;

use super::{find_exec_programs, is_assignment, named_words, INTERPRETERS, SHELL_PREFIXES};

/// Stands in for a bounded substitution's output: one ordinary word.
const OUTPUT: &str = "guard_substituted_output";

/// Lookups the lookup reader proves on its own. One it left in place names a
/// word it could not prove is an operand.
const LOOKUPS: &[&str] = &["command", "which", "type", "whence", "where", "hash"];

/// Launchers the unmodeled reader does not list as interpreters. Each runs
/// the program named by a later word.
const LAUNCHERS: &[&str] = &[
    "pkexec",
    "runuser",
    "unshare",
    "nsenter",
    "firejail",
    "systemd-run",
];

/// How far a substitution's output is followed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ValueFlow {
    /// To an argument of a program this text names. The rewrite read.
    Arguments,
    /// Also to a value a standalone assignment keeps. The reviewability read.
    Assignments,
}

pub(super) struct BoundedSubstitutions {
    /// The text with each bounded substitution replaced by an inert word.
    pub(super) text: String,
    /// The programs the substitutions run and the commands their output
    /// reaches.
    pub(super) programs: BTreeSet<String>,
}

/// The text with every `$(...)` read as the words it prints and every `<(...)`
/// as the path it opens, or `None` when one is not bounded. Text with no
/// substitution comes back unchanged.
pub(super) fn bounded_substitutions(text: &str) -> Option<BoundedSubstitutions> {
    scan(text, ValueFlow::Arguments)
}

/// The same read, following a value a standalone assignment keeps as well.
///
/// `latest=$(ls | sort -V | tail -n 1)` runs exactly the programs it names and
/// keeps their output as a word the rest of the text expands, yet no program
/// receives that output here, so the rewrite read stops and the command
/// reached an evaluation failure: a block with no approval row, where the same
/// pipeline written as an argument got a review card. The commands that expand
/// the name are its receivers and join the owners, so a contributed extension
/// that owns one still judges arguments this text does not hold.
pub(super) fn reviewable_substitutions(text: &str) -> Option<BoundedSubstitutions> {
    scan(text, ValueFlow::Assignments)
}

fn scan(text: &str, flow: ValueFlow) -> Option<BoundedSubstitutions> {
    if text.contains("<<") || text.contains('`') {
        return None;
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut programs = BTreeSet::new();
    let (mut single, mut double, mut escaped) = (false, false, false);
    // The words of the current simple command, and whether the word being read
    // is the target of a redirect.
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut redirect_target = false;
    // The names standalone assignments gave a substitution's output.
    let mut assigned: BTreeSet<String> = BTreeSet::new();
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        if single {
            single = character != '\'';
            word.push(character);
            out.push(character);
            index += 1;
            continue;
        }
        if escaped {
            escaped = false;
            word.push(character);
            out.push(character);
            index += 1;
            continue;
        }
        if character == '$' && chars.get(index + 1) == Some(&'(') {
            // `$(( … ))` is arithmetic: it expands to a number and runs no
            // program at all. The shell reads the same three characters as a
            // substitution around a subshell only when the arithmetic does
            // not close on a `))` of its own, so `$((count + 1))` is a number
            // and `$((cat id) | sh)` is a pipeline.
            let arithmetic = match chars.get(index + 2) {
                Some(&'(') => Some(crate::parser_segments::arithmetic_close(&chars, index)?),
                _ => None,
            };
            let close = match arithmetic {
                Some(close) => close,
                None => closing_parenthesis(&chars, index + 2)?,
            };
            let receiver = receiving_program(
                &words,
                &word,
                redirect_target,
                flow,
                command_continues(&chars, close + 1),
            )?;
            if receiver.is_none() {
                if let Some((name, _)) = word.split_once('=') {
                    assigned.insert(name.to_owned());
                }
            }
            // Arithmetic prints a number and reaches no program of its own,
            // so it leaves the owner set the rest of the text names.
            let printed = match arithmetic {
                Some(_) => crate::parser_segments::ARITHMETIC_VALUE,
                None => {
                    let inner: String = chars[index + 2..close].iter().collect();
                    programs.extend(inner_programs(&inner, flow)?);
                    programs.extend(receiver);
                    OUTPUT
                }
            };
            word.push_str(printed);
            out.push_str(printed);
            index = close + 1;
            continue;
        }
        if character == '<' && !double && chars.get(index + 1) == Some(&'(') {
            // `<(cmd)` runs `cmd` and leaves the path of a pipe the command
            // around it opens for reading. That path is an operand, never a
            // program, an operator or a redirect target, so the shape reads
            // exactly as a printed word does. Inside double quotes the same
            // characters are literal text and never run anything, and `>(cmd)`
            // writes into a program this text does not bound, so neither is
            // read here.
            let close = closing_parenthesis(&chars, index + 2)?;
            let receiver = receiving_program(
                &words,
                &word,
                redirect_target,
                flow,
                command_continues(&chars, close + 1),
            )?;
            if receiver.is_none() {
                if let Some((name, _)) = word.split_once('=') {
                    assigned.insert(name.to_owned());
                }
            }
            let inner: String = chars[index + 2..close].iter().collect();
            programs.extend(inner_programs(&inner, flow)?);
            programs.extend(receiver);
            word.push_str(OUTPUT);
            out.push_str(OUTPUT);
            index = close + 1;
            continue;
        }
        if character == '$' && chars.get(index + 1) == Some(&'{') {
            // `${NAME}` is one parameter, part of the word it sits in. Bash
            // 5.3 runs `${ cmd; }` and `${| cmd; }`, and a nested
            // substitution runs whatever it names.
            let close = chars[index..].iter().position(|value| *value == '}')? + index;
            let parameter: String = chars[index + 2..close].iter().collect();
            if parameter.is_empty()
                || parameter.starts_with(|value: char| value.is_whitespace() || value == '|')
                || parameter.contains(['$', '`', '(', '{'])
            {
                return None;
            }
            let parameter: String = chars[index..=close].iter().collect();
            word.push_str(&parameter);
            out.push_str(&parameter);
            index = close + 1;
            continue;
        }
        out.push(character);
        index += 1;
        match character {
            '\\' => escaped = true,
            '\'' if !double => single = true,
            '"' => double = !double,
            _ if double => word.push(character),
            '<' | '>' => {
                // `2>` names a descriptor, not an argument.
                if !word.is_empty() && !word.chars().all(|value| value.is_ascii_digit()) {
                    words.push(std::mem::take(&mut word));
                }
                word.clear();
                redirect_target = true;
                // `>&`, `>>`, `>|` and `<>` are one operator.
                while let Some(&next) = chars.get(index) {
                    if !matches!(next, '&' | '>' | '|' | '<') {
                        break;
                    }
                    out.push(next);
                    index += 1;
                }
            }
            ';' | '&' | '|' | '(' | ')' | '{' | '}' | '\n' => {
                words.clear();
                word.clear();
                redirect_target = false;
            }
            _ if character.is_whitespace() => {
                if !word.is_empty() {
                    let finished = std::mem::take(&mut word);
                    if redirect_target {
                        redirect_target = false;
                    } else {
                        words.push(finished);
                    }
                }
            }
            _ => word.push(character),
        }
    }
    // The rewrite read never records an assignment, so this reader is reached
    // only by the reviewability read and the `Arguments` negatives stay exactly
    // where they were.
    if !assigned.is_empty() {
        programs.extend(value_consumers(text, &assigned)?);
    }
    Some(BoundedSubstitutions {
        text: out,
        programs,
    })
}

/// Whether another word of the same simple command follows the position.
///
/// `NAME=$(...)` that stands alone keeps the output as a value the rest of the
/// text expands. `GH_HOST=$(cat host.txt) gh pr list` hands it straight to the
/// command beside it as a setting that program reads, which is neither a value
/// this reader follows nor an argument, so the two shapes are told apart by
/// what comes after the assignment rather than by what came before it.
///
/// The lookahead starts at the word *after* the one the substitution sits in.
/// `latest="$(cat VERSION)"` closes its quote after the `)`, and reading that
/// quote as a following program made an everyday spelling of a standalone
/// assignment look like a prefix, so the value was never followed and the
/// command kept the block this pass exists to remove.
fn command_continues(chars: &[char], start: usize) -> bool {
    let rest: String = chars[start.min(chars.len())..]
        .iter()
        .take_while(|value| !matches!(**value, ';' | '&' | '|' | '\n'))
        .collect();
    let Some((_, following)) = rest.split_once(char::is_whitespace) else {
        return false;
    };
    following
        .split_whitespace()
        .any(|raw| !is_assignment(raw) && !SHELL_PREFIXES.contains(&program_name(raw).as_str()))
}

/// Whether the text expands a parameter one of `names` holds.
///
/// A saved value is read as `$NAME`, as `${NAME}` and through every parameter
/// operator — `${NAME:-fallback}`, `${NAME%%/*}`, `${#NAME}` — so the name is
/// taken out of the reference rather than matched against two spellings.
/// Missing a reference drops the receiver that owns the value, which is the
/// one thing this pass may not do.
fn expands_a_name(piece: &str, names: &BTreeSet<String>) -> bool {
    let chars: Vec<char> = piece.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] != '$' {
            index += 1;
            continue;
        }
        let mut start = index + 1;
        if chars.get(start) == Some(&'{') {
            start += 1;
            // `${#NAME}` is the value's length and `${!NAME}` reads the name
            // the value holds: the parameter still follows the operator.
            while matches!(chars.get(start), Some(&('#' | '!'))) {
                start += 1;
            }
        }
        let mut end = start;
        while chars
            .get(end)
            .is_some_and(|value| value.is_ascii_alphanumeric() || *value == '_')
        {
            end += 1;
        }
        if names.contains(&chars[start..end].iter().collect::<String>()) {
            return true;
        }
        index = end.max(index + 1);
    }
    false
}

/// The programs the text hands a value one of `names` holds.
///
/// A value an assignment keeps reaches the commands that expand the name, so
/// those are its receivers: `TARGET=$(cat id); gh pr view $TARGET` hands the
/// output to `gh` exactly as `gh pr view "$(cat id)"` does, and the owner that
/// judges `gh` arguments still refuses text it cannot read.
///
/// A statement that reads the value without naming the program it reaches is
/// `None`: an owner this reader cannot name is exactly the evaluation failure
/// the pass has to keep. A subshell or a brace group around the statement is
/// read through, because `(gh pr view $TARGET)` runs `gh` and taking the
/// bracket as the receiver would hand the owner check a name no extension can
/// own.
fn value_consumers(text: &str, names: &BTreeSet<String>) -> Option<BTreeSet<String>> {
    let mut consumers = BTreeSet::new();
    for piece in statements(text)? {
        if !expands_a_name(&piece, names) {
            continue;
        }
        let mut receiver = None;
        for raw in piece.split_whitespace() {
            let raw = raw.trim_start_matches(['{', '}']);
            let name = program_name(raw);
            if raw.is_empty()
                || raw.starts_with('-')
                || is_assignment(raw)
                || SHELL_PREFIXES.contains(&name.as_str())
            {
                continue;
            }
            // A program position built from an expansion names whatever the
            // value holds, and one that is quoting alone names nothing this
            // reader can hand an owner check.
            if raw.contains('$') || name.is_empty() {
                return None;
            }
            // A construct that rebinds the value to a name this reader does
            // not follow hands it to a program the text names nowhere this
            // scan reads: in `for t in $TARGET; do gh pr view $t; done` the
            // receiver is `for`, and taking that for the owner would drop
            // `gh` from the set the owner check reads.
            if matches!(
                name.as_str(),
                "for"
                    | "select"
                    | "set"
                    | "read"
                    | "mapfile"
                    | "readarray"
                    | "getopts"
                    | "done"
                    | "eval"
            ) {
                return None;
            }
            receiver = Some(name);
            break;
        }
        consumers.insert(receiver?);
    }
    Some(consumers)
}

/// The text's statements, split where the shell reads a separator.
///
/// A `(`, a `)` or a `|` inside a quoted word is ordinary text:
/// `printf "(%s)" "$version"` is one statement whose program is `printf`.
/// Splitting on the parenthesis cut it in half and left a piece whose first
/// word was quoting, so the receiver that owns the value was lost.
///
/// A `#` that opens a word starts a comment the shell runs nothing from, so
/// the rest of the line is dropped rather than read as a statement whose
/// program is `#`. Text whose quoting never closes is `None`: an open quote
/// swallows every separator after it, and the piece holding the value would
/// carry words belonging to statements that are not its own.
fn statements(text: &str) -> Option<Vec<String>> {
    let mut pieces = vec![String::new()];
    let (mut single, mut double, mut escaped, mut comment) = (false, false, false, false);
    let mut word_start = true;
    for character in text.chars() {
        if comment {
            if character == '\n' {
                comment = false;
                pieces.push(String::new());
                word_start = true;
            }
            continue;
        }
        if single {
            single = character != '\'';
        } else if escaped {
            escaped = false;
        } else {
            match character {
                '\\' => escaped = true,
                '\'' if !double => single = true,
                '"' => double = !double,
                '#' if !double && word_start => {
                    comment = true;
                    continue;
                }
                '\n' | ';' | '&' | '|' | '(' | ')' if !double => {
                    pieces.push(String::new());
                    word_start = true;
                    continue;
                }
                _ => {}
            }
        }
        word_start = !single && !double && character.is_whitespace();
        if let Some(piece) = pieces.last_mut() {
            piece.push(character);
        }
    }
    (!single && !double).then_some(pieces)
}

/// The program a substitution's result reaches, or `None` when this text does
/// not name it.
///
/// Output glued to the command's first word is part of the program name, and
/// output read before any word is an assignment or a prefix: neither is an
/// argument. A launcher such as `timeout` or `sudo`, or a `find -exec`, runs
/// a program named by a later word, and an option in command position, such as
/// the `-p` of `command -p`, can be followed by the program itself. `env
/// NAME=$(...)` and `make NAME=$(...)` set a variable the program reads, so a
/// word shaped like a setting is never read as a substitution's result
/// whatever program receives it. The POSIX dot builtin runs what it is given
/// as shell code, exactly as `source` does, so it is refused the same way.
fn receiving_program(
    words: &[String],
    word: &str,
    redirect_target: bool,
    flow: ValueFlow,
    followed: bool,
) -> Option<Option<String>> {
    if redirect_target {
        return None;
    }
    if is_assignment(word) {
        // `NAME=$(...)` keeps the output as a value: no program receives it
        // here. The reviewability read follows that value to the commands
        // that expand the name; the rewrite read stops, because a prefix
        // assignment hands the value straight to the program the rest of this
        // command names and `env NAME=` and `make NAME=` are settings whatever
        // program receives them.
        return (flow == ValueFlow::Assignments && words.is_empty() && !followed).then_some(None);
    }
    let receiver = words
        .iter()
        .skip_while(|word| SHELL_PREFIXES.contains(&word.as_str()))
        .find(|word| !is_assignment(word))?;
    let name = program_name(receiver);
    if receiver.starts_with('-')
        || name == "."
        || INTERPRETERS.contains(&name.as_str())
        || LAUNCHERS.contains(&name.as_str())
        || words
            .iter()
            .any(|word| matches!(word.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir"))
    {
        return None;
    }
    Some(Some(name))
}

/// The `)` that closes a substitution opened just before `start`. A nested
/// parenthesis, an unterminated quote or a missing close is `None`.
fn closing_parenthesis(chars: &[char], start: usize) -> Option<usize> {
    let (mut single, mut double, mut escaped) = (false, false, false);
    for (index, &character) in chars.iter().enumerate().skip(start) {
        if single {
            single = character != '\'';
        } else if escaped {
            escaped = false;
        } else {
            match character {
                '\\' => escaped = true,
                '\'' if !double => single = true,
                '"' => double = !double,
                ')' if !double => return Some(index),
                '(' if !double => return None,
                _ => {}
            }
        }
    }
    None
}

/// The programs a substitution's text runs when each is named and plain.
/// A `#` is refused along with the other shell punctuation: the scan for the
/// closing `)` does not read comments, so a `)` inside one ends the text early
/// and the words after it would never reach this list.
fn inner_programs(inner: &str, flow: ValueFlow) -> Option<Vec<String>> {
    if inner.contains(['`', '<', '>', '(', ')', '\n', '#'])
        || inner.contains("$(")
        || !expansions_are_names(inner)
    {
        return None;
    }
    let mut programs = Vec::new();
    let mut plain = inner.to_owned();
    // An `-exec` action runs a program only this reader names, whatever
    // spelling ends its body: `-exec basename {} \;` and `-exec basename ';'`
    // are the same walk, so the brace-free one must not skip the reader that
    // refuses an interpreter, a launcher or an expansion standing there.
    //
    // An action only runs something when a `find` is there to run it. Both
    // halves are read out of `named_words`, so a quoted spelling cannot hide
    // either from the walk reader, and both are required, so neither
    // `rg -- "-exec" src` nor `grep -r find src` is mistaken for a walk.
    let named = named_words(inner);
    // `gfind` and `/opt/homebrew/bin/gnufind` run the same walk, so the walk
    // reader judges every program whose name ends in `find` and lets it refuse
    // the ones it does not recognise. A `-exec` that no walker could be running
    // -- `rg -l -- "-exec" src` -- is ordinary text.
    let walks = flow == ValueFlow::Assignments
        && named.iter().any(|name| name.ends_with("find"))
        && super::EXEC_ACTIONS
            .iter()
            .any(|action| named.contains(*action));
    if inner.contains(['{', '}', '\\']) {
        // `{}` is find's placeholder for the path it found and `\;` ends an
        // `-exec` body: neither opens a brace group nor hides punctuation, and
        // the walk's programs are the ones `find_exec_programs` already reads
        // outside a substitution. Any other brace or escape stays refused.
        if !walks {
            return None;
        }
        plain = inner.replace("{}", " ").replace("\\;", " ");
        if plain.contains(['{', '}', '\\']) {
            return None;
        }
    }
    if walks {
        let walked = find_exec_programs(inner)?;
        if walked.is_empty() {
            return None;
        }
        programs.extend(walked);
    }
    // An interpreter runs text this scan does not hold. The rewrite read looks
    // for its name anywhere in the substitution; the reviewability read looks
    // at the programs it runs, because a word such as `versions/node` inside a
    // path the substitution reads starts nothing.
    if flow != ValueFlow::Assignments
        && named
            .iter()
            .any(|name| INTERPRETERS.contains(&name.as_str()))
    {
        return None;
    }
    for command in split_commands(&plain)? {
        let Some(first) = command.split_whitespace().next() else {
            continue;
        };
        let first = first.trim_matches(['\'', '"']);
        let name = program_name(first);
        if first.is_empty()
            || first.starts_with('-')
            || is_assignment(first)
            || !first
                .chars()
                .all(|value| value.is_ascii_alphanumeric() || "._-/+".contains(value))
            || SHELL_PREFIXES.contains(&name.as_str())
            || LOOKUPS.contains(&name.as_str())
        {
            return None;
        }
        programs.push(name);
    }
    if flow == ValueFlow::Assignments
        && programs
            .iter()
            .any(|name| INTERPRETERS.contains(&name.as_str()))
    {
        return None;
    }
    (!programs.is_empty()).then_some(programs)
}

/// The commands of a substitution's text, split on `|`, `||`, `&&` and `;`
/// outside quotes. A lone `&` would start a job the substitution never waits
/// for, so it is `None`.
fn split_commands(inner: &str) -> Option<Vec<String>> {
    let chars: Vec<char> = inner.chars().collect();
    let mut commands = vec![String::new()];
    let (mut single, mut double) = (false, false);
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        index += 1;
        if single {
            single = character != '\'';
        } else if character == '\'' && !double {
            single = true;
        } else if character == '"' {
            double = !double;
        } else if !double && matches!(character, '|' | ';' | '&') {
            let doubled = matches!(character, '|' | '&') && chars.get(index) == Some(&character);
            if character == '&' && !doubled {
                return None;
            }
            if doubled {
                index += 1;
            }
            commands.push(String::new());
            continue;
        }
        commands.last_mut()?.push(character);
    }
    (!single && !double).then_some(commands)
}

/// Every `$` starts a plain parameter name, such as `$PWD`, `$1` or `$?`.
fn expansions_are_names(inner: &str) -> bool {
    let chars: Vec<char> = inner.chars().collect();
    chars.iter().enumerate().all(|(index, &character)| {
        character != '$'
            || chars
                .get(index + 1)
                .is_some_and(|next| next.is_ascii_alphanumeric() || matches!(next, '_' | '?'))
    })
}

/// A program word as the floor names it: lowercase, its basename, without a
/// Windows suffix.
fn program_name(word: &str) -> String {
    let lowered = word.trim_matches(['\'', '"']).to_ascii_lowercase();
    let base = lowered.rsplit(['/', '\\']).next().unwrap_or_default();
    base.strip_suffix(".exe")
        .or_else(|| base.strip_suffix(".cmd"))
        .unwrap_or(base)
        .to_owned()
}
