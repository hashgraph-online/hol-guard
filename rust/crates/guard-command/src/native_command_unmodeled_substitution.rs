//! A command substitution whose commands are named in the text prints words
//! into the command around it. `printf '%s\n' "$(dirname "$PWD")"` and
//! `kill $(cat server.pid)` run `dirname` and `cat`, and the output becomes
//! arguments of `printf` and `kill`: never a program, an operator or a
//! redirect target. Every program such a command runs is named, so its owners
//! bound it the way they bound the rest of the text.
//!
//! The substitution that stays an evaluation failure is the one that could run
//! a program the text does not name or put its output somewhere the floor
//! cannot read: in command position, in an assignment, as a redirect target,
//! or holding a nested substitution, a backtick, a redirect, a subshell, a
//! background job, an expansion that builds a program name, an interpreter or
//! a lookup the lookup reader did not prove, or fed to a launcher, a
//! `find -exec` or an option that can stand before the program.

use std::collections::BTreeSet;

use super::{is_assignment, named_words, INTERPRETERS, SHELL_PREFIXES};

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

pub(super) struct BoundedSubstitutions {
    /// The text with each bounded substitution replaced by an inert word.
    pub(super) text: String,
    /// The programs the substitutions run and the commands their output
    /// reaches.
    pub(super) programs: BTreeSet<String>,
}

/// The text with every `$(...)` read as the words it prints, or `None` when one
/// is not bounded. Text with no substitution comes back unchanged.
pub(super) fn bounded_substitutions(text: &str) -> Option<BoundedSubstitutions> {
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
            if chars.get(index + 2) == Some(&'(') || redirect_target {
                return None;
            }
            // Output glued to the command's first word is part of the program
            // name, and output read before any word is an assignment or a
            // prefix: neither is an argument.
            let receiver = words
                .iter()
                .skip_while(|word| SHELL_PREFIXES.contains(&word.as_str()))
                .find(|word| !is_assignment(word))?;
            // A launcher such as `timeout` or `sudo`, or a `find -exec`, runs
            // a program named by a later word, and an option in command
            // position, such as the `-p` of `command -p`, can be followed by
            // the program itself. The program this output reaches is not
            // named here.
            let name = program_name(receiver);
            if receiver.starts_with('-')
                || INTERPRETERS.contains(&name.as_str())
                || LAUNCHERS.contains(&name.as_str())
                || words
                    .iter()
                    .any(|word| matches!(word.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir"))
            {
                return None;
            }
            // `env NAME=$(...)` and `make NAME=$(...)` set a variable the
            // program reads. A word shaped like a setting is never read as
            // printed output, whatever program receives it.
            if is_assignment(&word) {
                return None;
            }
            let close = closing_parenthesis(&chars, index + 2)?;
            let inner: String = chars[index + 2..close].iter().collect();
            programs.extend(inner_programs(&inner)?);
            programs.insert(program_name(receiver));
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
    Some(BoundedSubstitutions {
        text: out,
        programs,
    })
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
fn inner_programs(inner: &str) -> Option<Vec<String>> {
    if inner.contains(['`', '<', '>', '(', ')', '{', '}', '\n', '\\'])
        || inner.contains("$(")
        || !expansions_are_names(inner)
        || named_words(inner)
            .iter()
            .any(|name| INTERPRETERS.contains(&name.as_str()))
    {
        return None;
    }
    let mut programs = Vec::new();
    for command in split_commands(inner)? {
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
