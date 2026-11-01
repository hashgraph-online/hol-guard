//! Telling an interpreter the text runs from one it only hands another program.
use super::xargs::command_index;
use super::{command_basename, INTERPRETERS};
use crate::launch_screen::PRIVILEGE_WRAPPERS;

/// Words that run the program their own operands name without standing among
/// the interpreters.
///
/// A launcher's first operand is its command, not a file it reads: `run0 node
/// app.js` runs `node`. `coproc` and `trap` are shell keywords that take
/// command text, and `runuser` is `su`'s non-interactive spelling.
const LAUNCHERS: &[&str] = &["coproc", "runuser", "trap"];

/// The text with each piece's plain operand words removed, keeping every word
/// that can name a program.
///
/// A program's own name is read out of its command position. `foo fd` runs
/// `foo` and hands it the word `fd`, and an unknown `foo` is no more likely to
/// run that word than it is to run the `bar` in `foo bar`, which has always
/// been reviewed behind an approval card. Reading the operand as a program
/// refused ordinary work outright, with no approval left to give it, for every
/// name that stands among the interpreters: `foo env`, `foo node`, `foo watch`
/// and `foo source` all blocked while `foo bar` ran.
///
/// Only a bare word that follows no option is dropped. One that carries an
/// expansion, a glob, a quote or an `=` may still spell a program this reader
/// cannot follow, and the word after an option is the value that option names:
/// `find . -exec xargs wc \;`, `foo --pre node` and `fd -x rm` all hand their
/// option a program, so the word after any option stays. A piece whose own
/// program runs what it is handed keeps every word it holds, and that is not
/// only the interpreters: a privilege wrapper and a launcher each run their
/// first operand, so `pkexec bash -c x` and `run0 node app.js` are unchanged. A piece with no command position of its own is kept whole.
pub(super) fn text_in_command_positions(shell: &str) -> String {
    let mut pieces: Vec<String> = Vec::new();
    for piece in shell.split(['\n', ';', '&', '|', '(', ')', '`']) {
        let words: Vec<&str> = piece.split_whitespace().collect();
        let Some(command) = command_index(&words) else {
            // Nothing in the piece holds a command position, so this reader
            // cannot say which word is an operand.
            pieces.push(words.join(" "));
            continue;
        };
        if runs_its_operands(words[command]) {
            // The piece runs what it is handed, so its operands are command
            // text: `sh -c 'fd -x rm'`, `xargs rm` and `pkexec bash -c x` keep
            // every word.
            pieces.push(words.join(" "));
            continue;
        }
        let kept: Vec<&str> = words
            .iter()
            .enumerate()
            .filter(|(index, word)| {
                *index <= command
                    || !is_bare_operand(word)
                    // The word after an option is the value that option names,
                    // and an option this reader does not know may name the
                    // program its command runs.
                    || words[index - 1].starts_with('-')
            })
            .map(|(_, word)| *word)
            .collect();
        pieces.push(kept.join(" "));
    }
    pieces.join("\n")
}

/// Whether the word is an ordinary literal argument.
///
/// Anything that could expand, glob, quote or assign is not: those spellings
/// can still carry a program name this reader does not follow, so they stay.
/// An option is not one either: `find src -exec echo {} \;` names the program
/// it runs through `-exec`, which stands among the interpreters itself, and
/// dropping the option word would hide the nested executor the `-exec` reader
/// is there to bound.
fn is_bare_operand(word: &str) -> bool {
    !word.is_empty()
        && !word.starts_with('-')
        && word.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | '+' | '/')
        })
}

/// Whether the word names something that runs the program its operands name.
///
/// The interpreters read command text, and so do two kinds of word that do not
/// stand among them. A privilege wrapper runs its first operand with other
/// credentials, and a launcher takes command text of its own. Dropping an
/// operand under either would hide the program that actually runs: `pkexec
/// bash -c x` would keep only `pkexec`. A shell prefix needs no entry here,
/// because `command_index` walks past one to the command it precedes.
fn runs_its_operands(word: &str) -> bool {
    let name = command_basename(word);
    let name = name.as_str();
    INTERPRETERS.contains(&name) || PRIVILEGE_WRAPPERS.contains(&name) || LAUNCHERS.contains(&name)
}
