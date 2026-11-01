//! Telling an interpreter the text runs from one it only hands another program.
use super::xargs::command_index;
use super::{command_basename, INTERPRETERS};

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
/// Only a bare word is dropped. One that carries an expansion, a glob, a quote
/// or an `=` may still spell a program this reader cannot follow, and a piece
/// whose own program is an interpreter runs the words it is given, so both
/// keep every word they hold: `sh -c 'fd -x rm'` and `foo --exec=rm` are
/// unchanged. A piece with no command position of its own is kept whole.
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
        if INTERPRETERS.contains(&command_basename(words[command]).as_str()) {
            // The piece runs what it is handed, so its operands are command
            // text: `sh -c 'fd -x rm'` and `xargs rm` keep every word.
            pieces.push(words.join(" "));
            continue;
        }
        let kept: Vec<&str> = words
            .iter()
            .enumerate()
            .filter(|(index, word)| *index <= command || !is_bare_operand(word))
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
