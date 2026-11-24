//! A credential assigned from a command's output is not the credential.
//!
//! Shell scripts, CI steps and setup notes fill a credential variable from a
//! tool: `GH_TOKEN=$(gh auth token)`, `API_KEY="$(op read op://app/api/key)"`,
//! `password=$(security find-generic-password -s app -w)`. The credential
//! assignment rule reads `$(gh` as the value, so reading such a script, or a
//! command line that sets a git credential helper this way, was withheld as a
//! leak although no secret is written in it.
//!
//! The command can still carry a literal. It stays flagged when it prints one
//! (`echo`, `printf`, a here-string or here-document), when any of its words is
//! quoted, when a word reads like key material rather than a name, flag or
//! path, when the substitution is not closed on the line, and when text is
//! joined to it after the closing `)`.

/// How far past the match the closing `)` is looked for.
const MAX_COMMAND_BYTES: usize = 512;

/// A word longer than this that mixes letters and digits reads as key
/// material (`Kq7xY2mN9pL4`), not a command name or flag (`python3`, `-c`,
/// `sha256sum`).
const MAX_MIXED_WORD_CHARS: usize = 10;

/// A word that is not a path and mixes letters and digits over this many
/// characters, once its separators are dropped, reads as key material split
/// into groups (a UUID, `Kq7x-Y2mN-9pL4-vR8t`).
const MAX_JOINED_MIXED_CHARS: usize = 16;

/// A word that is not a path and runs longer than this, once its
/// separators are dropped, reads as key material whatever its characters.
const MAX_PLAIN_WORD_CHARS: usize = 32;

/// Commands that write their arguments to their output.
const PRINTERS: [&str; 5] = ["echo", "printf", "print", "yes", "expr"];

/// Whether a credential assignment match assigns the output of a command
/// substitution that holds no literal. `rest_of_line` is the text after the
/// match on the same line.
pub(crate) fn is_command_substitution(matched: &str, rest_of_line: &str) -> bool {
    let Some(index) = matched.find([':', '=']) else {
        return false;
    };
    let value = matched[index + 1..].trim_start();
    let quoted = value.starts_with('"');
    let opened = value.trim_start_matches('"').trim_start_matches('\\');
    let Some(start) = opened.strip_prefix("$(") else {
        return false;
    };
    let line = format!("{start}{rest_of_line}");
    let Some((command, after)) = closed_command(&line) else {
        return false;
    };
    let after = if quoted {
        match after.strip_prefix('"') {
            Some(rest) => rest,
            None => return false,
        }
    } else {
        after
    };
    ends_word(after) && inert_command(command)
}

/// The command up to its matching `)` and the text after it, if the
/// substitution closes within `MAX_COMMAND_BYTES`.
fn closed_command(line: &str) -> Option<(&str, &str)> {
    let mut depth = 0usize;
    for (at, character) in line.char_indices() {
        if at > MAX_COMMAND_BYTES {
            return None;
        }
        match character {
            '(' => depth += 1,
            ')' if depth == 0 => return Some((&line[..at], &line[at + 1..])),
            ')' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// Whether the shell word ends right after the substitution.
fn ends_word(after: &str) -> bool {
    after.chars().next().is_none_or(|character| {
        character.is_ascii_whitespace() || matches!(character, ';' | ')' | '&' | '|' | '<' | '>')
    })
}

/// Whether every command in `command` takes only names, flags and paths and
/// none of them prints its arguments. A nested substitution, a pipe or a
/// command separator starts a new command, as does a leading `NAME=value`.
fn inert_command(command: &str) -> bool {
    if command.contains(['"', '\'', '`']) || command.contains("<<") {
        return false;
    }
    let spaced = command.replace(['(', ')', '|', ';', '&'], " ; ");
    let mut head = true;
    for word in spaced.split_ascii_whitespace() {
        if word == ";" {
            head = true;
            continue;
        }
        let word = word.trim_start_matches('$');
        let name = word.rsplit('/').next().unwrap_or(word);
        if head && PRINTERS.contains(&name) {
            return false;
        }
        if !inert_word(word) {
            return false;
        }
        head = head && word.contains('=');
    }
    true
}

/// A name, flag, path or short number, not something that reads as key
/// material: no part between separators mixes letters and digits for more
/// than `MAX_MIXED_WORD_CHARS`, and a word that is not a path is not long
/// once its separators are dropped.
fn inert_word(word: &str) -> bool {
    let value = word.split_once('=').map_or(word, |(_, value)| value);
    let separators = ['/', '.', '-', '_', ':', '@', '{', '}', '[', ']', ',', '='];
    let mixed = |text: &str| {
        text.chars().any(|c| c.is_ascii_digit()) && text.chars().any(|c| c.is_ascii_alphabetic())
    };
    let parts_ok = value
        .split(separators)
        .all(|part| !mixed(part) || part.chars().count() <= MAX_MIXED_WORD_CHARS);
    let joined: String = value.chars().filter(|c| !separators.contains(c)).collect();
    let length = joined.chars().count();
    let path = value.contains('/');
    parts_ok
        && (path || !mixed(&joined) || length < MAX_JOINED_MIXED_CHARS)
        && (path || length <= MAX_PLAIN_WORD_CHARS)
}

#[cfg(test)]
#[path = "command_value_tests.rs"]
mod tests;
