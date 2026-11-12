//! `diff <(sort a.txt) b.txt` and the operand it leaves behind.
//!
//! A process substitution runs its inner command and hands the command around
//! it the path of a pipe to read. The shell parser has no model for the
//! operator, so the whole command reaches the fail-closed path and every
//! read-only comparison asks, which is the common shape for comparing two
//! sorted files, two revisions of one file or a list against a filter.
//!
//! The text names both halves, so both can be proven. This projection puts a
//! plain relative word where each `<(...)` stood and keeps the inner commands
//! beside it. The caller proves the inner commands and the command around them
//! separately, and adopts the projected answer only when every one of them
//! settles to a silent allow on its own. A placeholder reads like any operand
//! the command was handed, so a command that runs, applies or writes what it
//! is given keeps the answer it has for a file.
//!
//! A `#` that begins a word comments out the rest of the line, the `)` that
//! would close a substitution among it, so the text the shell reads is not
//! the text this walk reads. Both walks stop at one instead of guessing which
//! parenthesis closes.
//!
//! Only the input form is read. `>(cmd)` feeds the inner program bytes this
//! text does not hold, a nested substitution or a backtick runs a program the
//! projected text no longer names, and a substitution in command position runs
//! the pipe itself, so each of those keeps the fail-closed path.

use guard_contracts::PreToolResultV1;

/// The projected command and the commands its substitutions run.
pub(super) struct Substitutions {
    pub(super) command: String,
    pub(super) inner: Vec<String>,
}

/// Longest command the walk reads, in bytes.
const MAX_COMMAND_BYTES: usize = 4096;
/// Longest inner command a substitution may hold, in bytes.
const MAX_INNER_BYTES: usize = 512;
/// How many substitutions one command may spend a proof on.
const MAX_SUBSTITUTIONS: usize = 3;
/// The word each substitution leaves behind, numbered from zero.
const PLACEHOLDER: &str = "guard_process_substitution_";

/// Replace every `<(...)` in `raw` with a plain operand, or `None` when any of
/// them is a form this text cannot stand in for.
pub(super) fn project(raw: &str) -> Option<Substitutions> {
    if raw.len() > MAX_COMMAND_BYTES
        || !raw.contains("<(")
        || raw.contains('`')
        || raw.contains("<<")
        || raw.contains(PLACEHOLDER)
    {
        return None;
    }
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::with_capacity(raw.len());
    let mut inner: Vec<String> = Vec::new();
    let mut single = false;
    let mut double = false;
    // Words completed in the simple command being read, so a substitution in
    // command position is told apart from one that is an operand.
    let mut words = 0usize;
    let mut open_word = false;
    let mut index = 0usize;
    while let Some(&current) = chars.get(index) {
        if single {
            out.push(current);
            single = current != '\'';
            index += 1;
            continue;
        }
        if double {
            out.push(current);
            match current {
                '\\' => {
                    if let Some(&escaped) = chars.get(index + 1) {
                        out.push(escaped);
                        index += 1;
                    }
                }
                '"' => double = false,
                _ => {}
            }
            index += 1;
            continue;
        }
        match current {
            '\\' => {
                out.push(current);
                if let Some(&escaped) = chars.get(index + 1) {
                    out.push(escaped);
                    index += 1;
                }
                open_word = true;
            }
            '\'' => {
                single = true;
                open_word = true;
                out.push(current);
            }
            '"' => {
                double = true;
                open_word = true;
                out.push(current);
            }
            '#' if starts_a_comment(&chars, index) => return None,
            '>' if chars.get(index + 1) == Some(&'(') => return None,
            '<' if chars.get(index + 1) == Some(&'(') => {
                if open_word || words == 0 || inner.len() == MAX_SUBSTITUTIONS {
                    return None;
                }
                let close = closing_parenthesis(&chars, index + 2)?;
                let body: String = chars[index + 2..close].iter().collect();
                if !readable_body(&body) {
                    return None;
                }
                out.push_str(PLACEHOLDER);
                out.push_str(&inner.len().to_string());
                inner.push(body);
                words += 1;
                index = close + 1;
                continue;
            }
            '<' | '>' => {
                open_word = false;
                out.push(current);
            }
            ';' | '|' | '&' | '\n' | '(' | ')' => {
                words = 0;
                open_word = false;
                out.push(current);
            }
            _ if current.is_whitespace() => {
                words += usize::from(open_word);
                open_word = false;
                out.push(current);
            }
            _ => {
                open_word = true;
                out.push(current);
            }
        }
        index += 1;
    }
    if single || double || inner.is_empty() {
        return None;
    }
    Some(Substitutions {
        command: out,
        inner,
    })
}

/// Whether the result settles on its own, with nothing shown and nothing to
/// approve. A contained verdict is not one: the sandbox runs the text the call
/// carries, which still holds the operator this projection read past.
pub(super) fn reads_only(result: &PreToolResultV1) -> bool {
    result.decision == "allow"
        && matches!(result.minimum_action.as_str(), "allow" | "warn")
        && !result.action.sensitive_target
}

/// Whether the inner command is one the projected text still names in full.
/// A nested substitution, a backtick or a background job runs a program the
/// proof of this command would not cover.
fn readable_body(body: &str) -> bool {
    !body.trim().is_empty()
        && body.len() <= MAX_INNER_BYTES
        && !body.contains('\n')
        && !body.contains("<(")
        && !body.contains(">(")
        && !body.contains("$(")
        && !body.contains('`')
        && !body.contains('&')
}

/// Whether the `#` at `at` begins a word, where the shell starts a comment
/// that reaches the end of the line. A `#` stuck to the word before it, as in
/// `grep issue#4 notes.md`, is an ordinary character and names no comment.
fn starts_a_comment(chars: &[char], at: usize) -> bool {
    chars[at] == '#'
        && at.checked_sub(1).is_none_or(|before| {
            chars[before].is_whitespace()
                || matches!(chars[before], ';' | '|' | '&' | '(' | ')' | '<' | '>')
        })
}

/// The `)` that closes a substitution opened before `start`, honouring quotes
/// and the parentheses of a subshell inside it.
fn closing_parenthesis(chars: &[char], start: usize) -> Option<usize> {
    let mut depth = 1usize;
    let mut index = start;
    let mut single = false;
    let mut double = false;
    while let Some(&current) = chars.get(index) {
        if single {
            single = current != '\'';
        } else if double {
            match current {
                '\\' => index += 1,
                '"' => double = false,
                _ => {}
            }
        } else {
            match current {
                '\\' => index += 1,
                '\'' => single = true,
                '"' => double = true,
                '#' if starts_a_comment(chars, index) => return None,
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(index);
                    }
                }
                _ => {}
            }
        }
        index += 1;
    }
    None
}

#[cfg(test)]
#[path = "process_substitution_tests.rs"]
mod tests;
