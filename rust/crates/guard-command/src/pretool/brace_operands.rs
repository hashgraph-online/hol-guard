//! A command list with its comma braces written out as the words the shell
//! makes of them.
//!
//! Bash and zsh expand `{README.md,AGENTS.md}` into two operands before the
//! program runs, so `wc -l {README.md,AGENTS.md}` is `wc -l README.md
//! AGENTS.md`. The single-command proofs read a braced word as one operand
//! they cannot name and sent the whole command to review, while the spelled
//! out form was allowed. Writing the words out lets every step go through the
//! same proofs as its plain spelling, and an extension permission settles the
//! commands the shell actually runs.
//!
//! Only plain lists are rewritten. A braced word next to a quote, a
//! backslash, a `$` or a backtick, an assignment, a redirection target, a
//! comment, a heredoc, a `[[` test, an arithmetic `((` or a `case` (none of
//! which the shell brace-expands the same way, or which this scan does not
//! follow) leaves the command as it was. A `{a..b}` sequence, a brace inside
//! another and an expansion of more than sixteen words are not followed
//! either.

use super::brace_words::shell_brace_words;

/// Longest rewritten command this writes out.
const MAX_REWRITTEN_BYTES: usize = 8 * 1024;

/// `command` with every unquoted comma brace written out as its words, or
/// `None` when no word expands or the command holds a shape this does not
/// follow.
pub(super) fn expanded(command: &str) -> Option<String> {
    if command.contains(['\\', '$', '`'])
        || command.contains("<<")
        || command.contains("((")
        || command.contains("[[")
        || command
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return None;
    }
    let (mut out, mut changed) = (String::with_capacity(command.len()), false);
    let (mut quote, mut redirect_target) = (None::<char>, false);
    let mut word = Word::default();
    for character in command.chars() {
        if let Some(open) = quote {
            word.push(character);
            if character == open {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => {
                quote = Some(character);
                word.quoted = true;
                word.push(character);
            }
            ' ' | '\t' | '\n' | ';' | '&' | '|' | '(' | ')' | '<' | '>' => {
                if !word.text.is_empty() {
                    changed |= word.write(&mut out, redirect_target)?;
                    redirect_target = false;
                }
                redirect_target |= matches!(character, '<' | '>');
                out.push(character);
            }
            _ => {
                if character == '{' {
                    word.brace = true;
                }
                word.push(character);
            }
        }
    }
    if quote.is_some() {
        return None;
    }
    if !word.text.is_empty() {
        changed |= word.write(&mut out, redirect_target)?;
    }
    (changed && out.len() <= MAX_REWRITTEN_BYTES).then_some(out)
}

/// One shell word as the scan reads it.
#[derive(Default)]
struct Word {
    text: String,
    /// The word holds a quote.
    quoted: bool,
    /// The word holds a `{` outside any quote.
    brace: bool,
}

impl Word {
    fn push(&mut self, character: char) {
        self.text.push(character);
    }

    /// Writes the word, or the words it expands to, onto `out` and resets
    /// it. `Some(true)` when it expanded, `None` when it is a word this does
    /// not follow.
    fn write(&mut self, out: &mut String, redirect_target: bool) -> Option<bool> {
        let word = std::mem::take(self);
        if word.text.starts_with('#') || matches!(word.text.as_str(), "case" | "esac") {
            return None;
        }
        if !word.brace {
            out.push_str(&word.text);
            return Some(false);
        }
        // A brace inside another one is not followed: the reader below
        // expands the inner pair first, which repeats the outer words.
        if nested_brace(&word.text) {
            return None;
        }
        let words = shell_brace_words(&word.text)?;
        if words.len() == 1 {
            out.push_str(&word.text);
            return Some(false);
        }
        if word.quoted || redirect_target || word.text.contains('=') {
            return None;
        }
        // An alternative left empty, as in `{,x}`, is dropped by bash but
        // passed as an empty argument by zsh, so it is not followed.
        // A word that would read differently once spelled out is not
        // followed either: `{#,x}` gives the shell a literal `#`, but written
        // out it starts a comment that hides the rest of the line.
        if words.iter().any(|word| changes_parse(word)) {
            return None;
        }
        let words: Vec<&str> = words.iter().rev().map(String::as_str).collect();
        out.push_str(&words.join(" "));
        Some(true)
    }
}

/// Whether `word`, written out as a bare word, would parse as something
/// other than the plain argument the shell passes.
fn changes_parse(word: &str) -> bool {
    word.is_empty()
        // A word of digits next to `<` or `>` would become a descriptor.
        || word.bytes().all(|byte| byte.is_ascii_digit())
        || word.starts_with(['#', '!', '{', '}'])
        || matches!(
            word,
            "case"
                | "esac"
                | "if"
                | "then"
                | "else"
                | "elif"
                | "fi"
                | "for"
                | "while"
                | "until"
                | "do"
                | "done"
                | "in"
                | "function"
                | "select"
                | "time"
                | "coproc"
                | "[["
                | "]]"
        )
}

/// Whether `text` opens a `{` while another is still open.
fn nested_brace(text: &str) -> bool {
    let mut depth = 0usize;
    for character in text.chars() {
        match character {
            '{' if depth > 0 => return true,
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

#[cfg(test)]
#[path = "brace_operands_tests.rs"]
mod tests;
