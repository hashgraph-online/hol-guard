//! The `a` (append) and `i` (insert) text commands, for scratch edits only.
//!
//! BSD sed spells a line insert as `/pat/a\` followed by the text, which is
//! what an agent reaches for when it adds a line to a scratch copy:
//! `sed -i '' '/export const a/a\
//! export const b = 2;' /tmp/a.ts`.
//!
//! Only the address and the command letter decide what `sed` executes. The
//! text after `a\` is written to the file and never run, so the script is
//! accepted when it is exactly one address, one `a` or `i`, and text that
//! stays one command:
//! - the address is a line number or a `/regex/` that GNU and BSD sed
//!   close at the same slash (no bracket expression holds the delimiter);
//! - the command is followed by a backslash, then the text, optionally after
//!   a newline;
//! - a newline in the text is escaped by a backslash, because an unescaped
//!   one ends the text and starts a new command (`w`, `e`, `r`, ...).
//!
//! Every spelling that is not exactly this stays reviewed.

use super::{bracket_closed, MAX_SCRIPT};

pub(super) fn inert_text_insert(script: &str) -> bool {
    if script.len() > MAX_SCRIPT || script.contains(['\r', '\0']) {
        return false;
    }
    let Some(rest) = after_address(script) else {
        return false;
    };
    let Some(rest) = rest
        .strip_prefix(['a', 'i'])
        .and_then(|rest| rest.strip_prefix('\\'))
    else {
        return false;
    };
    let text = rest.strip_prefix('\n').unwrap_or(rest);
    !text.is_empty() && !text.starts_with('\n') && text_stays_one_command(text)
}

/// The script after a leading line number or `/regex/`. `$` is not accepted:
/// the shell screen refuses it before any expansion could be ruled out.
fn after_address(script: &str) -> Option<&str> {
    let digits = script.bytes().take_while(u8::is_ascii_digit).count();
    if digits > 0 {
        return (digits <= 9).then(|| &script[digits..]);
    }
    let mut chars = script.strip_prefix('/')?.chars().peekable();
    let mut closed = false;
    while let Some(value) = chars.next() {
        match value {
            '\n' => return None,
            '\\' => {
                chars.next().filter(|escaped| *escaped != '\n')?;
            }
            '/' => {
                closed = true;
                break;
            }
            '[' if !bracket_closed(&mut chars, '/') => return None,
            _ => {}
        }
    }
    // A `Peekable` yields a peeked character first, so what is left is
    // exactly the text after the closing slash.
    let unread: usize = chars.map(char::len_utf8).sum();
    closed.then(|| &script[script.len() - unread..])
}

/// A backslash escapes the next character, including a newline, and any
/// other newline would end the text.
fn text_stays_one_command(text: &str) -> bool {
    let mut chars = text.chars();
    while let Some(value) = chars.next() {
        match value {
            '\\' => {
                if chars.next().is_none() {
                    return false;
                }
            }
            '\n' => return false,
            _ => {}
        }
    }
    true
}
