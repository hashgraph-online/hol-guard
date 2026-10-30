//! A conditional written as one item of a longer command list, as in
//! `git status && if [ -f .git/MERGE_HEAD ]; then echo merging; fi && git log -1`.
//!
//! `control_flow_flatten` reads a command that is one conditional on its own.
//! Here the conditional's lists are written out in its place, so the list
//! above becomes `git status && [ -f .git/MERGE_HEAD ]; echo merging && git log -1`.
//! The flat list runs every command the original can, in the same order, and
//! each one still faces the ordinary proofs.
//!
//! A branch the test skips does not run, so a command inside the conditional
//! that changes what later commands see (the directory, a variable, an option,
//! a function) would make the flat list describe a context the original may
//! never be in. A conditional holding one of those is not spliced, and neither
//! is a nested construct, a subshell, a group, a substitution, a here-document
//! or a background job anywhere in the command. Anything else this does not
//! fully understand returns `None` and keeps the existing review.

use super::control_flow_flatten::{
    conditional_parts, keyword, unnegated_part, MAX_FLATTENED_BYTES,
};

/// Commands that change the state later commands in the same shell run with.
const STATE_CHANGING: &[&str] = &[
    "cd",
    "pushd",
    "popd",
    "export",
    "unset",
    "set",
    "shopt",
    "setopt",
    "unsetopt",
    "source",
    ".",
    "alias",
    "unalias",
    "umask",
    "eval",
    "exec",
    "read",
    "mapfile",
    "readarray",
    "declare",
    "typeset",
    "local",
    "readonly",
    "trap",
    "hash",
    "builtin",
    "command",
    "enable",
    "ulimit",
    "getopts",
    "let",
    "shift",
    "chdir",
    "integer",
    "float",
    "private",
    "autoload",
    "unfunction",
    "unhash",
    "emulate",
    "zmodload",
    "vared",
    "disable",
    "noglob",
    "nocorrect",
    "-",
];

/// Keywords that open or continue a construct this splice does not read.
const OTHER_CONSTRUCTS: &[&str] = &[
    "for", "while", "until", "case", "select", "function", "coproc", "then", "else", "elif", "fi",
    "do", "done", "esac", "in",
];

/// The command list with each top-level conditional replaced by the lists it
/// holds, or `None` when the command holds no such conditional or anything
/// around it is outside the plain list grammar.
pub(super) fn spliced(command: &str) -> Option<String> {
    if command
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return None;
    }
    let mut rest = command.trim();
    let mut out = String::new();
    let mut spliced_any = false;
    while let Some(start) = next_conditional(rest)? {
        let (before, construct) = rest.split_at(start);
        out.push_str(before);
        let (parts, after) = conditional_parts(keyword(construct, "if")?)?;
        if parts.iter().any(|(item, _)| changes_shell_state(item)) {
            return None;
        }
        let tail = after.trim_start_matches([' ', '\t']);
        if !(tail.is_empty()
            || tail.starts_with("&&")
            || tail.starts_with("||")
            || (tail.starts_with([';', '\n']) && !tail.starts_with(";;")))
        {
            return None;
        }
        let last = parts.len() - 1;
        for (index, (item, separator)) in parts.iter().enumerate() {
            // The last item keeps any `!` it carries: the splice drops its
            // separator and the text around the conditional reads the
            // outcome in its place.
            if index < last {
                out.push_str(&unnegated_part(item, separator));
                out.push_str(separator);
            } else {
                out.push_str(item);
            }
        }
        if !tail.is_empty() {
            out.push(' ');
        }
        if out.len() > MAX_FLATTENED_BYTES {
            return None;
        }
        spliced_any = true;
        rest = tail;
    }
    out.push_str(rest);
    (spliced_any && out.len() <= MAX_FLATTENED_BYTES).then_some(out)
}

/// The byte offset of the first `if` in command position, `Some(None)` when
/// there is none, or `None` when the text leaves the plain list grammar.
fn next_conditional(text: &str) -> Option<Option<usize>> {
    let bytes = text.as_bytes();
    let mut command_position = true;
    // A conditional read from a pipe gives its stdin to every list inside it,
    // which no flat list can say.
    let mut piped = false;
    let mut word_start = true;
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        match byte {
            b' ' | b'\t' => {
                word_start = true;
                i += 1;
                continue;
            }
            b'\n' | b';' => {
                if text[i..].starts_with(";;") || text[i..].starts_with(";&") {
                    return None;
                }
                command_position = true;
                i += 1;
            }
            b'|' => {
                let or = text[i..].starts_with("||");
                command_position = true;
                piped = !or;
                i += if or { 2 } else { 1 };
                word_start = true;
                continue;
            }
            b'&' => {
                if text[i..].starts_with("&&") {
                    command_position = true;
                    i += 2;
                } else if text[i..].starts_with("&>")
                    || (i > 0 && matches!(bytes[i - 1], b'>' | b'<'))
                {
                    command_position = false;
                    i += 1;
                } else {
                    return None;
                }
            }
            b'\'' => {
                i += 1 + text[i + 1..].find('\'')? + 1;
                command_position = false;
            }
            b'"' => {
                i = double_quote_end(text, i)?;
                command_position = false;
            }
            b'\\' => {
                i += 1 + text[i + 1..].chars().next()?.len_utf8();
                command_position = false;
            }
            b'`' | b'(' | b')' | b'{' | b'}' => return None,
            b'$' if text[i..].starts_with("$(") || text[i..].starts_with("$[") => return None,
            b'<' if text[i..].starts_with("<<") => return None,
            b'#' if word_start => return None,
            _ => {
                if command_position {
                    let word = &text[i..];
                    if starts_with_word(word, "if") {
                        return (!piped).then_some(Some(i));
                    }
                    if OTHER_CONSTRUCTS
                        .iter()
                        .any(|keyword| starts_with_word(word, keyword))
                    {
                        return None;
                    }
                }
                command_position = false;
                i += text[i..].chars().next()?.len_utf8();
            }
        }
        if !matches!(byte, b'\n' | b';' | b'&') {
            piped = false;
        }
        word_start = matches!(byte, b'\n' | b';' | b'&');
    }
    Some(None)
}

/// The offset just past the `"` that closes the one at `open`. A command
/// substitution inside the quotes leaves the plain grammar.
fn double_quote_end(text: &str, open: usize) -> Option<usize> {
    let mut chars = text[open + 1..].char_indices();
    while let Some((offset, c)) = chars.next() {
        match c {
            '"' => return Some(open + 1 + offset + 1),
            '`' => return None,
            '\\' => {
                chars.next()?;
            }
            '$' if text[open + 1 + offset..].starts_with("$(") => return None,
            _ => {}
        }
    }
    None
}

fn starts_with_word(text: &str, word: &str) -> bool {
    text.strip_prefix(word)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with([' ', '\t', '\n', ';', '&', '|']))
}

/// Whether running this item, or skipping it, changes what later commands see:
/// a state builtin at the head of any stage, a nested construct's keyword, or
/// a head word the shell would rewrite first (quoted, escaped or expanded), so
/// its real name is unknown here.
fn changes_shell_state(item: &str) -> bool {
    item.split('|').any(|stage| {
        let first = stage.split_whitespace().next().unwrap_or_default();
        STATE_CHANGING.contains(&first)
            || first == "if"
            || OTHER_CONSTRUCTS.contains(&first)
            || first.contains(['\'', '"', '\\', '$'])
            || (first == "printf" && stage.split_whitespace().any(|word| word.starts_with("-v")))
            || first.split_once('=').is_some_and(|(name, _)| {
                !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
    })
}

#[cfg(test)]
#[path = "control_flow_chain_tests.rs"]
mod tests;
