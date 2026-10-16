//! The body grammar of a `for` loop: the command list between `do` and
//! `done`, the references to the loop variable inside it, and the redirections
//! that may follow the loop.

use super::{CONTROL_WORDS, MAX_BODY_BYTES};

/// Split the body into list items (with the separator that follows each) and
/// return the text after the closing `done`. Items keep a marker where
/// `$NAME` appeared; `substitute` expands it. Any construct outside the simple
/// command list grammar returns `None`.
pub(super) fn body_items<'a>(
    text: &'a str,
    name: &str,
) -> Option<(Vec<(String, &'static str)>, &'a str)> {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut items: Vec<(String, &'static str)> = Vec::new();
    let mut item = String::new();
    // Whether the next word to start is a command word, and whether the
    // previous operator was a redirection (so the next word is its target).
    let mut command_position = true;
    let mut redirect_target = false;
    let mut at_word_start = true;
    let mut i = 0;
    if chars.last().map_or(0, |(index, _)| *index) > MAX_BODY_BYTES {
        return None;
    }
    while i < chars.len() {
        let (byte, c) = chars[i];
        let rest = &text[byte..];
        match c {
            ' ' | '\t' => {
                item.push(c);
                at_word_start = true;
                i += 1;
            }
            '\n' | ';' | '&' | '|' => {
                let (separator, width): (&'static str, usize) =
                    if c == '|' && rest.starts_with("||") {
                        (" || ", 2)
                    } else if c == '&' && rest.starts_with("&&") {
                        (" && ", 2)
                    } else if c == '|' {
                        if rest.starts_with("|&") || item.trim().is_empty() {
                            return None;
                        }
                        item.push('|');
                        command_position = true;
                        redirect_target = false;
                        at_word_start = true;
                        i += 1;
                        continue;
                    } else if c == '&' {
                        // `>&2` and `&>file` are redirections; a lone `&` backgrounds.
                        if item.ends_with(['>', '<']) || rest.starts_with("&>") {
                            item.push('&');
                            redirect_target = true;
                            at_word_start = true;
                            i += 1;
                            continue;
                        }
                        return None;
                    } else if c == ';' && (rest.starts_with(";;") || rest.starts_with(";&")) {
                        return None;
                    } else {
                        ("; ", 1)
                    };
                let trimmed = item.trim().to_owned();
                if trimmed.is_empty() {
                    // Blank separators (after `do`, doubled newlines) are fine;
                    // an empty slot around && or || is not.
                    if separator != "; " {
                        return None;
                    }
                    if let Some(last) = items.last() {
                        if last.1 != "; " {
                            return None;
                        }
                    }
                } else {
                    items.push((trimmed, separator));
                }
                item.clear();
                command_position = true;
                redirect_target = false;
                at_word_start = true;
                i += width;
                if separator == "; " {
                    let after = &text[chars.get(i).map_or(text.len(), |(b, _)| *b)..];
                    let lead = after.trim_start_matches([' ', '\t', '\n', ';']);
                    if starts_with_done(lead) {
                        if items.last().is_none_or(|last| last.1 != "; ") {
                            return None;
                        }
                        return Some((items, &lead["done".len()..]));
                    }
                }
            }
            '>' | '<' => {
                if rest.starts_with("<<") || rest.starts_with("<(") || rest.starts_with(">(") {
                    return None;
                }
                item.push(c);
                command_position = false;
                redirect_target = true;
                at_word_start = true;
                i += 1;
            }
            '`' | '(' | ')' | '{' | '}' => return None,
            '#' if at_word_start => return None,
            '\\' => {
                let next = chars.get(i + 1)?.1;
                if next == '\n' {
                    return None;
                }
                item.push('\\');
                item.push(next);
                at_word_start = false;
                command_position = false;
                redirect_target = false;
                i += 2;
            }
            '\'' => {
                item.push('\'');
                i += 1;
                loop {
                    let q = chars.get(i)?.1;
                    item.push(q);
                    i += 1;
                    if q == '\'' {
                        break;
                    }
                }
                at_word_start = false;
                command_position = false;
                redirect_target = false;
            }
            '"' => {
                let argument = !command_position && !redirect_target;
                item.push('"');
                i += 1;
                loop {
                    let q = chars.get(i)?.1;
                    i += 1;
                    match q {
                        '"' => {
                            item.push('"');
                            break;
                        }
                        '`' => return None,
                        '\\' => {
                            let escaped = chars.get(i)?.1;
                            i += 1;
                            item.push('\\');
                            item.push(escaped);
                        }
                        '$' => item.push_str(&reference(&chars, &mut i, name, argument)?),
                        other => item.push(other),
                    }
                }
                at_word_start = false;
                command_position = false;
                redirect_target = false;
            }
            '$' => {
                let argument = !command_position && !redirect_target;
                i += 1;
                item.push_str(&reference(&chars, &mut i, name, argument)?);
                at_word_start = false;
                command_position = false;
                redirect_target = false;
            }
            other => {
                item.push(other);
                at_word_start = false;
                command_position = false;
                redirect_target = false;
                i += 1;
            }
        }
    }
    None
}

/// Whether a body item can change the loop variable or `IFS`, so a later
/// `$NAME` would not expand to the word written in the header. References
/// are already placeholders here, so any remaining bare `NAME` or `IFS` is a
/// target for `read`, `printf -v`, `declare`, `unset`, an assignment and so
/// on. A `-NAME` flag such as `[ -f ... ]` is not a target; an attached
/// `-vNAME` is.
pub(super) fn rebinds(item: &str, name: &str) -> bool {
    let mut previous = ' ';
    let mut token = String::new();
    let mut flagged = false;
    for c in item.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_alphanumeric() || c == '_' {
            if token.is_empty() {
                flagged = previous == '-';
            }
            token.push(c);
        } else if !token.is_empty() {
            let target = |candidate: &str| {
                if flagged {
                    candidate.strip_prefix('v') == Some(name) || candidate == "vIFS"
                } else {
                    candidate == name || candidate == "IFS"
                }
            };
            if target(&token) {
                return true;
            }
            token.clear();
        }
        previous = c;
    }
    false
}

fn starts_with_done(text: &str) -> bool {
    text.strip_prefix("done").is_some_and(|rest| {
        rest.is_empty() || rest.starts_with([' ', '\t', '\n', ';', '>', '<', '&'])
    })
}

/// Consume a `$NAME` or `${NAME}` reference (the `$` is already consumed) and
/// return a placeholder. A reference in command or redirect position, a
/// different variable, or any other expansion rejects the loop.
fn reference(chars: &[(usize, char)], i: &mut usize, name: &str, argument: bool) -> Option<String> {
    if !argument {
        return None;
    }
    let braced = chars.get(*i).is_some_and(|(_, c)| *c == '{');
    if braced {
        *i += 1;
    }
    let mut ident = String::new();
    while let Some(&(_, c)) = chars.get(*i) {
        if c.is_ascii_alphanumeric() || c == '_' {
            ident.push(c);
            *i += 1;
        } else {
            break;
        }
    }
    if ident != name {
        return None;
    }
    if braced {
        if chars.get(*i)?.1 != '}' {
            return None;
        }
        *i += 1;
    }
    Some(MARKER.to_owned())
}

const MARKER: &str = "\u{1}";

pub(super) fn substitute(item: &str, word: &str) -> Option<String> {
    // Every pipeline stage must start with a plain word: no marker, no
    // assignment, no shell keyword. A leading redirection such as
    // `2>/dev/null $f` would hide the real command word from this check, so a
    // stage that starts with one is rejected. A glob in the command word
    // (`/usr/bin/doc?er`) could name any program, so it keeps the loop on
    // the unmodeled path.
    for stage in item.split('|') {
        let first = stage.split_whitespace().next()?;
        let bare = first.trim_start_matches(|c: char| c.is_ascii_digit());
        if first.contains(MARKER)
            || first.contains('=')
            || bare.starts_with(['>', '<', '&'])
            || (first != "[" && first.contains(['*', '?', '[']))
            || CONTROL_WORDS.contains(&first)
        {
            return None;
        }
    }
    Some(item.replace(MARKER, word))
}

/// The redirect text after `done`, restricted to plain redirections.
pub(super) fn redirect_tail(tail: &str) -> Option<String> {
    // Newlines after done start new commands and must not be trimmed away.
    let tail = tail.trim_start_matches([' ', '\t']).trim_end();
    if tail.is_empty() {
        return Some(String::new());
    }
    if !(tail.starts_with(['>', '<', '&']) || tail.starts_with(|c: char| c.is_ascii_digit())) {
        return None;
    }
    let bytes: Vec<char> = tail.chars().collect();
    for (index, &c) in bytes.iter().enumerate() {
        match c {
            ';' | '|' | '$' | '`' | '(' | ')' | '\n' | '{' | '}' | '#' | '\'' | '"' | '\\'
            | '*' | '?' | '[' | '~' => return None,
            '&' => {
                let prev = index.checked_sub(1).map(|i| bytes[i]);
                if !(prev == Some('>') || bytes.get(index + 1) == Some(&'>')) {
                    return None;
                }
            }
            '<' if bytes.get(index + 1) == Some(&'<') => return None,
            _ => {}
        }
    }
    Some(tail.to_owned())
}
