//! Python `shlex` in the exact mode the archive binder uses: POSIX, with
//! `punctuation_chars=True`, `whitespace_split=True` and no comment character.
//!
//! The states mirror `shlex.shlex.read_token`, so a command is tokenised the
//! way the retired Python binder tokenised it. `None` is Python's `ValueError`
//! (an unterminated quote or escape).

const PUNCTUATION: &str = "();<>|&";

#[derive(Clone, Copy, PartialEq)]
enum State {
    Space,
    Word,
    Punctuation,
    Quote(char),
    Escape(Resume),
}

#[derive(Clone, Copy, PartialEq)]
enum Resume {
    Word,
    Quote(char),
}

fn is_whitespace(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\n')
}

/// Every token of `command`, or `None` when Python would raise `ValueError`.
pub(crate) fn split(command: &str) -> Option<Vec<String>> {
    split_with(command, PUNCTUATION, "")
}

/// `shlex.shlex(command, posix=True, punctuation_chars=punctuation)` with
/// `whitespace_split=True` and `commenters` as the comment characters (Python's
/// default is `"#"`: a comment character in a word or between words discards
/// the rest of its line).
pub(crate) fn split_with(
    command: &str,
    punctuation: &str,
    commenters: &str,
) -> Option<Vec<String>> {
    let is_punctuation = |character: char| punctuation.contains(character);
    let is_comment = |character: char| commenters.contains(character);
    let characters: Vec<char> = command.chars().collect();
    let mut index = 0usize;
    let mut tokens = Vec::new();
    loop {
        let mut state = State::Space;
        let mut token = String::new();
        let mut quoted = false;
        let mut exhausted = false;
        loop {
            let next = characters.get(index).copied();
            index += usize::from(next.is_some());
            match state {
                State::Space => match next {
                    None => {
                        exhausted = true;
                        break;
                    }
                    Some(c) if is_whitespace(c) => {
                        if !token.is_empty() || quoted {
                            break;
                        }
                    }
                    Some(c) if is_comment(c) => skip_line(&characters, &mut index),
                    Some('\\') => state = State::Escape(Resume::Word),
                    Some(c) if is_punctuation(c) => {
                        token.push(c);
                        state = State::Punctuation;
                    }
                    Some(c @ ('\'' | '"')) => state = State::Quote(c),
                    Some(c) => {
                        token.push(c);
                        state = State::Word;
                    }
                },
                State::Word => match next {
                    None => {
                        exhausted = true;
                        break;
                    }
                    Some(c) if is_whitespace(c) => {
                        state = State::Space;
                        if !token.is_empty() || quoted {
                            break;
                        }
                    }
                    Some(c) if is_comment(c) => {
                        skip_line(&characters, &mut index);
                        state = State::Space;
                        if !token.is_empty() || quoted {
                            break;
                        }
                    }
                    Some(c @ ('\'' | '"')) => state = State::Quote(c),
                    Some('\\') => state = State::Escape(Resume::Word),
                    Some(c) if is_punctuation(c) => {
                        index -= 1;
                        state = State::Space;
                        if !token.is_empty() || quoted {
                            break;
                        }
                    }
                    Some(c) => token.push(c),
                },
                State::Punctuation => match next {
                    None => {
                        exhausted = true;
                        break;
                    }
                    Some(c) if is_whitespace(c) => {
                        state = State::Space;
                        if !token.is_empty() || quoted {
                            break;
                        }
                    }
                    Some(c) if is_comment(c) => {
                        skip_line(&characters, &mut index);
                        state = State::Space;
                        if !token.is_empty() || quoted {
                            break;
                        }
                    }
                    Some(c) if is_punctuation(c) => token.push(c),
                    Some(_) => {
                        index -= 1;
                        break;
                    }
                },
                State::Quote(open) => {
                    quoted = true;
                    match next {
                        None => return None,
                        Some(c) if c == open => state = State::Word,
                        Some('\\') if open == '"' => state = State::Escape(Resume::Quote(open)),
                        Some(c) => token.push(c),
                    }
                }
                State::Escape(resume) => {
                    let escaped = next?;
                    if let Resume::Quote(open) = resume {
                        if escaped != '\\' && escaped != open {
                            token.push('\\');
                        }
                        state = State::Quote(open);
                    } else {
                        state = State::Word;
                    }
                    token.push(escaped);
                }
            }
        }
        if token.is_empty() && !quoted {
            return Some(tokens);
        }
        tokens.push(token);
        if exhausted {
            return Some(tokens);
        }
    }
}

/// `instream.readline()`: consume through the next newline.
fn skip_line(characters: &[char], index: &mut usize) {
    while let Some(&character) = characters.get(*index) {
        *index += 1;
        if character == '\n' {
            break;
        }
    }
}

/// `shlex.quote`.
pub(crate) fn quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_owned();
    }
    let safe = |c: char| c.is_ascii_alphanumeric() || "@%_+=:,./-_".contains(c);
    if value.chars().all(safe) {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// `shlex.join`.
pub(crate) fn join(tokens: &[String]) -> String {
    tokens
        .iter()
        .map(|t| quote(t))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether `token` is nothing but shell control punctuation.
pub(crate) fn is_control(token: &str) -> bool {
    !token.is_empty() && token.chars().all(|c| PUNCTUATION.contains(c))
}
