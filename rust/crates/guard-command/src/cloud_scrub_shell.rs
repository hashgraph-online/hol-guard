//! Shell tokenisation used by the cloud text scrub
//! (`local_request_snapshots.py` `_shell_tokens`, `shlex.split`,
//! `shlex.quote`). Positions are `char` indices, like Python string indices.

#[derive(Clone, Debug)]
pub(crate) struct ShellToken {
    pub value: String,
    pub start: usize,
    pub end: usize,
    pub is_control: bool,
}

/// Python `str.isspace()`.
pub(crate) fn py_isspace(c: char) -> bool {
    matches!(
        c,
        '\t'..='\r'
            | '\u{1c}'..='\u{1f}'
            | ' '
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn is_control_char(c: char) -> bool {
    matches!(c, '|' | ';' | '&' | '<' | '>')
}

/// `shlex.split(text, posix=True, comments=False)`; `None` is Python's
/// `ValueError`.
pub(crate) fn shlex_split(text: &str) -> Option<Vec<String>> {
    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Space,
        Word,
        Quote(char),
        Escape(Option<char>),
    }
    let is_whitespace = |c: char| matches!(c, ' ' | '\t' | '\r' | '\n');
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    let mut state = State::Space;
    let mut position = 0usize;
    loop {
        let next = chars.get(position).copied();
        position += 1;
        match state {
            State::Space => match next {
                None => return Some(tokens),
                Some(c) if is_whitespace(c) => {
                    if !token.is_empty() || quoted {
                        tokens.push(std::mem::take(&mut token));
                        quoted = false;
                    }
                }
                Some('\\') => state = State::Escape(None),
                Some(c @ ('\'' | '"')) => state = State::Quote(c),
                Some(c) => {
                    token.push(c);
                    state = State::Word;
                }
            },
            State::Quote(open) => {
                quoted = true;
                match next {
                    None => return None,
                    Some(c) if c == open => state = State::Word,
                    Some('\\') if open == '"' => state = State::Escape(Some(open)),
                    Some(c) => token.push(c),
                }
            }
            State::Escape(escaped_in) => match next {
                None => return None,
                Some(c) => {
                    if let Some(open) = escaped_in {
                        if c != '\\' && c != open {
                            token.push('\\');
                        }
                        token.push(c);
                        state = State::Quote(open);
                    } else {
                        token.push(c);
                        state = State::Word;
                    }
                }
            },
            State::Word => match next {
                None => {
                    if !token.is_empty() || quoted {
                        tokens.push(std::mem::take(&mut token));
                    }
                    return Some(tokens);
                }
                Some(c) if is_whitespace(c) => {
                    state = State::Space;
                    if !token.is_empty() || quoted {
                        tokens.push(std::mem::take(&mut token));
                        quoted = false;
                    }
                }
                Some(c @ ('\'' | '"')) => state = State::Quote(c),
                Some('\\') => state = State::Escape(None),
                Some(c) => token.push(c),
            },
        }
    }
}

/// `shlex.quote`.
pub(crate) fn shlex_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_owned();
    }
    let safe = |c: char| {
        c.is_ascii_alphanumeric()
            || matches!(c, '_' | '@' | '%' | '+' | '=' | ':' | ',' | '.' | '/' | '-')
    };
    if value.chars().all(safe) {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// `_shell_tokens`; `None` when the text is not tokenisable.
pub(crate) fn shell_tokens(value: &[char]) -> Option<Vec<ShellToken>> {
    let mut tokens = Vec::new();
    let length = value.len();
    let mut index = 0usize;
    while index < length {
        while index < length && py_isspace(value[index]) {
            index += 1;
        }
        if index >= length {
            break;
        }
        let start = index;
        if is_control_char(value[index]) {
            let pair_len = if index + 1 < length {
                let pair = [value[index], value[index + 1]];
                matches!(pair, ['&', '&'] | ['|', '|'] | ['>', '>'] | ['<', '<'])
            } else {
                false
            };
            index += if pair_len { 2 } else { 1 };
            tokens.push(ShellToken {
                value: value[start..index].iter().collect(),
                start,
                end: index,
                is_control: true,
            });
            continue;
        }
        let mut quote: Option<char> = None;
        while index < length {
            let character = value[index];
            if let Some(open) = quote {
                if open == '"' && character == '\\' {
                    index += 2;
                    continue;
                }
                if character == open {
                    quote = None;
                }
                index += 1;
                continue;
            }
            if character == '\'' || character == '"' {
                quote = Some(character);
                index += 1;
                continue;
            }
            if character == '\\' {
                index += 2;
                continue;
            }
            if py_isspace(character) || is_control_char(character) {
                break;
            }
            index += 1;
        }
        if quote.is_some() {
            return None;
        }
        let end = index.min(length);
        let raw: String = value[start..end].iter().collect();
        let parsed = shlex_split(&raw)?;
        if parsed.len() != 1 {
            return None;
        }
        tokens.push(ShellToken {
            value: parsed.into_iter().next().unwrap_or_default(),
            start,
            end: index,
            is_control: false,
        });
    }
    Some(tokens)
}
