//! `shlex.shlex(text, posix=True, punctuation_chars=True)` with
//! `whitespace_split = True` and no commenters (`_codex_shell_split`).

#[derive(Clone, Copy, PartialEq)]
enum State {
    Space,
    Word,
    Punct,
    Quote(char),
    Escape(Escaped),
}

#[derive(Clone, Copy, PartialEq)]
enum Escaped {
    Word,
    Double,
}

fn is_whitespace(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

fn is_punctuation(c: char) -> bool {
    matches!(c, '(' | ')' | ';' | '<' | '>' | '|' | '&')
}

/// `list(lexer)`; `None` is Python's `ValueError`.
pub(crate) fn shell_split(text: &str) -> Option<Vec<String>> {
    let chars: Vec<char> = text.chars().collect();
    let mut position = 0;
    let mut tokens = Vec::new();
    let mut state = State::Space;
    let mut token = String::new();
    let mut quoted = false;
    loop {
        let next = chars.get(position).copied();
        if next.is_some() {
            position += 1;
        }
        match state {
            State::Space => match next {
                None => return Some(tokens),
                Some(c) if is_whitespace(c) => {
                    if !token.is_empty() || quoted {
                        tokens.push(std::mem::take(&mut token));
                        quoted = false;
                    }
                }
                Some('\\') => state = State::Escape(Escaped::Word),
                Some(c) if is_punctuation(c) => {
                    token.push(c);
                    state = State::Punct;
                }
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
                    Some('\\') if open == '"' => state = State::Escape(Escaped::Double),
                    Some(c) => token.push(c),
                }
            }
            State::Escape(kind) => match next {
                None => return None,
                Some(c) => {
                    let quote = match kind {
                        Escaped::Word => None,
                        Escaped::Double => Some('"'),
                    };
                    if let Some(open) = quote {
                        if c != '\\' && c != open {
                            token.push('\\');
                        }
                    }
                    token.push(c);
                    state = if quote.is_some() {
                        State::Quote('"')
                    } else {
                        State::Word
                    };
                }
            },
            State::Word | State::Punct => {
                let Some(c) = next else {
                    // End of input emits the pending token (it is non-empty or
                    // quoted whenever the state is `a` or `c`).
                    if !token.is_empty() || quoted {
                        tokens.push(std::mem::take(&mut token));
                    }
                    return Some(tokens);
                };
                if is_whitespace(c) {
                    state = State::Space;
                    if !token.is_empty() || quoted {
                        tokens.push(std::mem::take(&mut token));
                        quoted = false;
                    }
                } else if state == State::Punct {
                    if is_punctuation(c) {
                        token.push(c);
                    } else {
                        position -= 1;
                        state = State::Space;
                        tokens.push(std::mem::take(&mut token));
                        quoted = false;
                    }
                } else if c == '\'' || c == '"' {
                    state = State::Quote(c);
                } else if c == '\\' {
                    state = State::Escape(Escaped::Word);
                } else if is_punctuation(c) {
                    position -= 1;
                    state = State::Space;
                    if !token.is_empty() || quoted {
                        tokens.push(std::mem::take(&mut token));
                    }
                    quoted = false;
                } else {
                    token.push(c);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(text: &str) -> Vec<String> {
        shell_split(text).expect("split")
    }

    #[test]
    fn punctuation_lexer_matches_python() {
        assert_eq!(split("a 2>&1"), vec!["a", "2", ">&", "1"]);
        assert_eq!(split("a&&b;c"), vec!["a", "&&", "b", ";", "c"]);
        assert_eq!(split("echo \"x y\"|cat"), vec!["echo", "x y", "|", "cat"]);
        assert_eq!(split("a ''"), vec!["a", ""]);
        assert_eq!(split("x\"a b\"y"), vec!["xa by"]);
        assert_eq!(split("a>/dev/null"), vec!["a", ">", "/dev/null"]);
        assert_eq!(split("(a)"), vec!["(", "a", ")"]);
        assert_eq!(split("a\\ b"), vec!["a b"]);
        assert_eq!(split("a;;b"), vec!["a", ";;", "b"]);
        assert!(shell_split("'a").is_none());
        assert!(shell_split("a\\").is_none());
        assert_eq!(split(""), Vec::<String>::new());
    }
}
