//! Python-exact `shlex.split(text)` (POSIX mode, whitespace splitting, no
//! comment characters). The shell-word rules differ from the general command
//! model in ways that matter here: only space, tab, CR and LF separate words,
//! and a backslash inside double quotes only escapes `\` and `"`.

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Space,
    Word,
    Single,
    Double,
    EscapeWord,
    EscapeDouble,
}

/// Split like Python's `shlex.split`. `None` for an unclosed quote or a
/// dangling escape, which Python reports as `ValueError`.
pub(crate) fn split(text: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    let mut state = State::Space;
    for ch in text.chars() {
        state = match state {
            State::Space | State::Word => match ch {
                ' ' | '\t' | '\r' | '\n' => {
                    if state == State::Word {
                        words.push(std::mem::take(&mut word));
                        quoted = false;
                    }
                    State::Space
                }
                '\\' => State::EscapeWord,
                '\'' => {
                    quoted = true;
                    State::Single
                }
                '"' => {
                    quoted = true;
                    State::Double
                }
                other => {
                    word.push(other);
                    State::Word
                }
            },
            State::Single => match ch {
                '\'' => State::Word,
                other => {
                    word.push(other);
                    State::Single
                }
            },
            State::Double => match ch {
                '"' => State::Word,
                '\\' => State::EscapeDouble,
                other => {
                    word.push(other);
                    State::Double
                }
            },
            State::EscapeWord => {
                word.push(ch);
                State::Word
            }
            State::EscapeDouble => {
                if ch != '\\' && ch != '"' {
                    word.push('\\');
                }
                word.push(ch);
                State::Double
            }
        };
    }
    match state {
        State::Space => {}
        State::Word => {
            if !word.is_empty() || quoted {
                words.push(word);
            }
        }
        State::Single | State::Double | State::EscapeWord | State::EscapeDouble => return None,
    }
    Some(words)
}

#[cfg(test)]
mod tests {
    use super::split;

    fn words(text: &str) -> Option<Vec<String>> {
        split(text)
    }

    #[test]
    fn matches_python_shlex_edges() {
        assert_eq!(
            words("a  b\tc\nd"),
            Some(
                vec!["a", "b", "c", "d"]
                    .into_iter()
                    .map(String::from)
                    .collect()
            )
        );
        assert_eq!(words("''"), Some(vec![String::new()]));
        assert_eq!(words("a''"), Some(vec!["a".to_owned()]));
        assert_eq!(words(" "), Some(vec![]));
        // Non-ASCII and form-feed are ordinary word characters.
        assert_eq!(words("a\u{a0}b"), Some(vec!["a\u{a0}b".to_owned()]));
        assert_eq!(words("a\x0cb"), Some(vec!["a\x0cb".to_owned()]));
        // `#` is not a comment character in `shlex.split`.
        assert_eq!(words("a #b"), Some(vec!["a".to_owned(), "#b".to_owned()]));
        // Backslash in double quotes keeps itself unless escaping `\` or `"`.
        assert_eq!(words(r#""a\$b""#), Some(vec![r"a\$b".to_owned()]));
        assert_eq!(words(r#""a\"b""#), Some(vec![r#"a"b"#.to_owned()]));
        assert_eq!(words(r#""a\\b""#), Some(vec![r"a\b".to_owned()]));
        assert_eq!(words(r"a\ b"), Some(vec!["a b".to_owned()]));
        assert_eq!(words(r"'a\b'"), Some(vec![r"a\b".to_owned()]));
        assert_eq!(words("'open"), None);
        assert_eq!(words("\"open"), None);
        assert_eq!(words("trail\\"), None);
    }
}
