//! How `ls`, `grep` and `rg` read their segment text as shell words: which
//! words reach the program exactly as written, and which carry a glob the
//! shell expands first.

pub(in crate::pretool) struct Word {
    pub(super) value: String,
    pub(in crate::pretool) unquoted_glob: bool,
    pub(super) quoted_glob: bool,
    pub(in crate::pretool) unquoted_expansion: bool,
}

/// Split segment text into shell words, tracking where glob characters sit.
/// `None` for anything beyond plain words and simple quotes, which makes the
/// caller treat every glob character as unquoted.
///
/// A backslash inside quotes is read as the shell reads it. Inside single
/// quotes it is an ordinary character. Inside double quotes it escapes only
/// `$`, a backtick, `"`, `\` and a newline; before anything else it stays in
/// the word, so `"a\|b"` hands the program `a\|b`, the alternation `grep`
/// reads. A backslash outside quotes still yields `None`.
pub(in crate::pretool) fn quoted_words(text: &str) -> Option<Vec<Word>> {
    let mut words = Vec::new();
    let mut current: Option<Word> = None;
    let mut quote: Option<char> = None;
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match quote {
            Some(open) if character == open => quote = None,
            Some(open) => {
                let mut character = character;
                if open == '"' && character == '\\' {
                    match characters.peek() {
                        Some('\n') => {
                            characters.next();
                            continue;
                        }
                        // None of these is a glob character, and an escaped
                        // `$` or backtick substitutes nothing.
                        Some(&escaped @ ('$' | '`' | '"' | '\\')) => {
                            characters.next();
                            character = escaped;
                        }
                        _ => {}
                    }
                } else if open == '"' && matches!(character, '$' | '`') {
                    return None;
                }
                let word = current.get_or_insert_with(|| Word {
                    value: String::new(),
                    unquoted_glob: false,
                    quoted_glob: false,
                    unquoted_expansion: false,
                });
                word.quoted_glob |= matches!(character, '*' | '?' | '[');
                word.value.push(character);
            }
            None if matches!(character, '\'' | '"') => {
                quote = Some(character);
                current.get_or_insert_with(|| Word {
                    value: String::new(),
                    unquoted_glob: false,
                    quoted_glob: false,
                    unquoted_expansion: false,
                });
            }
            None if character == '\\' => return None,
            None if character.is_whitespace() => words.extend(current.take()),
            None => {
                let started = current.is_some();
                let word = current.get_or_insert_with(|| Word {
                    value: String::new(),
                    unquoted_glob: false,
                    quoted_glob: false,
                    unquoted_expansion: false,
                });
                // A brace list is expanded too: `.env{,.local}` becomes two
                // words, the second of them a file operand. zsh reads
                // parentheses in a word as a pattern group, so
                // `"app/"(x)"/[id]"` is a glob there even with the class
                // quoted. With `EXTENDED_GLOB` it also reads `^` as "not",
                // `#` as repetition and a `~` after the start of a word as
                // "except", so `"site/"^"[id]"` names every other entry.
                word.unquoted_glob |=
                    matches!(character, '*' | '?' | '[' | '{' | '(' | ')' | '^' | '#')
                        || (character == '~' && started);
                word.unquoted_expansion |= matches!(character, '$' | '`');
                word.value.push(character);
            }
        }
    }
    if quote.is_some() {
        return None;
    }
    words.extend(current);
    Some(words)
}

/// Words of `text` that reach the program exactly as written: every glob
/// character in them is quoted, so the shell expands nothing. A word that
/// shares its text with a word carrying an unquoted glob is left out,
/// because the caller matches by value and cannot tell the two apart. The
/// text is shared when either word ends with the other, since an option
/// reader hands over only the part after the option: `--regexp=".env*"`
/// and an unquoted `-e .env*` both give `grep` the pattern `.env*`. Text with an
/// unquoted `$` or backtick, or a here-document, yields no words: the shell
/// substitutes those, and the parser may hand over a value no word spells.
pub(in crate::pretool) fn literal_words(text: &str) -> Vec<String> {
    if text.contains("<<") {
        return Vec::new();
    }
    let Some(words) = quoted_words(text) else {
        return Vec::new();
    };
    if words.iter().any(|word| word.unquoted_expansion) {
        return Vec::new();
    }
    words
        .iter()
        .filter(|word| {
            !word.unquoted_glob
                && !words
                    .iter()
                    .any(|other| other.unquoted_glob && shared_text(&other.value, &word.value))
        })
        .map(|word| word.value.clone())
        .collect()
}

fn shared_text(left: &str, right: &str) -> bool {
    left.ends_with(right) || right.ends_with(left)
}

#[cfg(test)]
#[path = "listing_words_tests.rs"]
mod tests;
