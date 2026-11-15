//! How `ls`, `grep` and `rg` read their segment text as shell words: which
//! words reach the program exactly as written, and which carry a glob the
//! shell expands first.

pub(super) struct Word {
    pub(super) value: String,
    pub(super) unquoted_glob: bool,
    pub(super) quoted_glob: bool,
    unquoted_expansion: bool,
}

/// Split segment text into shell words, tracking where glob characters sit.
/// `None` for anything beyond plain words and simple quotes, which makes the
/// caller treat every glob character as unquoted.
pub(super) fn quoted_words(text: &str) -> Option<Vec<Word>> {
    let mut words = Vec::new();
    let mut current: Option<Word> = None;
    let mut quote: Option<char> = None;
    for character in text.chars() {
        match quote {
            Some(open) if character == open => quote = None,
            Some(open) => {
                if character == '\\' || (open == '"' && matches!(character, '$' | '`')) {
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
                let word = current.get_or_insert_with(|| Word {
                    value: String::new(),
                    unquoted_glob: false,
                    quoted_glob: false,
                    unquoted_expansion: false,
                });
                // A brace list is expanded too: `.env{,.local}` becomes two
                // words, the second of them a file operand.
                word.unquoted_glob |= matches!(character, '*' | '?' | '[' | '{');
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
