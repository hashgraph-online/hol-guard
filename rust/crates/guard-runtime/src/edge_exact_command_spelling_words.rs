//! Words of a shell step as written, quotes kept, and where a comment cuts it.

/// The argument where bash's comment starts: the first word that begins
/// with an unquoted `#`. A quoted or escaped `#` is text. The nth earlier
/// word whose first character is `#` once quotes are removed is the nth
/// argument that starts with one, so the cut lands after them. `Err` means
/// the words could not be lined up with the arguments, or that the text holds
/// what this reading does not model: `$'...'` and `$"..."` quotes, whose
/// escapes can hide a quote or spell `#`, and a `#` right after an unquoted
/// `;|&()<>`, where bash starts a comment without whitespace.
pub(super) fn comment_cut(text: &str, arguments: &[String]) -> Result<Option<usize>, ()> {
    if text.contains('#') && (text.contains("$'") || text.contains("$\"") || glued_comment(text)) {
        return Err(());
    }
    let words = words(text);
    let Some(comment) = words.iter().position(|w| w.starts_with('#')) else {
        return Ok(None);
    };
    let mut nth = 0;
    for word in &words[..comment] {
        nth += usize::from(lead(word)? == Some('#'));
    }
    let mut hashed = (0..arguments.len()).filter(|&index| arguments[index].starts_with('#'));
    hashed.nth(nth).map(Some).ok_or(())
}

/// Whether a `#` bash reads as the start of a comment is glued to one of
/// `;|&()<>`. Both characters have to stand outside quotes: inside them the
/// operator is ordinary text and so is the `#` after it, which is how a pull
/// request number such as `"(#12)"` or an alternation such as `"a|## b"`
/// reads. Matching either one anywhere in the line sent every such command to
/// review as a line the spellings could not be read from.
fn glued_comment(text: &str) -> bool {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut previous: Option<char> = None;
    for c in text.chars() {
        if escaped {
            escaped = false;
            previous = None;
            continue;
        }
        match (quote, c) {
            (Some('\''), '\'') | (Some('"'), '"') => {
                quote = None;
                previous = None;
            }
            (Some('"') | None, '\\') => {
                escaped = true;
                previous = None;
            }
            (Some(_), _) => previous = None,
            (None, '\'' | '"') => {
                quote = Some(c);
                previous = None;
            }
            (None, '#') => {
                if previous.is_some_and(|previous| ";|&()<>".contains(previous)) {
                    return true;
                }
                previous = Some('#');
            }
            (None, _) => previous = Some(c),
        }
    }
    false
}

/// The first character of `word` once bash removes its quotes. `Err` when
/// an escape decides it and the reading is not certain.
fn lead(word: &str) -> Result<Option<char>, ()> {
    let mut rest = word;
    while let Some(next) = rest
        .strip_prefix("''")
        .or_else(|| rest.strip_prefix("\"\""))
    {
        rest = next;
    }
    let mut chars = rest.chars();
    let first = match chars.next() {
        Some('\'') => chars.next(),
        Some('"') => double_quoted(chars.next(), chars.next())?,
        Some('\\') => match chars.next() {
            Some('\n') => return Err(()),
            other => other,
        },
        other => other,
    };
    Ok(first)
}

/// The first character inside double quotes, where `\` escapes only a few.
fn double_quoted(first: Option<char>, second: Option<char>) -> Result<Option<char>, ()> {
    match (first, second) {
        (Some('\\'), Some('$' | '`' | '"' | '\\')) => Ok(second),
        (Some('\\'), Some('\n')) => Err(()),
        _ => Ok(first),
    }
}

/// The words of `text` split at whitespace outside quotes, quotes kept.
pub(super) fn words(text: &str) -> Vec<&str> {
    let mut words = Vec::new();
    let mut start: Option<usize> = None;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (index, c) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match (quote, c) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('"') | None, '\\') => {
                start.get_or_insert(index);
                escaped = true;
            }
            (Some(_), _) => {}
            (None, '\'' | '"') => {
                start.get_or_insert(index);
                quote = Some(c);
            }
            (None, c) if c.is_whitespace() => {
                if let Some(begin) = start.take() {
                    words.push(&text[begin..index]);
                }
            }
            (None, _) => {
                start.get_or_insert(index);
            }
        }
    }
    if let Some(begin) = start {
        words.push(&text[begin..]);
    }
    words
}
