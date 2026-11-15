//! Words of a shell step as written, quotes kept, and where a comment cuts it.

/// The argument where bash's comment starts: the first word that begins
/// with an unquoted `#`. A quoted or escaped `#` is text. The nth word that
/// spells a leading `#` is the nth argument that starts with one once quotes
/// are removed, so the cut lands on that argument.
pub(super) fn comment_cut(text: &str, arguments: &[String]) -> Option<usize> {
    let nth = words(text)
        .into_iter()
        .filter(|w| {
            w.trim_start_matches(['\'', '"', '\\', '$'])
                .starts_with('#')
        })
        .position(|w| w.starts_with('#'))?;
    (0..arguments.len())
        .filter(|&index| arguments[index].starts_with('#'))
        .nth(nth)
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
