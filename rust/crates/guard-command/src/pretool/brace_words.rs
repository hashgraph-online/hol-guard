//! The words the shell makes of one argument by brace expansion.

/// At most this many words; a larger expansion is not followed.
const MAX_WORDS: usize = 16;

/// The words the shell makes of `text` by brace expansion, or `None` when
/// that takes more than [`MAX_WORDS`] words or holds a `{a..b}` sequence,
/// which this does not expand.
///
/// Only a brace with a comma at its own level expands, so
/// `if={safe:dummy,.env}` makes `if=safe:dummy` and `if=.env`, while a
/// compact GraphQL `query=mutation{...}` keeps its comma-free braces as
/// literal text: `{thread{id,isResolved}}` makes `{threadid}` and
/// `{threadisResolved}`.
pub(super) fn shell_brace_words(text: &str) -> Option<Vec<String>> {
    let (mut pending, mut words) = (vec![text.to_owned()], Vec::new());
    while let Some(word) = pending.pop() {
        let Some((open, close)) = expanding_brace(&word)? else {
            words.push(word);
            continue;
        };
        for alternative in top_level_alternatives(&word[open + 1..close]) {
            pending.push(format!(
                "{}{alternative}{}",
                &word[..open],
                &word[close + 1..]
            ));
        }
        if pending.len() + words.len() > MAX_WORDS {
            return None;
        }
    }
    Some(words)
}

/// The first closed `{...}` in `word` with a comma at its own level, as the
/// byte offsets of its braces. `Err` when a brace holds a sequence such as
/// `{v..v}` or `{1..3..1}`.
fn expanding_brace(word: &str) -> Option<Option<(usize, usize)>> {
    let bytes = word.as_bytes();
    let (mut opens, mut index) = (Vec::<(usize, bool)>::new(), 0);
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'\\' => index += 1,
            b'{' => opens.push((index, false)),
            b',' => {
                if let Some(open) = opens.last_mut() {
                    open.1 = true;
                }
            }
            b'}' => match opens.pop() {
                Some((open, true)) => return Some(Some((open, index))),
                Some((open, false)) if sequence(&word[open + 1..index]) => return None,
                _ => {}
            },
            _ => {}
        }
        index += 1;
    }
    Some(None)
}

/// Whether a comma-free brace body is a bash sequence: two or three
/// non-empty parts split by `..`, such as `v..v` or `1..9..2`.
fn sequence(body: &str) -> bool {
    let parts: Vec<&str> = body.split("..").collect();
    (2..=3).contains(&parts.len())
        && parts.iter().all(|part| {
            let digits = part.strip_prefix('-').unwrap_or(part);
            !part.is_empty()
                && (part.chars().count() == 1 || digits.chars().all(|c| c.is_ascii_digit()))
        })
}

/// `body` split at its commas that are not inside a nested brace.
fn top_level_alternatives(body: &str) -> Vec<&str> {
    let (mut alternatives, mut depth, mut start, mut escaped) = (Vec::new(), 0usize, 0, false);
    for (index, character) in body.char_indices() {
        match character {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                alternatives.push(&body[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    alternatives.push(&body[start..]);
    alternatives
}

#[cfg(test)]
mod tests {
    use super::shell_brace_words;

    fn words(text: &str) -> Option<Vec<String>> {
        shell_brace_words(text).map(|mut words| {
            words.sort();
            words
        })
    }

    #[test]
    fn only_comma_braces_expand_and_sequences_are_not_followed() {
        assert_eq!(
            words("if={safe:dummy,.env}").unwrap(),
            ["if=.env", "if=safe:dummy"]
        );
        assert_eq!(words("a{b{c,d}}").unwrap(), ["a{bc}", "a{bd}"]);
        assert_eq!(words("{a,b}{c,d}").unwrap().len(), 4);
        assert_eq!(words("q={viewer{...F}}").unwrap(), ["q={viewer{...F}}"]);
        assert_eq!(words(r"x{a\,b}").unwrap(), [r"x{a\,b}"]);
        assert_eq!(words(".e{n..n}{v..v}"), None);
        assert_eq!(words("{1..3..1}"), None);
        assert_eq!(words("{a,b}{c,d}{e,f}{g,h}{i,j}"), None);
    }
}
